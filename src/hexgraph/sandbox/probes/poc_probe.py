#!/usr/bin/env python3
"""Verify a proof-of-concept by EXECUTING the target in the sandbox (dynamic).

  argv: /artifact /out --spec <json>

The spec describes how to run the target and how to know the PoC worked:
  {
    "argv":  ["..."],                 # extra args after the program (optional)
    "env":   {"QUERY_STRING": "..."}, # environment for the run (optional)
    "stdin": "...",                   # stdin to feed as text (optional)
    "stdin_b64": "...",               # stdin to feed as RAW BYTES, base64'd (optional, byte-faithful)
    "timeout": 20,                    # wall-clock seconds (optional)
    "oracle": {"type": "output_contains"|"exit_code"|"exit_nonzero"|"crash", "value": ...}
  }

Emits JSON: {ran, verified, exit_code, signal, output, oracle, detail}.

Runs ONLY when the analysis policy permits execution (PoC/fuzzing enabled) — the
runner gates this via requires_execution=True. Still --network none, capped,
timed, disposable. We copy the target to the writable+exec /out and run it there.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys

# ELF e_machine -> qemu-user binary base name. Endianness/word-size are resolved
# from the ELF header at runtime (e.g. MIPS LE -> qemu-mipsel, BE -> qemu-mips).
_EM = {
    3: ("i386", "i386"), 62: ("x86_64", "x86_64"),
    8: ("mipsel", "mips"),            # (little, big)
    40: ("arm", "armeb"),
    183: ("aarch64", "aarch64_be"),
    20: ("ppc", "ppc"), 21: ("ppc64le", "ppc64"),
    42: ("sh4", "sh4eb"),
    243: ("riscv64", "riscv64"),
}
_HOST_MACHINES = {62}  # x86-64 host runs these natively


def _qemu_prefix(target_path: str, sysroot: str | None, argv0: str | None = None) -> list:
    """[] if the target is host-native; else [qemu-<arch>, (-L sysroot), (-0 argv0)]
    so a foreign-arch (MIPS/ARM/…) binary runs under qemu-user. sysroot supplies the
    target's shared libraries for dynamically-linked binaries; argv0 overrides
    argv[0] (e.g. a busybox multiplexer needs argv[0]=='busybox')."""
    try:
        with open(target_path, "rb") as fh:
            head = fh.read(20)
        if head[:4] != b"\x7fELF":
            return []
        is_le = head[5] == 1
        e_machine = struct.unpack("<H" if is_le else ">H", head[18:20])[0]
    except OSError:
        return []
    if e_machine in _HOST_MACHINES:
        return []
    entry = _EM.get(e_machine)
    if not entry:
        return []  # unknown arch — try to run native (will likely fail clearly)
    base = entry[0] if is_le else entry[1]
    qemu = shutil.which(f"qemu-{base}") or shutil.which(f"qemu-{base}-static")
    if not qemu:
        return []
    pre = [qemu]
    if sysroot and os.path.isdir(sysroot):
        pre += ["-L", sysroot]
    if argv0:
        pre += ["-0", argv0]
    return pre


def _flag(args, name, default=None):
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            return args[i + 1]
    return default


def _check_oracle(oracle: dict, output: str, rc: int) -> tuple[bool, str]:
    t = (oracle or {}).get("type", "output_contains")
    val = (oracle or {}).get("value")
    if t == "output_contains":
        return (str(val) in output, f"output {'contains' if str(val) in output else 'missing'} {val!r}")
    if t == "exit_code":
        return (rc == int(val), f"exit {rc} vs expected {val}")
    if t == "exit_nonzero":
        return (rc != 0, f"exit {rc}")
    if t == "crash":
        # killed by signal (negative rc) or ASan-style abort
        crashed = rc < 0 or rc in (134, 139) or "AddressSanitizer" in output or "Segmentation fault" in output
        return (crashed, f"exit {rc}{' (crash)' if crashed else ''}")
    return (False, f"unknown oracle type {t!r}")


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: poc_probe.py <artifact> <outdir> --spec <json>"}))
        return 2
    artifact, outdir, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    try:
        spec = json.loads(_flag(rest, "--spec", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --spec json: {exc}"}))
        return 2

    target = os.path.join(outdir, "poc_target")
    shutil.copyfile(artifact, target)
    os.chmod(target, 0o755)

    # Start from a minimal environment (not the sandbox's full os.environ) so the
    # executed target only sees what the PoC spec deliberately provides.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/scratch", "TMPDIR": "/scratch"}
    env.update({str(k): str(v) for k, v in (spec.get("env") or {}).items()})
    # Foreign-arch targets (MIPS/ARM/…) run under qemu-user; host-native run directly.
    prefix = _qemu_prefix(target, spec.get("sysroot"), spec.get("argv0"))
    cmd = [*prefix, target, *[str(a) for a in (spec.get("argv") or [])]]
    timeout = int(spec.get("timeout", 20))

    # stdin: prefer the BYTE-FAITHFUL `stdin_b64` (raw bytes — 0x00/0xff preserved exactly,
    # never text-encoded; the fix for replaying a binary fuzz reproducer over stdin). Falls
    # back to the text `stdin` field. Byte-mode subprocess (text=False) when bytes are given.
    stdin_b64 = spec.get("stdin_b64")
    stdin_bytes = None
    if stdin_b64 is not None:
        import base64
        try:
            stdin_bytes = base64.b64decode(stdin_b64)
        except Exception:  # noqa: BLE001 — a malformed b64 just yields no stdin
            stdin_bytes = b""
    try:
        if stdin_bytes is not None:
            proc = subprocess.run(cmd, env=env, cwd=outdir, capture_output=True,
                                  input=stdin_bytes, timeout=timeout)
            rc = proc.returncode
            out = (proc.stdout or b"").decode("utf-8", "replace") + \
                  (proc.stderr or b"").decode("utf-8", "replace")
        else:
            proc = subprocess.run(cmd, env=env, cwd=outdir, capture_output=True, text=True,
                                  input=spec.get("stdin"), timeout=timeout)
            rc, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        rc, out = 124, (exc.output or "") if isinstance(exc.output, str) else ""
    except OSError as exc:
        print(json.dumps({"tool": "poc_probe", "ran": False, "verified": False,
                          "detail": f"could not execute target: {exc}"}))
        return 0

    verified, detail = _check_oracle(spec.get("oracle") or {}, out, rc)
    print(json.dumps({"tool": "poc_probe", "ran": True, "verified": verified,
                      "exit_code": rc, "output": out[:8000], "oracle": spec.get("oracle"),
                      "detail": detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
