#!/usr/bin/env python3
"""Launch a LOCAL server binary as a long-lived loopback service (launch-and-join,
design §5.8b). This is the SERVICE half of the loopback-reachable network-fuzz path:
HexGraph runs this probe in its OWN detached, hardened sandbox container; the server
listens on THAT container's loopback (`127.0.0.1:<port>`), and the fuzzer container then
joins this container's network namespace (`--network container:<this>`) so it can reach
`127.0.0.1:<port>` WITHOUT --network host — same isolation, no host networking.

  argv: /artifact (the server ELF, ro)  /out (rw)  [flags...]
  flags: --port=P  [--sysroot=/sysroot]  [--cmd=<json array of extra argv>]

The container HexGraph launches it in already supplies the hardening (--read-only,
--cap-drop ALL, --no-new-privileges, --user 1000, resource caps). This probe only
EXECUTES the (hostile) target — so it runs ONLY when the policy permits execution (the
runner gates the launch via requires_execution=True; the campaign engine asserts the
exec tier). Foreign-arch (MIPS/ARM/…) binaries run under qemu-user with the parent
firmware rootfs as the `-L` sysroot (the proven PoC/desock path). STDLIB only.

The process is run in the FOREGROUND so the container's lifetime IS the service's
lifetime: the reaper/stop tears the container (and thus the service) down. (A server that
double-forks/daemonizes off the foreground process would exit the container and break the
netns join — pass a `launch_command` keeping it in the foreground, e.g. a `-f`/`-D` flag.)
A small `status.json` ({launched, pid, port, ...}) and a `READY`/`EXITED` marker stream to
/out; the fuzzer waits out a startup grace (boofuzz `_wait_alive`) for the port to bind.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
import time

_EM = {3: ("i386", "i386"), 62: ("x86_64", "x86_64"), 8: ("mipsel", "mips"),
       40: ("arm", "armeb"), 183: ("aarch64", "aarch64_be"), 20: ("ppc", "ppc"),
       21: ("ppc64le", "ppc64"), 42: ("sh4", "sh4eb"), 243: ("riscv64", "riscv64")}
_HOST = {62}


def _qemu_prefix(target_path, sysroot):
    try:
        with open(target_path, "rb") as fh:
            head = fh.read(20)
        if head[:4] != b"\x7fELF":
            return []
        is_le = head[5] == 1
        em = struct.unpack("<H" if is_le else ">H", head[18:20])[0]
    except OSError:
        return []
    if em in _HOST:
        return []
    entry = _EM.get(em)
    if not entry:
        return []
    base = entry[0] if is_le else entry[1]
    qemu = shutil.which(f"qemu-{base}") or shutil.which(f"qemu-{base}-static")
    if not qemu:
        return []
    pre = [qemu]
    if sysroot and os.path.isdir(sysroot):
        pre += ["-L", sysroot]
    return pre


def _flag(args, name, default=None):
    for a in args:
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _write_status(outdir, obj):
    tmp = os.path.join(outdir, "status.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, os.path.join(outdir, "status.json"))


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: service_launch_probe.py <elf> <outdir> [flags]"}))
        return 1
    artifact, outdir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    port = int(_flag(args, "--port", "0") or 0)
    sysroot = _flag(args, "--sysroot", None)
    cmd_raw = _flag(args, "--cmd", None)
    extra_argv = []
    if cmd_raw:
        try:
            extra_argv = [str(a) for a in (json.loads(cmd_raw) or [])]
        except (ValueError, TypeError):
            extra_argv = []

    os.makedirs(outdir, exist_ok=True)
    # Copy the server ELF to the writable+exec /out and run it from there (the rootfs is
    # read-only; /artifact is ro). chmod +x so a foreign-arch or stripped ELF runs.
    target = os.path.join(outdir, "service")
    shutil.copyfile(artifact, target)
    os.chmod(target, 0o755)

    prefix = _qemu_prefix(target, sysroot)

    # setarch -R = personality(ADDR_NO_RANDOMIZE): run the launched service with ASLR OFF.
    # On high-ASLR-entropy kernels (vm.mmap_rnd_bits=32 — WSL2 6.6.x / Ubuntu 23.10+ / CI
    # runners) an ASan-instrumented daemon's MAP_FIXED shadow reservation otherwise
    # intermittently collides with a randomized mapping and the process SIGSEGVs during ASan
    # init, BEFORE main (exit_code -11, ~nondeterministic). ASLR-off makes the address space
    # deterministic so the shadow always fits — identical to the AFL/desock probes. The
    # container is launched with the minimal default+personality seccomp profile
    # (start_detached(disable_aslr=True) → runner) so this is permitted under
    # --no-new-privileges. If setarch isn't present we fall through to a bare invocation
    # (the bug is then latent but the launch still attempts to run). NOT a security flag:
    # it does not touch --network/caps/read-only/--user.
    setarch = shutil.which("setarch")
    aslr_off = [setarch, os.uname().machine, "-R"] if setarch else []
    cmd = [*aslr_off, *prefix, target, *extra_argv]

    # ASan defaults: abort (so a real crash is a clean SIGABRT, not a confusing later state),
    # symbolize the report (we read the launched-service log directly, no AFL parser to satisfy
    # — unlike the fuzz child which needs symbolize=0), no leak detection at exit (a long-lived
    # daemon torn down by the container would otherwise spew bogus leak reports). Merge over
    # any inherited env so a target that needs its own vars keeps them.
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0:symbolize=1"

    # The hostile target writes nothing we trust; capture its output to a log on /out so a
    # failed launch is diagnosable, but keep stdin closed (a daemon does not read our stdin).
    log = open(os.path.join(outdir, "service.log"), "wb")
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                cwd=outdir, env=env)
    except OSError as exc:
        _write_status(outdir, {"launched": False, "port": port,
                               "error": f"could not launch service: {exc}"})
        open(os.path.join(outdir, "EXITED"), "w").write("launch-failed")
        return 1

    _write_status(outdir, {"launched": True, "pid": proc.pid, "port": port,
                           "foreign_arch": bool(prefix), "started_at": time.time()})
    # Signal readiness (best-effort: the service is up; the campaign engine + boofuzz's own
    # connect-with-retry confirm the port is actually accepting). The container stays alive
    # as long as the service does — its teardown is the reaper's/stop's job.
    open(os.path.join(outdir, "READY"), "w").write(str(proc.pid))
    rc = proc.wait()
    log.close()
    _write_status(outdir, {"launched": True, "pid": proc.pid, "port": port,
                           "foreign_arch": bool(prefix), "exit_code": rc})
    open(os.path.join(outdir, "EXITED"), "w").write(str(rc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
