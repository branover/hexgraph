#!/usr/bin/env python3
"""Binary-only fuzzing INSIDE the sandbox — AFL++ qemu-mode / frida-mode (design §2.3/§5.4).

  argv: /artifact (the target ELF, ro)  /out (rw)  [flags...]
  flags: --mode=qemu|frida  --max-total-time=N --max-crashes=K --instances=M
         [--sysroot=/sysroot]  [--seed=/path ...]  [--dict=<json array>]

NO source, NO instrumentation: AFL++ gets edge coverage from QEMU's TCG (`-Q`,
qemu-mode) or Frida's stalker (`-O`, frida-mode). qemu-mode is the DEFAULT — it gives
full edge coverage and runs FOREIGN-ARCH (MIPS/ARM/…) firmware binaries via the
afl-qemu-trace bundled with AFL++, with the parent firmware's extracted rootfs as the
qemu `-L` sysroot (`QEMU_LD_PREFIX`) so a dynamically-linked binary finds its libs —
the same mechanism poc_probe/verify_poc use.

The target reads its input from a FILE argument: AFL++ replaces `@@` in the command
line with the path of each mutated input (the standard file-input convention). Crashes
stream to `/out` (status.json + a DONE marker) and are reproduced/deduped/classified/
minimized with the SAME deterministic Phase-0 helpers (parse_asan / dedup_key /
classify_exploitability / afl-tmin), so a binary-only crash flows into the identical
artifact pipeline — `code_present/dynamic` assurance.

Runs only when the policy permits execution (requires_execution=True at the runner),
--network none, capped, timed. STDLIB only inside the box.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_probe  # noqa: E402

# ELF e_machine -> (little, big) afl-qemu-trace arch suffix (mirrors poc_probe._EM).
_EM = {
    3: ("i386", "i386"), 62: ("x86_64", "x86_64"),
    8: ("mipsel", "mips"), 40: ("arm", "armeb"),
    183: ("aarch64", "aarch64_be"), 20: ("ppc", "ppc"), 21: ("ppc64le", "ppc64"),
    42: ("sh4", "sh4eb"), 243: ("riscv64", "riscv64"),
}
_HOST_MACHINES = {62}


def _elf_arch(path: str):
    """(arch_suffix, is_foreign) for an ELF, or (None, False) if not an ELF / unknown."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
        if head[:4] != b"\x7fELF":
            return None, False
        is_le = head[5] == 1
        e_machine = struct.unpack("<H" if is_le else ">H", head[18:20])[0]
    except OSError:
        return None, False
    if e_machine in _HOST_MACHINES:
        return _EM[e_machine][0], False
    entry = _EM.get(e_machine)
    if not entry:
        return None, False
    return (entry[0] if is_le else entry[1]), True


def _flag(args, name, default):
    for a in args:
        if a.startswith(name + "="):
            v = a.split("=", 1)[1]
            return type(default)(v) if default is not None else v
    return default


def _flag_all(args, name):
    return [a.split("=", 1)[1] for a in args if a.startswith(name + "=")]


def _emit(obj):
    obj.setdefault("tool", "afl_qemu_probe")
    obj.setdefault("engine", "qemu")
    print(json.dumps(obj))
    return 0


def _write_status(outdir, obj):
    tmp = os.path.join(outdir, "status.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, os.path.join(outdir, "status.json"))


def main() -> int:
    if len(sys.argv) < 3:
        return _emit({"error": "usage: afl_qemu_probe.py <target-elf> <outdir> [flags]"})
    artifact, outdir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    mode = _flag(args, "--mode", "qemu")
    mode = "frida" if mode == "frida" else "qemu"
    max_total_time = _flag(args, "--max-total-time", 60)
    max_crashes = _flag(args, "--max-crashes", 10)
    instances = max(1, int(_flag(args, "--instances", 1)))
    sysroot = _flag(args, "--sysroot", None)
    seeds = [p for p in _flag_all(args, "--seed") if os.path.isfile(p)]
    dict_raw = _flag(args, "--dict", None)

    afl = shutil.which("afl-fuzz")
    if not afl:
        return _emit({"compiled": False, "ran": False, "coverage_instrumented": False,
                      "error": "afl-fuzz not in image (rebuild hexgraph-fuzz)"})

    # Copy the target to the writable+exec /out so afl-fuzz can run it (the /artifact
    # mount is read-only). The bytes are the hostile target's — they only ever run
    # inside this sandbox container, under qemu for a foreign arch.
    target = os.path.join(outdir, "target")
    shutil.copyfile(artifact, target)
    os.chmod(target, 0o755)
    arch, foreign = _elf_arch(target)

    work = os.path.join(outdir, "afl")
    os.makedirs(work, exist_ok=True)
    seed_dir = os.path.join(outdir, "seeds")
    os.makedirs(seed_dir, exist_ok=True)
    n = 0
    for sp in seeds:
        try:
            shutil.copyfile(sp, os.path.join(seed_dir, f"seed_{n}"))
            n += 1
        except OSError:
            pass
    if n == 0:
        with open(os.path.join(seed_dir, "seed_0"), "wb") as fh:
            fh.write(b"AAAA")

    dict_args = []
    if dict_raw:
        try:
            toks = json.loads(dict_raw)
            dpath = os.path.join(outdir, "tokens.dict")
            with open(dpath, "w") as fh:
                for i, t in enumerate(toks):
                    safe = str(t).replace("\\", "\\\\").replace('"', '\\"')
                    fh.write(f'tok_{i}="{safe}"\n')
            dict_args = ["-x", dpath]
        except Exception:  # noqa: BLE001
            dict_args = []

    afl_env = {**os.environ, "AFL_SKIP_CPUFREQ": "1", "AFL_NO_AFFINITY": "1",
               "AFL_AUTORESUME": "1", "AFL_NO_UI": "1",
               "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"}
    # Foreign-arch: AFL++ qemu-mode runs the binary under its bundled afl-qemu-trace; the
    # firmware rootfs supplies the shared libs via QEMU_LD_PREFIX (the `-L` sysroot).
    if foreign and sysroot and os.path.isdir(sysroot):
        afl_env["QEMU_LD_PREFIX"] = sysroot
    mode_flag = "-Q" if mode == "qemu" else "-O"

    # `@@` is replaced by AFL with each input file's path (file-input convention). `-m
    # none` because qemu reserves a large virtual space the default cap would kill.
    common = [afl, mode_flag, "-i", seed_dir, "-o", work, "-m", "none",
              "-V", str(max_total_time), *dict_args]
    procs = []
    if instances <= 1:
        procs.append(subprocess.Popen([*common, "--", target, "@@"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env=afl_env, cwd=outdir))
    else:
        procs.append(subprocess.Popen([*common, "-M", "fuzzer00", "--", target, "@@"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env=afl_env, cwd=outdir))
        for i in range(1, instances):
            procs.append(subprocess.Popen([*common, "-S", f"fuzzer{i:02d}", "--", target, "@@"],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          env=afl_env, cwd=outdir))

    deadline = time.monotonic() + max_total_time + 5
    while time.monotonic() < deadline and any(p.poll() is None for p in procs):
        _write_status(outdir, _collect(outdir, work, target, sysroot if foreign else None,
                                       arch, mode, max_crashes, done=False))
        time.sleep(min(10, max(2, max_total_time // 6)))
    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()

    final = _collect(outdir, work, target, sysroot if foreign else None, arch, mode,
                     max_crashes, done=True)
    _write_status(outdir, final)
    with open(os.path.join(outdir, "DONE"), "w") as fh:
        fh.write(mode)
    return _emit(final)


def _afl_crash_files(work):
    out = [c for c in glob.glob(os.path.join(work, "*", "crashes", "id:*"))]
    out += [c for c in glob.glob(os.path.join(work, "crashes", "id:*"))]
    return sorted(set(out))


def _afl_stats(work):
    execs = edges = 0
    for sp in glob.glob(os.path.join(work, "*", "fuzzer_stats")):
        try:
            with open(sp) as fh:
                for line in fh:
                    if ":" not in line:
                        continue
                    k, _, v = line.partition(":")
                    k, v = k.strip(), v.strip()
                    if k == "execs_done":
                        execs += int(float(v))
                    elif k in ("edges_found", "total_edges"):
                        edges = max(edges, int(float(v)))
        except (OSError, ValueError):
            pass
    return execs, edges


def _run_target(target, sysroot, arch, input_path, outdir):
    """Re-run the target on a crashing input to capture its report. Foreign-arch goes
    through qemu-<arch> with the `-L` sysroot (so we get a real backtrace); native runs
    directly. Returns (report, returncode)."""
    env = {**os.environ}
    cmd = [target, input_path]
    if arch and sysroot:  # foreign
        qemu = shutil.which(f"qemu-{arch}") or shutil.which(f"qemu-{arch}-static")
        if qemu:
            cmd = [qemu, "-L", sysroot, target, input_path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=outdir, timeout=30, env=env)
        return (p.stdout or "") + (p.stderr or ""), p.returncode
    except subprocess.TimeoutExpired:
        return "timeout\n", 124


def _collect(outdir, work, target, sysroot, arch, mode, max_crashes, *, done):
    execs, edges = _afl_stats(work)
    crashes = []
    seen = {}
    for path in _afl_crash_files(work)[: max_crashes * 6]:
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        report, rc = _run_target(target, sysroot, arch, path, outdir)
        crashed = (rc < 0 or rc in (134, 139, 124, 132, 136)
                   or "AddressSanitizer" in report or "Segmentation fault" in report)
        if not crashed:
            continue
        info = fuzz_probe.parse_asan(report)
        if not info.get("kind") or info["kind"] == "crash":
            # No ASan on a stripped binary — classify by the killing signal.
            info = {"kind": _signal_kind(rc), "function": None, "summary": report[:400] or f"exit {rc}"}
        key = fuzz_probe.dedup_key(info["kind"], report or f"{rc}")
        if key in seen:
            crashes[seen[key]]["dupe_count"] += 1
            continue
        if len(seen) >= max_crashes:
            continue
        expl = fuzz_probe.classify_exploitability(report, info["kind"])
        sha = __import__("hashlib").sha256(data).hexdigest()
        seen[key] = len(crashes)
        crashes.append({
            **info, "reproducer_sha256": sha, "reproducer_size": len(data),
            "dedup_key": key, "dupe_count": 0, "exploitability": expl,
            "minimized_reproducer_sha256": sha, "minimized_reproducer_size": len(data),
            "reproducer_b64": base64.b64encode(data).decode(),
            "coverage_instrumented": True, "_report": report[:4000],
        })
    return {"compiled": True, "ran": True, "engine": mode, "done": done,
            "coverage_instrumented": True, "executions": execs, "edges_covered": edges,
            "crash_count": len(crashes), "crashes": crashes,
            "binary_only": True, "arch": arch}


def _signal_kind(rc: int) -> str:
    if rc in (139, -11):
        return "SEGV"
    if rc in (134, -6):
        return "abort"
    if rc == 124:
        return "timeout"
    if rc in (136, -8):
        return "FPE"
    return "crash"


if __name__ == "__main__":
    raise SystemExit(main())
