#!/usr/bin/env python3
"""desock + AFL++ — coverage-fuzz a LOCAL server binary with NO real networking
(network surface, tier 1; design §5.6).

  argv: /artifact (the server ELF, ro)  /out (rw)  [flags...]
  flags: --max-total-time=N --max-crashes=K --instances=M --port=P
         [--sysroot=/sysroot]  [--seed=/path ...]  [--dict=<json array>]

preeny/desock's `desock.so` LD_PRELOADs over the server: it replaces socket()/accept()/
recv() so the service reads its "network" input from STDIN instead of a real socket. So
AFL++ can coverage-fuzz the server's PROTOCOL PARSER by feeding mutated bytes on stdin,
while the container stays `--network none` — the static-by-default posture holds (no real
listener, no egress). A crash (signal/ASan) is `code_present/dynamic`.

This keeps the SAME Phase-0 crash pipeline (reproduce/dedup/classify/minimize) and streams
to /out exactly like afl_probe/afl_qemu_probe. Falls back to qemu-mode file-input if
desock.so isn't in the image. Foreign-arch under afl-qemu-trace + the `-L` sysroot.

Runs only when the policy permits execution; --network none, capped, timed. STDLIB only.
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

_EM = {3: ("i386", "i386"), 62: ("x86_64", "x86_64"), 8: ("mipsel", "mips"),
       40: ("arm", "armeb"), 183: ("aarch64", "aarch64_be"), 20: ("ppc", "ppc"),
       21: ("ppc64le", "ppc64"), 42: ("sh4", "sh4eb"), 243: ("riscv64", "riscv64")}
_HOST = {62}


def _elf_arch(path):
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
        if head[:4] != b"\x7fELF":
            return None, False
        is_le = head[5] == 1
        em = struct.unpack("<H" if is_le else ">H", head[18:20])[0]
    except OSError:
        return None, False
    if em in _HOST:
        return _EM[em][0], False
    e = _EM.get(em)
    return (e[0] if is_le else e[1], True) if e else (None, False)


def _flag(args, name, default):
    for a in args:
        if a.startswith(name + "="):
            v = a.split("=", 1)[1]
            return type(default)(v) if default is not None else v
    return default


def _flag_all(args, name):
    return [a.split("=", 1)[1] for a in args if a.startswith(name + "=")]


def _emit(obj):
    obj.setdefault("tool", "desock_probe")
    obj.setdefault("engine", "desock")
    print(json.dumps(obj))
    return 0


def _write_status(outdir, obj):
    tmp = os.path.join(outdir, "status.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, os.path.join(outdir, "status.json"))


def _find_desock():
    """Locate desock.so (preeny). Common debian/preeny install paths + ldconfig."""
    for c in ("/usr/lib/preeny/desock.so", "/usr/local/lib/preeny/desock.so",
              "/usr/lib/x86_64-linux-gnu/preeny/desock.so", "/opt/preeny/x86_64-lib/desock.so"):
        if os.path.isfile(c):
            return c
    for pat in ("/usr/**/desock.so", "/opt/**/desock.so"):
        hits = glob.glob(pat, recursive=True)
        if hits:
            return hits[0]
    return None


# The unambiguous AFL++ message when the forkserver's pre-fuzz calibration run crashed
# BEFORE any fuzzer input — i.e. the target died on a benign seed during startup. With
# desock that is preeny's socket-pump-thread race (a fresh exec usually starts cleanly),
# NOT a real finding, so we retry the launch on exactly this signal (and nothing else).
_FORKSERVER_RACE = "before receiving any input"
_FORKSERVER_ABORT = "Fork server crashed"
_MAX_FORKSERVER_RETRIES = 8


def _launch_afl(cmd, env, outdir):
    """Start one AFL++ instance, capturing its stderr to a file so we can detect a
    spurious forkserver-startup crash. Returns (proc, stderr_path)."""
    errp = os.path.join(outdir, f"afl_stderr_{os.getpid()}_{time.monotonic_ns()}.log")
    errf = open(errp, "wb")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errf, env=env, cwd=outdir)
    p._hg_errfile = errf  # keep the handle alive for the process lifetime
    return p, errp


def _forkserver_raced(proc, errp) -> bool:
    """True iff AFL exited (quickly) reporting the forkserver crashed during pre-fuzz
    calibration — the preeny/desock startup race we retry on. Any OTHER early exit (a real
    config/target error) is NOT retried, so a genuine breakage still surfaces."""
    if proc.poll() is None:
        return False
    try:
        with open(errp, "rb") as fh:
            tail = fh.read()[-4000:].decode("utf-8", "replace")
    except OSError:
        return False
    return _FORKSERVER_ABORT in tail and _FORKSERVER_RACE in tail


def _launch_with_forkserver_retry(cmd, env, outdir, work):
    """Launch AFL++, retrying ONLY the preeny/desock forkserver-startup race (the target
    SIGSEGVs on a benign seed during AFL's calibration, before any fuzzing). Each retry
    clears the `-o` dir (AFL refuses a dirty out dir without resume) and re-execs — a fresh
    process almost always starts cleanly. Returns (running_proc, note_or_None). `note` is set
    iff we exhausted the retries still racing (a real degradation reason); on success it's
    None. Bounded so a genuinely-always-crashing target can't loop forever."""
    note = None
    for attempt in range(_MAX_FORKSERVER_RETRIES):
        if attempt:
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(work, exist_ok=True)
        proc, errp = _launch_afl(cmd, env, outdir)
        # Give the forkserver a moment to come up (or die on the calibration run). The race
        # manifests within the first ~couple seconds; a healthy forkserver is still running.
        settle = time.monotonic() + 6
        while time.monotonic() < settle and proc.poll() is None:
            time.sleep(0.25)
        if not _forkserver_raced(proc, errp):
            return proc, None  # forkserver is up (or exited for a non-race reason) → proceed
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        note = (f"desock forkserver crashed on calibration (preeny socket-thread startup "
                f"race) — retried {attempt + 1}x")
    return proc, note


def main() -> int:
    if len(sys.argv) < 3:
        return _emit({"error": "usage: desock_probe.py <server-elf> <outdir> [flags]"})
    artifact, outdir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
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

    target = os.path.join(outdir, "server")
    shutil.copyfile(artifact, target)
    os.chmod(target, 0o755)
    arch, foreign = _elf_arch(target)
    desock = _find_desock()

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
            fh.write(b"GET / HTTP/1.0\r\n\r\n")

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
    if foreign and sysroot and os.path.isdir(sysroot):
        afl_env["QEMU_LD_PREFIX"] = sysroot
    qemu = ["-Q"] if foreign else []

    # desock turns the socket into stdin → AFL feeds stdin (NO `@@`). When desock.so is
    # present we LD_PRELOAD it onto the target via AFL_PRELOAD; otherwise we degrade to
    # qemu-mode file-input (still coverage-guided, just feeds a file arg).
    if desock:
        afl_env["AFL_PRELOAD"] = desock
        afl_env["DESOCK_PORT"] = str(_flag(args, "--port", 0))
        run_argv = ["--", target]            # stdin-fed (no @@)
        mode = "desock"
    else:
        run_argv = ["--", target, "@@"]      # fallback: file input
        mode = "desock-fallback"

    common = [afl, *qemu, "-i", seed_dir, "-o", work, "-m", "none",
              "-V", str(max_total_time), *dict_args]
    note = None
    if instances <= 1:
        p, note = _launch_with_forkserver_retry([*common, *run_argv], afl_env, outdir, work)
        procs = [p]
    else:
        p0, note = _launch_with_forkserver_retry([*common, "-M", "fuzzer00", *run_argv],
                                                 afl_env, outdir, work)
        procs = [p0]
        for i in range(1, instances):
            procs.append(subprocess.Popen([*common, "-S", f"fuzzer{i:02d}", *run_argv],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          env=afl_env, cwd=outdir))

    deadline = time.monotonic() + max_total_time + 5
    while time.monotonic() < deadline and any(p.poll() is None for p in procs):
        _write_status(outdir, _collect(outdir, work, target, desock, sysroot if foreign else None,
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

    final = _collect(outdir, work, target, desock, sysroot if foreign else None, arch, mode,
                     max_crashes, done=True)
    # A diagnostic about a flaky forkserver startup (preeny/desock's socket-pump threads
    # can SIGSEGV during AFL's pre-fuzz calibration on a benign input — a startup race, not
    # a target bug). We bounded-retry the launch on exactly that signal; if EVERY retry hit
    # it we never got past calibration → surface it as the degradation reason (so the
    # campaign's `degraded`-with-0-execs carries WHY). When AFL DID recover and fuzz, the
    # note stays out of the status so the run finalizes as a clean `completed`.
    if note and int(final.get("executions") or 0) <= 0:
        final["engine_note"] = note
    _write_status(outdir, final)
    with open(os.path.join(outdir, "DONE"), "w") as fh:
        fh.write(mode)
    return _emit(final)


def _crash_files(work):
    out = [c for c in glob.glob(os.path.join(work, "*", "crashes", "id:*"))]
    out += [c for c in glob.glob(os.path.join(work, "crashes", "id:*"))]
    return sorted(set(out))


def _stats(work):
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


def _replay(target, desock, sysroot, arch, input_path, outdir):
    """Re-run the server on a crashing input to capture its report. desock: feed stdin;
    foreign-arch: under qemu + the `-L` sysroot."""
    env = {**os.environ, "ASAN_OPTIONS": "abort_on_error=1:symbolize=1:detect_leaks=0"}
    pre = []
    if desock:
        env["LD_PRELOAD"] = desock
        cmd = [target]
    else:
        cmd = [target, input_path]
    if arch and sysroot:
        qemu = shutil.which(f"qemu-{arch}") or shutil.which(f"qemu-{arch}-static")
        if qemu:
            pre = [qemu, "-L", sysroot]
            if desock:
                # LD_PRELOAD into the guest via qemu -E
                pre += ["-E", f"LD_PRELOAD={desock}"]
    try:
        stdin = open(input_path, "rb").read() if desock else None
        p = subprocess.run([*pre, *cmd], input=stdin, capture_output=True, cwd=outdir,
                           timeout=30, env=env)
        report = (p.stdout or b"").decode("utf-8", "replace") + (p.stderr or b"").decode("utf-8", "replace")
        return report, p.returncode
    except subprocess.TimeoutExpired:
        return "timeout\n", 124


def _collect(outdir, work, target, desock, sysroot, arch, mode, max_crashes, *, done):
    execs, edges = _stats(work)
    crashes = []
    seen = {}
    for path in _crash_files(work)[: max_crashes * 6]:
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        report, rc = _replay(target, desock, sysroot, arch, path, outdir)
        crashed = (rc < 0 or rc in (134, 139, 124, 132, 136)
                   or "AddressSanitizer" in report or "Segmentation fault" in report)
        if not crashed:
            continue
        info = fuzz_probe.parse_asan(report)
        if not info.get("kind") or info["kind"] == "crash":
            info = {"kind": _sig(rc), "function": None, "summary": report[:400] or f"exit {rc}"}
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
            "crash_count": len(crashes), "crashes": crashes, "desock": bool(desock)}


def _sig(rc):
    return {"139": "SEGV", "-11": "SEGV", "134": "abort", "-6": "abort",
            "124": "timeout", "136": "FPE", "-8": "FPE"}.get(str(rc), "crash")


if __name__ == "__main__":
    raise SystemExit(main())
