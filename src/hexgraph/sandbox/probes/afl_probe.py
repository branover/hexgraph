#!/usr/bin/env python3
"""Coverage-guided AFL++ source fuzzing INSIDE the sandbox (design §2.3, Phase 3).

  argv: /artifact (harness .c, ro)  /out (rw)  [flags...]
  flags: --max-total-time=N --max-crashes=K --instances=M
         --target-source=/path.c ...  [--seed=/path ...]  [--dict=<json array>]

This is the REAL coverage-guided path: the harness + the TARGET's own sources are
compiled with `afl-clang-fast` (SanitizerCoverage + ASan in the target's objects —
the Phase-2 instrumented derived target), a CmpLog binary is built with
`AFL_LLVM_CMPLOG=1` to defeat magic-byte / memcmp gates, a seed corpus + an
auto-dictionary jump-start it, and `afl-fuzz` runs in PERSISTENT mode for the budget
(a master + N-1 secondaries scale to host cores). Crashes are streamed to `/out` as
they happen: the probe writes `status.json` periodically (so a long campaign surfaces
its first crash in minutes) and a `DONE` marker on completion.

Each unique crash is reproduced for its ASan report, deduped by the normalized
stack-hash, classified for exploitability, and minimized with `afl-tmin` — REUSING
the deterministic Phase-0 helpers in fuzz_probe.py (dedup_key / classify_exploitability
/ parse_asan), now with llvm-symbolizer present so frames symbolize to function:line.
Coverage is reported from afl's own `plot_data`/`fuzzer_stats`.

Falls back gracefully: if afl-clang-fast isn't in the image it reports compiled=false;
if afl-fuzz can't bind shmem etc. it still collects whatever crashes appeared. Runs
only when the policy permits execution (requires_execution=True), --network none,
capped, timed.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import shutil
import subprocess
import sys
import time

# Reuse the deterministic Phase-0 triage helpers (same image path: probes are mounted).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_probe  # noqa: E402

SCRATCH = os.environ.get("TMPDIR", "/scratch")


def _flag(args, name, default):
    for a in args:
        if a.startswith(name + "="):
            val = a.split("=", 1)[1]
            return type(default)(val) if default is not None else val
    return default


def _flag_all(args, name):
    return [a.split("=", 1)[1] for a in args if a.startswith(name + "=")]


def _emit(obj):
    obj.setdefault("tool", "afl_probe")
    obj.setdefault("engine", "afl")
    print(json.dumps(obj))
    return 0


def _write_status(outdir, obj):
    obj.setdefault("engine", "afl")
    tmp = os.path.join(outdir, "status.json.tmp")
    with open(tmp, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, os.path.join(outdir, "status.json"))


def main() -> int:
    if len(sys.argv) < 3:
        return _emit({"error": "usage: afl_probe.py <harness.c> <outdir> [flags]"})
    src, outdir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    max_total_time = _flag(args, "--max-total-time", 60)
    max_crashes = _flag(args, "--max-crashes", 10)
    instances = max(1, int(_flag(args, "--instances", 1)))
    target_sources = [p for p in _flag_all(args, "--target-source") if os.path.isfile(p)]
    include_dirs = [d for d in _flag_all(args, "--include-dir") if os.path.isdir(d)]
    inc_flags = [f"-I{d}" for d in include_dirs]
    seeds = [p for p in _flag_all(args, "--seed") if os.path.isfile(p)]
    dict_raw = _flag(args, "--dict", None)

    cc = shutil.which("afl-clang-fast") or shutil.which("afl-clang-lto")
    if not cc:
        return _emit({"compiled": False, "ran": False, "coverage_instrumented": False,
                      "error": "afl-clang-fast not in image (rebuild hexgraph-fuzz)"})
    if not target_sources:
        return _emit({"compiled": False, "ran": False,
                      "error": "AFL++ source fuzzing needs --target-source"})

    work = os.path.join(outdir, "afl")
    os.makedirs(work, exist_ok=True)
    fuzzer = os.path.join(outdir, "fuzzer")
    cmplog = os.path.join(outdir, "fuzzer_cmplog")

    is_cxx = any(s.endswith((".cc", ".cpp", ".cxx", ".C", ".c++")) for s in target_sources)
    ccx = (shutil.which("afl-clang-fast++") or cc) if is_cxx else cc
    # Build the instrumented fuzzer: the harness exposes LLVMFuzzerTestOneInput (no
    # main), so link AFL++'s libFuzzer-compatible driver (`-fsanitize=fuzzer`) to supply
    # `main` + the persistent loop, while afl-clang-fast bakes SanCov+ASan into the
    # TARGET's own objects (real coverage). This runs under afl-fuzz in persistent mode.
    base_cmd = [ccx, "-g", "-O1", "-w", "-fsanitize=fuzzer,address", *inc_flags,
                "-x", "c", src, "-x", "none", *target_sources, "-o", fuzzer]
    benv = {**os.environ, "AFL_USE_ASAN": "1"}
    build = subprocess.run(base_cmd, capture_output=True, text=True, env=benv)
    if build.returncode != 0:
        return _emit({"compiled": False, "ran": False, "coverage_instrumented": False,
                      "stage": "instrumented-build", "stderr": (build.stderr or "")[:2000]})

    # CmpLog binary (magic-byte / memcmp gating). We build it, but CmpLog's auxiliary
    # forkserver is unstable when the harness `main` comes from the libFuzzer-compat
    # driver (`-fsanitize=fuzzer`) under ASan — it can crash AFL's `-c` forkserver. So
    # CmpLog is OPT-IN via AFL_HG_CMPLOG=1 here (the coverage-guided afl-clang-fast run
    # is already strong); when CmpLog gets its own AFL-instrumented `main` (a future
    # __AFL_FUZZ harness), it can default on. Best-effort either way.
    cmplog_ok = False
    if os.environ.get("AFL_HG_CMPLOG") == "1":
        cl = subprocess.run([ccx, "-g", "-O1", "-w", "-fsanitize=fuzzer", *inc_flags, "-x", "c", src,
                             "-x", "none", *target_sources, "-o", cmplog],
                            capture_output=True, text=True,
                            env={**os.environ, "AFL_LLVM_CMPLOG": "1"})
        cmplog_ok = cl.returncode == 0

    # Seed corpus (AFL++ needs at least one non-empty seed).
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

    # Auto-dictionary (magic tokens from the target's strings).
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

    afl = shutil.which("afl-fuzz")
    if not afl:
        return _emit({"compiled": True, "ran": False, "coverage_instrumented": True,
                      "error": "afl-fuzz not in image"})

    afl_env = {**os.environ, "AFL_SKIP_CPUFREQ": "1", "AFL_NO_AFFINITY": "1",
               "AFL_AUTORESUME": "1", "AFL_NO_UI": "1",
               # The sandbox can't write /proc/sys/kernel/core_pattern (read-only,
               # non-root) — without this AFL++ ABORTS on the pipe-core check. We DON'T
               # miss crashes: ASan aborts the child (abort_on_error=1) so AFL sees the
               # crash via waitpid, and we re-run + symbolize every saved input anyway.
               "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
               "AFL_SKIP_BIN_CHECK": "1",  # the libFuzzer-driver binary isn't afl-cc-shaped
               # Give the forkserver a generous handshake budget. The FIRST persistent-mode
               # exec under ASan+SanCov is heavy (the sanitizer runtime initialises lazily)
               # and on slow / heavily-constrained hosts can exceed AFL's default forkserver
               # init timeout — which AFL reports as "the fork server never came up". This
               # is a TIMING ceiling, NOT a security flag (it does not touch --network/caps/
               # read-only/--user); it only lets a slow-but-legitimate first exec complete.
               "AFL_FORKSRV_INIT_TMOUT": os.environ.get("AFL_FORKSRV_INIT_TMOUT", "60000"),
               # AFL++ REQUIRES symbolize=0 for the fuzzed child (it parses raw ASan
               # output); we symbolize later, at the reproduce stage, with symbolize=1.
               "ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0"}
    procs = []
    # afl-fuzz's stdout/stderr carry the forkserver/dry-run diagnostics; capture them to a
    # log so we can DISTINGUISH "couldn't even calibrate" (handshake/dry-run abort) from
    # "ran but found nothing" and report it loudly (vs. silently emitting zero crashes).
    afl_log = os.path.join(outdir, "afl.log")
    logfh = open(afl_log, "wb")
    # `-m none`: ASan reserves a huge virtual address space, which AFL's default memory
    # cap would kill (fork-server signal 11). The container's --memory cap (the
    # ResourceSpec) is the real RSS bound; AFL's per-exec vsize cap must be off for ASan.
    # `-t`: the per-exec timeout. The default is 1000 ms, but the FIRST instrumented
    # persistent exec (sanitizer init) can exceed that on a constrained box and trip AFL's
    # dry-run calibration ("test case results in a timeout"), aborting the whole campaign.
    # A generous fixed `-t` (overridable via AFL_HG_EXEC_TMOUT) clears that without masking
    # real hangs — a genuinely wedged input still times out, just at a saner bound. Like
    # AFL_FORKSRV_INIT_TMOUT this is a timing budget, not a sandbox relaxation.
    exec_tmout = os.environ.get("AFL_HG_EXEC_TMOUT", "10000")
    common = [afl, "-i", seed_dir, "-o", work, "-m", "none", "-t", exec_tmout,
              "-V", str(max_total_time), *dict_args]
    if cmplog_ok:
        common += ["-c", cmplog]
    # Master (-M) + secondaries (-S) for >1 instance.
    if instances <= 1:
        procs.append(subprocess.Popen([*common, "--", fuzzer],
                                      stdout=logfh, stderr=subprocess.STDOUT, env=afl_env))
    else:
        procs.append(subprocess.Popen([*common, "-M", "fuzzer00", "--", fuzzer],
                                      stdout=logfh, stderr=subprocess.STDOUT, env=afl_env))
        for i in range(1, instances):
            procs.append(subprocess.Popen([*common, "-S", f"fuzzer{i:02d}", "--", fuzzer],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          env=afl_env))

    # Stream status while afl runs (so a long campaign surfaces crashes in minutes).
    deadline = time.monotonic() + max_total_time + 5
    while time.monotonic() < deadline and any(p.poll() is None for p in procs):
        _write_status(outdir, _collect(outdir, work, fuzzer, max_crashes, done=False,
                                       coverage_instrumented=True))
        time.sleep(min(10, max(2, max_total_time // 6)))

    for p in procs:
        if p.poll() is None:
            p.terminate()
    for p in procs:
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    logfh.close()

    final = _collect(outdir, work, fuzzer, max_crashes, done=True, coverage_instrumented=True)
    # If afl-fuzz never managed a single exec (the forkserver handshake failed or the
    # dry-run calibration aborted — e.g. a host kernel where AFL++ persistent mode is
    # unstable), say so LOUDLY rather than passing off "0 crashes" as a clean run. The
    # campaign stays a real result (compiled=true, coverage_instrumented=true) but carries
    # an explicit diagnostic the engine/UI surface, so a maintainer isn't misled.
    if final.get("executions", 0) == 0:
        note = _afl_failure_note(afl_log)
        if note:
            final["afl_note"] = note
            final["ran"] = False
    _write_status(outdir, final)
    with open(os.path.join(outdir, "DONE"), "w") as fh:
        fh.write("afl")
    return _emit(final)


# Signatures of an afl-fuzz launch that never reached steady-state fuzzing — the
# forkserver handshake or the dry-run calibration aborted. Reported, never swallowed.
_AFL_FAIL_SIGNATURES = (
    ("Fork server crashed", "afl-fuzz forkserver crashed during the handshake (AFL++ "
                            "persistent mode may be unstable on this host kernel)"),
    ("Unable to communicate with fork server", "afl-fuzz forkserver did not come up"),
    ("All test cases time out", "afl-fuzz could not calibrate any seed (slow/unstable "
                                "persistent-mode forkserver on this host kernel)"),
    ("results in a timeout", "afl-fuzz dry-run calibration timed out (slow first exec — "
                             "AFL++ persistent mode may be unstable on this host kernel)"),
    ("PROGRAM ABORT", "afl-fuzz aborted before fuzzing began"),
)


def _afl_failure_note(afl_log: str) -> str | None:
    """Extract a human-readable reason from afl-fuzz's captured output when no exec ran.
    Returns None if the log doesn't match a known early-abort signature."""
    try:
        with open(afl_log, "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    for needle, msg in _AFL_FAIL_SIGNATURES:
        if needle in text:
            return msg
    return None


def _afl_crash_files(work):
    """All crash inputs across master+secondary output dirs (skip the README)."""
    out = []
    for c in glob.glob(os.path.join(work, "*", "crashes", "id:*")):
        out.append(c)
    out += [c for c in glob.glob(os.path.join(work, "crashes", "id:*"))]
    return sorted(set(out))


def _afl_stats(work):
    """(execs, edges_covered) from afl's fuzzer_stats across instances."""
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


def _collect(outdir, work, fuzzer, max_crashes, *, done, coverage_instrumented):
    """Reproduce, dedup, classify + minimize the crashes afl found so far (REUSING the
    Phase-0 helpers). Idempotent so streaming status mid-run is cheap + safe."""
    execs, edges = _afl_stats(work)
    crashes = []
    seen = {}
    for path in _afl_crash_files(work)[: max_crashes * 6]:
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        try:
            repro = subprocess.run([fuzzer, path], capture_output=True, text=True,
                                   cwd=outdir, timeout=30, env=fuzz_probe.symbolizer_env())
            report = (repro.stdout or "") + (repro.stderr or "")
            rc = repro.returncode
        except subprocess.TimeoutExpired:
            report, rc = "libFuzzer: timeout\n", 1
        if rc == 0:
            continue
        info = fuzz_probe.parse_asan(report)
        key = fuzz_probe.dedup_key(info["kind"], report)
        if key in seen:
            crashes[seen[key]]["dupe_count"] += 1
            continue
        if len(seen) >= max_crashes:
            continue
        expl = fuzz_probe.classify_exploitability(report, info["kind"])
        min_sha, min_size, min_bytes = _tmin(fuzzer, path, outdir)
        sha = __import__("hashlib").sha256(data).hexdigest()
        repro_bytes = min_bytes if min_bytes is not None else data
        seen[key] = len(crashes)
        crashes.append({
            **info, "reproducer_sha256": sha, "reproducer_size": len(data),
            "dedup_key": key, "dupe_count": 0, "exploitability": expl,
            "minimized_reproducer_sha256": min_sha, "minimized_reproducer_size": min_size,
            "reproducer_b64": base64.b64encode(repro_bytes).decode(),
            "coverage_instrumented": coverage_instrumented,
            "_report": report[:8000],
        })
    return {"compiled": True, "ran": True, "engine": "afl", "done": done,
            "coverage_instrumented": coverage_instrumented, "executions": execs,
            "edges_covered": edges, "crash_count": len(crashes), "crashes": crashes}


def _tmin(fuzzer, crash_path, outdir):
    """Minimize a crashing input with afl-tmin. Returns (sha, size, bytes) or
    (None, None, None) — best-effort, never fatal."""
    tmin = shutil.which("afl-tmin")
    if not tmin:
        return None, None, None
    out = os.path.join(outdir, "min-" + os.path.basename(crash_path))
    try:
        subprocess.run([tmin, "-i", crash_path, "-o", out, "--", fuzzer],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AFL_SKIP_CPUFREQ": "1", "AFL_NO_AFFINITY": "1"})
        if os.path.isfile(out) and os.path.getsize(out) < os.path.getsize(crash_path):
            b = open(out, "rb").read()
            return __import__("hashlib").sha256(b).hexdigest(), len(b), b
    except Exception:  # noqa: BLE001
        pass
    return None, None, None


if __name__ == "__main__":
    raise SystemExit(main())
