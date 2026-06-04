#!/usr/bin/env python3
"""Fuzz a generated harness INSIDE the sandbox (dynamic — opt-in only).

  argv: /artifact (harness .c, ro)  /out (rw, crash artifacts)  [flags...]
  flags: --max-total-time=N --max-len=M --max-crashes=K
         [--target-lib=/path.so] [--target-source=/path.c ...] [--minimize-runs=R]

**Coverage-guided when source is present.** `-fsanitize=fuzzer` only instruments
the file(s) clang compiles for the fuzzer; if a stripped/optimized prebuilt `.so`
is linked via `--target-lib`, libFuzzer mutates with ZERO coverage feedback from
the code under test (effectively black-box fuzzing of the harness glue). So when
the target SOURCE is provided (`--target-source=`), we compile those sources with
`-fsanitize=fuzzer-no-link,address` (SanitizerCoverage + ASan baked into the
*target's own objects*) and link them into the libFuzzer harness → real
coverage-guided fuzzing. When only an uninstrumented `.so` is available, we keep
working but record `coverage_instrumented=false` so nothing overstates a black-box
run (instrumenting a prebuilt binary is a later AFL++ qemu-mode phase).

For each unique crash we: dedup by a normalized stack-hash (top-N ASan frames,
addresses/offsets/build-path/anon-namespace noise stripped), minimize the
reproducer with libFuzzer's own `-minimize_crash=1 -runs=R`, and classify
exploitability deterministically from the sanitizer report text (no LLM).

Emits JSON {compiled, ran, engine, coverage_instrumented, executions, crashes:[...]}.

Runs only when the analysis policy permits execution (fuzzing enabled in Settings)
— the runner gates this via requires_execution=True. Still --network none, with
mem/cpu/pids caps, tmpfs scratch, and a hard timeout. We execute only the harness
WE compiled, never the original target as-is.
"""

from __future__ import annotations

import base64
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

SCRATCH = os.environ.get("TMPDIR", "/scratch")

# The SUMMARY line is the AUTHORITATIVE normalized type ("heap-use-after-free",
# "double-free", …); prefer it. The ERROR line's first token after "AddressSanitizer:"
# is unreliable — for a double-free it reads "attempting double-free on address …", so a
# naive first-word capture yields "attempting". Match each separately.
_ASAN_SUMMARY_TYPE = re.compile(r"SUMMARY: AddressSanitizer: ([a-zA-Z0-9_\-]+)")
_ASAN_ERROR_TYPE = re.compile(r"ERROR: AddressSanitizer: ([a-zA-Z0-9_\-]+)")
# ASan phrases (double-)free differently on the ERROR line: "attempting double-free on
# address …" / "attempting free on address which was not malloc()-ed". Normalize these
# to the canonical SUMMARY-style type so the finding's `sanitizer` label is correct even
# when no SUMMARY line is present.
_ASAN_ATTEMPTING = re.compile(r"attempting (double-free|free)\b")
_LIBFUZZER_DEADLY = re.compile(r"==\d+== ERROR|libFuzzer: (deadly signal|timeout|out-of-memory)")
_FRAME0 = re.compile(r"#0 0x[0-9a-f]+ in (\S+)")
_SUMMARY = re.compile(r"SUMMARY: AddressSanitizer: .*")

# A single ASan/sanitizer backtrace frame:  "#N 0xADDR in <func> <file>:<line>"
# or "#N 0xADDR in <func> (<module>+0xOFF)" or "#N 0xADDR (<module>+0xOFF)".
_FRAME = re.compile(r"#(\d+)\s+0x[0-9a-f]+\s+(?:in\s+)?(.*)$", re.MULTILINE)
# ASan declares the access "READ"/"WRITE" of a buffer overflow / UAF, e.g.
#   "READ of size 4 at 0x..." / "WRITE of size 8 at 0x..."
_ACCESS = re.compile(r"\b(READ|WRITE) of size \d+", re.IGNORECASE)
# A SEGV report carries the operation + whether the fault address is near the PC.
_SEGV_OP = re.compile(r"caused by a (READ|WRITE) memory access", re.IGNORECASE)
_SEGV_UNKNOWN = re.compile(r"unknown address.*\bpc\s+0x[0-9a-f]+", re.IGNORECASE)


def parse_asan(stderr: str) -> dict:
    """Pull a crash classification out of an ASan/libFuzzer report (pure; testable)."""
    text = stderr or ""
    kind = "crash"
    # Prefer the SUMMARY line — it carries the canonical normalized type. Fall back to the
    # ERROR line, but special-case its "attempting (double-)free" phrasing (where the first
    # token is the verb "attempting", not the bug type) so a double-free isn't mislabeled.
    sm = _ASAN_SUMMARY_TYPE.search(text)
    em = _ASAN_ERROR_TYPE.search(text)
    am = _ASAN_ATTEMPTING.search(text)
    if sm:
        kind = sm.group(1)
    elif am:
        kind = am.group(1)
    elif em:
        kind = em.group(1)
    elif "libFuzzer: timeout" in text:
        kind = "timeout"
    elif "out-of-memory" in text:
        kind = "out-of-memory"
    elif "deadly signal" in text:
        kind = "deadly-signal"
    summary = _SUMMARY.search(stderr or "")
    # The faulting function is the first MEANINGFUL frame — skipping sanitizer
    # interceptors (__asan_memcpy / operator new / …) that sit above the real site —
    # so a heap-write reports the target function, not the ASan write hook. Fall back
    # to raw frame0 (then None) when nothing symbolizes.
    frames = normalized_frames(stderr or "", limit=1)
    if frames:
        function = frames[0]
    else:
        f0 = _FRAME0.search(stderr or "")
        function = f0.group(1) if f0 else None
    return {
        "kind": kind,
        "function": function,
        "summary": (summary.group(0) if summary else (stderr or "").strip().splitlines()[-1] if stderr else "")[:300],
    }


# ── Crash dedup: a normalized, deterministic stack hash ─────────────────────────
#
# Today's `(kind, frame0_function)` over-merges (distinct bugs sharing frame 0) AND
# is fragile (a frame with no symbol → None collapses everything). We instead hash
# the *normalized* top-N frames: strip the runtime addresses, module offsets,
# build-path prefixes, line/column numbers, and C++ anonymous-namespace / template
# noise that vary run-to-run or box-to-box, keeping only the stable symbol chain.
# This is the ClusterFuzz / AFL++ norm and yields a stable `dedup_key`.

_DEDUP_FRAMES = 5  # top-N frames that define a crash's identity

# Sanitizer-internal interceptor frames sit ABOVE the real fault site; drop them so
# the same bug reached through different libc entry points buckets together.
_INTERCEPTOR_PREFIXES = (
    "__asan", "__interceptor", "__sanitizer", "asan_", "__lsan", "__ubsan",
    "operator new", "operator delete", "malloc", "free", "calloc", "realloc",
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
)


def _normalize_frame(raw: str) -> str | None:
    """Normalize ONE backtrace-frame symbol to a stable token, or None to drop it.

    `raw` is everything after "#N 0xADDR in " (or after the address). We keep the
    function name, drop the source path / line / module offset, collapse C++
    anonymous-namespace and template parameters, and reject sanitizer-internal
    interceptor frames (they're noise above the real fault site)."""
    s = (raw or "").strip()
    if not s:
        return None
    # "func (/path/to.so+0x123)"  →  "func"   ;   "(/path+0x1)" alone → drop
    s = re.sub(r"\s*\([^()]*\+0x[0-9a-fA-F]+\)\s*$", "", s).strip()
    if not s or s.startswith("(") or s.startswith("<"):
        return None
    # "func /build/src/foo.c:42:7"  →  "func"  (strip the trailing file:line[:col])
    s = re.sub(r"\s+[^\s]+:\d+(:\d+)?\s*$", "", s).strip()
    # "func /abs/path/foo.c" (no line) → "func"
    s = re.sub(r"\s+/[^\s]+$", "", s).strip()
    if not s:
        return None
    # Collapse C++ template args and anonymous namespaces (build-config dependent).
    s = re.sub(r"<.*>", "", s)
    s = s.replace("(anonymous namespace)::", "")
    # Drop a trailing call-signature "(int, char*)" — overload set, not identity-bearing here.
    s = re.sub(r"\(.*\)$", "", s).strip()
    if not s:
        return None
    low = s.lower()
    if any(low.startswith(p) for p in _INTERCEPTOR_PREFIXES):
        return None
    return s


# Runtime entry/startup frames sit BELOW the meaningful call chain; stop at them so
# a crash buckets the same whether or not libc symbols happen to be present.
_TERMINAL_FRAMES = ("__libc_start_main", "_start", "__libc_start_call_main",
                    "LLVMFuzzerTestOneInput", "main")


def normalized_frames(report: str, limit: int = _DEDUP_FRAMES) -> list[str]:
    """The top-`limit` stable symbol frames from an ASan/sanitizer report (pure).
    Stops at the program-entry frame (main/_start/the fuzzer entry) so libc startup
    noise below it never perturbs the bucket key."""
    frames: list[str] = []
    for _, raw in _FRAME.findall(report or ""):
        norm = _normalize_frame(raw)
        if not norm:
            continue
        if norm in _TERMINAL_FRAMES:
            frames.append(norm)
            break
        frames.append(norm)
        if len(frames) >= limit:
            break
    return frames


def dedup_key(kind: str, report: str, *, limit: int = _DEDUP_FRAMES) -> str:
    """A deterministic, collision-resistant bucket key for a crash: sha256 over the
    bug type + the normalized top-N frame symbols. Two crashes with the same bug
    type and the same stable call chain bucket together; distinct chains don't.

    Falls back to the raw frame0 symbol (then the kind alone) when no symbolized
    frame survives normalization, so a stripped/black-box run still gets a stable —
    if coarser — key rather than collapsing every crash into one bucket."""
    frames = normalized_frames(report, limit=limit)
    if not frames:
        f0 = _FRAME0.search(report or "")
        frames = [f0.group(1)] if f0 else []
    basis = (kind or "crash") + "|" + "|".join(frames)
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()


# ── Deterministic exploitability classifier (from sanitizer text only) ──────────
#
# A documented, deterministic mapping from the sanitizer report to (rating, signals).
# Ratings, weakest→strongest concern:
#   not_exploitable < dos < info_leak < probably_exploitable < likely_exploitable
# This is a triage HEURISTIC (the crashwalk / MSEC !exploitable lineage), never a
# proof — it's surfaced honestly as a label, not a verdict.

# rating order for "take the worst"
_RATING_ORDER = {
    "unknown": 0, "not_exploitable": 1, "dos": 2, "info_leak": 3,
    "probably_exploitable": 4, "likely_exploitable": 5,
}


def classify_exploitability(report: str, kind: str | None = None) -> dict:
    """Classify a crash's exploitability from the sanitizer report text alone (pure,
    deterministic). Returns {rating, access, signals}. Documented mapping:

      - WRITE to a corrupted heap/stack/global buffer, or WRITE-after-free / WRITE
        SEGV near a controllable address → `likely_exploitable` (memory the attacker
        can corrupt → control-flow hijack primitive).
      - use-after-free / double-free (write or unknown access) → `likely_exploitable`
        (classic UAF → arbitrary write / vtable hijack); a READ UAF → `info_leak`.
      - a READ overflow / READ UAF / global READ → `info_leak` (out-of-bounds read
        can disclose memory).
      - SEGV on a READ / null-ish deref, stack-overflow (recursion), OOM, timeout,
        leak → `dos` (a denial-of-service, not obviously a code-exec primitive).
      - nothing recognized → `unknown`.
    """
    text = report or ""
    k = (kind or parse_asan(text).get("kind") or "crash").lower()
    signals: list[str] = []

    am = _ACCESS.search(text)
    access = am.group(1).upper() if am else None
    sm = _SEGV_OP.search(text)
    if not access and sm:
        access = sm.group(1).upper()
    if access:
        signals.append(f"{access.lower()}-access")

    is_write = access == "WRITE"
    is_read = access == "READ"

    rating = "unknown"

    if "double-free" in k:
        rating = "likely_exploitable"
        signals.append("double-free corrupts allocator metadata")
    elif "use-after-free" in k:
        if is_read:
            rating = "info_leak"
            signals.append("read of freed memory may disclose heap contents")
        else:
            rating = "likely_exploitable"
            signals.append("use-after-free with a write/control access (allocator/vtable hijack primitive)")
    elif "dynamic-stack-buffer-overflow" in k or "buffer-overflow" in k:
        # covers heap/stack/global/dynamic-stack buffer overflows
        if is_write:
            rating = "likely_exploitable"
            signals.append("out-of-bounds WRITE can corrupt adjacent memory / control data")
        elif is_read:
            rating = "info_leak"
            signals.append("out-of-bounds READ can disclose adjacent memory")
        else:
            rating = "probably_exploitable"
            signals.append("buffer overflow with undetermined access direction")
    elif "stack-overflow" in k:
        # plain stack-overflow = unbounded recursion / deep stack → DoS
        rating = "dos"
        signals.append("stack exhaustion (recursion / deep stack) — denial of service")
    elif k in ("segv", "deadly-signal") or "SEGV" in text:
        if is_write:
            rating = "probably_exploitable"
            signals.append("SEGV on a WRITE — potentially a controllable destination")
        elif is_read:
            # A read fault is a disclosure/DoS, not a write primitive — the explicit
            # access direction wins over the (weaker) near-PC heuristic.
            rating = "dos"
            signals.append("SEGV on a READ / null-ish dereference — denial of service")
        elif _SEGV_UNKNOWN.search(text):
            rating = "probably_exploitable"
            signals.append("SEGV at an address near the program counter — possible control-flow corruption")
        else:
            rating = "dos"
            signals.append("SEGV with an undetermined access — denial of service")
    elif k in ("out-of-memory", "memory-leak", "timeout"):
        rating = "dos"
        signals.append(f"{k} — resource exhaustion / denial of service")
    else:
        # An unrecognized ASan kind that nonetheless fired: treat a WRITE access as a
        # corruption signal, otherwise leave it as a DoS-class crash if anything fired.
        if is_write:
            rating = "probably_exploitable"
            signals.append("memory-corruption write in an unclassified sanitizer report")
        elif text.strip():
            rating = "dos"

    return {"rating": rating, "access": access, "signals": signals}


def worst_rating(*ratings: str) -> str:
    """The most-severe of several exploitability ratings (helper for callers)."""
    return max((r for r in ratings if r), key=lambda r: _RATING_ORDER.get(r, 0), default="unknown")


def symbolizer_env(base: dict | None = None) -> dict:
    """An env that forces ASan to SYMBOLIZE its backtraces to `func file:line:col`.

    ASan only emits module+offset frames (unsymbolized) unless it can find
    llvm-symbolizer; the base sandbox image lacks it, but the dedicated `hexgraph-fuzz`
    image HAS it (docker/fuzz.Dockerfile). We point ASAN_SYMBOLIZER_PATH at it explicitly +
    `symbolize=1` so the crash replay produces source-mapped frames (battle-test H — the
    headline 'frame → source jump' + symbolized stack). Best-effort: if no symbolizer is
    on PATH the env is harmless (ASan falls back to module+offset, as before)."""
    env = dict(base if base is not None else os.environ)
    sym = (shutil.which("llvm-symbolizer") or shutil.which("llvm-symbolizer-19")
           or shutil.which("llvm-symbolizer-18") or shutil.which("llvm-symbolizer-16")
           or shutil.which("addr2line"))
    opts = "abort_on_error=1:symbolize=1:detect_leaks=0"
    if sym:
        env["ASAN_SYMBOLIZER_PATH"] = sym
        opts += f":external_symbolizer_path={sym}"
    env["ASAN_OPTIONS"] = opts
    env.setdefault("UBSAN_OPTIONS", "symbolize=1:print_stacktrace=1")
    return env


def _flag(args: list[str], name: str, default):
    for a in args:
        if a.startswith(name + "="):
            val = a.split("=", 1)[1]
            return type(default)(val) if default is not None else val
    return default


def _flag_all(args: list[str], name: str) -> list[str]:
    """All values of a repeatable `--name=VALUE` flag, in order."""
    return [a.split("=", 1)[1] for a in args if a.startswith(name + "=")]


# libFuzzer progress / final-stats parsing. A `-fork=1` run prints periodic
#   #NNN: cov: C ft: F corp: ... exec/s: ...
# lines (the LAST `#NNN:` is the cumulative exec count; `cov:`/`ft:` are the edges /
# features reached so far — monotonic, so the MAX seen is the coverage). A single-process
# run ends with `#N DONE` / `stat::number_of_executed_units: N`. We parse all of them so
# a fork-mode run reports both real execs AND real edge coverage (else the campaign showed
# 0 edges forever — that field was never collected).
_PROGRESS = re.compile(r"^#(\d+):", re.MULTILINE)
_COV = re.compile(r"\bcov:\s*(\d+)")
_FT = re.compile(r"\bft:\s*(\d+)")
_DONE = re.compile(r"#(\d+)\s+DONE")
_UNITS = re.compile(r"stat::number_of_executed_units:\s*(\d+)")


def parse_libfuzzer_progress(out: str) -> dict:
    """Pull (executions, edges_covered, features) out of libFuzzer's output (pure, testable).

    `executions` is the final `#N DONE` / `number_of_executed_units` count, else the LAST
    fork-mode `#NNN:` progress line. `edges_covered` is the MAX `cov:` seen and `features`
    the MAX `ft:` seen (both monotonic in libFuzzer). Missing values come back as None so a
    caller can fall through to other evidence (corpus growth, AFL stats, …)."""
    text = out or ""
    execs = None
    em = _DONE.search(text) or _UNITS.search(text)
    if em:
        execs = int(em.group(1))
    else:
        counts = _PROGRESS.findall(text)
        if counts:
            execs = max(int(c) for c in counts)
    covs = [int(c) for c in _COV.findall(text)]
    fts = [int(c) for c in _FT.findall(text)]
    return {
        "executions": execs,
        "edges_covered": max(covs) if covs else None,
        "features": max(fts) if fts else None,
    }


def _write_status(outdir: str, obj: dict) -> None:
    """Atomically replace `<outdir>/status.json` with the current progress (NO DONE marker).
    Called PERIODICALLY mid-run so the reaper sees live execs/edges/crashes (matching the
    AFL probe's streaming). The reaper's `_update_stats` is monotonic + crash dedup is by
    `dedup_key`, so re-emitting a partial status repeatedly is safe (no double-ingest, no
    early finalize — finalize is gated on the DONE marker, written only by `_emit`)."""
    obj.setdefault("tool", "fuzz_probe")
    obj.setdefault("engine", "libfuzzer")
    try:
        tmp = os.path.join(outdir, "status.json.tmp")
        with open(tmp, "w") as fh:
            json.dump(obj, fh)
        os.replace(tmp, os.path.join(outdir, "status.json"))
    except OSError:
        pass


def _emit(obj: dict, *, outdir: str | None = None) -> int:
    """Print the result JSON to stdout (the single-pass `fuzzing` task reads stdout).
    When `outdir` is given (a detached campaign), ALSO write it to `<outdir>/status.json`
    + a `DONE` marker so the reaper ingests it + finalizes — the same shape from either path."""
    obj.setdefault("tool", "fuzz_probe")
    obj.setdefault("engine", "libfuzzer")
    if outdir:
        try:
            tmp = os.path.join(outdir, "status.json.tmp")
            with open(tmp, "w") as fh:
                json.dump(obj, fh)
            os.replace(tmp, os.path.join(outdir, "status.json"))
            with open(os.path.join(outdir, "DONE"), "w") as fh:
                fh.write("libfuzzer")
        except OSError:
            pass
    print(json.dumps(obj))
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        return _emit({"error": "usage: fuzz_probe.py <harness.c> <outdir> [flags]"})
    src, outdir = sys.argv[1], sys.argv[2]
    args = sys.argv[3:]
    max_total_time = _flag(args, "--max-total-time", 60)
    max_len = _flag(args, "--max-len", 4096)
    max_crashes = _flag(args, "--max-crashes", 10)
    minimize_runs = _flag(args, "--minimize-runs", 2000)
    target_lib = _flag(args, "--target-lib", None)
    target_sources = [p for p in _flag_all(args, "--target-source") if os.path.isfile(p)]
    # Include dirs (`-I`) so a target source that `#include`s its own header / a sibling
    # header compiles (the sources are mounted preserving their directory layout).
    include_dirs = [d for d in _flag_all(args, "--include-dir") if os.path.isdir(d)]
    inc_flags = [f"-I{d}" for d in include_dirs]
    seeds = [p for p in _flag_all(args, "--seed") if os.path.isfile(p)]

    clang = shutil.which("clang")
    if not clang:
        return _emit({"compiled": False, "ran": False,
                      "error": "clang+libFuzzer not in sandbox image (rebuild with fuzzing toolchain)"},
                     outdir=outdir)

    # Build + run the fuzzer in the /out bind-mount: the tmpfs /scratch can be
    # noexec / not writable for an output executable, whereas /out is a host bind
    # mount (writable + executable, same place crash artifacts are collected).
    FUZZER = os.path.join(outdir, "fuzzer")

    # ── Instrumentation strategy ────────────────────────────────────────────────
    # If the target SOURCE is present, compile it WITH SanitizerCoverage + ASan baked
    # into the target's own objects (`-fsanitize=fuzzer-no-link,address`) and link it
    # into the libFuzzer harness → real coverage-guided fuzzing. Otherwise (only a
    # prebuilt uninstrumented `.so`), we fall back to a coverage-BLIND link and report
    # it honestly — instrumenting a stripped binary is out of scope here.
    coverage_instrumented = False
    obj_files: list[str] = []
    if target_sources:
        for i, ts in enumerate(target_sources):
            obj = os.path.join(outdir, f"target_{i}.o")
            is_cxx = ts.endswith((".cc", ".cpp", ".cxx", ".C", ".c++"))
            cc = shutil.which("clang++") if (is_cxx and shutil.which("clang++")) else clang
            tcmd = [cc, "-g", "-O1", "-w", "-fsanitize=fuzzer-no-link,address",
                    *inc_flags, "-c", ts, "-o", obj]
            tbuild = subprocess.run(tcmd, capture_output=True, text=True)
            if tbuild.returncode != 0:
                return _emit({"compiled": False, "ran": False, "returncode": tbuild.returncode,
                              "stage": "target-source", "coverage_instrumented": False,
                              "stderr": (tbuild.stderr or "")[:2000]}, outdir=outdir)
            obj_files.append(obj)
        coverage_instrumented = True

    # The harness is mounted at /artifact (no extension), so tell clang it's C —
    # otherwise ld treats the extensionless input as a linker script and fails.
    cmd = [clang, "-g", "-O1", "-w", "-fsanitize=fuzzer,address", *inc_flags, "-x", "c", src,
           "-x", "none", "-o", FUZZER]
    cmd.extend(obj_files)
    # A prebuilt .so is only linked when we have NO instrumented source — linking both
    # would double-define symbols. With source present the .so is redundant.
    if not coverage_instrumented and target_lib and os.path.isfile(target_lib):
        cmd.append(target_lib)
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0:
        return _emit({"compiled": False, "ran": False, "returncode": build.returncode,
                      "stage": "harness-link", "coverage_instrumented": coverage_instrumented,
                      "stderr": (build.stderr or "")[:2000]}, outdir=outdir)

    # A seed corpus (optional) jump-starts the fuzzer past trivial input gates — copied
    # into a corpus dir libFuzzer reads from and grows. Standard, deterministic kick.
    corpus_dir = os.path.join(outdir, "corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    for i, sp in enumerate(seeds):
        try:
            shutil.copyfile(sp, os.path.join(corpus_dir, f"seed_{i}"))
        except OSError:
            pass

    # Fork mode keeps fuzzing through crashes, saving each crashing input to /out. We run it
    # NON-BLOCKING (Popen, stdout/stderr → a log file) and PERIODICALLY parse the partial log
    # + count crash artifacts to stream a live status.json — so a long campaign's execs/edges/
    # crashes advance on the card mid-run instead of looking idle until completion. The final
    # authoritative parse happens after the process exits.
    log_path = os.path.join(outdir, "libfuzzer.log")
    logfh = open(log_path, "wb")
    proc = subprocess.Popen(
        [FUZZER, "-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1",
         f"-max_total_time={max_total_time}", f"-max_len={max_len}",
         "-rss_limit_mb=2048", f"-artifact_prefix={outdir.rstrip('/')}/", corpus_dir],
        stdout=logfh, stderr=subprocess.STDOUT, cwd=outdir,
    )

    def _read_log() -> str:
        try:
            with open(log_path, "rb") as fh:
                return fh.read().decode("utf-8", "replace")
        except OSError:
            return ""

    # Stream live progress while libFuzzer runs (so the card isn't idle until the end).
    # A generous deadline (the run self-limits via -max_total_time) keeps us from spinning
    # forever if the process wedges; we still wait + parse the final log below either way.
    deadline = time.monotonic() + int(max_total_time) + 60
    interval = min(5, max(2, int(max_total_time) // 6))
    while proc.poll() is None and time.monotonic() < deadline:
        prog = parse_libfuzzer_progress(_read_log())
        crash_n = len(glob.glob(os.path.join(outdir, "crash-*")))
        partial = {"compiled": True, "ran": True, "engine": "libfuzzer",
                   "executions": prog["executions"], "edges_covered": prog["edges_covered"],
                   "coverage_instrumented": coverage_instrumented,
                   "max_total_time": max_total_time, "crash_count": crash_n}
        if prog["features"] is not None:
            partial["features"] = prog["features"]
        _write_status(outdir, partial)
        time.sleep(interval)
    if proc.poll() is None:  # past the deadline — stop it and reap what ran
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
    else:
        proc.wait()
    logfh.close()

    out = _read_log()
    # Total executions + edge coverage. Single-process libFuzzer ends with `#N DONE` /
    # `stat::number_of_executed_units: N`; FORK mode (-fork=1, our default) never prints
    # those — its progress lines are `#NNN: cov: C ft: F exec/s ..`, the LAST `#NNN:` is the
    # cumulative exec count and the MAX `cov:` the edges reached. Parse all so a fork-mode run
    # reports real execs AND real edge coverage (the latter was previously discarded → the
    # campaign showed 0 edges forever, and was sometimes wrongly finalized `degraded`).
    prog = parse_libfuzzer_progress(out)
    execs = prog["executions"]
    edges_covered = prog["edges_covered"]
    features = prog["features"]

    # Each saved artifact is a crashing input; reproduce it for its report, then
    # bucket by the normalized stack-hash (keeping one representative per bucket) and
    # minimize the representative with libFuzzer's own -minimize_crash. We ALSO replay
    # any provided seeds directly: a known-crashing seed reproduces deterministically
    # regardless of how the fork-mode campaign happened to schedule (so a planted-bug
    # reproducer is never missed) — non-crashing seeds are dropped by the exit check.
    artifacts = sorted(
        f for pat in ("crash-*", "oom-*", "timeout-*", "leak-*")
        for f in glob.glob(os.path.join(outdir, pat))
    )
    # Replay provided seeds FIRST (a known-crashing reproducer should always claim a
    # bucket before random campaign artifacts fill the max_crashes budget), then the
    # campaign's own crashing inputs.
    candidates = [s for s in seeds if os.path.isfile(s)] + artifacts[: max_crashes * 4]
    crashes = []
    seen: dict[str, int] = {}  # dedup_key → index into crashes
    # Minimization is bounded by a CUMULATIVE wall-clock budget so the triage phase
    # never blows the sandbox's hard timeout (DEFAULT_TIMEOUT 300s): max_total_time of
    # fuzzing + per-crash repro + N×minimize must fit. We give minimization at most a
    # third of the remaining budget below the 300s ceiling (leaving headroom for
    # repro/IO), split as a per-crash cap; once exhausted we still record every unique
    # crash, just without a minimized reproducer (best-effort, never fatal).
    minimize_budget = max(0, int((300 - int(max_total_time)) * 0.33))
    minimize_deadline = time.monotonic() + minimize_budget
    for path in candidates:
        data = open(path, "rb").read()
        sha = hashlib.sha256(data).hexdigest()
        try:
            repro = subprocess.run([FUZZER, path], capture_output=True, text=True, cwd=outdir,
                                   timeout=60, env=symbolizer_env())
        except subprocess.TimeoutExpired:
            # A single input that hangs the replay is a finding (a hang/DoS), but we
            # can't symbolize it; treat it as a timeout crash so it's not lost, and
            # never let it kill the whole triage phase.
            report, rc = "libFuzzer: timeout\n", 1
        else:
            report = (repro.stdout or "") + (repro.stderr or "")
            rc = repro.returncode
        # libFuzzer exits nonzero on a crash/leak/timeout; a clean replay (e.g. a
        # benign seed) is not a finding.
        if rc == 0:
            continue
        info = parse_asan(report)
        key = dedup_key(info["kind"], report)
        if key in seen:
            crashes[seen[key]]["dupe_count"] += 1
            continue
        if len(seen) >= max_crashes:
            continue
        expl = classify_exploitability(report, info["kind"])
        remaining = minimize_deadline - time.monotonic()
        if remaining >= 5:
            min_sha, min_size, min_bytes = _minimize(FUZZER, path, outdir, minimize_runs,
                                                     timeout=min(120, int(remaining)))
        else:
            min_sha, min_size, min_bytes = None, None, None  # budget exhausted — skip minimize
        seen[key] = len(crashes)
        # The (minimized) reproducer BYTES, base64'd, so the detached-campaign reaper can
        # store them in CAS for one-click re-verify (verify_poc(reproducer_ref)). Bounded
        # to keep the JSON small — a minimized reproducer is tiny by construction.
        repro_bytes = min_bytes if min_bytes is not None else data
        crashes.append({
            **info,
            "reproducer_sha256": sha,
            "reproducer_size": len(data),
            "dedup_key": key,
            "dupe_count": 0,
            "exploitability": expl,
            "minimized_reproducer_sha256": min_sha,
            "minimized_reproducer_size": min_size,
            "reproducer_b64": base64.b64encode(repro_bytes[:65536]).decode(),
            "coverage_instrumented": coverage_instrumented,
            # The symbolized ASan report — the reaper parses source-mapped stack frames
            # (`func file:line`) from this for the clickable triage stack (battle-test H).
            "_report": report[:8000],
        })

    # Per-line source coverage map (battle-test H — the Source viewer's line shading +
    # coverage_for). Best-effort: a separate PGO-coverage build replayed over the corpus,
    # exported via llvm-cov. Only when we have the target SOURCE (coverage-guided run).
    coverage_percent = None
    if coverage_instrumented and target_sources:
        cov = _collect_coverage(clang, src, target_sources, inc_flags, corpus_dir, outdir)
        if cov is not None:
            coverage_percent = cov.get("percent")

    # Exec floor: libFuzzer's -fork=1 wrapper can occasionally exit before printing a
    # parseable final stats line (its child forkserver is fragile under the hardened
    # sandbox) — but if the run grew the corpus or saved crashing inputs, fuzzing DID
    # happen. Floor execs to that evidence so the campaign is NOT mis-finalized as a
    # `degraded` zero-exec no-op when it actually ran (battle-test live-stats robustness).
    if not execs:
        corpus_n = len(glob.glob(os.path.join(corpus_dir, "*")))
        crash_n = len(glob.glob(os.path.join(outdir, "crash-*")))
        if corpus_n > 1 or crash_n > 0 or coverage_percent:
            execs = max(execs or 0, corpus_n + crash_n, 1)

    out_obj = {"compiled": True, "ran": True, "executions": execs,
               "edges_covered": edges_covered,
               "coverage_instrumented": coverage_instrumented, "done": True,
               "max_total_time": max_total_time, "crash_count": len(crashes), "crashes": crashes}
    if features is not None:
        out_obj["features"] = features
    if coverage_percent is not None:
        out_obj["coverage_percent"] = coverage_percent
    return _emit(out_obj, outdir=outdir)


def _collect_coverage(clang: str, harness: str, target_sources: list[str], inc_flags: list[str],
                      corpus_dir: str, outdir: str) -> dict | None:
    """Build a clang source-based-coverage variant of the harness + target sources
    (`-fprofile-instr-generate -fcoverage-mapping`), replay the corpus through it, and
    export a per-line coverage map to `<outdir>/coverage.json` in HexGraph's shape
    ({percent, files:{rel:{covered:[lines], uncovered:[lines], total}}}). Best-effort —
    returns the parsed map or None (no shading, reported honestly). Skips quietly when
    llvm-cov/llvm-profdata aren't present. NEVER fatal — coverage is an extra, not the run."""
    profdata_tool = shutil.which("llvm-profdata")
    cov_tool = shutil.which("llvm-cov")
    if not (profdata_tool and cov_tool):
        return None
    try:
        covbin = os.path.join(outdir, "coverage_bin")
        # libFuzzer driver supplies main; instrument the harness + target sources for
        # source-based coverage. -fsanitize=fuzzer gives us the corpus-replay entry point.
        build = subprocess.run(
            [clang, "-g", "-O0", "-w", "-fsanitize=fuzzer",
             "-fprofile-instr-generate", "-fcoverage-mapping", *inc_flags,
             "-x", "c", harness, "-x", "none", *target_sources, "-o", covbin],
            capture_output=True, text=True, timeout=180)
        if build.returncode != 0 or not os.path.isfile(covbin):
            return None
        # Replay the corpus PER FILE (each in its own process) rather than `-runs=0` over
        # the whole dir: a single crashing input (e.g. a copied seed that crashes) would
        # otherwise abort the one-shot replay and truncate the profile, suppressing the whole
        # map. Per-file `%m`-merge-pool profraws are robust to a mid-corpus crash — a
        # crashing input contributes whatever it covered and the rest still run.
        corpus_files = [p for p in glob.glob(os.path.join(corpus_dir, "*")) if os.path.isfile(p)]
        if not corpus_files:
            return None
        profpat = os.path.join(outdir, "cov-%m.profraw")
        deadline = time.monotonic() + 100
        for cf in corpus_files:
            if time.monotonic() > deadline:
                break
            try:
                subprocess.run([covbin, "-runs=1", cf], capture_output=True, cwd=outdir,
                               timeout=20, env={**os.environ, "LLVM_PROFILE_FILE": profpat})
            except subprocess.TimeoutExpired:
                continue  # a hang on one input must not suppress coverage of the rest
        profraws = glob.glob(os.path.join(outdir, "cov-*.profraw"))
        if not profraws:
            return None
        profdata = os.path.join(outdir, "cov.profdata")
        merge = subprocess.run([profdata_tool, "merge", "-sparse", *profraws, "-o", profdata],
                               capture_output=True, text=True, timeout=60)
        if merge.returncode != 0 or not os.path.isfile(profdata):
            return None
        exp = subprocess.run(
            [cov_tool, "export", covbin, f"-instr-profile={profdata}", "-format=text",
             *target_sources],
            capture_output=True, text=True, timeout=60)
        if exp.returncode != 0 or not exp.stdout:
            return None
        cov_map = _llvm_cov_to_linemap(exp.stdout)
        if cov_map is None:
            return None
        with open(os.path.join(outdir, "coverage.json"), "w") as fh:
            json.dump(cov_map, fh)
        return cov_map
    except Exception:  # noqa: BLE001 — coverage is best-effort
        return None


def _llvm_cov_to_linemap(export_json: str) -> dict | None:
    """Convert `llvm-cov export -format=text` JSON into HexGraph's per-line map. We read the
    per-function `segments` (each `[line, col, count, hasCount, isRegionEntry, …]`): a line
    with count>0 is covered, count==0 is uncovered. Keyed by the source BASENAME (the Source
    viewer matches on rel/basename suffix). Returns {percent, files:{...}} or None."""
    try:
        data = json.loads(export_json)
    except (json.JSONDecodeError, ValueError):
        return None
    files: dict[str, dict] = {}
    total_lines = 0
    total_covered = 0
    for export in data.get("data", []):
        for f in export.get("files", []):
            rel = os.path.basename(f.get("filename") or "")
            if not rel:
                continue
            covered: set[int] = set()
            uncovered: set[int] = set()
            for seg in f.get("segments", []):
                # segment: [line, col, count, hasCount, isRegionEntry, isGapRegion]
                if len(seg) < 4 or not seg[3]:
                    continue
                line, count = int(seg[0]), int(seg[2])
                (covered if count > 0 else uncovered).add(line)
            uncovered -= covered
            if not (covered or uncovered):
                continue
            tot = len(covered | uncovered)
            files[rel] = {"covered": sorted(covered), "uncovered": sorted(uncovered),
                          "total": tot}
            total_lines += tot
            total_covered += len(covered)
    if not files:
        return None
    pct = round(100.0 * total_covered / total_lines, 1) if total_lines else 0.0
    return {"percent": pct, "files": files}


def _minimize(fuzzer: str, crash_path: str, outdir: str, runs: int,
              *, timeout: int = 120) -> tuple[str | None, int | None, bytes | None]:
    """Shrink a crashing input with libFuzzer's own `-minimize_crash=1 -runs=R`
    (no AFL++ needed). libFuzzer writes a successively smaller input to the
    `-exact_artifact_path`; we return (sha256, size, bytes) of the result when it
    actually shrank, else (None, None, None) (best-effort, never fatal). `timeout`
    bounds this single minimize so the cumulative triage stays under the wall-clock."""
    try:
        exact = os.path.join(outdir, "minimized-current")
        before = set(glob.glob(os.path.join(outdir, "minimized-from-*")))
        subprocess.run(
            [fuzzer, "-minimize_crash=1", f"-runs={int(runs)}",
             f"-exact_artifact_path={exact}", crash_path],
            capture_output=True, text=True, cwd=outdir, timeout=timeout,
        )
        candidates = [
            p for p in glob.glob(os.path.join(outdir, "minimized-from-*")) if p not in before
        ]
        if os.path.isfile(exact):
            candidates.append(exact)
        if not candidates:
            return None, None, None
        orig_size = os.path.getsize(crash_path)
        # Smallest-first, but ONLY accept a minimized form that (a) actually shrank AND
        # (b) STILL CRASHES when replayed. libFuzzer's -minimize_crash can, under a flaky
        # forkserver, emit a "minimized" file that no longer reproduces — storing that as the
        # reproducer would make one-click re-verify spuriously fail (the crash bytes must
        # always re-crash). We verify each candidate and fall back to the original crash
        # bytes (which DID crash) rather than ship a non-reproducing reproducer.
        for best in sorted(candidates, key=lambda p: os.path.getsize(p)):
            if os.path.getsize(best) >= orig_size:
                continue
            try:
                rc = subprocess.run([fuzzer, best], capture_output=True, cwd=outdir,
                                    timeout=30).returncode
            except subprocess.TimeoutExpired:
                rc = 1  # a hang is still a crash/finding
            if rc != 0:
                data = open(best, "rb").read()
                return hashlib.sha256(data).hexdigest(), len(data), data
        return None, None, None
    except Exception:  # noqa: BLE001 — minimization is best-effort
        return None, None, None


if __name__ == "__main__":
    raise SystemExit(main())
