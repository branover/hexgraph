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

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

SCRATCH = os.environ.get("TMPDIR", "/scratch")

_ASAN_TYPE = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer: ([a-zA-Z0-9_\-]+)")
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
    kind = "crash"
    m = _ASAN_TYPE.search(stderr or "")
    if m:
        kind = m.group(1)
    elif "libFuzzer: timeout" in (stderr or ""):
        kind = "timeout"
    elif "out-of-memory" in (stderr or ""):
        kind = "out-of-memory"
    elif "deadly signal" in (stderr or ""):
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


def _flag(args: list[str], name: str, default):
    for a in args:
        if a.startswith(name + "="):
            val = a.split("=", 1)[1]
            return type(default)(val) if default is not None else val
    return default


def _flag_all(args: list[str], name: str) -> list[str]:
    """All values of a repeatable `--name=VALUE` flag, in order."""
    return [a.split("=", 1)[1] for a in args if a.startswith(name + "=")]


def _emit(obj: dict) -> int:
    obj.setdefault("tool", "fuzz_probe")
    obj.setdefault("engine", "libfuzzer")
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
    seeds = [p for p in _flag_all(args, "--seed") if os.path.isfile(p)]

    clang = shutil.which("clang")
    if not clang:
        return _emit({"compiled": False, "ran": False,
                      "error": "clang+libFuzzer not in sandbox image (rebuild with fuzzing toolchain)"})

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
            tcmd = [cc, "-g", "-O1", "-w", "-fsanitize=fuzzer-no-link,address", "-c", ts, "-o", obj]
            tbuild = subprocess.run(tcmd, capture_output=True, text=True)
            if tbuild.returncode != 0:
                return _emit({"compiled": False, "ran": False, "returncode": tbuild.returncode,
                              "stage": "target-source", "coverage_instrumented": False,
                              "stderr": (tbuild.stderr or "")[:2000]})
            obj_files.append(obj)
        coverage_instrumented = True

    # The harness is mounted at /artifact (no extension), so tell clang it's C —
    # otherwise ld treats the extensionless input as a linker script and fails.
    cmd = [clang, "-g", "-O1", "-w", "-fsanitize=fuzzer,address", "-x", "c", src,
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
                      "stderr": (build.stderr or "")[:2000]})

    # A seed corpus (optional) jump-starts the fuzzer past trivial input gates — copied
    # into a corpus dir libFuzzer reads from and grows. Standard, deterministic kick.
    corpus_dir = os.path.join(outdir, "corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    for i, sp in enumerate(seeds):
        try:
            shutil.copyfile(sp, os.path.join(corpus_dir, f"seed_{i}"))
        except OSError:
            pass

    # Fork mode keeps fuzzing through crashes, saving each crashing input to /out.
    run = subprocess.run(
        [FUZZER, "-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1",
         f"-max_total_time={max_total_time}", f"-max_len={max_len}",
         "-rss_limit_mb=2048", f"-artifact_prefix={outdir.rstrip('/')}/", corpus_dir],
        capture_output=True, text=True, cwd=outdir,
    )
    out = (run.stdout or "") + "\n" + (run.stderr or "")
    execs = None
    em = re.search(r"#(\d+)\s+DONE", out) or re.search(r"stat::number_of_executed_units:\s*(\d+)", out)
    if em:
        execs = int(em.group(1))

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
    for path in candidates:
        data = open(path, "rb").read()
        sha = hashlib.sha256(data).hexdigest()
        repro = subprocess.run([FUZZER, path], capture_output=True, text=True, cwd=outdir)
        report = (repro.stdout or "") + (repro.stderr or "")
        # libFuzzer exits nonzero on a crash/leak/timeout; a clean replay (e.g. a
        # benign seed) is not a finding.
        if repro.returncode == 0:
            continue
        info = parse_asan(report)
        key = dedup_key(info["kind"], report)
        if key in seen:
            crashes[seen[key]]["dupe_count"] += 1
            continue
        if len(seen) >= max_crashes:
            continue
        expl = classify_exploitability(report, info["kind"])
        min_sha, min_size = _minimize(FUZZER, path, outdir, minimize_runs)
        seen[key] = len(crashes)
        crashes.append({
            **info,
            "reproducer_sha256": sha,
            "reproducer_size": len(data),
            "dedup_key": key,
            "dupe_count": 0,
            "exploitability": expl,
            "minimized_reproducer_sha256": min_sha,
            "minimized_reproducer_size": min_size,
            "coverage_instrumented": coverage_instrumented,
        })

    return _emit({"compiled": True, "ran": True, "executions": execs,
                  "coverage_instrumented": coverage_instrumented,
                  "max_total_time": max_total_time, "crash_count": len(crashes), "crashes": crashes})


def _minimize(fuzzer: str, crash_path: str, outdir: str, runs: int) -> tuple[str | None, int | None]:
    """Shrink a crashing input with libFuzzer's own `-minimize_crash=1 -runs=R`
    (no AFL++ needed). libFuzzer writes a successively smaller input to the
    `-exact_artifact_path`; we return the sha256 + size of the result when it
    actually shrank, else (None, None) (best-effort, never fatal)."""
    try:
        exact = os.path.join(outdir, "minimized-current")
        before = set(glob.glob(os.path.join(outdir, "minimized-from-*")))
        subprocess.run(
            [fuzzer, "-minimize_crash=1", f"-runs={int(runs)}",
             f"-exact_artifact_path={exact}", crash_path],
            capture_output=True, text=True, cwd=outdir, timeout=120,
        )
        candidates = [
            p for p in glob.glob(os.path.join(outdir, "minimized-from-*")) if p not in before
        ]
        if os.path.isfile(exact):
            candidates.append(exact)
        if not candidates:
            return None, None
        best = min(candidates, key=lambda p: os.path.getsize(p))
        orig_size = os.path.getsize(crash_path)
        # Only report the minimized form if it actually shrank the input.
        if os.path.getsize(best) >= orig_size:
            return None, None
        data = open(best, "rb").read()
        return hashlib.sha256(data).hexdigest(), len(data)
    except Exception:  # noqa: BLE001 — minimization is best-effort
        return None, None


if __name__ == "__main__":
    raise SystemExit(main())
