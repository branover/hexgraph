#!/usr/bin/env python3
"""Fuzz a generated harness INSIDE the sandbox (dynamic — opt-in only).

  argv: /artifact (harness .c, ro)  /out (rw, crash artifacts)  [flags...]
  flags: --max-total-time=N --max-len=M --max-crashes=K [--target-lib=/path.so]

Compiles the harness with clang's libFuzzer + AddressSanitizer, runs it under a
wall-clock budget collecting crashing inputs, then reproduces each to extract its
ASan report. Emits JSON {compiled, ran, engine, executions, crashes:[...]}.

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
FUZZER = os.path.join(SCRATCH, "fuzzer")

_ASAN_TYPE = re.compile(r"(?:ERROR|SUMMARY): AddressSanitizer: ([a-zA-Z0-9_\-]+)")
_LIBFUZZER_DEADLY = re.compile(r"==\d+== ERROR|libFuzzer: (deadly signal|timeout|out-of-memory)")
_FRAME0 = re.compile(r"#0 0x[0-9a-f]+ in (\S+)")
_SUMMARY = re.compile(r"SUMMARY: AddressSanitizer: .*")


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
    frame = _FRAME0.search(stderr or "")
    summary = _SUMMARY.search(stderr or "")
    return {
        "kind": kind,
        "function": frame.group(1) if frame else None,
        "summary": (summary.group(0) if summary else (stderr or "").strip().splitlines()[-1] if stderr else "")[:300],
    }


def _flag(args: list[str], name: str, default):
    for a in args:
        if a.startswith(name + "="):
            val = a.split("=", 1)[1]
            return type(default)(val) if default is not None else val
    return default


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
    target_lib = _flag(args, "--target-lib", None)

    clang = shutil.which("clang")
    if not clang:
        return _emit({"compiled": False, "ran": False,
                      "error": "clang+libFuzzer not in sandbox image (rebuild with fuzzing toolchain)"})

    cmd = [clang, "-g", "-O1", "-w", "-fsanitize=fuzzer,address", src, "-o", FUZZER]
    if target_lib and os.path.isfile(target_lib):
        cmd.append(target_lib)
    build = subprocess.run(cmd, capture_output=True, text=True)
    if build.returncode != 0:
        return _emit({"compiled": False, "ran": False, "returncode": build.returncode,
                      "stderr": (build.stderr or "")[:2000]})

    # Fork mode keeps fuzzing through crashes, saving each crashing input to /out.
    run = subprocess.run(
        [FUZZER, "-fork=1", "-ignore_crashes=1", "-ignore_timeouts=1", "-ignore_ooms=1",
         f"-max_total_time={max_total_time}", f"-max_len={max_len}",
         "-rss_limit_mb=2048", f"-artifact_prefix={outdir.rstrip('/')}/"],
        capture_output=True, text=True, cwd=SCRATCH,
    )
    out = (run.stdout or "") + "\n" + (run.stderr or "")
    execs = None
    em = re.search(r"#(\d+)\s+DONE", out) or re.search(r"stat::number_of_executed_units:\s*(\d+)", out)
    if em:
        execs = int(em.group(1))

    # Each saved artifact is a unique crashing input; reproduce it for its report.
    artifacts = sorted(
        f for pat in ("crash-*", "oom-*", "timeout-*", "leak-*")
        for f in glob.glob(os.path.join(outdir, pat))
    )
    crashes = []
    seen = set()
    for path in artifacts[: max_crashes * 2]:
        data = open(path, "rb").read()
        sha = hashlib.sha256(data).hexdigest()
        repro = subprocess.run([FUZZER, path], capture_output=True, text=True, cwd=SCRATCH)
        info = parse_asan((repro.stdout or "") + (repro.stderr or ""))
        sig = (info["kind"], info["function"])
        if sig in seen:
            continue
        seen.add(sig)
        crashes.append({**info, "reproducer_sha256": sha, "reproducer_size": len(data)})
        if len(crashes) >= max_crashes:
            break

    return _emit({"compiled": True, "ran": True, "executions": execs,
                  "max_total_time": max_total_time, "crash_count": len(crashes), "crashes": crashes})


if __name__ == "__main__":
    raise SystemExit(main())
