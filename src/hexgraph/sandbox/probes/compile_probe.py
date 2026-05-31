#!/usr/bin/env python3
"""Compile a generated harness INSIDE the sandbox (SPEC §5, harness_generation).

argv[1] = /artifact (a .c source file, read-only). Compiles to an object file in
the tmpfs scratch (no link, no fuzzing in v1 — we only prove it builds) and emits
a JSON build result. Always exits 0; the build outcome is in the JSON.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: compile_probe.py <source.c>"}))
        return 2
    src = sys.argv[1]
    compiler = "clang" if shutil.which("clang") else "cc"
    # -c: compile to object only (no link) so extern stubs / fuzzer entry points
    # build without the fuzzing runtime. cwd is the tmpfs /scratch.
    proc = subprocess.run(
        [compiler, "-c", "-w", src, "-o", "harness.o"],
        capture_output=True,
        text=True,
    )
    ok = proc.returncode == 0
    print(
        json.dumps(
            {
                "tool": "compile_probe",
                "compiler": compiler,
                "result": "ok" if ok else "error",
                "returncode": proc.returncode,
                "stderr": (proc.stderr or "")[:2000],
                "artifact": "harness.o" if ok else None,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
