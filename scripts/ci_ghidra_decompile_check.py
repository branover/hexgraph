#!/usr/bin/env python3
"""CI gate: prove the WITH_GHIDRA sandbox image really decompiles.

Ghidra shipped broken twice (absent, then a JDK/version mismatch) because nothing
exercised a `WITH_GHIDRA=1` build end to end. This script is that exercise: it runs
the unmodified `ghidra_probe.py` over a tiny fixture ELF inside the sandbox image —
exactly the way `SandboxRunner.run_probe` does (plain `--network none`, read-only
artifact, probes mounted, scratch tmpfs) — and asserts the result is REAL Ghidra C
decompilation, not radare2 pseudo-asm and not an error.

Usage:
    ci_ghidra_decompile_check.py [IMAGE] [FIXTURE]

Defaults: IMAGE=hexgraph-sandbox:latest, FIXTURE=tests/fixtures/vuln_httpd.
Exits non-zero (failing the CI job) if Ghidra decompilation is broken.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = "hexgraph-sandbox:latest"
DEFAULT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vuln_httpd"
PROBES_DIR = REPO_ROOT / "src" / "hexgraph" / "sandbox" / "probes"
# The fixture (vuln_httpd.c) has cgi_handler() do `strcpy(buf, token)`. Real Ghidra C
# recovers exactly this; radare2 `pdc` pseudo-asm would not. We assert on the function
# signature shape and the strcpy call, which only a true decompile produces.
FOCUS = "cgi_handler"


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    image = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IMAGE
    fixture = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else DEFAULT_FIXTURE

    if not fixture.is_file():
        _fail(f"fixture not found: {fixture}")
    if not PROBES_DIR.is_dir():
        _fail(f"probes dir not found: {PROBES_DIR}")

    # Mirror SandboxRunner.run_probe's FULL production hardening so the gate proves the
    # REAL config works, not a looser one: --network none, read-only rootfs + artifact,
    # all caps dropped, no-new-privileges, unprivileged uid 1000, a writable scratch tmpfs
    # (mode 1777 so uid 1000 can write) + /dev/shm, with HOME/TMPDIR pointed at scratch.
    # Production runs Ghidra under exactly these flags, so a decompile that fails here is a
    # real breakage — which is the point of the gate.
    cmd = [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", "1000:1000",
        "-v", f"{fixture}:/artifact:ro",
        "-v", f"{PROBES_DIR}:/opt/hexgraph:ro",
        "--tmpfs", "/scratch:rw,exec,mode=1777",
        "--tmpfs", "/dev/shm:rw,mode=1777",
        "--workdir", "/scratch",
        "-e", "HOME=/scratch",
        "-e", "TMPDIR=/scratch",
        image,
        "python3", "/opt/hexgraph/ghidra_probe.py", "/artifact", FOCUS,
    ]
    print("Running:", " ".join(cmd), flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        _fail(f"ghidra probe exited {proc.returncode}\nstderr:\n{proc.stderr[:2000]}")

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        _fail(f"probe did not emit JSON ({exc})\nstdout:\n{proc.stdout[:2000]}")

    if "error" in result:
        _fail(f"probe reported an error: {result['error']}")

    funcs = result.get("functions") or []
    if FOCUS not in funcs:
        _fail(f"{FOCUS!r} not in recovered function inventory: {funcs[:30]}")

    focus = result.get("focus") or {}
    pseudo = (focus.get("pseudocode") or "").strip()
    if not pseudo:
        _fail("no pseudocode returned for the focus function (analysis produced nothing)")

    # Assert it's REAL C decompilation. Ghidra's decompiler emits a C function with a
    # signature line and the recovered strcpy call; radare2 `pdc` and any error path
    # would not satisfy all of these together.
    checks = {
        "has a C function signature for cgi_handler": f"{FOCUS}(" in pseudo,
        "recovered the strcpy call": "strcpy" in pseudo,
        "looks like C, not an error blob": "{" in pseudo and "}" in pseudo,
    }
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        print("--- pseudocode ---\n" + pseudo[:2000], file=sys.stderr)
        _fail("decompiled output failed C checks: " + "; ".join(failed))

    print("--- decompiled C (Ghidra) ---")
    print(pseudo)
    print(f"\nPASS: Ghidra decompiled {FOCUS} to real C "
          f"({len(funcs)} functions recovered).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
