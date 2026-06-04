#!/usr/bin/env python3
"""CI gate: prove the WITH_GHIDRA sandbox image really decompiles UNDER PRODUCTION HARDENING.

Ghidra shipped broken three times: absent, then a JDK/version mismatch, then it built
fine but DIED INSTANTLY under the real sandbox hardening (`--read-only --user 1000:1000`)
because its launcher couldn't write its user-settings / temp dirs anywhere but the
read-only image home. Each slip happened because nothing exercised a `WITH_GHIDRA=1` build
through the genuine production path. This script is that exercise.

The gate drives the EXACT production code path: `SandboxRunner.run_probe("ghidra_probe.py",
...)`, the same call `GhidraDecompiler` makes. That is deliberate — it can never again
diverge from production hardening, because it IS production hardening (`--network none`,
`--read-only`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000:1000`, scratch tmpfs,
HOME/TMPDIR/XDG_* pinned at scratch). A decompile that fails here is a real, shipping
breakage of `hexgraph` decompilation — which is the whole point of the gate.

It then asserts the result is REAL Ghidra C decompilation (a recovered C function with the
`strcpy` call from the fixture), not radare2 pseudo-asm and not an error.

Usage:
    ci_ghidra_decompile_check.py [IMAGE] [FIXTURE]

Defaults: IMAGE=hexgraph-sandbox:latest (override with the WITH_GHIDRA image tag),
FIXTURE=tests/fixtures/vuln_httpd. Exits non-zero (failing the CI job) if Ghidra
decompilation is broken.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = "hexgraph-sandbox:latest"
DEFAULT_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vuln_httpd"
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

    # Drive the REAL production path so the gate can never diverge from how `hexgraph`
    # actually runs Ghidra: GhidraDecompiler → SandboxRunner.run_probe. run_probe applies
    # the full, UNCONDITIONAL hardening (--network none, --read-only, --cap-drop ALL,
    # --no-new-privileges, --user 1000:1000, scratch tmpfs, HOME/TMPDIR/XDG_* at scratch)
    # and mounts the on-disk probe over the baked copy, exactly as in production.
    try:
        from hexgraph.sandbox.runner import SandboxError, SandboxRunner
    except ImportError as exc:  # pragma: no cover - the CI job installs the package
        _fail(f"could not import hexgraph (install the package in this job): {exc}")

    runner = SandboxRunner(image=image)
    try:
        # run_json_probe == run_probe + json.loads of stdout, the same call GhidraDecompiler
        # makes. On a non-zero probe exit it raises SandboxError; ghidra_probe.py emits its
        # diagnostic (the analyzeHeadless log tail) on STDOUT as {"error": ...}, so surface
        # that too — the previous standalone gate printed only the empty stderr, hiding the
        # cause (the launcher's "Failed to create directory" under --read-only).
        result = runner.run_json_probe("ghidra_probe.py", str(fixture), extra_args=[FOCUS])
    except SandboxError as exc:
        # The probe's JSON error blob (with the analyzeHeadless tail) rides along on the
        # SandboxRunner result; re-run capturing raw stdout so the failure log shows the
        # actual Ghidra error instead of an opaque exit code.
        try:
            raw = runner.run_probe("ghidra_probe.py", str(fixture), extra_args=[FOCUS])
            print("--- probe stdout ---\n" + (raw.stdout or "")[:4000], file=sys.stderr)
            print("--- probe stderr ---\n" + (raw.stderr or "")[:2000], file=sys.stderr)
        except SandboxError as inner:
            # run_probe itself raises on non-zero exit; its message carries the stderr tail.
            print(f"--- run_probe error ---\n{inner}", file=sys.stderr)
        _fail(f"ghidra probe failed under production hardening: {exc}")

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

    print("--- decompiled C (Ghidra, under full production hardening) ---")
    print(pseudo)
    print(f"\nPASS: Ghidra decompiled {FOCUS} to real C "
          f"({len(funcs)} functions recovered) via SandboxRunner.run_probe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
