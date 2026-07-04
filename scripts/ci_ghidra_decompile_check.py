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
`strcpy` call from the fixture), not radare2 pseudo-asm and not an error. Finally it runs the
warm-project cross-reference query (`--xrefs callers strcpy`, the ReferenceManager path the
re_xrefs family serves from the warm project) and asserts cgi_handler is among strcpy's callers —
the only CI coverage of that Jython, since the offline tier has no Ghidra.

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
        # SandboxRunner raises on a non-zero probe exit and the SandboxError message carries
        # the probe's STDERR tail (runner._run: proc.stderr.strip()[:500]); it does NOT carry
        # stdout, so re-running here cannot recover the {"error": ...} blob the probe writes to
        # stdout (run_probe would just raise again). Surface the SandboxError message, which is
        # the diagnostic available through this seam; the probe's own analyzeHeadless tail must
        # reach stderr (see ghidra_probe) for the root cause to show up here.
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

    # Also exercise the cross-reference path's Jython (ghidra_probe.py XREFS_SCRIPT) end to end on
    # REAL Ghidra: this is the reference-index query the re_xrefs / re_function_xrefs / re_call_graph
    # verbs serve from the warm project, and the offline tier has no Ghidra to run it. cgi_handler
    # does `strcpy(buf, token)`, so "who calls strcpy" (ReferenceManager.getReferencesTo, filtered
    # to the containing function) MUST include cgi_handler. Drives the SAME production run_probe path
    # (a cold throwaway project here, which still imports+analyzes then runs XREFS_SCRIPT).
    try:
        xr = runner.run_json_probe("ghidra_probe.py", str(fixture),
                                   extra_args=["--xrefs", "callers", "strcpy"])
    except SandboxError as exc:
        _fail(f"ghidra xrefs probe failed under production hardening: {exc}")
    if "error" in xr:
        _fail(f"xrefs probe reported an error: {xr['error']}")
    callers = [c.get("caller") for c in (xr.get("callers") or [])]
    if FOCUS not in callers:
        _fail(f"xrefs(callers of strcpy) did not include {FOCUS!r} — the warm-project reference "
              f"index is wrong or empty: {callers[:30]}")
    print(f"PASS: Ghidra xrefs (ReferenceManager) found {FOCUS} among callers of strcpy "
          f"({len(callers)} caller site(s)) via SandboxRunner.run_probe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
