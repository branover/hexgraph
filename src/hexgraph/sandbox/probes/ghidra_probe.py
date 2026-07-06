#!/usr/bin/env python3
"""Run Ghidra over a target INSIDE the sandbox — the Ghidra probe entrypoint.

Drives Ghidra IN-PROCESS via **PyGhidra** (CPython 3 over jpype), NOT `analyzeHeadless` +
Jython postScripts. The Ghidra Java API is identical, so each analysis core ports ~1:1 from
its former Jython script; they now live in `pyghidra_lib` (real Python 3, shared with the
resident bridge). The host seam is unchanged — `run_json_probe("ghidra_probe.py", artifact,
extra_args=…)` — and the emitted JSON contracts are byte-for-byte the same.

  argv: /artifact [function]        decompile/inventory (focus = a name or 0xADDR)
        /artifact --check           report Ghidra presence + version (no analysis, no JVM)
        /artifact --analyze         whole-binary cold analysis + COMMIT the warm slot (no focus)
        /artifact --taint           grounded P-Code source->sink data-flow taint
        /artifact --emulate <fn>    emulate <fn> in the P-Code emulator + recover its constant
        /artifact --xrefs <mode> [subj]   cross-reference query from the warm reference index
        /artifact --rename <addr> <name>  rename the fn at addr + re-decompile (persists)

Ghidra must be in the image (built WITH_GHIDRA=1). The target is imported + statically analyzed,
NEVER executed. Runs with --network none, a read-only rootfs, --user 1000, and /scratch as the
only writable area (HOME/temp/user-settings + the JVM's user.home/java.io.tmpdir — see
pyghidra_lib for the hardened-sandbox env recipe). MUST run from /opt/hexgraph (a read-only mount):
pyghidra's namespace-path finder recurses if sys.path[0] is writable — the runner invokes
`python3 /opt/hexgraph/ghidra_probe.py`, so sys.path[0] is the read-only probe dir. Fine.

**Analyze once, reuse.** When a writable persistent project is bind-mounted at /ghidra-project
(engine.re.ghidra_project), the FIRST call imports + analyzes into that on-disk project and COMMITS
a warm marker; SUBSEQUENT calls open it warm (NO re-analysis). Without the mount it falls back to a
throwaway /scratch project. `cached` reports whether the warm path was taken. The persistent slot's
layout + marker are shared with the Jython-era cache, so slots analyzed before the flip open warm."""
from __future__ import annotations

import json
import os
import sys
import traceback

# The probe dir (this file's dir, /opt/hexgraph) is on sys.path[0]; pyghidra_lib sits beside it.
# Dual-mode: a bare import when RUN as a script from /opt/hexgraph; the package path when IMPORTED
# as a module (host tests do `from hexgraph.sandbox.probes import ghidra_probe`).
try:
    import pyghidra_lib as L
except ModuleNotFoundError:  # pragma: no cover — the package-import path (tests)
    from hexgraph.sandbox.probes import pyghidra_lib as L

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")


def _pyghidra_installed() -> bool:
    import importlib.util

    return importlib.util.find_spec("pyghidra") is not None


def _check() -> int:
    """Report Ghidra presence + version WITHOUT launching the JVM (the host calls this to gate
    availability and to read the version for the persistent-cache key). `present` needs both the
    Ghidra install and the pyghidra module; `version` is Ghidra's (e.g. '12.1'), never pyghidra's."""
    have_ghidra = os.path.isdir(os.path.join(GHIDRA_DIR, "Ghidra"))
    have_pyghidra = _pyghidra_installed()
    version = L.ghidra_version()
    present = have_ghidra and have_pyghidra
    if present:
        detail = f"PyGhidra + Ghidra {version or '?'} available in the sandbox."
    elif not have_ghidra:
        detail = "Ghidra not found — rebuild the sandbox image with WITH_GHIDRA=1."
    else:
        detail = "pyghidra module not installed in the sandbox image (rebuild WITH_GHIDRA=1)."
    print(json.dumps({"present": present, "version": version, "detail": detail}))
    return 0


def _parse(argv):
    """Parse the probe argv into a mode dict. Mirrors the Jython arg grammar exactly."""
    artifact = argv[1]
    rest = argv[2:]
    m = {"artifact": artifact, "mode": "decompile", "focus": None,
         "rename": None, "xrefs_mode": "sinks", "xrefs_subject": ""}
    if "--analyze" in rest:
        m["mode"] = "analyze"  # cold whole-binary analysis, no focus
        return m
    if "--taint" in rest:
        m["mode"] = "taint"
        return m
    if "--emulate" in rest:
        m["mode"] = "emulate"
        i = rest.index("--emulate")
        m["focus"] = rest[i + 1] if i + 1 < len(rest) else None
        return m
    if "--xrefs" in rest:
        m["mode"] = "xrefs"
        i = rest.index("--xrefs")
        if i + 1 < len(rest) and not rest[i + 1].startswith("--"):
            m["xrefs_mode"] = rest[i + 1]
        if i + 2 < len(rest) and not rest[i + 2].startswith("--"):
            m["xrefs_subject"] = rest[i + 2]
        return m
    if "--rename" in rest:
        i = rest.index("--rename")
        if i + 2 < len(rest):
            m["rename"] = (rest[i + 1], rest[i + 2])
    # plain decompile: focus = the first positional (non-flag) arg, if any.
    m["focus"] = next((a for a in rest if not a.startswith("--")), None)
    return m


def _run(m) -> dict:
    """Open the target (warm or cold) and run the requested core; returns the JSON payload."""
    from ghidra.util.task import ConsoleTaskMonitor

    with L.open_target(m["artifact"], cold_analyze=True) as (program, flat, cached):
        monitor = ConsoleTaskMonitor()
        mode = m["mode"]
        if mode == "taint":
            result = L.taint_core(program, flat, monitor)
        elif mode == "emulate":
            result = L.emulate_core(program, flat, monitor, m["focus"])
        elif mode == "xrefs":
            result = L.xrefs_core(program, flat, monitor, m["xrefs_mode"], m["xrefs_subject"] or None)
        else:  # decompile / analyze (analyze = inventory with no focus; the cold analysis already ran)
            result = L.decompile_core(program, flat, monitor, focus=m["focus"], rename=m["rename"])
        result["tool"] = "ghidra_probe"
        result["cached"] = cached
    return result


def main() -> int:
    if "--check" in sys.argv:
        return _check()
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: ghidra_probe.py <artifact> [focus|--taint|--emulate fn|"
                                   "--xrefs mode [subj]|--rename addr name|--analyze|--check]"}))
        return 2
    if not os.path.isdir(os.path.join(GHIDRA_DIR, "Ghidra")) or not _pyghidra_installed():
        print(json.dumps({"error": "Ghidra/PyGhidra not installed in this sandbox image — rebuild "
                                   "it with WITH_GHIDRA=1 (just sandbox-build with_ghidra=1), or "
                                   "switch the decompiler back to radare2"}))
        return 3
    try:
        L.start()
        print(json.dumps(_run(_parse(sys.argv))))
        return 0
    except Exception as exc:  # noqa: BLE001 — always emit a structured payload, never nothing
        print(json.dumps({"error": f"ghidra probe failed: {exc}", "tb": traceback.format_exc(),
                          "functions": [], "focus": None, "calls": [], "structs": [],
                          "tool": "ghidra_probe"}))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
