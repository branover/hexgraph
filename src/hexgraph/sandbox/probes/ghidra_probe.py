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
        /artifact --script          run an AGENT-SUPPLIED Python-3 script (from env
                                    HEXGRAPH_USER_SCRIPT_B64) over the WARM program READ-ONLY

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

import base64
import json
import os
import subprocess  # noqa: F401 — kept importable so tests can assert the native path never shells out
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

# --script (re_script) mode. The AGENT-SUPPLIED script body arrives out-of-band via this env var
# (base64), NEVER on the argv — so it can't leak through the world-readable docker command line and
# isn't bounded by ARG_MAX. It is decoded, size-capped, and (since the PyGhidra re-platform) run
# IN-PROCESS by pyghidra_lib.script_core against the WARM program opened READ-ONLY — so the agent's
# script can query but NEVER mutate/corrupt the persistent project (re_script is a QUERY tool).
USER_SCRIPT_ENV = "HEXGRAPH_USER_SCRIPT_B64"
# Hard cap on the decoded user-script size (bytes). A script larger than this is rejected before it
# ever reaches Ghidra — a cheap guard against a pathological/accidental multi-MB body. 64 KiB is
# generous for a data-flow/stack-frame query yet keeps the surface small. (Mirrors the host's
# agent_tools._SCRIPT_MAX_BYTES.)
USER_SCRIPT_MAX_BYTES = 64 * 1024
# The persistent-project mount (engine.re.ghidra_project.CONTAINER_PROJECT_DIR). re_script is
# WARM-ONLY: a committed warm slot must exist here or the script-mode refuses (→ re_analyze lead),
# doing zero Ghidra work on a cold miss. Kept as a module attribute so tests can point it elsewhere.
PROJECT_MOUNT = L.PROJECT_MOUNT
META_NAME = L.META_NAME


def _load_user_script():
    """Decode + validate the agent-supplied --script body from `HEXGRAPH_USER_SCRIPT_B64`.

    Returns `(script_body, None)` on success or `(None, error_message)` on any problem — a
    missing/empty env var, undecodable base64, non-UTF-8 bytes, an empty body, or a body over the
    size cap. The body is NEVER read from argv (it rides the env out-of-band), so it can't leak
    through the world-readable docker command line and isn't bounded by ARG_MAX."""
    raw = os.environ.get(USER_SCRIPT_ENV)
    if not raw:
        return None, (f"--script requires the user script in ${USER_SCRIPT_ENV} (base64); "
                      "none was provided")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except Exception:  # noqa: BLE001 — any decode fault is a bad script, reported as such
        return None, f"${USER_SCRIPT_ENV} is not valid base64"
    if len(decoded) > USER_SCRIPT_MAX_BYTES:
        return None, (f"user script is {len(decoded)} bytes, over the "
                      f"{USER_SCRIPT_MAX_BYTES}-byte cap for re_script")
    try:
        body = decoded.decode("utf-8")
    except UnicodeDecodeError:
        return None, "user script is not valid UTF-8 text"
    if not body.strip():
        return None, "user script is empty"
    return body, None


def _script_warm() -> bool:
    """A committed warm slot at PROJECT_MOUNT (the same signal pyghidra_lib._is_warm reads), keyed
    off THIS module's PROJECT_MOUNT so tests can redirect it. re_script refuses when this is False."""
    if not os.path.isdir(PROJECT_MOUNT):
        return False
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    try:
        with open(marker) as fh:
            json.load(fh)
    except (OSError, ValueError):
        return False
    proj_dir = os.path.join(PROJECT_MOUNT, "project")
    return os.path.isdir(proj_dir) and bool(os.listdir(proj_dir))


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


def _flag_value(argv, flag):
    """The value immediately following `flag` in argv, or None (for `--sbytes <hex>` / `--simm <v>`)."""
    if flag in argv:
        i = argv.index(flag)
        if i + 1 < len(argv):
            return argv[i + 1]
    return None


def _parse(argv):
    """Parse the probe argv into a mode dict. Mirrors the Jython arg grammar exactly."""
    artifact = argv[1]
    rest = argv[2:]
    m = {"artifact": artifact, "mode": "decompile", "focus": None,
         "rename": None, "xrefs_mode": "sinks", "xrefs_subject": "", "user_script": None,
         "search_bytes": None, "search_imm": None}
    if "--script" in rest:
        m["mode"] = "script"  # run the agent-supplied script over the WARM program, read-only
        return m
    if "--search" in rest:
        m["mode"] = "search"  # byte/immediate memory scan over the WARM program, read-only
        m["search_bytes"] = _flag_value(rest, "--sbytes")
        m["search_imm"] = _flag_value(rest, "--simm")
        return m
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
    """Open the target (warm or cold) and run the requested core; returns the JSON payload.

    The `script` mode opens the WARM program READ-ONLY (open_target(read_only=True)) so the
    agent-supplied script can query but never mutate the persistent project."""
    from ghidra.util.task import ConsoleTaskMonitor

    mode = m["mode"]
    # script + search are READ-ONLY, WARM-ONLY queries: they open the warm program immutable and
    # never trigger a cold analysis (a byte scan that cold-analyzes a large target IS the timeout
    # bug; the host falls back to the r2 raw scan on a warm miss instead).
    read_only = mode in ("script", "search")
    with L.open_target(m["artifact"], cold_analyze=not read_only,
                       read_only=read_only) as (program, flat, cached):
        monitor = ConsoleTaskMonitor()
        if mode == "script":
            result = L.script_core(program, flat, monitor, m["user_script"])
        elif mode == "search":
            result = L.search_bytes_core(program, flat, monitor,
                                         bytes_pattern=m.get("search_bytes"),
                                         immediate=m.get("search_imm"))
        elif mode == "taint":
            result = L.taint_core(program, flat, monitor)
        elif mode == "emulate":
            result = L.emulate_core(program, flat, monitor, m["focus"])
        elif mode == "xrefs":
            result = L.xrefs_core(program, flat, monitor, m["xrefs_mode"], m["xrefs_subject"] or None)
        else:  # decompile / analyze (analyze = inventory with no focus; the cold analysis already ran)
            result = L.decompile_core(program, flat, monitor, focus=m["focus"], rename=m["rename"])
        result.setdefault("tool", "ghidra_probe")
        result["cached"] = cached
    return result


def main() -> int:
    if "--check" in sys.argv:
        return _check()
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: ghidra_probe.py <artifact> [focus|--taint|--emulate fn|"
                                   "--xrefs mode [subj]|--rename addr name|--analyze|--script|--check]"}))
        return 2
    m = _parse(sys.argv)
    script_mode = m["mode"] == "script"
    if script_mode:
        # Decode + validate the agent script up front so a bad/oversized/missing body fails FAST —
        # before any Ghidra work (matches the Jython --script pre-flight). rc=2 on a bad script.
        body, err = _load_user_script()
        if err is not None:
            print(json.dumps({"error": err, "tool": "ghidra_script"}))
            return 2
        m["user_script"] = body
        # re_script is WARM-ONLY: without a committed warm project there is nothing to query, so
        # refuse BEFORE launching the JVM / touching Ghidra and point at re_analyze (which builds
        # the warm project once, detached). rc=5 — the host maps this to the re_analyze lead.
        if not _script_warm():
            print(json.dumps({
                "error": "re_script needs a WARM Ghidra project for this target, but none is built "
                         "(cold). Run re_analyze(target) first to build it ONCE (detached; poll "
                         "until state='analyzed'), then re-run re_script — it is warm-only and "
                         "never runs a cold analysis.",
                "tool": "ghidra_script"}))
            return 5
    if not os.path.isdir(os.path.join(GHIDRA_DIR, "Ghidra")) or not _pyghidra_installed():
        print(json.dumps({"error": "Ghidra/PyGhidra not installed in this sandbox image — rebuild "
                                   "it with WITH_GHIDRA=1 (just sandbox-build with_ghidra=1), or "
                                   "switch the decompiler back to radare2"}))
        return 3
    try:
        L.start()
        print(json.dumps(_run(m)))
        return 0
    except Exception as exc:  # noqa: BLE001 — always emit a structured payload, never nothing
        tool = "ghidra_script" if script_mode else "ghidra_probe"
        print(json.dumps({"error": f"ghidra probe failed: {exc}", "tb": traceback.format_exc(),
                          "functions": [], "focus": None, "calls": [], "structs": [],
                          "tool": tool}))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
