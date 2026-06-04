#!/usr/bin/env python3
"""Run Ghidra headless (`analyzeHeadless`) over a target INSIDE the sandbox.

  argv: /artifact [function]        normal decompile/inventory run
        /artifact --check           report Ghidra presence + version (no analysis)

Emits JSON matching the Decompiler contract plus enrichment extras:
  { tool, functions: [...], focus: {name,resolved,pseudocode,disasm,callees}|null,
    calls: [[caller,callee],...], structs: [{name,size,fields}] }
For --check: { present: bool, version: str|null, detail: str }.

Ghidra must be installed in the image (built with WITH_GHIDRA=1). The target is
imported and statically analyzed — NEVER executed. Runs with --network none, a
read-only rootfs, and /scratch as the only writable area (Ghidra project + HOME).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
SCRATCH = os.environ.get("TMPDIR", "/scratch")

# Under the production sandbox hardening (`--read-only --user 1000:1000`) the ONLY
# writable area is the /scratch tmpfs. Ghidra's launcher writes outside the project
# dir before any analysis runs: `analyzeHeadless` → LaunchSupport saves the resolved
# Java home into the user-settings dir, which it derives from XDG_CONFIG_HOME (NOT
# $HOME), and Java's own caches/tmp come from XDG_CACHE_HOME / TMPDIR. If any of those
# still point at the read-only image home (`/home/analyst/.config/ghidra/...`) the
# launch dies instantly with "Failed to create directory" (exit 1) — long before our
# postScript runs, so the gate just saw "no output". `SandboxRunner.run_probe` already
# exports HOME/TMPDIR/XDG_* at /scratch; we re-assert them HERE so the probe works under
# full hardening regardless of which caller invokes it (the gate, a future executor),
# pinning every writable Ghidra/Java path at the one tmpfs. This adds NO privilege — it
# only redirects writes to the already-writable scratch tmpfs.
for _var in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
             "XDG_STATE_HOME"):
    os.environ.setdefault(_var, SCRATCH)
# Ghidra's launcher (ApplicationUtilities) creates its per-run temp dir under the JVM's
# `java.io.tmpdir`, which defaults to /tmp regardless of $TMPDIR — and under --read-only
# /tmp is NOT writable unless a caller happens to mount a /tmp tmpfs. Pin the JVM temp at
# /scratch via _JAVA_OPTIONS so EVERY writable Ghidra/Java path lands on the one tmpfs the
# hardened sandbox guarantees, making the probe self-sufficient under bare --read-only +
# --user 1000 with only /scratch writable. Prepend so a caller-supplied _JAVA_OPTIONS wins.
_existing_jopts = os.environ.get("_JAVA_OPTIONS", "")
os.environ["_JAVA_OPTIONS"] = (f"-Djava.io.tmpdir={SCRATCH} {_existing_jopts}").strip()

# Jython postScript Ghidra runs after auto-analysis. It writes JSON to args[0];
# args[1] (optional) is the focus function to decompile.
POST_SCRIPT = r'''
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
focus = args[1] if len(args) > 1 and args[1] else None
monitor = ConsoleTaskMonitor()
fm = currentProgram.getFunctionManager()
funcs = list(fm.getFunctions(True))
result = {"functions": [f.getName() for f in funcs][:400], "focus": None, "calls": [], "structs": []}

edges = []
for f in funcs[:600]:
    try:
        for callee in f.getCalledFunctions(monitor):
            edges.append([f.getName(), callee.getName()])
            if len(edges) >= 2000:
                break
    except:
        pass
    if len(edges) >= 2000:
        break
result["calls"] = edges

dtm = currentProgram.getDataTypeManager()
try:
    for dt in dtm.getAllStructures():
        comps = dt.getComponents()
        result["structs"].append({
            "name": dt.getName(), "size": dt.getLength(),
            "fields": [{"name": c.getFieldName(), "type": str(c.getDataType())} for c in comps[:64]],
        })
        if len(result["structs"]) >= 200:
            break
except:
    pass

if focus:
    target = None
    for f in funcs:
        if f.getName() == focus:
            target = f
            break
    if target is not None:
        deci = DecompInterface()
        deci.openProgram(currentProgram)
        res = deci.decompileFunction(target, 60, monitor)
        pseudo = ""
        if res is not None and res.decompileCompleted():
            df = res.getDecompiledFunction()
            if df is not None:
                pseudo = df.getC()
        callees = []
        try:
            callees = [c.getName() for c in target.getCalledFunctions(monitor)]
        except:
            pass
        result["focus"] = {"name": focus, "resolved": target.getName(),
                           "pseudocode": pseudo, "disasm": "", "callees": callees}

fh = open(out_path, "w")
fh.write(json.dumps(result))
fh.close()
'''


def _find_headless() -> str | None:
    cand = os.path.join(GHIDRA_DIR, "support", "analyzeHeadless")
    if os.path.isfile(cand):
        return cand
    import shutil

    return shutil.which("analyzeHeadless")


def _version() -> str | None:
    props = os.path.join(GHIDRA_DIR, "Ghidra", "application.properties")
    try:
        with open(props) as fh:
            for line in fh:
                if line.startswith("application.version"):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


def _check() -> int:
    hl = _find_headless()
    print(json.dumps({
        "present": bool(hl),
        "version": _version(),
        "detail": (f"analyzeHeadless found at {hl}" if hl
                   else "analyzeHeadless not found — rebuild the sandbox image with WITH_GHIDRA=1"),
    }))
    return 0


def main() -> int:
    if "--check" in sys.argv:
        return _check()
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: ghidra_probe.py <artifact> [function]"}))
        return 2
    artifact = sys.argv[1]
    focus = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else None

    hl = _find_headless()
    if not hl:
        print(json.dumps({"error": "Ghidra not installed in this sandbox image — rebuild it "
                                   "with WITH_GHIDRA=1 (just sandbox-build with_ghidra=1), or "
                                   "switch the decompiler back to radare2"}))
        return 3

    proj_dir = os.path.join(SCRATCH, "ghidra_proj")
    os.makedirs(proj_dir, exist_ok=True)
    script_path = os.path.join(SCRATCH, "hexgraph_post.py")
    out_path = os.path.join(SCRATCH, "ghidra_out.json")
    with open(script_path, "w") as fh:
        fh.write(POST_SCRIPT)

    cmd = [
        hl, proj_dir, "hexgraph",
        "-import", artifact,
        "-scriptPath", SCRATCH,
        "-postScript", "hexgraph_post.py", out_path, focus or "",
        "-deleteProject",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not os.path.isfile(out_path):
        # analyzeHeadless logs to STDOUT, not stderr — read stdout for the real reason
        # (the old code read the empty stderr, so the surfaced detail was blank). Prefer
        # the tail of stdout (the failing analysis log lines); fall back to stderr.
        log = (proc.stdout or "").strip() or (proc.stderr or "").strip()
        tail = "\n".join(log.splitlines()[-12:])[-1500:] if log else "(no analyzeHeadless output)"
        print(json.dumps({"error": f"analyzeHeadless produced no output (exit {proc.returncode}); "
                                   f"analysis log tail:\n{tail}"}))
        return 4
    with open(out_path) as fh:
        result = json.load(fh)
    result["tool"] = "ghidra_probe"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
