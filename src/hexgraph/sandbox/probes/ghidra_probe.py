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
        print(json.dumps({"error": "Ghidra not installed in sandbox image (WITH_GHIDRA=1)"}))
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
        print(json.dumps({"error": f"analyzeHeadless produced no output (exit {proc.returncode}): "
                                   f"{proc.stderr.strip()[:400]}"}))
        return 4
    with open(out_path) as fh:
        result = json.load(fh)
    result["tool"] = "ghidra_probe"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
