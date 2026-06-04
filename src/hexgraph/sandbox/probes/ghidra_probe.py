#!/usr/bin/env python3
"""Run Ghidra headless (`analyzeHeadless`) over a target INSIDE the sandbox.

  argv: /artifact [function]        normal decompile/inventory run
        /artifact --check           report Ghidra presence + version (no analysis)

Emits JSON matching the Decompiler contract plus enrichment extras:
  { tool, functions: [...], focus: {name,resolved,pseudocode,disasm,callees}|null,
    calls: [[caller,callee],...], structs: [{name,size,fields}], cached: bool }
For --check: { present: bool, version: str|null, detail: str }.

Ghidra must be installed in the image (built with WITH_GHIDRA=1). The target is
imported and statically analyzed — NEVER executed. Runs with --network none, a
read-only rootfs, and /scratch as the only writable area for HOME/temp/user-settings.

**Analyze once, reuse (Phase 1).** When a writable persistent project is bind-mounted
at /ghidra-project (engine.ghidra_project), the FIRST call imports + analyzes the
artifact into that on-disk project (NO -deleteProject — it persists across container
runs); SUBSEQUENT calls reuse it via `-process <program>` (NO -import, NO re-analysis),
which is dramatically faster on real firmware. Without that mount it falls back to the
old behavior: a throwaway project in the /scratch tmpfs, deleted on exit. Either way the
emitted JSON is identical (`cached` reports whether the warm path was taken). The target
artifact is always read-only at /artifact; the project dir is HexGraph's OWN data."""

from __future__ import annotations

import json
import os
import subprocess
import sys

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
SCRATCH = os.environ.get("TMPDIR", "/scratch")
# The writable persistent-project bind-mount (engine.ghidra_project.CONTAINER_PROJECT_DIR +
# runner.CONTAINER_PROJECT_DIR). Present only when the caller threads a project_mount; absent
# for --check, for radare2 callers, or when the cache is disabled.
PROJECT_MOUNT = "/ghidra-project"
# analyzeHeadless names the GHIDRA PROJECT by the positional arg we pass ("hexgraph", the .gpr),
# but names the imported PROGRAM after the imported file's basename. The artifact is always
# mounted at a fixed path, so the program name inside the project is deterministic — `-process`
# on the warm path targets THAT, not the project name.
PROJECT_NAME = "hexgraph"


def _program_name(artifact: str) -> str:
    """The name analyzeHeadless stores the imported program under (the artifact's basename)."""
    return os.path.basename(artifact) or "artifact"

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

    # The postScript + its JSON output ALWAYS live on the /scratch tmpfs (the project mount
    # holds only the Ghidra project itself — keeps the persistent dir lean and the hardening
    # comment honest: only the project lives on the writable mount, never user-settings/temp).
    script_path = os.path.join(SCRATCH, "hexgraph_post.py")
    out_path = os.path.join(SCRATCH, "ghidra_out.json")
    with open(script_path, "w") as fh:
        fh.write(POST_SCRIPT)

    # Persistent-project cache (analyze-once / reuse). The host resolves
    # <data_dir>/ghidra/<sha256>__<version>/project and bind-mounts it writable here; if a
    # prior COLD run already imported the program (a non-empty project dir), reuse it via
    # `-process` with NO -import / NO re-analysis. Otherwise this is the cold run: import +
    # analyze + PERSIST (no -deleteProject). Without the mount, fall back to a throwaway
    # /scratch project deleted on exit (old behavior).
    persistent = os.path.isdir(PROJECT_MOUNT)
    if persistent:
        proj_dir = os.path.join(PROJECT_MOUNT, "project")
        os.makedirs(proj_dir, exist_ok=True)
        warm = bool(os.path.isdir(proj_dir) and os.listdir(proj_dir))
    else:
        proj_dir = os.path.join(SCRATCH, "ghidra_proj")
        os.makedirs(proj_dir, exist_ok=True)
        warm = False

    prog = _program_name(artifact)
    if warm:
        # WARM: open the existing project, re-run the postScript over the already-imported
        # PROGRAM (named after the artifact basename). No -import, no auto-analysis — the
        # expensive work is reused.
        cmd = [
            hl, proj_dir, PROJECT_NAME,
            "-process", prog,
            "-noanalysis",
            "-scriptPath", SCRATCH,
            "-postScript", "hexgraph_post.py", out_path, focus or "",
        ]
    else:
        # COLD: import + analyze. Persist the project (no -deleteProject) only when the
        # writable mount is present; otherwise delete it (throwaway /scratch fallback).
        cmd = [
            hl, proj_dir, PROJECT_NAME,
            "-import", artifact,
            "-scriptPath", SCRATCH,
            "-postScript", "hexgraph_post.py", out_path, focus or "",
        ]
        if not persistent:
            cmd.append("-deleteProject")
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
    result["cached"] = warm  # True ⇒ reused the persistent project (-process, no re-analysis)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
