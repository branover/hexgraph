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
import shutil
import subprocess
import sys
import time

GHIDRA_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
SCRATCH = os.environ.get("TMPDIR", "/scratch")
# The writable persistent-project bind-mount (engine.ghidra_project.CONTAINER_PROJECT_DIR +
# runner.CONTAINER_PROJECT_DIR). Present only when the caller threads a project_mount; absent
# for --check, for radare2 callers, or when the cache is disabled.
PROJECT_MOUNT = "/ghidra-project"
# The COMMITTED warm marker (engine.ghidra_project.META_NAME), written under PROJECT_MOUNT as the
# LAST step of a successful cold import. Its presence — NOT the raw non-emptiness of the project
# dir — is the authoritative "this slot is a valid warm project" signal: a crashed/timed-out cold
# import leaves a non-empty project dir but NO marker, so the next run re-imports cold instead of
# opening a never-fully-imported program with -process (which would fail forever).
META_NAME = "meta.json"
# analyzeHeadless names the GHIDRA PROJECT by the positional arg we pass ("hexgraph", the .gpr),
# but names the imported PROGRAM after the imported file's basename. The artifact is always
# mounted at a fixed path, so the program name inside the project is deterministic — `-process`
# on the warm path targets THAT, not the project name.
PROJECT_NAME = "hexgraph"


def _program_name(artifact: str) -> str:
    """The name analyzeHeadless stores the imported program under (the artifact's basename)."""
    return os.path.basename(artifact) or "artifact"


def _valid_marker(path: str) -> bool:
    """True iff `path` is a committed, parseable warm marker. Anything else (absent, empty,
    truncated/corrupt JSON from a crash) ⇒ treat the slot as cold."""
    try:
        with open(path) as fh:
            json.load(fh)
        return True
    except (OSError, ValueError):
        return False


def _clear_partial(proj_dir: str, marker: str | None) -> None:
    """Wipe a partially-written persistent slot before a cold re-import: drop the stale marker
    and the incomplete project dir, then recreate an empty project dir. Best-effort."""
    if marker:
        try:
            os.remove(marker)
        except OSError:
            pass
    try:
        if os.path.isdir(proj_dir):
            shutil.rmtree(proj_dir)
    except OSError:
        pass
    os.makedirs(proj_dir, exist_ok=True)


def _commit_marker(marker: str, prog: str) -> None:
    """COMMIT the warm marker — the LAST step of a successful cold import, written atomically
    (tmp + os.replace) so a crash never leaves a half-written marker that reads as warm. Mirrors
    engine.ghidra_project.GhidraProject.write_meta; its presence makes the slot warm next call."""
    payload = json.dumps({
        "program_name": prog,
        "version": _version(),
        "created_at": time.time(),
    })
    tmp = marker + ".tmp"
    try:
        with open(tmp, "w") as fh:
            fh.write(payload)
        os.replace(tmp, marker)
    except OSError:
        pass  # best-effort; without a marker the next call simply re-imports cold (correct)

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
import re
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
        # Flag compiler/library built-ins so the enrichment extractor drops them and only
        # program-recovered (DWARF/GDT) layouts reach the substrate. A built-in type comes
        # from the BUILTIN source archive (or, as a fallback, a system category path).
        builtin = False
        try:
            sa = dt.getSourceArchive()
            if sa is not None and str(sa.getArchiveType()) == "BUILTIN":
                builtin = True
            else:
                cp = dt.getCategoryPath().getPath()
                if cp.startswith("/DWARF") is False and ("/std" in cp or "/__" in cp):
                    builtin = True
        except:
            pass
        result["structs"].append({
            "name": dt.getName(), "size": dt.getLength(), "builtin": builtin,
            "fields": [{"name": c.getFieldName(), "type": str(c.getDataType()),
                        "offset": c.getOffset()} for c in comps[:64]],
        })
        if len(result["structs"]) >= 200:
            break
except:
    pass

if focus:
    target = None
    # A focus given as a strict hex address resolves to the function CONTAINING it
    # (analyze-at-address); otherwise match by name. The strict regex matches the
    # radare2 path so the two backends agree on what counts as an address.
    is_addr = bool(re.match(r"^0x[0-9a-fA-F]+$", focus))
    if is_addr:
        try:
            target = getFunctionContaining(toAddr(focus))
        except:
            target = None
    else:
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
        try:
            addr = "0x" + target.getEntryPoint().toString()
        except:
            addr = None
        # Rich, always-welcome facts recovered for the function being promoted: the C
        # prototype, calling convention, and parameter/local variables. Each guarded so a
        # single failing Jython API call drops only that fact, never the whole focus.
        prototype = None
        try:
            prototype = target.getSignature().getPrototypeString()
        except:
            pass
        calling_convention = None
        try:
            calling_convention = target.getCallingConventionName()
        except:
            pass
        params = []
        try:
            params = [{"name": p.getName(), "type": str(p.getDataType())}
                      for p in target.getParameters()]
        except:
            pass
        local_vars = []
        try:
            param_names = set(p.get("name") for p in params)
            # getLocalVariables() excludes parameters by definition; still, drop any name
            # that surfaced as a parameter so a spilled-param slot can't double-count.
            local_vars = [{"name": v.getName(), "type": str(v.getDataType())}
                          for v in target.getLocalVariables()
                          if v.getName() not in param_names]
        except:
            pass
        focus_out = {"name": target.getName(), "resolved": target.getName(),
                     "address": addr, "pseudocode": pseudo, "disasm": "", "callees": callees}
        if prototype:
            focus_out["prototype"] = prototype
        if calling_convention:
            focus_out["calling_convention"] = calling_convention
        if params:
            focus_out["params"] = params
            focus_out["param_count"] = len(params)
        if local_vars:
            focus_out["locals"] = local_vars
            focus_out["local_count"] = len(local_vars)
        result["focus"] = focus_out

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
        marker = os.path.join(PROJECT_MOUNT, META_NAME)
        # WARM only on the COMMITTED marker (written as the last step of a prior successful cold
        # import) AND a non-empty project dir — never on raw dir non-emptiness, so a half-written
        # cold run reads as cold.
        warm = bool(_valid_marker(marker)
                    and os.path.isdir(proj_dir) and os.listdir(proj_dir))
        if not warm:
            # Cold (fresh OR half-written): wipe any partial project + stale marker so the import
            # starts clean, then re-import.
            _clear_partial(proj_dir, marker)
    else:
        proj_dir = os.path.join(SCRATCH, "ghidra_proj")
        marker = None
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
    # COMMIT the warm marker as the LAST step of a successful COLD persistent import — the
    # postScript only wrote out_path after a complete import+analyze, so reaching here means the
    # project is fully imported. This atomic commit is the cold→warm transition: only now does the
    # slot read as warm next call. (Warm runs already have it; throwaway runs have no mount.)
    if persistent and not warm and marker:
        _commit_marker(marker, prog)
    result["tool"] = "ghidra_probe"
    result["cached"] = warm  # True ⇒ reused the persistent project (-process, no re-analysis)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
