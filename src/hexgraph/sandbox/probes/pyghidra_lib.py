#!/usr/bin/env python3
"""Shared PyGhidra runtime + analysis cores (Python 3), used by the headless probe
(`pyghidra_probe.py`) AND the resident bridge. Replaces the Jython `ghidra_probe.py` scripts:
the Ghidra Java API is identical via jpype, so each core ports ~1:1 from its Jython original,
now in real Python 3 — no encoding cookie, f-strings, shared between headless + bridge.

Sandbox hardening recipe (proven under --user 1000:1000 --read-only --network none --cap-drop ALL):
pin every writable Ghidra/Java path at the /scratch tmpfs. Beyond HOME/TMPDIR/XDG (which the runner
sets), pyghidra ALSO needs (a) Python's tempfile via $TMPDIR (its plugin lock) and (b) the JVM's
`-Duser.home=/scratch` — under --user 1000 Java reads user.home from /etc/passwd (=/home/analyst,
read-only), IGNORING $HOME. Set these BEFORE pyghidra.start() (before the JVM launches). NOTE: never
run a pyghidra script from a writable dir on sys.path (e.g. /scratch) — its namespace-path finder
recurses; probes run from /opt/hexgraph (read-only), which is fine.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import time

SCRATCH = os.environ.get("TMPDIR", "/scratch")
PROJECT_MOUNT = "/ghidra-project"
PROJECT_NAME = "hexgraph"          # the Ghidra project name (matches ghidra_probe)
META_NAME = "meta.json"            # the committed warm marker (matches ghidra_probe)
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")

# Above this size a COLD import runs the "fast profile": disable the auto-analysis passes proven
# pathological on a 100 MB+ monolith (see _slow) so recon still gets functions/call-graph/strings
# but the O(n^2) / decompile-every-function passes don't grind for tens of minutes. Smaller binaries
# keep FULL analysis. (Ported from ghidra_probe.GHIDRA_FAST_PROFILE_BYTES.)
_FAST_PROFILE_BYTES = int(float(os.environ.get("HEXGRAPH_GHIDRA_FAST_PROFILE_MB", "100")) * 1024 * 1024)


def _setup_env() -> None:
    """Pin every writable Ghidra/Java/Python-temp path at /scratch BEFORE the JVM starts."""
    for var in ("HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                "XDG_STATE_HOME"):
        os.environ.setdefault(var, SCRATCH)
    heap = os.environ.get("HEXGRAPH_GHIDRA_HEAP_PCT", "45.0")
    existing = os.environ.get("_JAVA_OPTIONS", "")
    os.environ["_JAVA_OPTIONS"] = (
        f"-Djava.io.tmpdir={SCRATCH} -Duser.home={SCRATCH} -XX:MaxRAMPercentage={heap} {existing}"
    ).strip()


_STARTED = False


def start() -> None:
    """Idempotently launch the JVM + Ghidra (pyghidra). Sets the env first."""
    global _STARTED
    if _STARTED:
        return
    _setup_env()
    import pyghidra

    pyghidra.start()
    _STARTED = True


def program_name(artifact: str) -> str:
    """The name the program is stored under (the artifact basename — /artifact -> 'artifact')."""
    return os.path.basename(artifact) if artifact else "artifact"


def _is_warm(proj_dir: str) -> bool:
    """A committed, non-empty persistent slot (the marker is written as the last cold step).

    Mirrors the host's authoritative `GhidraProject.exists()`: the committed marker loads AND the
    project LOCATION (`proj_dir` = /ghidra-project/project) is non-empty. Ghidra lays a project out
    as `hexgraph.gpr` + `hexgraph.rep/` directly under the location (NOT a `hexgraph/` subdir), so
    it's the location itself that must be non-empty — same signal the Jython probe committed."""
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    try:
        with open(marker) as fh:
            json.load(fh)
    except (OSError, ValueError):
        return False
    return os.path.isdir(proj_dir) and bool(os.listdir(proj_dir))


def _commit_marker() -> None:
    """Commit the warm marker atomically — the LAST step of a successful cold analyze."""
    marker = os.path.join(PROJECT_MOUNT, META_NAME)
    tmp = marker + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump({"program_name": PROJECT_NAME, "created_at": time.time()}, fh)
        os.replace(tmp, marker)
    except OSError:
        pass


@contextlib.contextmanager
def open_target(artifact, *, cold_analyze=True):
    """Yield `(program, flat, cached)` for the target. WARM (a committed slot at PROJECT_MOUNT):
    open the resident project + program, NO re-analysis. COLD: import + analyze; persist into the
    slot (+ commit the marker) when the mount is present, else a throwaway /scratch project.

    `cached` is True on the warm path. The Program is closed / the project released on exit."""
    import pyghidra
    from ghidra.program.flatapi import FlatProgramAPI

    proj_dir = os.path.join(PROJECT_MOUNT, "project") if os.path.isdir(PROJECT_MOUNT) else None
    prog_name = program_name(artifact)

    if proj_dir and _is_warm(proj_dir):
        project = pyghidra.open_project(proj_dir, PROJECT_NAME)
        try:
            with pyghidra.program_context(project, "/" + prog_name) as program:
                yield program, FlatProgramAPI(program), True
        finally:
            with contextlib.suppress(Exception):
                project.close()
        return

    if not cold_analyze:
        raise RuntimeError("no warm analysis for this target (run re_analyze first)")

    # COLD import + analyze. Persist into the slot when mounted; else a throwaway.
    persist = bool(proj_dir)
    if persist:
        _clear_partial(proj_dir)
        loc, name = proj_dir, PROJECT_NAME
    else:
        loc = os.path.join(SCRATCH, "ghidra_proj")
        name = PROJECT_NAME
        os.makedirs(loc, exist_ok=True)
    # open_program imports (analyze=False so WE drive analysis with the fast profile) into loc/name
    # and yields the FlatProgramAPI. PERSISTENCE is handled by open_program's own context exit
    # (`project.save(program)`), NOT an explicit `program.save()`: auto-analysis leaves the program's
    # DB transaction settling, and `project.save` handles that the way analyzeHeadless does, whereas a
    # direct `program.save()` raises "Unable to lock due to active transaction" on any non-trivial
    # binary. The marker is committed only AFTER a clean exit (save succeeded), so a failed analysis
    # leaves no committed marker and the host re-analyzes.
    with pyghidra.open_program(artifact, project_location=loc, project_name=name,
                               program_name=prog_name, analyze=False,
                               nested_project_location=False) as flat:
        program = flat.getCurrentProgram()
        _analyze(program, artifact)
        yield program, flat, False
    if persist:
        _commit_marker()


def _slow_analyzer(name: str) -> bool:
    """The auto-analysis passes disabled under the fast profile — matched by suffix so it's
    architecture-agnostic ("PowerPC/ARM/x86 … Constant Reference Analyzer"). Mirrors the Jython
    FAST_PROFILE_SCRIPT: drop the O(n^2) Call-Fixup Installer, the per-processor constant/scalar
    propagation, and the decompile-EVERY-function passes; KEEP function/call-graph/reference
    discovery (HexGraph decompiles on demand)."""
    if "." in name:
        return False
    if name in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                "Aggressive Instruction Finder"):
        return True
    return name.endswith("Constant Reference Analyzer") or name.endswith("Scalar Operand References")


def _apply_fast_profile(program) -> None:
    """Disable the pathological analyzers on a large binary (in a transaction, as option writes
    modify the program). Best-effort per option so one failure doesn't abort the profile."""
    txid = program.startTransaction("hexgraph fast-profile")
    try:
        opts = program.getOptions("Analyzers")
        for name in list(opts.getOptionNames()):
            if _slow_analyzer(name):
                with contextlib.suppress(Exception):
                    opts.setBoolean(name, False)
    finally:
        program.endTransaction(txid, True)


def _analyze(program, artifact) -> None:
    """Run Ghidra auto-analysis over a freshly-imported program to completion: the fast profile for
    a large binary (disables the passes pathological on a monolith), then AutoAnalysisManager, then
    mark the program analyzed so a warm re-open skips analysis.

    NO in-process timeout: the Jython `-analysisTimeoutPerFile` graceful-partial-save doesn't port
    cleanly (cancelling AutoAnalysisManager mid-pass corrupts the DB transaction, so the partial
    can't be saved), and it's superseded anyway — `re_analyze` runs this DETACHED with a generous
    budget, and the fast profile is the real bound on a monolith. A pathological binary that outruns
    even the detached budget is stopped by the operator (re_bridge/re_analyze), not silently."""
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.util.task import ConsoleTaskMonitor

    large = False
    with contextlib.suppress(OSError):
        large = artifact is not None and os.path.getsize(artifact) >= _FAST_PROFILE_BYTES
    if large:
        _apply_fast_profile(program)

    mgr = AutoAnalysisManager.getAnalysisManager(program)
    mgr.initializeOptions()
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(ConsoleTaskMonitor())  # synchronous; persistence is open_program's exit save
    with contextlib.suppress(Exception):
        GhidraProgramUtilities.markProgramAnalyzed(program)


def _clear_partial(proj_dir: str) -> None:
    """Wipe a partially-written slot before a cold re-import (marker + project dir)."""
    with contextlib.suppress(OSError):
        os.remove(os.path.join(PROJECT_MOUNT, META_NAME))
    with contextlib.suppress(OSError):
        if os.path.isdir(proj_dir):
            shutil.rmtree(proj_dir)
    os.makedirs(proj_dir, exist_ok=True)


# --- Cores (ported from the Jython scripts; the Ghidra Java API is identical) ---------------

def _apply_rename(program, flat, addr, new_name) -> bool:
    """Rename the function CONTAINING `addr` to `new_name` and PERSIST it (a transaction-wrapped
    write + save). Shared by the headless `--rename` path and the bridge `rename` op — a warm-opened
    program has no lingering analysis transaction, so `program.save()` commits cleanly mid-life
    (a resident bridge keeps serving from the same program afterward). Returns True on a rename."""
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    fn = None
    with contextlib.suppress(Exception):
        fn = flat.getFunctionContaining(flat.toAddr(addr))
    if fn is None:
        return False
    txid = program.startTransaction("hexgraph rename")
    ok = False
    try:
        fn.setName(new_name, SourceType.USER_DEFINED)
        ok = True
    except Exception:  # noqa: BLE001 — a bad name leaves the program unchanged
        ok = False
    finally:
        program.endTransaction(txid, ok)
    if ok:
        with contextlib.suppress(Exception):
            program.save("hexgraph rename", ConsoleTaskMonitor())
    return ok


def decompile_core(program, flat, monitor, *, focus=None, rename=None) -> dict:
    """Ported POST_SCRIPT: whole-program inventory (functions/calls/structs) + a focused decompile
    with recovered facts. `focus` is a function NAME or hex ADDRESS; `rename` is (addr, new_name).
    The actual decompilation lives in `_focus_facts` (which opens its own DecompInterface)."""
    if rename:
        addr, new_name = rename
        if _apply_rename(program, flat, addr, new_name):
            focus = addr

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))
    result = {"functions": [f.getName() for f in funcs][:400], "focus": None,
              "calls": [], "structs": []}

    edges = []
    for f in funcs[:600]:
        with contextlib.suppress(Exception):
            for callee in f.getCalledFunctions(monitor):
                edges.append([f.getName(), callee.getName()])
                if len(edges) >= 2000:
                    break
        if len(edges) >= 2000:
            break
    result["calls"] = edges

    dtm = program.getDataTypeManager()
    with contextlib.suppress(Exception):
        for dt in dtm.getAllStructures():
            comps = dt.getComponents()
            builtin = False
            with contextlib.suppress(Exception):
                sa = dt.getSourceArchive()
                if sa is not None and str(sa.getArchiveType()) == "BUILTIN":
                    builtin = True
                else:
                    cp = dt.getCategoryPath().getPath()
                    if not cp.startswith("/DWARF") and ("/std" in cp or "/__" in cp):
                        builtin = True
            result["structs"].append({
                "name": dt.getName(), "size": dt.getLength(), "builtin": builtin,
                "fields": [{"name": c.getFieldName(), "type": str(c.getDataType()),
                            "offset": c.getOffset()} for c in comps[:64]]})
            if len(result["structs"]) >= 200:
                break

    if focus:
        target = None
        if _ADDR.match(focus):
            with contextlib.suppress(Exception):
                target = flat.getFunctionContaining(flat.toAddr(focus))
        else:
            target = next((f for f in funcs if f.getName() == focus), None)
        if target is not None:
            result["focus"] = _focus_facts(program, target, monitor)
    return result


def _focus_facts(program, target, monitor) -> dict:
    """The recovered facts for one function: pseudo-C + prototype/params/locals/callees (PREFER the
    decompiler's HighFunction over the listing-DB guess)."""
    from ghidra.app.decompiler import DecompInterface

    deci = DecompInterface()
    deci.openProgram(program)
    res = deci.decompileFunction(target, 60, monitor)
    pseudo, hf, df = "", None, None
    if res is not None and res.decompileCompleted():
        df = res.getDecompiledFunction()
        if df is not None:
            pseudo = df.getC()
        hf = res.getHighFunction()

    callees = []
    with contextlib.suppress(Exception):
        callees = [c.getName() for c in target.getCalledFunctions(monitor)]
    addr = None
    with contextlib.suppress(Exception):
        addr = "0x" + target.getEntryPoint().toString()

    prototype = None
    with contextlib.suppress(Exception):
        if df is not None:
            prototype = df.getSignature()
    if not prototype:
        with contextlib.suppress(Exception):
            prototype = target.getSignature().getPrototypeString()
    calling_convention = None
    with contextlib.suppress(Exception):
        calling_convention = target.getCallingConventionName()

    params, local_vars, from_hf = [], [], False
    if hf is not None:
        try:
            proto = hf.getFunctionPrototype()
            if proto is not None:
                for i in range(proto.getNumParams()):
                    ps = proto.getParam(i)
                    params.append({"name": ps.getName(), "type": str(ps.getDataType())})
            pnames = {p["name"] for p in params}
            it = hf.getLocalSymbolMap().getSymbols()
            while it.hasNext():
                sym = it.next()
                if not sym.isParameter() and sym.getName() not in pnames:
                    local_vars.append({"name": sym.getName(), "type": str(sym.getDataType())})
            from_hf = True
        except Exception:
            params, local_vars, from_hf = [], [], False
    if not from_hf:
        with contextlib.suppress(Exception):
            params = [{"name": p.getName(), "type": str(p.getDataType())}
                      for p in target.getParameters()]
        with contextlib.suppress(Exception):
            pnames = {p["name"] for p in params}
            local_vars = [{"name": v.getName(), "type": str(v.getDataType())}
                          for v in target.getLocalVariables() if v.getName() not in pnames]

    focus = {"name": target.getName(), "resolved": target.getName(), "address": addr,
             "pseudocode": pseudo, "disasm": "", "callees": callees}
    if prototype:
        focus["prototype"] = prototype
    if calling_convention:
        focus["calling_convention"] = calling_convention
    if params:
        focus["params"], focus["param_count"] = params, len(params)
    if local_vars:
        focus["locals"], focus["local_count"] = local_vars, len(local_vars)
    return focus


# --- Taint: grounded P-Code source->sink data-flow (ported from TAINT_SCRIPT) --------------

# Library calls whose RETURN value is attacker-influenced (a taint source).
_SOURCE_RET = {"getenv", "getchar", "fgetc"}
# Buffer-filling input calls: name -> the 0-based C-arg index of the dest buffer (op input i+1).
_SOURCE_BUF = {"fgets": 0, "gets": 0, "fread": 0, "read": 1, "recv": 1, "recvfrom": 1, "pread": 1}
# Calls that COPY a (possibly tainted) source arg into a dest pointer = input[1].
_COPY_TO_DEST = {"strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove",
                 "stpcpy", "sprintf", "snprintf", "vsprintf", "vsnprintf"}
# Calls whose RETURN is tainted iff a source arg is (string locators/tokenizers/duplicators).
_COPY_TO_RET = {"strdup", "strndup", "strtok", "strtok_r", "strsep",
                "strchr", "strrchr", "strstr", "strpbrk"}
_SINK_EXEC = {"system", "popen", "execl", "execlp", "execle",
              "execv", "execvp", "execvpe", "execve"}
_SINK_OVERFLOW = {"strcpy", "strcat", "sprintf"}
_SINKS = _SINK_EXEC | _SINK_OVERFLOW
_SANITIZERS = {"sanitize", "escape", "quote", "filter", "validate", "clean", "encode"}


def taint_core(program, flat, monitor) -> dict:
    """Grounded P-Code source->sink taint over each function's HighFunction SSA (ported 1:1 from
    the Jython TAINT_SCRIPT; the Java API is identical). Marks untrusted SOURCES (params + returns
    of source calls + buffer-fill dest slots), propagates to a fixpoint through data ops AND
    string/mem copy calls, and reports every tainted value reaching a dangerous SINK. Returns
    `{taint: {flows, analyzed}}`. Intra-procedural (reachability stitches across the call graph)."""
    from java.lang import System
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp

    prop_ops = {PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ADD, PcodeOp.INT_SUB,
                PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_MULT,
                PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE,
                PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_DIV,
                PcodeOp.INT_REM, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.PTRADD, PcodeOp.PTRSUB,
                PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT, PcodeOp.LOAD}

    fm = program.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    def callee_name(op):
        t = op.getInput(0)
        if t is None:
            return None
        fa = None
        with contextlib.suppress(Exception):
            fa = flat.getFunctionAt(t.getAddress())
        return fa.getName() if fa is not None else None

    def addr_of(op):
        with contextlib.suppress(Exception):
            return "0x" + op.getSeqnum().getTarget().toString()
        return None

    def calls_a_sink(f):
        with contextlib.suppress(Exception):
            for c in f.getCalledFunctions(monitor):
                if c.getName() in _SINKS:
                    return True
        return False

    candidates = [f for f in funcs if not f.isExternal() and calls_a_sink(f)][:200]
    deci = DecompInterface()
    deci.openProgram(program)

    flows = []
    for f in candidates:
        res = None
        with contextlib.suppress(Exception):
            res = deci.decompileFunction(f, 60, monitor)
        if res is None or not res.decompileCompleted():
            continue
        hf = res.getHighFunction()
        if hf is None:
            continue

        tainted = set()        # identity hashes of value-tainted varnodes
        src_of = {}            # identity hash -> source descriptor
        tainted_slot = {}      # stack-slot key -> source descriptor

        def vmark(vn, desc):
            if vn is None:
                return False
            h = System.identityHashCode(vn)
            if h in tainted:
                return False
            tainted.add(h)
            src_of[h] = desc
            return True

        def slot_key(vn, depth=0):
            if vn is None or depth > 6:
                return None
            d = vn.getDef()
            if d is None:
                sp = None
                with contextlib.suppress(Exception):
                    sp = vn.getAddress().getAddressSpace().getName()
                return ("stk", sp, vn.getOffset()) if sp == "stack" else None
            mn = d.getMnemonic()
            if mn == "PTRSUB" and d.getNumInputs() == 2 and d.getInput(1).isConstant():
                b = d.getInput(0)
                bs = "?"
                with contextlib.suppress(Exception):
                    bs = b.getAddress().getAddressSpace().getName()
                return ("stk", bs, b.getOffset(), d.getInput(1).getOffset())
            if mn in ("COPY", "CAST"):
                return slot_key(d.getInput(0), depth + 1)
            if mn == "INT_ADD" and d.getNumInputs() == 2 and d.getInput(1).isConstant():
                return slot_key(d.getInput(0), depth + 1)
            return None

        def arg_taint(vn):
            if vn is None:
                return None
            h = System.identityHashCode(vn)
            if h in tainted:
                return src_of[h]
            k = slot_key(vn)
            if k is not None and k in tainted_slot:
                return tainted_slot[k]
            return None

        # Sources A: function parameters.
        with contextlib.suppress(Exception):
            it = hf.getLocalSymbolMap().getSymbols()
            while it.hasNext():
                sym = it.next()
                if sym.isParameter():
                    hv = sym.getHighVariable()
                    if hv is not None:
                        for inst in hv.getInstances():
                            vmark(inst, {"kind": "param", "detail": sym.getName()})

        ops = list(hf.getPcodeOps())
        # Sources B/C: library-call sources in one pass over the CALL ops.
        for op in ops:
            if op.getOpcode() != PcodeOp.CALL:
                continue
            cn = callee_name(op)
            if cn in _SOURCE_RET and op.getOutput() is not None:
                vmark(op.getOutput(), {"kind": "call_return", "detail": cn})
            elif cn in _SOURCE_BUF:
                di = _SOURCE_BUF[cn] + 1
                if op.getNumInputs() > di:
                    k = slot_key(op.getInput(di))
                    if k is not None and k not in tainted_slot:
                        tainted_slot[k] = {"kind": "libc_input", "detail": cn}

        # Forward propagation to a fixpoint over BOTH domains.
        changed, guard = True, 0
        while changed and guard < 4096:
            changed, guard = False, guard + 1
            for op in ops:
                oc = op.getOpcode()
                out = op.getOutput()
                n = op.getNumInputs()
                ins = [op.getInput(i) for i in range(n)]
                if oc in prop_ops:
                    d = None
                    for v in ins:
                        d = arg_taint(v)
                        if d is not None:
                            break
                    if d is not None and out is not None and vmark(out, d):
                        changed = True
                elif oc == PcodeOp.CALL:
                    cn = callee_name(op)
                    if cn in _COPY_TO_DEST and n > 2:
                        d = None
                        for i in range(2, n):
                            d = arg_taint(ins[i])
                            if d is not None:
                                break
                        if d is not None:
                            k = slot_key(ins[1])
                            if k is not None and k not in tainted_slot:
                                tainted_slot[k] = d
                                changed = True
                    if cn in _COPY_TO_RET and out is not None:
                        d = None
                        for i in range(1, n):
                            d = arg_taint(ins[i])
                            if d is not None:
                                break
                        if d is not None and vmark(out, d):
                            changed = True

        sanitizer_hits = set()
        for op in ops:
            if op.getOpcode() == PcodeOp.CALL and callee_name(op) in _SANITIZERS:
                sanitizer_hits.add(callee_name(op))

        for op in ops:
            if op.getOpcode() != PcodeOp.CALL:
                continue
            cn = callee_name(op)
            cat, lo = None, 1
            if cn in _SINK_EXEC:
                cat = "command_exec"
            elif cn in _SINK_OVERFLOW:
                cat, lo = "buffer_overflow", 2
            if cat is None:
                continue
            n = op.getNumInputs()
            hit_idx, src = None, None
            for i in range(lo, n):
                d = arg_taint(op.getInput(i))
                if d is not None:
                    hit_idx, src = i, d
                    break
            if hit_idx is None:
                continue
            flows.append({
                "function": f.getName(),
                "function_addr": "0x" + f.getEntryPoint().toString(),
                "source": src or {"kind": "unknown"},
                "sink": {"func": cn, "category": cat,
                         "call_addr": addr_of(op), "arg_index": hit_idx},
                "sanitized": sorted(sanitizer_hits),
            })
            if len(flows) >= 200:
                break
        if len(flows) >= 200:
            break

    return {"taint": {"flows": flows, "analyzed": len(candidates)}}


# --- Emulation: constant recovery via Ghidra's P-Code emulator (ported from EMU_SCRIPT) ------

def emulate_core(program, flat, monitor, focus) -> dict:
    """Emulate a self-contained parameterless routine in Ghidra's P-Code emulator and recover the
    constant it returns (no native execution — the routine runs inside the JVM interpreter).
    Ported 1:1 from EMU_SCRIPT. Returns `{emulation: {...}}`."""
    from ghidra.app.emulator import EmulatorHelper

    MAX_STEPS = 500000
    STACK_TOP = 0x10000000
    fm = program.getFunctionManager()
    ptr_size = program.getDefaultPointerSize()
    ret_sentinel = 0xbabecafe if ptr_size <= 4 else 0x0000babecafe0000

    target, err_msg = None, None
    if focus is not None:
        if _ADDR.match(focus):
            with contextlib.suppress(Exception):
                target = flat.getFunctionContaining(flat.toAddr(focus))
        else:
            matches = [f for f in fm.getFunctions(True) if f.getName() == focus]
            if len(matches) > 1:
                err_msg = (f"ambiguous function name {focus} ({len(matches)} matches) "
                           "- pass an address")
            elif matches:
                target = matches[0]

    if err_msg is not None:
        return {"emulation": {"error": err_msg}}
    if target is None:
        return {"emulation": {"error": f"function not found: {focus}"}}
    if target.getParameterCount() > 0:
        return {"emulation": {
            "function": target.getName(),
            "function_addr": "0x" + target.getEntryPoint().toString(),
            "param_count": target.getParameterCount(),
            "reached_ret": False, "steps": 0, "skipped": "arg_dependent",
            "error": (f"function takes {target.getParameterCount()} argument(s) — recover_constant "
                      "needs a self-contained, parameterless routine; use the solver instead"),
        }}

    ret = target.getReturn()
    ret_reg = ret.getRegister() if ret is not None else None
    ret_size = ret.getLength() if ret is not None else 0
    entry = target.getEntryPoint()

    emu = EmulatorHelper(program)
    pc_reg = emu.getPCRegister()
    sp_reg = emu.getStackPointerRegister()
    emu.writeRegister(sp_reg, STACK_TOP)
    emu.writeStackValue(0, ptr_size, ret_sentinel)
    emu.writeRegister(pc_reg, entry.getOffset())

    steps, reached_ret, err = 0, False, None
    while steps < MAX_STEPS:
        pc = emu.getExecutionAddress()
        if pc.getOffset() == ret_sentinel:
            reached_ret = True
            break
        try:
            ok = emu.step(monitor)
        except Exception:  # noqa: BLE001
            import traceback
            err = "step exception: %s" % traceback.format_exc().splitlines()[-1]
            break
        if not ok:
            err = emu.getLastError()
            break
        steps += 1

    emu_out = {
        "function": target.getName(),
        "function_addr": "0x" + entry.toString(),
        "steps": steps,
        "reached_ret": reached_ret,
        "return_register": ret_reg.getName() if ret_reg is not None else None,
    }
    if err:
        emu_out["error"] = err
    if not reached_ret and steps >= MAX_STEPS:
        emu_out["error"] = "step budget exhausted before return (%d)" % MAX_STEPS
    if reached_ret and ret_reg is not None:
        # readRegister returns a java.math.BigInteger; under jpype (unlike Jython) `int()` can't
        # consume it directly, so go via its decimal string. The mask normalizes to unsigned 64-bit.
        raw = int(str(emu.readRegister(ret_reg))) & 0xFFFFFFFFFFFFFFFF
        emu_out["value_hex"] = "0x%x" % raw
        if ret_size and ret_size < 8:
            mask = (1 << (ret_size * 8)) - 1
            emu_out["value"] = "0x%0*x" % (ret_size * 2, raw & mask)
            emu_out["width_bytes"] = ret_size
        else:
            emu_out["value"] = "0x%x" % raw
            emu_out["width_bytes"] = 8
    emu.dispose()
    return {"emulation": emu_out}


# --- Xrefs: cross-reference queries from the warm reference index (ported from XREFS_SCRIPT) --

_XREF_DEFAULT_SINKS = ["system", "popen", "execl", "execlp", "execle", "execv", "execvp",
                       "execve", "strcpy", "strcat", "gets", "scanf", "sscanf", "memcpy",
                       "alloca", "stpcpy"]
_XREF_FORMAT_SINKS = ["printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf",
                      "vfprintf", "vsprintf", "vsnprintf", "syslog", "vsyslog", "asprintf"]
_XREF_NETWORK_SINKS = ["socket", "bind", "listen", "accept", "accept4", "connect", "recv",
                       "recvfrom", "recvmsg", "read", "send", "sendto", "sendmsg",
                       "setsockopt", "getaddrinfo", "gethostbyname", "socketpair"]


def xrefs_core(program, flat, monitor, mode, subject) -> dict:
    """Cross-reference queries served from the program's already-built ReferenceManager index
    (ported 1:1 from XREFS_SCRIPT). Mirrors the r2 xrefs_probe output contract key-for-key.
    `mode` is callers | function | data | callgraph | sinks; `subject` a symbol/address (None for
    callgraph/sinks). A symbol the index doesn't know returns `not_found` (NOT a top-level error)."""
    MAX_REFS, MAX_SINK_REFS = 200, 30
    MAX_GRAPH_FUNCS, MAX_GRAPH_EDGES = 600, 2000

    st = program.getSymbolTable()
    fm = program.getFunctionManager()
    refmgr = program.getReferenceManager()

    def _rt_name(ref):
        try:
            return ref.getReferenceType().getName()
        except Exception:  # noqa: BLE001
            return str(ref.getReferenceType())

    def _syms_named(name):
        out, it = [], st.getSymbols(name)
        while it.hasNext():
            out.append(it.next())
        return out

    def _caller_target_addrs(name):
        addrs, seen_a = [], set()

        def _add(a):
            if a is not None and a.toString() not in seen_a:
                seen_a.add(a.toString())
                addrs.append(a)

        for sym in _syms_named(name):
            a = sym.getAddress()
            _add(a)
            f = fm.getFunctionAt(a) if a is not None else None
            if f is not None:
                thunk_addrs = None
                try:
                    thunk_addrs = f.getFunctionThunkAddresses(True)
                except Exception:  # noqa: BLE001
                    with contextlib.suppress(Exception):
                        thunk_addrs = f.getFunctionThunkAddresses()
                for ta in (thunk_addrs or []):
                    _add(ta)
        return addrs

    def _callers_of(name):
        out, seen = [], set()
        for addr in _caller_target_addrs(name):
            for ref in refmgr.getReferencesTo(addr):
                frm = ref.getFromAddress()
                if frm is None:
                    continue
                caller = flat.getFunctionContaining(frm)
                if caller is None or caller.isThunk():
                    continue
                key = (caller.getName(), frm.toString())
                if key in seen:
                    continue
                seen.add(key)
                caddr = None
                with contextlib.suppress(Exception):
                    caddr = "0x" + caller.getEntryPoint().toString()
                out.append({"caller": caller.getName(), "caller_addr": caddr,
                            "at": "0x" + frm.toString(), "kind": _rt_name(ref)})
        return out

    def _resolve_function(subj):
        if _ADDR.match(subj):
            with contextlib.suppress(Exception):
                return flat.getFunctionContaining(flat.toAddr(subj))
            return None
        for sym in _syms_named(subj):
            f = None
            with contextlib.suppress(Exception):
                f = fm.getFunctionAt(sym.getAddress())
            if f is not None:
                return f
        return None

    def _callees_of(func):
        out, seen = [], set()
        called = []
        with contextlib.suppress(Exception):
            called = func.getCalledFunctions(monitor)
        for c in called:
            nm = c.getName()
            if nm in seen:
                continue
            seen.add(nm)
            addr = None
            with contextlib.suppress(Exception):
                addr = "0x" + c.getEntryPoint().toString()
            out.append({"name": nm, "addr": addr})
        return out

    if mode == "callgraph":
        edges = []
        for f in list(fm.getFunctions(True))[:MAX_GRAPH_FUNCS]:
            with contextlib.suppress(Exception):
                for callee in f.getCalledFunctions(monitor):
                    edges.append([f.getName(), callee.getName()])
                    if len(edges) >= MAX_GRAPH_EDGES:
                        break
            if len(edges) >= MAX_GRAPH_EDGES:
                break
        return {"mode": "callgraph", "calls": edges, "total": len(edges)}

    if mode == "function":
        func = _resolve_function(subject) if subject else None
        if func is None:
            return {"mode": "function", "subject": subject, "callers": [], "callees": [],
                    "total_callers": 0, "total_callees": 0, "not_found": True}
        callers = _callers_of(func.getName())
        callees = _callees_of(func)
        return {"mode": "function", "subject": subject,
                "callers": callers[:MAX_REFS], "callees": callees[:MAX_REFS],
                "total_callers": len(callers), "total_callees": len(callees)}

    if mode == "data":
        addr = None
        if subject and _ADDR.match(subject):
            with contextlib.suppress(Exception):
                addr = flat.toAddr(subject)
        if addr is None and subject:
            for sym in _syms_named(subject):
                a = sym.getAddress()
                if a is not None:
                    addr = a
                    break
        if addr is None:
            return {"mode": "data", "subject": subject, "data_refs": [], "total": 0,
                    "not_found": True}
        refs, seen = [], set()
        for ref in refmgr.getReferencesTo(addr):
            frm = ref.getFromAddress()
            if frm is None:
                continue
            fn = flat.getFunctionContaining(frm)
            fname = fn.getName() if fn is not None else "?"
            key = (fname, frm.toString())
            if key in seen:
                continue
            seen.add(key)
            refs.append({"from_function": fname, "at": "0x" + frm.toString(),
                         "kind": _rt_name(ref)})
        return {"mode": "data", "subject": subject,
                "data_refs": refs[:MAX_REFS], "total": len(refs)}

    if mode == "callers":
        refs = _callers_of(subject) if subject else []
        return {"mode": "callers", "symbol": subject,
                "callers": refs[:MAX_REFS], "total": len(refs)}

    # sinks sweep (no subject)
    def _sweep(names):
        grp = {}
        for s in names:
            refs = _callers_of(s)
            if refs:
                grp[s] = {"callers": refs[:MAX_SINK_REFS], "total": len(refs)}
        return grp

    return {"mode": "sinks", "sinks": _sweep(_XREF_DEFAULT_SINKS),
            "format_sinks": _sweep(_XREF_FORMAT_SINKS), "network": _sweep(_XREF_NETWORK_SINKS)}


def ghidra_version() -> str | None:
    """The GHIDRA application version (e.g. '12.1') from application.properties — the SAME token
    the Jython probe reported, so the persistent-project cache key (`<sha>__<version>`) is stable
    across the Jython->pyghidra flip. NOT pyghidra's own package version (3.1.0)."""
    props = os.path.join(os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra"),
                         "Ghidra", "application.properties")
    try:
        with open(props) as fh:
            for line in fh:
                if line.startswith("application.version"):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return None


# --- Resident bridge: serve the cores over a line-delimited JSON socket -----------------------
# HexGraph's OWN managed bridge (engine.re.bridge) keeps a warm project resident behind this tiny
# stdlib RPC — replacing the Jython analyzeHeadless + jfx_bridge harness. The transport is plain
# newline-delimited JSON over TCP (no ghidra_bridge/jfx_bridge dependency): the client sends a
# vetted, structured request; the server runs the matching in-process core and returns JSON — no
# remote_eval of Ghidra internals (a smaller surface than the researcher-Ghidra `_RemoteOps` path).

def bridge_dispatch(program, flat, monitor, req) -> dict:
    """Map one bridge request to a core call over the RESIDENT program. A live bridge OWNS the
    project, so EVERY Ghidra op for the target routes here instead of a conflicting headless open:
      `ping`     liveness + function count
      `list`     function inventory
      `decompile`  focus = name or 0xADDR
      `xrefs`    mode (callers|function|data|callgraph|sinks) + optional subject
      `taint`    grounded source->sink flows
      `emulate`  focus = a parameterless routine (constant recovery)
      `rename`   address + new_name — the one WRITE, persisted into the resident project via
                 `_apply_rename`'s mid-life save (so it sticks for future reads over the bridge)."""
    import traceback

    op = (req or {}).get("op")
    try:
        if op == "ping":
            return {"ok": True, "functions_total": program.getFunctionManager().getFunctionCount()}
        if op == "list":
            names = [f.getName() for f in program.getFunctionManager().getFunctions(True)]
            return {"functions": names[:400], "tool": "ghidra_bridge"}
        if op == "decompile":
            result = decompile_core(program, flat, monitor, focus=req.get("focus"))
            result["tool"] = "ghidra_bridge"
            return result
        if op == "xrefs":
            return xrefs_core(program, flat, monitor, req.get("mode", "sinks"), req.get("subject"))
        if op == "taint":
            return taint_core(program, flat, monitor)
        if op == "emulate":
            return emulate_core(program, flat, monitor, req.get("focus"))
        if op == "rename":
            result = decompile_core(program, flat, monitor,
                                    rename=(req.get("address"), req.get("new_name")))
            result["tool"] = "ghidra_bridge"
            return result
        return {"error": f"unknown bridge op {op!r}"}
    except Exception as exc:  # noqa: BLE001 — one bad request must NEVER kill the resident server
        return {"error": f"bridge op {op} failed: {exc}", "tb": traceback.format_exc()}


def _serve_one(conn, program, flat, monitor) -> None:
    """Handle one connection: read one JSON request line, dispatch, write one JSON response line."""
    conn.settimeout(600)
    fh = conn.makefile("rwb")
    line = fh.readline()
    if not line:
        return
    try:
        req = json.loads(line.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        resp = {"error": "bad request json"}
    else:
        resp = bridge_dispatch(program, flat, monitor, req)
    fh.write((json.dumps(resp) + "\n").encode("utf-8"))
    fh.flush()


def serve_bridge(host, port, program, flat, monitor) -> None:
    """Block forever serving line-delimited JSON bridge requests over TCP against the RESIDENT
    (program, flat, monitor). Single-threaded — Ghidra program access is NOT concurrency-safe, so
    one connection + one request at a time (two host processes serialize). The caller binds AFTER
    the project is open, so a host TCP-liveness probe only succeeds once the project can serve."""
    import socket

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    while True:
        try:
            conn, _addr = srv.accept()
        except OSError:
            continue
        try:
            _serve_one(conn, program, flat, monitor)
        except Exception:  # noqa: BLE001 — never let one connection kill the resident loop
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()
