#!/usr/bin/env python3
"""Run Ghidra headless (`analyzeHeadless`) over a target INSIDE the sandbox.

  argv: /artifact [function]        normal decompile/inventory run
        /artifact --check           report Ghidra presence + version (no analysis)
        /artifact --taint           grounded P-Code source->sink data-flow taint (Phase 4)
        /artifact --emulate <fn>     emulate <fn> in the P-Code emulator + recover its constant

Emits JSON matching the Decompiler contract plus enrichment extras:
  { tool, functions: [...], focus: {name,resolved,pseudocode,disasm,callees}|null,
    calls: [[caller,callee],...], structs: [{name,size,fields}], cached: bool }
For --check: { present: bool, version: str|null, detail: str }.
For --taint: { tool, cached, taint: { analyzed: int, flows: [ {function, function_addr,
    source:{kind,detail}, sink:{func,category,call_addr,arg_index}, sanitized:[...]} ] } }.

Ghidra must be installed in the image (built with WITH_GHIDRA=1). The target is
imported and statically analyzed — NEVER executed. Runs with --network none, a
read-only rootfs, and /scratch as the only writable area for HOME/temp/user-settings.

**Analyze once, reuse (Phase 1).** When a writable persistent project is bind-mounted
at /ghidra-project (engine.re.ghidra_project), the FIRST call imports + analyzes the
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
# The writable persistent-project bind-mount (engine.re.ghidra_project.CONTAINER_PROJECT_DIR +
# runner.CONTAINER_PROJECT_DIR). Present only when the caller threads a project_mount; absent
# for --check, for radare2 callers, or when the cache is disabled.
PROJECT_MOUNT = "/ghidra-project"
# The COMMITTED warm marker (engine.re.ghidra_project.META_NAME), written under PROJECT_MOUNT as the
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
    engine.re.ghidra_project.GhidraProject.write_meta; its presence makes the slot warm next call."""
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
#
# F13: also let the heap scale with the container. The JVM's default max heap is ~25% of the
# cgroup RAM cap, which OOMs (the "DB buffer" failure) on a 100 MB+ ELF — and the sandbox now
# grants a large artifact a BIGGER `--memory` cap (sandbox/resources.py size-scaling). A RAM
# PERCENTAGE (the JDK is cgroup-aware) self-adjusts to whatever cap THIS container got, so there's
# no hardcoded -Xmx to drift from the cap and it tracks a larger/smaller `resources.sandbox.mem`
# too. ~45% leaves room for the tmpfs (which counts against the same cap) + JVM native overhead.
# Tunable per-run via HEXGRAPH_GHIDRA_HEAP_PCT without rebuilding. A caller-supplied -Xmx (appended
# below) still wins.
_GHIDRA_HEAP_PCT = os.environ.get("HEXGRAPH_GHIDRA_HEAP_PCT", "45.0")
_existing_jopts = os.environ.get("_JAVA_OPTIONS", "")
os.environ["_JAVA_OPTIONS"] = (
    f"-Djava.io.tmpdir={SCRATCH} -XX:MaxRAMPercentage={_GHIDRA_HEAP_PCT} {_existing_jopts}"
).strip()

# F13: bound Ghidra's auto-analysis so a 100 MB+ ELF whose FULL analysis would outrun the
# container's wall-clock budget stops GRACEFULLY and SAVES partial results (functions, call graph,
# the postScript still runs) instead of being torn down by the external timeout with nothing
# persisted. We read the budget the host advertised (HEXGRAPH_PROBE_TIMEOUT_S = run_probe's
# wall-clock) and leave headroom for import + save + the postScript, so analysis halts BEFORE the
# kill. Only the COLD import path runs auto-analysis (the warm -process path passes -noanalysis).
GHIDRA_SAVE_OVERHEAD_S = 180


def _analysis_timeout_args() -> list:
    """`-analysisTimeoutPerFile <s>` sized just under the host's wall-clock budget so analysis
    stops+saves before the external kill. Returns [] only when no budget is advertised or it's too
    small to usefully split import/analyze/save (a tiny budget can't run a monolith anyway). For a
    non-trivial budget we ALWAYS keep a graceful stop: leave the import/save headroom, but never
    fall below ~half the wall-clock, so lowering `resources.sandbox.timeout` can't silently drop
    the graceful save it's meant to provide on a large ELF."""
    try:
        total = int(float(os.environ.get("HEXGRAPH_PROBE_TIMEOUT_S", "")))
    except (TypeError, ValueError):
        return []
    if total < 120:
        return []
    budget = max(int(total * 0.5), total - GHIDRA_SAVE_OVERHEAD_S)
    return ["-analysisTimeoutPerFile", str(budget)]


# F13: above this size, the cold import runs a "fast profile" preScript (below) that turns off the
# auto-analysis passes that grind for ages on a monolith. Smaller binaries keep FULL analysis.
GHIDRA_FAST_PROFILE_BYTES = int(float(os.environ.get("HEXGRAPH_GHIDRA_FAST_PROFILE_MB", "100")) * 1024 * 1024)

# A Jython -preScript (runs BEFORE auto-analysis) that disables the passes proven pathological on a
# 100 MB+ monolith: Call-Fixup Installer (O(n^2) AddressSet — tens of minutes of CPU on a large ELF), the
# <processor> Constant Reference Analyzer + Scalar Operand References (constant propagation over
# every function), and the decompile-EVERY-function passes (Decompiler Parameter ID / Switch
# Analysis) + Aggressive Instruction Finder. The call-graph / reference / function-discovery
# analyzers are KEPT, so recon still gets functions + call graph + strings + basic xrefs; HexGraph
# decompiles on demand (re_decompile_function), so the batch decompile passes aren't needed here.
# Matched by suffix so it's architecture-agnostic ("PowerPC/ARM/x86 … Constant Reference Analyzer").
FAST_PROFILE_SCRIPT = """# -*- coding: utf-8 -*-
def _slow(name):
    if "." in name:
        return False
    if name in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                "Aggressive Instruction Finder"):
        return True
    return name.endswith("Constant Reference Analyzer") or name.endswith("Scalar Operand References")

opts = currentProgram.getOptions("Analyzers")
for _n in list(opts.getOptionNames()):
    if _slow(_n):
        try:
            opts.setBoolean(_n, False)
        except:
            pass
"""

# Jython postScript Ghidra runs after auto-analysis. It writes JSON to args[0];
# args[1] (optional) is the focus function to decompile.
POST_SCRIPT = r'''# -*- coding: utf-8 -*-
# Encoding cookie REQUIRED: Ghidra runs this under Jython 2.7, which (PEP 263) rejects any
# non-ASCII byte (e.g. an em-dash in a comment) with a hard SyntaxError when no encoding is
# declared — and a compile failure here writes NO output, which is undiagnosable. Keep this.
import json
import re
import traceback
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
# Whole body wrapped so the probe ALWAYS writes out_path — on any failure it writes an
# {error, tb} payload instead of producing nothing (the old silent "produced no output"
# was undiagnosable). The host surfaces the tb.
try:
    focus = args[1] if len(args) > 1 and args[1] else None
    rename_addr = args[2] if len(args) > 2 and args[2] else None
    rename_name = args[3] if len(args) > 3 and args[3] else None
    monitor = ConsoleTaskMonitor()

    # Rename round-trip (Phase 3): apply the analyst's rename to the function CONTAINING
    # rename_addr, then focus on it so the emitted result reflects the new name.
    # analyzeHeadless runs -process WITHOUT -readOnly, so it SAVES the program back into the
    # persistent project — the rename persists for every future decompile (analyze-once).
    if rename_addr and rename_name:
        from ghidra.program.model.symbol import SourceType
        try:
            _fn = getFunctionContaining(toAddr(rename_addr))
            if _fn is not None:
                _fn.setName(rename_name, SourceType.USER_DEFINED)
                focus = rename_addr  # decompile the just-renamed function in the focus block below
        except:
            pass

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
            hf = None
            df = None
            if res is not None and res.decompileCompleted():
                df = res.getDecompiledFunction()
                if df is not None:
                    pseudo = df.getC()
                hf = res.getHighFunction()
            callees = []
            try:
                callees = [c.getName() for c in target.getCalledFunctions(monitor)]
            except:
                pass
            try:
                addr = "0x" + target.getEntryPoint().toString()
            except:
                addr = None
            # Rich, always-welcome facts for the function being promoted. PREFER the
            # decompiler-RECOVERED facts (the refined signature + typed locals, e.g.
            # `bool check_password(char *param_1)`) from the HighFunction/DecompiledFunction
            # over the pre-decompile listing-DB guess (`undefined check_password(void)`); fall
            # back to the listing only when the decompile result is unavailable. Each fact is
            # guarded so a single failing Jython call drops only that fact, never the focus.
            prototype = None
            try:
                if df is not None:
                    prototype = df.getSignature()  # the decompiler's refined C signature
            except:
                pass
            if not prototype:
                try:
                    prototype = target.getSignature().getPrototypeString()
                except:
                    pass
            calling_convention = None
            try:
                calling_convention = target.getCallingConventionName()
            except:
                pass
            # Params (in order) + locals from the decompiler's HighFunction — the types it
            # recovered, not the listing DB's `undefinedN`. Fall back to the listing variables
            # if the HighFunction is unavailable.
            params = []
            local_vars = []
            from_hf = False
            if hf is not None:
                try:
                    proto = hf.getFunctionPrototype()
                    if proto is not None:
                        for i in range(proto.getNumParams()):
                            ps = proto.getParam(i)
                            params.append({"name": ps.getName(), "type": str(ps.getDataType())})
                    pnames = set(p["name"] for p in params)
                    it = hf.getLocalSymbolMap().getSymbols()
                    while it.hasNext():
                        sym = it.next()
                        if not sym.isParameter() and sym.getName() not in pnames:
                            local_vars.append({"name": sym.getName(),
                                               "type": str(sym.getDataType())})
                    from_hf = True
                except:
                    params = []
                    local_vars = []
                    from_hf = False
            if not from_hf:
                try:
                    params = [{"name": p.getName(), "type": str(p.getDataType())}
                              for p in target.getParameters()]
                except:
                    params = []
                try:
                    param_names = set(p["name"] for p in params)
                    # getLocalVariables() excludes parameters; still drop any name that
                    # surfaced as a parameter so a spilled-param slot can't double-count.
                    local_vars = [{"name": v.getName(), "type": str(v.getDataType())}
                                  for v in target.getLocalVariables()
                                  if v.getName() not in param_names]
                except:
                    local_vars = []
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

    _payload = json.dumps(result)
except:
    _payload = json.dumps({"error": "postscript exception", "tb": traceback.format_exc(),
                           "functions": [], "focus": None, "calls": [], "structs": []})

fh = open(out_path, "w")
fh.write(_payload)
fh.close()
'''


# Grounded P-Code data-flow taint (Phase 4). Runs after auto-analysis, over each function's
# HighFunction SSA P-Code: marks untrusted SOURCES (function parameters + returns of
# source-producing library calls), propagates taint forward to a fixpoint through data ops
# AND string/mem copy CALLS (which carry taint into their dest buffer), and reports every
# tainted value that reaches a dangerous SINK (command-exec / unbounded-copy). The claim is
# grounded in the real decompiled bytes — no LLM. Intra-procedural for this PR (reachability
# stitches across calls via the call graph); inter-procedural summaries are a follow-up.
TAINT_SCRIPT = r'''# -*- coding: utf-8 -*-
# Encoding cookie REQUIRED (Jython 2.7 / PEP 263) — keep this ASCII-only; a compile failure
# here writes NO output and is undiagnosable.
import json
import traceback
from java.lang import System
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
try:
    monitor = ConsoleTaskMonitor()

    # Library calls whose RETURN value is attacker-influenced (a taint source).
    SOURCE_RET = set(["getenv", "getchar", "fgetc"])
    # Library calls that FILL a destination buffer (passed by pointer) with untrusted input:
    # name -> the 0-based C-arg index of that dest buffer. The bytes land in the buffer, never
    # in the return value, so we taint the dest stack SLOT (the same domain COPY_TO_DEST uses).
    # This is what lets a self-contained function be caught: fgets(buf,..,stdin) -> ... ->
    # system(buf) (the inlined-main / firmware-handler shape) crosses no function parameter, so
    # the parameter-only source set (Sources A) misses it entirely. (C-arg i is op input i+1.)
    SOURCE_BUF = {"fgets": 0, "gets": 0, "fread": 0,
                  "read": 1, "recv": 1, "recvfrom": 1, "pread": 1}
    # Calls that COPY a (possibly tainted) source arg into a dest pointer = input[1]; any
    # tainted later arg taints the dest buffer (models string/mem propagation across the call).
    COPY_TO_DEST = set(["strcpy", "strncpy", "strcat", "strncat", "memcpy", "memmove",
                        "stpcpy", "sprintf", "snprintf", "vsprintf", "vsnprintf"])
    # Calls whose RETURN is tainted iff a source arg is tainted (duplicators). The string
    # locators/tokenizers return a pointer INTO their (tainted) input buffer, so taint must ride
    # through them — e.g. strtok(fgets_buf) -> sprintf(cmd,..,tok) -> system(cmd).
    COPY_TO_RET = set(["strdup", "strndup", "strtok", "strtok_r", "strsep",
                       "strchr", "strrchr", "strstr", "strpbrk"])
    # Dangerous sinks. command_exec: a tainted command/path => injection. buffer_overflow: a
    # tainted source into an unbounded copy => memory corruption.
    SINK_EXEC = set(["system", "popen", "execl", "execlp", "execle",
                     "execv", "execvp", "execvpe", "execve"])
    # Unbounded copies: a tainted SOURCE arg (input[2:]) => overflow. (gets() is excluded —
    # it has only a dest arg and IS a source, so it can never carry a tainted SOURCE arg.)
    SINK_OVERFLOW = set(["strcpy", "strcat", "sprintf"])
    SINKS = SINK_EXEC | SINK_OVERFLOW
    # Names that, if called on the path, indicate an (UNVERIFIED) sanitization attempt. We only
    # record that one was present; we never assume it is sufficient.
    SANITIZERS = set(["sanitize", "escape", "quote", "filter", "validate", "clean", "encode"])

    # P-Code opcodes that propagate taint from any input to the output (copy/arith/ptr/phi/load).
    PROP_OPS = set([PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ADD, PcodeOp.INT_SUB,
        PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_MULT,
        PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_2COMP, PcodeOp.INT_NEGATE,
        PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.INT_DIV,
        PcodeOp.INT_REM, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.PTRADD, PcodeOp.PTRSUB,
        PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT, PcodeOp.LOAD])

    fm = currentProgram.getFunctionManager()
    funcs = list(fm.getFunctions(True))

    def callee_name(op):
        t = op.getInput(0)
        if t is None:
            return None
        try:
            fa = getFunctionAt(t.getAddress())
        except:
            fa = None
        if fa is None:
            return None
        return fa.getName()

    def addr_of(op):
        try:
            return "0x" + op.getSeqnum().getTarget().toString()
        except:
            return None

    # Pre-filter: only decompile functions that actually CALL a sink — bounds the heavy
    # HighFunction pass to functions that could possibly host a source->sink flow.
    def calls_a_sink(f):
        try:
            for c in f.getCalledFunctions(monitor):
                if c.getName() in SINKS:
                    return True
        except:
            pass
        return False
    candidates = [f for f in funcs if not f.isExternal() and calls_a_sink(f)][:200]

    deci = DecompInterface()
    deci.openProgram(currentProgram)

    flows = []
    for f in candidates:
        try:
            res = deci.decompileFunction(f, 60, monitor)
        except:
            res = None
        if res is None or not res.decompileCompleted():
            continue
        hf = res.getHighFunction()
        if hf is None:
            continue

        # Two taint domains, both needed because stack buffers are addressed BY POINTER:
        #   * VALUE taint — an identity-keyed varnode set (HighFunction interns its VarnodeAST
        #     objects, so identityHashCode separates distinct SSA values that Varnode.equals
        #     would collapse). For scalar/pointer VALUES (a param, a getenv() return).
        #   * SLOT taint — a set of stack-slot keys whose CONTENTS are tainted. A stack array
        #     (`char hbuf[128]`) is reached at each use via a freshly-computed pointer
        #     (PTRSUB(frame, const)), so the pointer varnodes differ every time; we canonicalize
        #     a pointer to its (frame, offset) slot and taint the SLOT — so strncpy(hbuf, host)
        #     then snprintf(cmd, .., hbuf) then popen(cmd) connect through the hbuf/cmd buffers.
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
            # Canonicalize a pointer varnode to a frame-relative stack-slot key, or None. The
            # buffer pointer is PTRSUB(frame_reg, const_off) (seen via -O0/Ghidra); two uses of
            # the same buffer share that (frame, offset), so the slot key is stable.
            if vn is None or depth > 6:
                return None
            df = vn.getDef()
            if df is None:
                try:
                    sp = vn.getAddress().getAddressSpace().getName()
                except:
                    sp = None
                if sp == "stack":
                    return ("stk", sp, vn.getOffset())
                return None
            mn = df.getMnemonic()
            if mn == "PTRSUB" and df.getNumInputs() == 2 and df.getInput(1).isConstant():
                b = df.getInput(0)
                try:
                    bs = b.getAddress().getAddressSpace().getName()
                except:
                    bs = "?"
                return ("stk", bs, b.getOffset(), df.getInput(1).getOffset())
            if mn in ("COPY", "CAST"):
                return slot_key(df.getInput(0), depth + 1)
            if mn == "INT_ADD" and df.getNumInputs() == 2 and df.getInput(1).isConstant():
                # A pointer INTO a stack buffer (buffer base + constant index) maps to the SAME
                # slot as the buffer itself — whole-buffer taint granularity — so a write to the
                # buffer and a read at buffer+k connect (appending the index would split one
                # buffer across two keys and drop the flow).
                return slot_key(df.getInput(0), depth + 1)
            return None

        def arg_taint(vn):
            # Source descriptor if this arg is tainted by VALUE or points to a tainted stack
            # SLOT, else None — unifies the two domains for propagation + sink checks.
            if vn is None:
                return None
            h = System.identityHashCode(vn)
            if h in tainted:
                return src_of[h]
            k = slot_key(vn)
            if k is not None and k in tainted_slot:
                return tainted_slot[k]
            return None

        # Sources A: function parameters (untrusted at the boundary; reachability decides
        # whether the function is actually reachable from a real entry/source).
        try:
            it = hf.getLocalSymbolMap().getSymbols()
            while it.hasNext():
                sym = it.next()
                if sym.isParameter():
                    hv = sym.getHighVariable()
                    if hv is not None:
                        for inst in hv.getInstances():
                            vmark(inst, {"kind": "param", "detail": sym.getName()})
        except:
            pass

        ops = list(hf.getPcodeOps())
        # Sources B/C: library-call sources, in ONE pass over the CALL ops. B = a
        # source-producing call's RETURN value (getenv, ...). C = a buffer-filling input call
        # (fgets/read/recv/...) -> the untrusted bytes land in the DEST BUFFER, not the return,
        # so taint that buffer's stack SLOT (the same domain COPY_TO_DEST uses); C-arg i is op
        # input i+1. SOURCE_RET and SOURCE_BUF are disjoint, so the elif is exact.
        for op in ops:
            if op.getOpcode() != PcodeOp.CALL:
                continue
            cn = callee_name(op)
            if cn in SOURCE_RET and op.getOutput() is not None:
                vmark(op.getOutput(), {"kind": "call_return", "detail": cn})
            elif cn in SOURCE_BUF:
                di = SOURCE_BUF[cn] + 1
                if op.getNumInputs() > di:
                    k = slot_key(op.getInput(di))
                    if k is not None and k not in tainted_slot:
                        tainted_slot[k] = {"kind": "libc_input", "detail": cn}

        # Forward propagation to a fixpoint over BOTH domains.
        changed = True
        guard = 0
        while changed and guard < 4096:
            changed = False
            guard += 1
            for op in ops:
                oc = op.getOpcode()
                out = op.getOutput()
                n = op.getNumInputs()
                ins = [op.getInput(i) for i in range(n)]
                if oc in PROP_OPS:
                    d = None
                    for v in ins:
                        d = arg_taint(v)
                        if d is not None:
                            break
                    if d is not None and out is not None and vmark(out, d):
                        changed = True
                elif oc == PcodeOp.CALL:
                    cn = callee_name(op)
                    if cn in COPY_TO_DEST and n > 2:
                        # dest = input[1]; sources = input[2:]. A tainted source taints the dest
                        # stack SLOT (the buffer contents), not the dest pointer varnode.
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
                    if cn in COPY_TO_RET and out is not None:
                        d = None
                        for i in range(1, n):
                            d = arg_taint(ins[i])
                            if d is not None:
                                break
                        if d is not None and vmark(out, d):
                            changed = True

        # Sanitizer-looking calls present in this function (an UNVERIFIED mitigation note).
        sanitizer_hits = set()
        for op in ops:
            if op.getOpcode() == PcodeOp.CALL and callee_name(op) in SANITIZERS:
                sanitizer_hits.add(callee_name(op))

        # Sinks: a tainted argument reaching a dangerous call is a grounded source->sink flow.
        # command_exec: the command/path arg (from input[1]) is tainted => injection.
        # buffer_overflow: a tainted SOURCE (input[2:], skipping the dest) into an unbounded
        # copy => memory corruption.
        for op in ops:
            if op.getOpcode() != PcodeOp.CALL:
                continue
            cn = callee_name(op)
            cat = None
            lo = 1
            if cn in SINK_EXEC:
                cat = "command_exec"
            elif cn in SINK_OVERFLOW:
                cat = "buffer_overflow"
                lo = 2
            if cat is None:
                continue
            n = op.getNumInputs()
            hit_idx = None
            src = None
            for i in range(lo, n):
                d = arg_taint(op.getInput(i))
                if d is not None:
                    hit_idx = i
                    src = d
                    break
            if hit_idx is None:
                continue
            flows.append({
                "function": f.getName(),
                "function_addr": "0x" + f.getEntryPoint().toString(),
                "source": src or {"kind": "unknown"},
                "sink": {"func": cn, "category": cat,
                         "call_addr": addr_of(op), "arg_index": hit_idx},
                "sanitized": sorted(list(sanitizer_hits)),
            })
            if len(flows) >= 200:
                break
        if len(flows) >= 200:
            break

    result = {"taint": {"flows": flows, "analyzed": len(candidates)}}
    _payload = json.dumps(result)
except:
    _payload = json.dumps({"error": "taint postscript exception",
                           "tb": traceback.format_exc(), "taint": {"flows": []}})

fh = open(out_path, "w")
fh.write(_payload)
fh.close()
'''


# Grounded P-Code EMULATION for constant/key recovery (Phase 4). Runs a self-contained routine
# (e.g. a key-derivation / string-decode schedule whose result never appears as a literal) inside
# Ghidra's P-Code emulator and recovers the value it returns — no native execution of the target.
# The recipe: seed RSP + push a sentinel return address, set the PC to the function entry, single-
# step the P-Code until the PC reaches the sentinel (the routine executed `ret`), then read the
# architecture's return register. Bounded by a hard step budget; a routine that calls out to code
# the emulator has no body for (an external/PLT call) stops cleanly and is reported not-returned.
EMU_SCRIPT = r'''# -*- coding: utf-8 -*-
# Encoding cookie REQUIRED (Jython 2.7 / PEP 263) — keep this ASCII-only; a compile failure
# writes NO output and is undiagnosable.
import json
import re
import traceback
from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
focus = args[1] if len(args) > 1 and args[1] else None
MAX_STEPS = 500000
# A stack base for the emulated frame. The return-address SENTINEL (when the routine executes
# `ret` the PC becomes this, telling us it returned) is width-matched to the target's pointer
# size below, so 32-bit ARM/MIPS firmware works as well as 64-bit. Chosen far from real code.
STACK_TOP = 0x10000000
try:
    monitor = ConsoleTaskMonitor()
    fm = currentProgram.getFunctionManager()
    ptr_size = currentProgram.getDefaultPointerSize()
    ret_sentinel = 0xbabecafe if ptr_size <= 4 else 0x0000babecafe0000
    target = None
    err_msg = None
    if focus is not None:
        if re.match(r"^0x[0-9a-fA-F]+$", focus):
            try:
                target = getFunctionContaining(toAddr(focus))
            except:
                target = None
        else:
            matches = [f for f in fm.getFunctions(True) if f.getName() == focus]
            if len(matches) > 1:
                err_msg = ("ambiguous function name %s (%d matches) - pass an address"
                           % (focus, len(matches)))
            elif matches:
                target = matches[0]
    if err_msg is not None:
        result = {"emulation": {"error": err_msg}}
    elif target is None:
        result = {"emulation": {"error": "function not found: %s" % focus}}
    elif target.getParameterCount() > 0:
        # Authoritative arg guard (the engine pre-check uses recorded node attrs; this catches
        # a cold path with no recorded signature). An argument-dependent routine emulated over
        # uninitialized inputs won't reach a clean ret, so don't burn the step budget on it.
        result = {"emulation": {
            "function": target.getName(),
            "function_addr": "0x" + target.getEntryPoint().toString(),
            "param_count": target.getParameterCount(),
            "reached_ret": False, "steps": 0, "skipped": "arg_dependent",
            "error": ("function takes %d argument(s) — recover_constant needs a self-contained, "
                      "parameterless routine; use the solver instead" % target.getParameterCount()),
        }}
    else:
        ret = target.getReturn()
        ret_reg = ret.getRegister() if ret is not None else None
        ret_size = ret.getLength() if ret is not None else 0
        entry = target.getEntryPoint()

        emu = EmulatorHelper(currentProgram)
        pc_reg = emu.getPCRegister()
        sp_reg = emu.getStackPointerRegister()
        emu.writeRegister(sp_reg, STACK_TOP)
        # Push the sentinel as the return address at [SP] (so the routine's `ret` lands there),
        # width-matched to the target's pointer size (8 on x86-64/AArch64, 4 on 32-bit).
        emu.writeStackValue(0, ptr_size, ret_sentinel)
        emu.writeRegister(pc_reg, entry.getOffset())

        steps = 0
        reached_ret = False
        err = None
        while steps < MAX_STEPS:
            pc = emu.getExecutionAddress()
            if pc.getOffset() == ret_sentinel:
                reached_ret = True
                break
            try:
                ok = emu.step(monitor)
            except:
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
        # The recovered value is only trustworthy when the routine actually returned.
        if reached_ret and ret_reg is not None:
            raw = int(emu.readRegister(ret_reg)) & 0xFFFFFFFFFFFFFFFF
            emu_out["value_hex"] = "0x%x" % raw
            # Width-correct view from the C return type size (e.g. uint32_t -> low 32 bits).
            if ret_size and ret_size < 8:
                mask = (1 << (ret_size * 8)) - 1
                emu_out["value"] = "0x%0*x" % (ret_size * 2, raw & mask)
                emu_out["width_bytes"] = ret_size
            else:
                emu_out["value"] = "0x%x" % raw
                emu_out["width_bytes"] = 8
        emu.dispose()
        result = {"emulation": emu_out}
    _payload = json.dumps(result)
except:
    _payload = json.dumps({"error": "emulation postscript exception",
                           "tb": traceback.format_exc(), "emulation": {}})

fh = open(out_path, "w")
fh.write(_payload)
fh.close()
'''


# Cross-reference queries served from the WARM persistent project's already-built reference
# index (ghidra.program.model.symbol.ReferenceManager) — an index lookup over the ALREADY-analyzed
# program, NO re-analysis, so a warm target answers in the same near-instant timeframe as a warm
# decompile (unlike the r2 xrefs_probe, which runs a full `aaa` sweep cold on every call and times
# out on a large binary). Mirrors the r2 xrefs_probe.py output contract key-for-key so the
# agent-tool handlers format either backend identically. Modes (postScript args[1]):
#   callers   <symbol>  who references/calls a symbol (call sites + the function each lives in)
#   function  <fn>      callers AND callees of one function (the bidirectional neighbourhood)
#   data      <addr>    every reference TO an address (or a symbol that resolves to one)
#   callgraph           the whole-program call graph as [caller, callee] pairs (bounded)
#   sinks               (no subject) the dangerous/format/network sink sweep
# args[2] is the subject (symbol name / hex address), "" for callgraph/sinks. A symbol/address the
# index doesn't know returns an EMPTY result with `not_found` (NOT a top-level `error`) so the host
# fast-fails instead of falling back to the cold r2 sweep; a top-level `error` means the query
# genuinely could not run (Ghidra missing / Jython fault) and the host may fall back.
XREFS_SCRIPT = r'''# -*- coding: utf-8 -*-
# Encoding cookie REQUIRED (Jython 2.7 / PEP 263); keep this body ASCII-only -- a compile failure
# here writes NO output and is undiagnosable.
import json
import re
import traceback
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0]
try:
    mode = args[1] if len(args) > 1 and args[1] else "sinks"
    subject = args[2] if len(args) > 2 and args[2] else None
    monitor = ConsoleTaskMonitor()

    _ADDR = re.compile(r"^0x[0-9a-fA-F]+$")
    MAX_REFS = 200        # cap one symbol/address ref list (the host shows total + "... N more")
    MAX_SINK_REFS = 30    # per-sink cap in the sweep (mirrors xrefs_probe _MAX_CALLERS)
    MAX_GRAPH_FUNCS = 600
    MAX_GRAPH_EDGES = 2000

    # Sink name lists -- MIRROR sandbox/probes/xrefs_probe.py (_DEFAULT_SINKS / _FORMAT_SINKS /
    # _NETWORK_SINKS). Keep the two in sync so the two backends sweep the same surface.
    DEFAULT_SINKS = ["system", "popen", "execl", "execlp", "execle", "execv", "execvp",
                     "execve", "strcpy", "strcat", "gets", "scanf", "sscanf", "memcpy",
                     "alloca", "stpcpy"]
    FORMAT_SINKS = ["printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf",
                    "vfprintf", "vsprintf", "vsnprintf", "syslog", "vsyslog", "asprintf"]
    NETWORK_SINKS = ["socket", "bind", "listen", "accept", "accept4", "connect", "recv",
                     "recvfrom", "recvmsg", "read", "send", "sendto", "sendmsg",
                     "setsockopt", "getaddrinfo", "gethostbyname", "socketpair"]

    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    refmgr = currentProgram.getReferenceManager()

    def _rt_name(ref):
        try:
            return ref.getReferenceType().getName()
        except:
            return str(ref.getReferenceType())

    def _syms_named(name):
        out = []
        it = st.getSymbols(name)
        while it.hasNext():
            out.append(it.next())
        return out

    def _caller_target_addrs(name):
        # The addresses a call to `name` can reference: every symbol named `name`, PLUS the thunk
        # stubs that point at any function of that name. This matters for an IMPORTED function: the
        # call lands on its PLT/GOT thunk, and the external symbol's own only reference is the
        # thunk linkage -- so without the thunk-stub addresses the real call sites are invisible
        # (getFunctionThunkAddresses is the thunk-aware bridge; verified on real Ghidra 12.1).
        addrs = []
        seen_a = set()

        def _add(a):
            if a is not None and a.toString() not in seen_a:
                seen_a.add(a.toString())
                addrs.append(a)

        for sym in _syms_named(name):
            a = sym.getAddress()
            _add(a)
            f = fm.getFunctionAt(a) if a is not None else None
            if f is not None:
                try:
                    thunk_addrs = f.getFunctionThunkAddresses(True)
                except:
                    try:
                        thunk_addrs = f.getFunctionThunkAddresses()
                    except:
                        thunk_addrs = None
                for ta in (thunk_addrs or []):
                    _add(ta)
        return addrs

    def _callers_of(name):
        # Real callers of `name`: references TO its addresses (incl. thunk stubs), keeping the
        # containing function of each, read from the warm reference index. A thunk-origin ref (the
        # PLT stub -> external linkage) is dropped so only genuine callers remain.
        out = []
        seen = set()
        for addr in _caller_target_addrs(name):
            for ref in refmgr.getReferencesTo(addr):
                frm = ref.getFromAddress()
                if frm is None:
                    continue
                caller = getFunctionContaining(frm)
                if caller is None or caller.isThunk():
                    continue
                key = (caller.getName(), frm.toString())
                if key in seen:
                    continue
                seen.add(key)
                try:
                    caddr = "0x" + caller.getEntryPoint().toString()
                except:
                    caddr = None
                out.append({"caller": caller.getName(), "caller_addr": caddr,
                            "at": "0x" + frm.toString(), "kind": _rt_name(ref)})
        return out

    def _resolve_function(subj):
        if _ADDR.match(subj):
            try:
                return getFunctionContaining(toAddr(subj))
            except:
                return None
        for sym in _syms_named(subj):
            try:
                f = fm.getFunctionAt(sym.getAddress())
            except:
                f = None
            if f is not None:
                return f
        return None

    def _callees_of(func):
        out = []
        seen = set()
        try:
            called = func.getCalledFunctions(monitor)
        except:
            called = []
        for c in called:
            nm = c.getName()
            if nm in seen:
                continue
            seen.add(nm)
            try:
                addr = "0x" + c.getEntryPoint().toString()
            except:
                addr = None
            out.append({"name": nm, "addr": addr})
        return out

    if mode == "callgraph":
        edges = []
        for f in list(fm.getFunctions(True))[:MAX_GRAPH_FUNCS]:
            try:
                for callee in f.getCalledFunctions(monitor):
                    edges.append([f.getName(), callee.getName()])
                    if len(edges) >= MAX_GRAPH_EDGES:
                        break
            except:
                pass
            if len(edges) >= MAX_GRAPH_EDGES:
                break
        result = {"mode": "callgraph", "calls": edges, "total": len(edges)}

    elif mode == "function":
        func = _resolve_function(subject) if subject else None
        if func is None:
            result = {"mode": "function", "subject": subject, "callers": [], "callees": [],
                      "total_callers": 0, "total_callees": 0, "not_found": True}
        else:
            callers = _callers_of(func.getName())
            callees = _callees_of(func)
            result = {"mode": "function", "subject": subject,
                      "callers": callers[:MAX_REFS], "callees": callees[:MAX_REFS],
                      "total_callers": len(callers), "total_callees": len(callees)}

    elif mode == "data":
        addr = None
        if subject and _ADDR.match(subject):
            try:
                addr = toAddr(subject)
            except:
                addr = None
        if addr is None and subject:
            for sym in _syms_named(subject):
                a = sym.getAddress()
                if a is not None:
                    addr = a
                    break
        if addr is None:
            result = {"mode": "data", "subject": subject, "data_refs": [], "total": 0,
                      "not_found": True}
        else:
            refs = []
            seen = set()
            for ref in refmgr.getReferencesTo(addr):
                frm = ref.getFromAddress()
                if frm is None:
                    continue
                fn = getFunctionContaining(frm)
                fname = fn.getName() if fn is not None else "?"
                key = (fname, frm.toString())
                if key in seen:
                    continue
                seen.add(key)
                refs.append({"from_function": fname, "at": "0x" + frm.toString(),
                             "kind": _rt_name(ref)})
            result = {"mode": "data", "subject": subject,
                      "data_refs": refs[:MAX_REFS], "total": len(refs)}

    elif mode == "callers":
        refs = _callers_of(subject) if subject else []
        result = {"mode": "callers", "symbol": subject,
                  "callers": refs[:MAX_REFS], "total": len(refs)}

    else:  # the dangerous/format/network sink sweep (no subject)
        def _sweep(names):
            grp = {}
            for s in names:
                refs = _callers_of(s)
                if refs:
                    grp[s] = {"callers": refs[:MAX_SINK_REFS], "total": len(refs)}
            return grp
        result = {"mode": "sinks", "sinks": _sweep(DEFAULT_SINKS),
                  "format_sinks": _sweep(FORMAT_SINKS), "network": _sweep(NETWORK_SINKS)}

    _payload = json.dumps(result)
except:
    _payload = json.dumps({"error": "xrefs postscript exception", "tb": traceback.format_exc()})

fh = open(out_path, "w")
fh.write(_payload)
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
    # --taint runs the grounded P-Code data-flow analysis (TAINT_SCRIPT) over the analyzed
    # program instead of the decompile/inventory postScript. It reuses the SAME persistent
    # project (warm -process) so it pays no re-analysis cost after a prior decompile run.
    taint_mode = "--taint" in sys.argv
    # --emulate <function> runs the P-Code emulator (EMU_SCRIPT) to recover the constant the
    # routine returns. The function (name or address) is the arg right after --emulate; it is
    # threaded to the postScript as its focus. Reuses the SAME persistent project (warm).
    emu_mode = "--emulate" in sys.argv
    if emu_mode:
        i = sys.argv.index("--emulate")
        focus = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
    # Rename round-trip: --rename <addr> <new_name> applies the rename in the project
    # (saved by the -process/-import run) and decompiles the renamed function.
    rename_addr = rename_name = ""
    if "--rename" in sys.argv:
        i = sys.argv.index("--rename")
        if i + 2 < len(sys.argv):
            rename_addr, rename_name = sys.argv[i + 1], sys.argv[i + 2]
    # --xrefs <mode> [subject] serves a cross-reference query from the warm project's already-built
    # reference index (XREFS_SCRIPT) instead of a cold whole-binary r2 pass. `mode` is the arg after
    # --xrefs; the optional `subject` (symbol/address) is the arg after that. Reuses the SAME
    # persistent project (warm -process) so it pays no re-analysis after a prior decompile.
    xrefs_mode = "--xrefs" in sys.argv
    xrefs_kind = "sinks"
    xrefs_subject = ""
    if xrefs_mode:
        i = sys.argv.index("--xrefs")
        if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
            xrefs_kind = sys.argv[i + 1]
        if i + 2 < len(sys.argv) and not sys.argv[i + 2].startswith("--"):
            xrefs_subject = sys.argv[i + 2]

    hl = _find_headless()
    if not hl:
        print(json.dumps({"error": "Ghidra not installed in this sandbox image — rebuild it "
                                   "with WITH_GHIDRA=1 (just sandbox-build with_ghidra=1), or "
                                   "switch the decompiler back to radare2"}))
        return 3

    # The postScript + its JSON output ALWAYS live on the /scratch tmpfs (the project mount
    # holds only the Ghidra project itself — keeps the persistent dir lean and the hardening
    # comment honest: only the project lives on the writable mount, never user-settings/temp).
    if emu_mode:
        script_name, script_body = "hexgraph_emu.py", EMU_SCRIPT
    elif taint_mode:
        script_name, script_body = "hexgraph_taint.py", TAINT_SCRIPT
    elif xrefs_mode:
        script_name, script_body = "hexgraph_xrefs.py", XREFS_SCRIPT
    else:
        script_name, script_body = "hexgraph_post.py", POST_SCRIPT
    # The positional postScript args differ by script: the xrefs query takes (mode, subject); every
    # other script takes (focus, rename_addr, rename_name). out_path is always args[0].
    if xrefs_mode:
        post_args = [xrefs_kind, xrefs_subject]
    else:
        post_args = [focus or "", rename_addr, rename_name]
    script_path = os.path.join(SCRATCH, script_name)
    out_path = os.path.join(SCRATCH, "ghidra_out.json")
    with open(script_path, "w") as fh:
        fh.write(script_body)

    # F13: a LARGE binary's cold import gets the fast-profile preScript (disables the pathological
    # auto-analysis passes); small binaries keep the FULL analysis (no preScript). The WARM path
    # runs no auto-analysis, so it never needs it.
    pre_script_args = []
    try:
        _large = artifact is not None and os.path.getsize(artifact) >= GHIDRA_FAST_PROFILE_BYTES
    except OSError:
        _large = False
    if _large:
        with open(os.path.join(SCRATCH, "hexgraph_fast_profile.py"), "w") as fh:
            fh.write(FAST_PROFILE_SCRIPT)
        pre_script_args = ["-preScript", "hexgraph_fast_profile.py"]

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
            "-postScript", script_name, out_path, *post_args,
        ]
    else:
        # COLD: import + analyze. Persist the project (no -deleteProject) only when the
        # writable mount is present; otherwise delete it (throwaway /scratch fallback).
        cmd = [
            hl, proj_dir, PROJECT_NAME,
            "-import", artifact,
            *_analysis_timeout_args(),       # F13: stop+save before the wall-clock kill on a monolith
            "-scriptPath", SCRATCH,
            *pre_script_args,                # F13: fast-profile preScript for a large binary
            "-postScript", script_name, out_path, *post_args,
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
