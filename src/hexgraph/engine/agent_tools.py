"""Agent tools — what an LLM task can call, each executed by HexGraph in the
sandbox (the model never touches the environment).

The registry is the single source for (a) the tool specs advertised to the model
and (b) executing a requested call. Static tools are read-only and need no policy
change; `fuzz_function` is dynamic and offered only when fuzzing is enabled
(policy-gated). Tools return bounded TEXT; errors come back as text so the model
can recover rather than the task failing.

**The query/enrich/promote contract (design §5.3).** Every tool result is recorded
as a durable Observation (the substrate — discoverable, reusable, scoped to the
exact bytes), but the GRAPH stays a curated result set. QUERY verbs (list_functions/
disassemble/xrefs/list_strings) mutate no graph; they only enrich already-existing
nodes via the Observation-write path. decompile_function is the PROMOTE act: it adds
THIS one function and draws `calls` edges ONLY to callees already in the graph — new
callees are surfaced as promotable, never auto-spawned (the both-endpoints-exist rule,
the fan-out guard). A per-call promotion budget backstops it, reporting any overflow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.llm.base import ToolSpec

logger = logging.getLogger(__name__)

_MAX = 6000  # cap any single tool result so the context stays bounded

# Per-call promotion budget (design §5.3, the backstop): a single tool call may add
# at most this many NEW nodes/edges to the graph. A promotion that would exceed it
# returns the overflow as promotable results with an explicit "capped" note — never
# silent truncation (the repo's no-silent-caps discipline).
_PROMOTE_BUDGET = 50


@dataclass
class ToolContext:
    session: Session
    project: Project
    target: Target
    cache: dict = field(default_factory=dict)


# --- specs (advertised to the model) ------------------------------------------

_STATIC_SPECS = [
    ToolSpec("list_functions", "List the function names discovered in the target binary. QUERY: "
             "returns the inventory and records an Observation; does NOT add graph nodes — the "
             "enumeration is an answer, not a graph object. Promote a function deliberately by "
             "decompiling it.",
             {"type": "object", "properties": {}}),
    ToolSpec("decompile_function", "Decompile one function to pseudo-C and list its callees. "
             "Use this to read the actual code before judging a vulnerability. PROMOTE: this "
             "deliberately adds THIS function to the graph (enriched in place with its recovered "
             "prototype/address) and draws `calls` edges only to callees ALREADY in the graph — "
             "new callees are listed for optional promotion, never auto-added (no fan-out).",
             {"type": "object", "properties": {"function": {"type": "string"}}, "required": ["function"]}),
    ToolSpec("decompile_at", "Decompile the function CONTAINING a hex ADDRESS (e.g. 0x401200) — "
             "analyze-at-address for when you have an address (from xrefs/strings/a crash) but not "
             "a name. PROMOTE: same as decompile_function for the resolved function (adds it, draws "
             "`calls` edges only to callees already in the graph; new callees listed, not auto-added).",
             {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}),
    ToolSpec("disassemble", "Disassemble one function by NAME or by ADDRESS (an address resolves to "
             "the function containing it) — when pseudo-C is unclear. QUERY: records an Observation; "
             "adds no graph nodes.",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "address": {"type": "string"}}}),
    ToolSpec("reanalyze", "Re-run the target's analysis at a HIGHER depth (and bust the cache) so a "
             "function or call edge the fast pass missed gets a second chance — use when "
             "list_functions/decompile look incomplete. QUERY: refreshes the inventory, adds no graph "
             "nodes.",
             {"type": "object", "properties": {}}),
    ToolSpec("xrefs", "Find which functions CALL a given symbol/sink (e.g. system, popen, "
             "strcpy) and where. With no symbol, map the binary's dangerous sinks, format-string "
             "sinks, AND network/socket surface (bind/listen/connect/recv) + who reaches each. Use "
             "to trace a sink back to its caller, or to find listen/connect sites for socket nodes. "
             "QUERY: records an Observation and tags is_sink on any dangerous-import symbol ALREADY "
             "in the graph; adds no new graph nodes.",
             {"type": "object", "properties": {"symbol": {"type": "string"}}}),
    ToolSpec("call_graph", "The target's call graph — who-calls-whom across the program, or (with a "
             "`function`) the neighbourhood rooted at it out to `depth` (default 2). QUERY: records a "
             "call_graph Observation and SELF-WIRES `calls` edges among functions ALREADY in the graph "
             "(creates no new nodes — promote functions first to grow the wired graph).",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "depth": {"type": "integer"}}}),
    ToolSpec("function_xrefs", "Both directions for ONE function: its CALLERS (who calls it) and its "
             "CALLEES (what it calls) — walk the call graph around a function of interest. QUERY: "
             "records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"function": {"type": "string"}}, "required": ["function"]}),
    ToolSpec("data_xrefs", "Cross-references TO a hex ADDRESS (or a symbol/label that resolves to one) "
             "— every code/data/string reference that points at it (who reads/writes/points to this "
             "datum or string constant). QUERY: records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}),
    ToolSpec("read_imports", "Return the target's imported symbols, linked libraries, and mitigation flags.",
             {"type": "object", "properties": {}}),
    ToolSpec("binutils_facts", "Authoritative low-level ELF facts via GNU binutils (nm/objdump/readelf/"
             "strings): the symbol table, dynamic imports/exports, relocations (incl. PLT jump-slot "
             "imports), sections, ELF/program headers, and the security mitigations (NX, RELRO, PIE, "
             "stack canary, FORTIFY). The fast first-minute facts pass — sharper than read_imports "
             "(recon caps imports/strings). QUERY: records a binutils_facts Observation and tags "
             "is_sink on any dangerous import ALREADY in the graph + folds mitigation flags onto the "
             "target; adds NO new graph nodes — promote what matters.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_strings", "List notable strings in the target, optionally filtered by a substring. "
             "QUERY: records an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"pattern": {"type": "string"}}}),
    ToolSpec("search_decompiled", "Search ACROSS already-decompiled function BODIES on this target for a "
             "string/identifier (a variable, constant, call, format string) — mines PRIOR "
             "decompilations in the Observation store, NO re-decompile. Returns the matching functions "
             "+ a snippet. Decompile candidates first if nothing's been decompiled yet. QUERY: records "
             "an Observation; adds no graph nodes.",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
    ToolSpec("check_decompiler", "Verify the decompiler decompile_function/disassemble use ACTUALLY "
             "works (not just the configured name): radare2 needs the sandbox image up; Ghidra needs "
             "WITH_GHIDRA=1 (headless) or a reachable bridge. Run it if a decompile fails so you don't "
             "keep retrying a broken backend — the result's detail says what to fix.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_observations", "Prior deterministic analysis recorded on THIS target — the "
             "OBSERVATION STORE (the substrate, NOT the curated graph): decompilations, function "
             "lists, xrefs, strings, structs, taint, each saved once as a reusable Observation. "
             "CHECK THIS BEFORE RE-RUNNING a heavy analysis; get_observation(id) loads a prior "
             "payload. Results persist here — promote only what matters into the graph.",
             {"type": "object", "properties": {"tool": {"type": "string"}, "kind": {"type": "string"}}}),
    ToolSpec("get_observation", "Read ONE Observation in full incl. its payload — reuse a prior "
             "decompilation/xref result instead of paying to re-run it.",
             {"type": "object", "properties": {"observation_id": {"type": "string"}},
              "required": ["observation_id"]}),
    ToolSpec("search_observations", "Search prior Observations (substring over tool/summary/kind) "
             "on this target — find earlier analysis to reuse before re-running it.",
             {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}),
]

_FUZZ_SPEC = ToolSpec(
    "fuzz_function", "Dynamically fuzz the target via its generated harness (libFuzzer) for a few "
    "seconds and report any crashes. Requires a harness from harness_generation.",
    {"type": "object", "properties": {"max_total_time": {"type": "integer"}}},
)


def available_tools(ctx: ToolContext) -> list[ToolSpec]:
    """Tool specs for this target. fuzz_function only when the policy permits
    execution (fuzzing enabled in Settings)."""
    specs = list(_STATIC_SPECS)
    try:
        from hexgraph.policy import current_policy

        if current_policy().allow_execution:
            specs.append(_FUZZ_SPEC)
    except Exception:  # noqa: BLE001
        pass
    return specs


# --- execution ----------------------------------------------------------------

def _clip(s: str) -> str:
    s = s or ""
    return s if len(s) <= _MAX else s[:_MAX] + "\n…[truncated]"


def _callee_names(callees) -> list[str]:
    """Callee names from the decompiler's callee list (entries are bare names or dicts)."""
    out = []
    for c in callees or []:
        n = c.get("name") if isinstance(c, dict) else c
        if n:
            out.append(n)
    return out


def _format_decomp(out: dict, label: str) -> str:
    """Render a focused decompile (decompile_function / decompile_at) result as text:
    the resolved name+address, callees, pseudocode, and any not-yet-promoted callees."""
    focus = out.get("focus")
    if not focus:
        return f"{label} not found among: {', '.join(out.get('functions', [])[:40])}"
    addr = f" @ {focus['address']}" if focus.get("address") else ""
    name = focus.get("name") or label
    promo = out.get("promotable_callees") or []
    note = ""
    if promo:
        # New callees were NOT added to the graph (no fan-out). Surface them for
        # deliberate promotion — decompile_function one of these to promote it.
        note = ("\n// callees not yet in the graph (promote any by decompiling it): "
                + ", ".join(promo))
    return _clip(f"// {name}{addr} (callees: {', '.join(_callee_names(focus.get('callees')))})\n"
                 f"{focus.get('pseudocode', '')}{note}")


def _record_obs(ctx: ToolContext, *, tool: str, args: dict | None, result_kind: str,
                payload, summary: str, status: str = "ok", node_refs: list | None = None):
    """Record one deterministic tool call as a durable Observation (design §5.2/§5.6)
    and return `(observation, cached)`. Passes the TARGET's analyzed-bytes content_hash
    (via content_hash_for) so the extract-at-write enrichment + passive invalidation fire
    correctly — a producer that omits this would write facts under a None hash that a
    properly-keyed node never matches. Recording an Observation creates ZERO graph nodes;
    enrichment of ALREADY-existing nodes happens automatically inside record_observation.
    Best-effort: a store failure must never break the tool call."""
    from hexgraph.engine import observations as O

    try:
        return O.record_observation(
            ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
            source="agent", tool=tool, args=args, result_kind=result_kind,
            payload=payload, summary=summary, status=status,
            content_hash=O.content_hash_for(ctx.target), node_refs=node_refs or [],
        )
    except Exception:  # noqa: BLE001 — discoverability is best-effort, never load-bearing
        # Swallow so a store hiccup never breaks the tool call, but debug-log so genuine
        # CAS/DB corruption is diagnosable rather than silently invisible.
        logger.debug("failed to record observation for tool=%s on target=%s",
                     tool, ctx.target.id, exc_info=True)
        return None, False


def _function_node(ctx: ToolContext, name: str):
    """The EXISTING (non-archived) function node for `name` in this target, by canonical
    identity (normalized), or None. Used for the both-endpoints-exist rule — we never
    mint a node here, only check whether one is already curated."""
    from hexgraph.db.models import Node
    from hexgraph.engine.nodes import normalize_symbol_name

    key = normalize_symbol_name(name)
    if not key:
        return None
    for n in (ctx.session.query(Node)
              .filter(Node.project_id == ctx.project.id, Node.target_id == ctx.target.id,
                      Node.node_type == "function", Node.archived.is_(False)).all()):
        if normalize_symbol_name(n.fq_name or n.name) == key:
            return n
    return None


def _decomp(ctx: ToolContext, function: str | None, *,
            address: str | None = None, reanalyze: bool = False):
    """Run the decompiler (cached per focus), record the result as an Observation, and for
    a focused decompile PROMOTE that one function (the deliberate curation act). A focus is
    a function NAME or a hex ADDRESS (resolved to the function CONTAINING it); `reanalyze`
    raises the analysis depth and busts the cache so a missed function/edge gets a retry.

    Returns the decompiler dict, augmented (on a focused decompile) with `observation_id`
    and `promotable_callees` — callees NOT yet in the graph that the agent may promote."""
    focused = bool(function or address)
    # The tool name + args this call is attributed to, for a discoverable, correctly-keyed
    # Observation: an address decompile is a decompile_at call, a name one decompile_function.
    if address:
        req_tool, req_args = "decompile_at", {"address": address}
    elif function:
        req_tool, req_args = "decompile_function", {"function": function}
    else:
        req_tool, req_args = ("reanalyze", {}) if reanalyze else ("list_functions", {})

    key = f"decomp:{function or address or '*'}:{int(reanalyze)}"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.sandbox.decompiler import get_decompiler
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        ctx.cache[key] = {"error": "decompilation unavailable (Docker/sandbox not running)"}
        return ctx.cache[key]
    try:
        out = get_decompiler().decompile(ctx.target.path, function, address=address,
                                         reanalyze=reanalyze, project=ctx.project)
    except Exception as exc:  # noqa: BLE001
        out = {"error": f"decompiler failed: {exc}"}
    ctx.cache[key] = out
    if not isinstance(out, dict):
        return out
    if out.get("error"):
        return out

    if focused and out.get("focus"):
        # A focused decompile is a QUERY (recorded) + an explicit PROMOTE of THIS one
        # function. result_kind="decompilation" so the enrichment extractor distills the
        # focus's whitelisted facts (prototype/address/callees) into the index.
        focus = out["focus"]
        obs, _cached = _record_obs(
            ctx, tool=req_tool, args=req_args,
            result_kind="decompilation", payload=out,
            summary=f"decompiled {focus.get('name') or function or address}",
            node_refs=[focus.get("name")] if focus.get("name") else [])
        promotable = _materialize(ctx, focus)
        out["observation_id"] = obs.id if obs is not None else None
        out["promotable_callees"] = promotable
    else:
        # A pure QUERY: record it, mutate NO graph. Attribute it to the call the agent
        # actually made — a requested-but-not-found focused decompile is a decompile_*
        # call (that yielded no focus), not a list_functions call, so it must not pollute
        # the discoverability index under the wrong tool name.
        fns = out.get("functions", [])
        if focused:
            subj = function or address
            obs, _cached = _record_obs(
                ctx, tool=req_tool, args=req_args, result_kind="function_list",
                payload={"functions": fns},
                summary=f"{subj!r} not found; {len(fns)} functions available")
        else:
            obs, _cached = _record_obs(
                ctx, tool=req_tool, args=req_args, result_kind="function_list",
                payload={"functions": fns},
                summary=f"{len(fns)} functions" + (" (re-analyzed)" if reanalyze else ""))
        out["observation_id"] = obs.id if obs is not None else None
    return out


def _materialize(ctx: ToolContext, focus: dict) -> list[str]:
    """Promote the decompiled FOCUS function into the graph (the deliberate curation act
    of decompiling THIS function), and draw `calls` edges ONLY to callees that ALREADY
    exist as nodes (the both-endpoints-exist rule, design §5.3). New callees are NOT
    spawned as nodes — they surface in the result as promotable.

    Bounded by the per-call promotion budget (one new focus node + edges to existing
    callees). Returns the callee names NOT promoted (so the caller can report them).

    The focus's enrichment (prototype/address/calling_convention) lands automatically:
    _record_obs already indexed the facts, and get_or_create_node pulls them at create."""
    from hexgraph.db.models import EdgeType
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.nodes import materialize_function

    if not focus.get("name"):
        return []
    budget = _PROMOTE_BUDGET
    fnode = materialize_function(ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
                                 name=focus["name"], address=focus.get("address"),
                                 pseudocode=focus.get("pseudocode") or None, created_by="agent")
    budget -= 1  # the focus node is the one promotion this call makes
    promotable: list[str] = []
    for callee in focus.get("callees", []) or []:
        cname = callee.get("name") if isinstance(callee, dict) else callee
        if not cname:
            continue
        cnode = _function_node(ctx, cname)
        if cnode is None:
            # Callee isn't curated yet: do NOT mint it (no fan-out). Surface it so the
            # agent can decompile/promote it deliberately if it matters.
            promotable.append(cname)
            continue
        if budget <= 0:
            # Edge to an existing endpoint would otherwise be free, but honor the
            # backstop strictly and report the overflow rather than silently truncate.
            promotable.append(cname)
            continue
        add_edge(ctx.session, project_id=ctx.project.id, src=("node", fnode.id), dst=("node", cnode.id),
                 type=EdgeType.calls, origin="tool", confidence=1.0, created_by_tool="agent")
        budget -= 1
    return promotable


def run_tool(ctx: ToolContext, name: str, args: dict) -> str:
    """Execute a tool call and return its result as text (errors as text too)."""
    args = args or {}
    meta = ctx.target.metadata_json or {}
    try:
        if name == "read_imports":
            return _clip(
                f"imports: {meta.get('imports', [])}\nlibraries: {meta.get('libraries', [])}\n"
                f"mitigations: {meta.get('mitigations', {})}\nexports: {meta.get('exports', [])[:60]}"
            )
        if name == "list_strings":
            strings = meta.get("strings", []) or []
            pat = (args.get("pattern") or "").lower()
            if pat:
                strings = [s for s in strings if pat in str(s).lower()]
            _record_obs(ctx, tool="list_strings",
                        args={"pattern": pat} if pat else {}, result_kind="strings",
                        payload={"strings": [str(s) for s in strings[:200]]},
                        summary=f"{len(strings)} strings" + (f" matching {pat!r}" if pat else ""))
            return _clip("strings:\n" + ("\n".join(str(s) for s in strings[:200]) or "(none)"))
        if name == "binutils_facts":
            return _binutils(ctx)
        if name == "list_functions":
            out = _decomp(ctx, None)
            if out.get("error"):
                return out["error"]
            return _clip("functions:\n" + "\n".join(out.get("functions", [])[:300]))
        if name == "disassemble":
            fn = args.get("function")
            addr = args.get("address")
            if not fn and not addr:
                return "error: 'function' or 'address' argument is required"
            subj = fn or addr
            # Always disassemble with radare2 — it gives real instruction listings;
            # the Ghidra decompiler path returns empty disasm (it's a decompiler). An
            # address resolves to the function CONTAINING it (analyze-at-address).
            from hexgraph.sandbox.decompiler import R2Decompiler
            from hexgraph.sandbox.runner import docker_available
            if not docker_available():
                return "disassembly unavailable (Docker/sandbox not running)"
            try:
                out = R2Decompiler().decompile(ctx.target.path, fn, address=addr)
            except Exception as exc:  # noqa: BLE001
                return f"disassembly failed: {exc}"
            focus = (out or {}).get("focus")
            disasm = (focus or {}).get("disasm") if focus else None
            # Keyed to the call the agent made (by name or by address).
            obs_args = {"address": addr} if addr else {"function": fn}
            if not disasm:
                # A requested-but-unresolved focus is still a discoverable disassemble call —
                # record the available inventory (mirrors decompile_at's not-found path) so the
                # miss is visible in the index, not silently dropped.
                fns = (out or {}).get("functions", [])
                _record_obs(ctx, tool="disassemble", args=obs_args, result_kind="function_list",
                            payload={"functions": fns},
                            summary=f"{subj!r} not found; {len(fns)} functions available")
                return f"{subj!r} not found / no disassembly (functions: {', '.join(fns[:40])})"
            at = f" @ {focus['address']}" if focus.get("address") else ""
            # Record the disassembly as a QUERY observation (no graph mutation).
            _record_obs(ctx, tool="disassemble", args=obs_args,
                        result_kind="disassembly",
                        payload={"function": focus.get("name") or subj,
                                 "address": focus.get("address"), "disasm": disasm},
                        summary=f"disassembled {focus.get('name') or subj}")
            return _clip(f"// {focus.get('name') or subj}{at} disassembly\n{disasm}")
        if name == "decompile_function":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            out = _decomp(ctx, fn)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"function {fn!r}")
        if name == "decompile_at":
            addr = args.get("address")
            if not addr:
                return "error: 'address' argument is required"
            # Decompile (and PROMOTE) the function CONTAINING this address — analyze-at-address
            # for when you have an address (from xrefs/strings) but not a function name.
            out = _decomp(ctx, None, address=addr)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"address {addr}")
        if name == "reanalyze":
            # Raise the analysis depth and bust the cache so a function/edge the fast pass
            # missed gets a retry. QUERY: re-runs the inventory, mutates no graph.
            out = _decomp(ctx, None, reanalyze=True)
            if out.get("error"):
                return out["error"]
            fns = out.get("functions", [])
            return _clip(f"re-analyzed ({len(fns)} functions):\n" + "\n".join(fns[:300]))
        if name == "check_decompiler":
            from hexgraph.engine.mcp_tools import check_decompiler
            d = check_decompiler()
            ver = f" {d['version']}" if d.get("version") else ""
            mode = f" ({d['mode']})" if d.get("mode") else ""
            status = "WORKING" if d["working"] else "NOT WORKING"
            return _clip(f"decompiler: {d['active']}{ver}{mode} — {status}\n{d['detail']}")
        if name in ("list_observations", "get_observation", "search_observations"):
            return _observations(ctx, name, args)
        if name == "xrefs":
            return _xrefs(ctx, args.get("symbol"))
        if name == "call_graph":
            return _call_graph_tool(ctx, args.get("function"), args.get("depth"))
        if name == "function_xrefs":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            return _function_xrefs(ctx, fn)
        if name == "data_xrefs":
            addr = args.get("address")
            if not addr:
                return "error: 'address' argument is required"
            return _data_xrefs(ctx, addr)
        if name == "search_decompiled":
            q = args.get("query")
            if not q:
                return "error: 'query' argument is required"
            return _search_decompiled(ctx, q)
        if name == "fuzz_function":
            return _fuzz(ctx, args)
        return f"error: unknown tool {name!r}"
    except Exception as exc:  # noqa: BLE001 — tools never crash the task
        return f"error running {name}: {exc}"


def _observations(ctx: ToolContext, name: str, args: dict) -> str:
    """Mirror the Observation-store read verbs for the in-process agent loop, scoped
    to this target (design §5.6). Results persist as Observations; this is how the
    agent discovers prior analysis instead of re-running it."""
    import json as _json

    from hexgraph.engine import observations as O

    if name == "get_observation":
        oid = args.get("observation_id")
        if not oid:
            return "error: 'observation_id' argument is required"
        out = O.get_observation(ctx.session, oid)
        return _clip(_json.dumps(out, default=str)) if out else f"observation {oid!r} not found"
    if name == "search_observations":
        q = args.get("query") or ""
        rows = O.search_observations(ctx.session, target_id=ctx.target.id, query=q)
    else:  # list_observations
        rows = O.list_observations(ctx.session, ctx.target.id,
                                   tool=args.get("tool"), kind=args.get("kind"))
    if not rows:
        return "no prior observations on this target"
    lines = [f"- {r['id']} [{r['result_kind']}] {r['tool']}: {r['summary'][:120]}" for r in rows]
    return _clip("prior observations (get_observation(id) for the full payload):\n"
                 + "\n".join(lines))


def _binutils(ctx: ToolContext) -> str:
    """Run the binutils quick-facts probe (the engine helper records the Observation +
    enriches already-curated symbols/the target's mitigations) and render a compact text
    summary for the agent. QUERY: mutates no graph beyond the always-welcome enrichment."""
    key = "binutils:*"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.engine.binutils import collect_binutils_facts

    out = collect_binutils_facts(ctx.session, ctx.project, ctx.target, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {})
    mit = f.get("mitigations", {}) or {}
    imports = f.get("imports", []) or []
    exports = f.get("exports", []) or []
    libs = f.get("libraries", []) or []
    sections = f.get("sections", []) or []
    jslots = f.get("jump_slot_imports", []) or []
    lines = [
        f"// binutils facts for {ctx.target.name}"
        + (" (cached)" if out.get("cached") else ""),
        f"type: {f.get('elf_type')}  machine: {f.get('machine')}  entry: {f.get('entry')}"
        + (f"  soname: {f.get('soname')}" if f.get("soname") else ""),
        "mitigations: " + ", ".join(f"{k}={mit.get(k)}" for k in ("nx", "relro", "pie", "canary", "fortify")),
        f"libraries ({len(libs)}): " + ", ".join(libs[:30]) if libs else "libraries: (none)",
        f"imports ({len(imports)}): " + ", ".join(imports[:60]),
        f"exports ({len(exports)}): " + ", ".join(exports[:60]),
        f"sections ({len(sections)}): " + ", ".join(sections[:40]),
        f"relocations: {f.get('relocation_count', 0)}"
        + (f"; PLT jump-slot imports: {', '.join(jslots[:40])}" if jslots else ""),
    ]
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _xrefs(ctx: ToolContext, symbol: str | None) -> str:
    """Map call sites of a sink (or all dangerous sinks) — the callers that reach it."""
    key = f"xrefs:{symbol or '*'}"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return "xrefs unavailable (Docker/sandbox not running)"
    try:
        out = get_executor().run_json_probe(
            "xrefs_probe.py", ctx.target.path,
            extra_args=[symbol] if symbol else None,
        )
    except Exception as exc:  # noqa: BLE001
        return f"xrefs failed: {exc}"
    # Record the xref result (a QUERY) — the enrichment extractor tags is_sink on any
    # already-curated dangerous-import symbol; no graph nodes are created here.
    _record_obs(ctx, tool="xrefs", args={"symbol": symbol} if symbol else {},
                result_kind="xrefs", payload=out,
                summary=f"xrefs for {symbol}" if symbol else "dangerous-sink map")
    if symbol:
        callers = out.get("callers") or []
        if not callers:
            text = f"no callers of {symbol!r} found (not imported/referenced, or unresolved)"
        else:
            more = out.get("total", len(callers)) - len(callers)
            text = f"callers of {symbol}:\n" + "\n".join(
                f"- {c['caller']} (@ {c.get('caller_addr')}) calls at {c.get('at')}" for c in callers)
            if more > 0:
                text += f"\n  … and {more} more"

    else:
        def fmt_group(group: dict) -> list[str]:
            lines = []
            for s, info in group.items():
                refs = info.get("callers", [])
                callers = ", ".join(sorted({c["caller"] for c in refs}))
                extra = f" (+{info['total'] - len(refs)} more)" if info.get("total", 0) > len(refs) else ""
                lines.append(f"- {s}: reached from {callers}{extra}")
            return lines

        sinks = out.get("sinks") or {}
        fmt_sinks = out.get("format_sinks") or {}
        net = out.get("network") or {}
        parts = []
        if sinks:
            parts.append("dangerous sinks (memory/exec) and who reaches them:\n"
                         + "\n".join(fmt_group(sinks)))
        if fmt_sinks:
            parts.append("format-string sinks (printf family) — only a bug if the FORMAT arg is "
                         "attacker-controlled; check each call:\n" + "\n".join(fmt_group(fmt_sinks)))
        if net:
            parts.append("network/IPC surface (sockets) — model endpoints as `socket` nodes with "
                         "listens_on/connects_to edges:\n" + "\n".join(fmt_group(net)))
        text = "\n\n".join(parts) if parts else \
            "no dangerous, format-string, or network sinks referenced in this target"
    ctx.cache[key] = _clip(text)
    return ctx.cache[key]


def _run_xrefs_probe(ctx: ToolContext, subject: str | None, mode: str):
    """Run xrefs_probe in `mode`, returning (out, error_text). `mode="callers"` passes no
    --mode flag (legacy compat); the breadth modes pass `--mode function|data|callgraph`."""
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None, f"{mode} unavailable (Docker/sandbox not running)"
    extra = ([subject] if subject else []) + (["--mode", mode] if mode != "callers" else [])
    try:
        return get_executor().run_json_probe("xrefs_probe.py", ctx.target.path,
                                             extra_args=extra or None), None
    except Exception as exc:  # noqa: BLE001
        return None, f"{mode} xrefs failed: {exc}"


def _function_xrefs(ctx: ToolContext, function: str) -> str:
    """Callers AND callees of one function (the bidirectional neighbourhood). QUERY."""
    key = f"fxrefs:{function}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, function, "function")
    if err:
        return err
    if out.get("error"):
        return f"function {function!r} not found"
    callers = out.get("callers") or []
    callees = out.get("callees") or []
    _record_obs(ctx, tool="function_xrefs", args={"function": function},
                result_kind="function_xrefs", payload=out,
                summary=f"{function}: {len(callers)} callers, {len(callees)} callees")
    lines = [f"// {function}: callers (who calls it) and callees (what it calls)", "callers:"]
    lines += [f"- {c['caller']} (@ {c.get('caller_addr')}) at {c.get('at')}" for c in callers] or ["  (none)"]
    more_c = out.get("total_callers", len(callers)) - len(callers)
    if more_c > 0:
        lines.append(f"  … and {more_c} more callers")
    lines.append("callees:")
    lines += [f"- {c.get('name')} (@ {c.get('addr')})" for c in callees] or ["  (none)"]
    more_e = out.get("total_callees", len(callees)) - len(callees)
    if more_e > 0:
        lines.append(f"  … and {more_e} more callees")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _data_xrefs(ctx: ToolContext, address: str) -> str:
    """Every code/data/string reference TO an address. QUERY."""
    key = f"dxrefs:{address}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, address, "data")
    if err:
        return err
    if out.get("error"):
        return f"no resolvable references to {address!r}"
    refs = out.get("data_refs") or []
    _record_obs(ctx, tool="data_xrefs", args={"address": address},
                result_kind="data_xrefs", payload=out,
                summary=f"{len(refs)} refs to {address}")
    if not refs:
        ctx.cache[key] = f"no references to {address} found"
        return ctx.cache[key]
    more = out.get("total", len(refs)) - len(refs)
    lines = [f"references to {address}:"]
    lines += [f"- {r['from_function']} at {r.get('at')} ({r.get('kind')})" for r in refs]
    if more > 0:
        lines.append(f"  … and {more} more")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _bfs_subgraph(edges: list, root: str, depth: int) -> list[tuple[str, str]]:
    """Edges reachable from `root` (matched by normalized name) within `depth` hops, deduped."""
    from collections import defaultdict, deque

    from hexgraph.engine.nodes import normalize_symbol_name as _norm

    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for pair in edges:
        if isinstance(pair, (list, tuple)) and len(pair) == 2 and pair[0] and pair[1]:
            adj[_norm(pair[0])].append((pair[0], pair[1]))
    out: list[tuple[str, str]] = []
    seen_edge: set[tuple[str, str]] = set()
    visited = {_norm(root)}
    q = deque([(_norm(root), 0)])
    while q:
        nk, d = q.popleft()
        if d >= depth:
            continue
        for a, b in adj.get(nk, []):
            if (a, b) not in seen_edge:
                seen_edge.add((a, b))
                out.append((a, b))
            bk = _norm(b)
            if bk not in visited:
                visited.add(bk)
                q.append((bk, d + 1))
    return out


def _call_graph_tool(ctx: ToolContext, function: str | None, depth) -> str:
    """The whole-program call graph (or the neighbourhood rooted at `function`). QUERY: records
    a call_graph Observation whose facts SELF-WIRE `calls` edges among already-curated functions
    (both-endpoints-safe); creates no new nodes."""
    key = f"callgraph:{function or '*'}:{depth or ''}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, None, "callgraph")
    if err:
        return err
    edges = out.get("calls") or []
    # Record as a call_graph Observation in the per-caller shape the extractor reads, so the
    # `A calls B` facts wire edges among functions ALREADY promoted (no new nodes). The payload
    # is the whole-program graph regardless of `function` (the root only shapes the returned
    # TEXT), so record under args={} — it dedups to ONE Observation no matter how many rooted
    # views are requested, instead of re-storing the identical graph per root.
    from hexgraph.engine.ghidra import _call_graph_records
    _record_obs(ctx, tool="call_graph", args={},
                result_kind="call_graph", payload={"functions": _call_graph_records(edges)},
                summary=f"{len(edges)} call edges")
    if function:
        d = max(1, min(int(depth or 2), 6))
        sub = _bfs_subgraph(edges, function, d)
        if not sub:
            ctx.cache[key] = f"{function!r} not found in the call graph (or it calls nothing)"
            return ctx.cache[key]
        text = f"call graph from {function} (depth {d}, {len(sub)} edges):\n" + \
               "\n".join(f"- {a} → {b}" for a, b in sub)
        ctx.cache[key] = _clip(text)
        return ctx.cache[key]
    shown = edges[:200]
    note = f"\n  … and {len(edges) - len(shown)} more edges" if len(edges) > len(shown) else ""
    text = f"call graph ({len(edges)} edges):\n" + \
           "\n".join(f"- {p[0]} → {p[1]}" for p in shown if len(p) == 2) + note
    ctx.cache[key] = _clip(text)
    return ctx.cache[key]


def _search_decompiled(ctx: ToolContext, query: str) -> str:
    """Grep already-decompiled function bodies on this target (mines the Observation store —
    no re-decompile). QUERY: records an Observation; adds no graph nodes."""
    from hexgraph.engine import observations as O

    hits = O.search_decompiled(ctx.session, ctx.target.id, query=query)
    _record_obs(ctx, tool="search_decompiled", args={"query": query},
                result_kind="search_decompiled", payload={"query": query, "hits": hits},
                summary=f"{len(hits)} functions matching {query!r}")
    if not hits:
        return (f"no decompiled body contains {query!r}. search_decompiled mines PRIOR "
                "decompilations — decompile_function the candidates first if nothing's been "
                "decompiled yet (it does not decompile on demand).")
    lines = [f"functions whose decompiled body contains {query!r}:"]
    lines += [f"- {h['function']}: …{h['snippet']}…" for h in hits]
    return _clip("\n".join(lines))


def _fuzz(ctx: ToolContext, args: dict) -> str:
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # only reachable when fuzzing is enabled
    import os
    import tempfile

    from hexgraph.engine.fuzzing import resolve_harness
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return "fuzzing unavailable (Docker/sandbox not running)"
    source, _fid, function = resolve_harness(ctx.session, ctx.target, _Stub())
    if not source:
        return "no harness available — run a harness_generation task first"
    budget = max(5, min(int(args.get("max_total_time", 20)), 60))
    crash_dir = tempfile.mkdtemp(prefix="hexgraph-agentfuzz-")
    fd, src = tempfile.mkstemp(suffix=".c")
    with os.fdopen(fd, "w") as fh:
        fh.write(source)
    try:
        res = get_executor().run_json_probe(
            "fuzz_probe.py", src, outdir=crash_dir,
            extra_args=[f"--max-total-time={budget}", "--max-len=4096", "--max-crashes=5"],
            requires_execution=True,
        )
    finally:
        os.unlink(src)
        import shutil
        shutil.rmtree(crash_dir, ignore_errors=True)
    if not res.get("compiled"):
        return f"harness did not compile: {res.get('stderr', '')[:400]}"
    crashes = res.get("crashes", [])
    if not crashes:
        return f"no crashes in {budget}s ({res.get('executions', '?')} execs)"
    return _clip("crashes:\n" + "\n".join(
        f"- {c.get('kind')} in {c.get('function')}: {c.get('summary')}" for c in crashes))


class _Stub:
    """Minimal task-like object for resolve_harness (params/parent only)."""
    params_json: dict = {}
    parent_finding_id = None
