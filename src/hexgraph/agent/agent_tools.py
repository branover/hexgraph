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

_MAX = 6000  # default cap on any single tool result so the context stays bounded

# An agent may ask a body-returning tool (decompile/disassemble/search) to inline more than
# the default with `max_chars`. The request is clamped to a sane window — a small floor so a
# fat-fingered tiny value still returns something useful, and a generous ceiling as a
# backstop (get_observation remains the truly-uncapped full-payload path). The default stays
# _MAX, so context stays bounded unless the agent deliberately asks for more.
_MAX_FLOOR = 200
_MAX_CEILING = 100_000

# Shared param description for the body-returning tools (decompile/disassemble/search). Public
# (re-exported as MAX_CHARS_DESC) so the MCP catalog schemas source the SAME copy — one authority,
# no drift between the in-process agent-loop specs and the advertised MCP schemas.
_MAX_CHARS_DESC = ("max chars of the body to inline; default 6000, clamped 200–100000; "
                   "use get_observation for the full payload")
MAX_CHARS_DESC = _MAX_CHARS_DESC

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
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["function"]}),
    ToolSpec("decompile_at", "Decompile the function CONTAINING a hex ADDRESS (e.g. 0x401200) — "
             "analyze-at-address for when you have an address (from xrefs/strings/a crash) but not "
             "a name. PROMOTE: same as decompile_function for the resolved function (adds it, draws "
             "`calls` edges only to callees already in the graph; new callees listed, not auto-added).",
             {"type": "object", "properties": {"address": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["address"]}),
    ToolSpec("disassemble", "Disassemble one function by NAME or by ADDRESS (an address resolves to "
             "the function containing it) — when pseudo-C is unclear. QUERY: records an Observation; "
             "adds no graph nodes.",
             {"type": "object", "properties": {"function": {"type": "string"},
                                               "address": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}}}),
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
             "`function`) the neighbourhood rooted at it out to `depth` (default 2). Returns the "
             "whole-program graph, falling back to the recon-computed graph in the Observation store "
             "when the probe path comes up empty (so you see the structure without promoting functions "
             "one by one). QUERY: records a call_graph Observation and also SELF-WIRES `calls` edges "
             "among functions ALREADY in the graph (creates no new nodes; promote functions to curate "
             "the wired graph).",
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
             {"type": "object", "properties": {"query": {"type": "string"},
                                               "max_chars": {"type": "integer", "description": _MAX_CHARS_DESC}},
              "required": ["query"]}),
    ToolSpec("check_decompiler", "Verify the decompiler decompile_function/disassemble use ACTUALLY "
             "works (not just the configured name): radare2 needs the sandbox image up; Ghidra needs "
             "WITH_GHIDRA=1 (headless) or a reachable bridge. Run it if a decompile fails so you don't "
             "keep retrying a broken backend — the result's detail says what to fix.",
             {"type": "object", "properties": {}}),
    ToolSpec("check_features", "Preflight the features whose runtime dep can diverge from what's "
             "configured (floss, yara, angr, ghidra/emulation): each reports available (its dep/image is "
             "present), BROKEN (the dep/image is missing — the stale-image trap, e.g. floss/yara need a "
             "sandbox rebuild), or disabled (only the gated ones — angr, ghidra — when their gate is off) "
             "with a remediation hint. floss + yara are always-on, so they report availability only. "
             "Lightweight + read-only. Run it before reaching for floss_strings / a yara / a solver tool "
             "so you don't burn turns against a broken feature.",
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

# FLOSS is ALWAYS advertised, like the binutils verb: it relaxes no boundary (it emulates
# decode routines in-process, never executes the target), so it rides the static surface
# ungated. It is slower than a plain strings pass, so the description tells the model to
# check prior Observations first.
_FLOSS_SPEC = ToolSpec(
    "floss_strings", "Recover OBFUSCATED strings a plain strings/list_strings pass MISSES — STACK "
    "strings (built byte-by-byte on the stack at runtime), TIGHT strings, and DECODED strings "
    "(produced by a decode routine FLOSS lightly EMULATES in the sandbox) — via FLARE FLOSS. On "
    "firmware/malware these hidden strings (URLs, command templates, keys, format strings) are "
    "often the lead. QUERY: records a floss_strings Observation; adds NO graph nodes — PROMOTE an "
    "interesting recovered string to a string node deliberately. FLOSS is slow, so check "
    "list_observations(target_id) first. NOTE: stack/decoded recovery supports x86/amd64 PE "
    "targets; on an ELF/foreign-arch artifact it degrades to a static-strings-only pass.",
    {"type": "object", "properties": {"min_length": {"type": "integer",
     "description": "minimum recovered string length (default 4, clamped 4–64)"}}},
)

# YARA is ALWAYS advertised, like the binutils verb: a static MATCH reads bytes and never
# executes the target, so it relaxes no boundary and rides the static surface ungated. Rule
# management is still an operator surface (drop your own .yar files in the rules dir), but
# that no longer gates whether the matcher is offered.
_YARA_SPEC = ToolSpec(
    "yara_scan", "Match THIS target's bytes against YARA rules (the bundled high-signal set + any "
    "user .yar rules) — embedded credentials, known-bad library banners, weak-crypto constants, "
    "packer signatures. The fuzzy/structural complement to the exact-hash n-day link. PROMOTE: "
    "each matched rule becomes a project-level `pattern` node + a `matches_rule` edge from this "
    "target, carrying the rule's DECLARED severity/cve (never a fabricated guess). Records a "
    "yara_matches Observation; check list_observations(target_id) first. `ruleset` (a bundled "
    "ruleset id, or 'all', default 'all') is the only knob — never a yara command line. To sweep "
    "the WHOLE project (every target + extracted firmware file), use the yara_sweep MCP verb.",
    {"type": "object", "properties": {"ruleset": {"type": "string",
     "description": "which bundled ruleset to sweep (a rule-file id, or 'all'; default 'all')"}}},
)


# angr solving is advertised ONLY when features.angr is enabled (like floss/yara): it is opt-in
# heavy compute (symbolic execution), so it stays out of the model's tool list until enabled.
_SOLVE_INPUT_SPEC = ToolSpec(
    "solve_reaching_input", "SOLVE for a concrete input that DRIVES execution to a sink (e.g. "
    "system/execve), via angr symbolic execution in the sandbox — the strongest STATIC claim "
    "short of a live PoC, because it produces a concrete reaching input. PROMOTE: on success this "
    "promotes the grounded path (the sink + the enclosing function + a `calls` edge) and emits a "
    "high-confidence `vulnerability` finding whose evidence.reproducer is the solved input (hex), "
    "assurance input_reachable/static. `sink_func` (the dangerous callee to reach, e.g. 'system') "
    "is the main knob; optionally `function` (the enclosing routine) and `budget` (quick|default|"
    "deep). angr is HEAVY + slow and the input is SOLVED (often non-ASCII bytes a guess can't hit) "
    "— check list_observations(target_id, kind='solver') first to reuse a prior solve. Returns "
    "None/unsolved cleanly when no reaching input exists within the budget (nothing fabricated).",
    {"type": "object", "properties": {
        "sink_func": {"type": "string", "description": "the dangerous callee to reach (e.g. 'system')"},
        "function": {"type": "string", "description": "the enclosing function to explore from (optional)"},
        "budget": {"type": "string", "description": "coarse resource tier: quick|default|deep"}},
     "required": ["sink_func"]},
)
_SOLVE_CONSTRAINT_SPEC = ToolSpec(
    "solve_constraint", "Recover a VALUE/input that SATISFIES a single check (e.g. the secret a "
    "strcmp compares against, or a serial a gate validates) via angr — the symbolic analogue of "
    "recover_constant. ENRICH: on success annotates the function node with the recovered value "
    "(attrs.recovered_value / satisfying_input_hex) and records a `solver` Observation; adds no new "
    "graph nodes. Single-check solving ONLY (not whole-program exploration). `function` names the "
    "routine; optionally `check_addr` pins the pass block, or `sink_func` when the check gates a "
    "sink; `budget` is quick|default|deep. Opt-in (features.angr); slow — check list_observations first.",
    {"type": "object", "properties": {
        "function": {"type": "string", "description": "the routine containing the check"},
        "check_addr": {"type": "string", "description": "hex address of the pass/success block (optional)"},
        "sink_func": {"type": "string", "description": "a sink the check gates, if the pass block is unknown (optional)"},
        "budget": {"type": "string", "description": "coarse resource tier: quick|default|deep"}}},
)


def available_tools(ctx: ToolContext) -> list[ToolSpec]:
    """Tool specs for this target. FLOSS + YARA are ALWAYS offered (always-on static tools,
    like binutils — they relax no boundary); fuzz_function only when the policy permits
    execution (fuzzing enabled in Settings); the solve_* verbs only when features.angr is."""
    specs = [*_STATIC_SPECS, _FLOSS_SPEC, _YARA_SPEC]
    try:
        from hexgraph.policy import current_policy

        if current_policy().allow_execution:
            specs.append(_FUZZ_SPEC)
    except Exception:  # noqa: BLE001
        pass
    try:
        from hexgraph.engine.re.solver import solver_enabled

        if solver_enabled():
            specs.append(_SOLVE_INPUT_SPEC)
            specs.append(_SOLVE_CONSTRAINT_SPEC)
    except Exception:  # noqa: BLE001
        pass
    return specs


# --- execution ----------------------------------------------------------------

def _clip(s: str) -> str:
    s = s or ""
    return s if len(s) <= _MAX else s[:_MAX] + "\n…[truncated]"


def _effective_limit(max_chars) -> int:
    """The body inline-limit for a body-returning tool: the agent's `max_chars` clamped to
    [_MAX_FLOOR, _MAX_CEILING], defaulting to _MAX. A bad/missing value falls back to _MAX."""
    try:
        if max_chars is None:
            return _MAX
        return max(_MAX_FLOOR, min(int(max_chars), _MAX_CEILING))
    except (TypeError, ValueError):
        return _MAX


def _clip_body(s: str, *, limit: int, obs_id: str | None) -> str:
    """Truncate a body-returning tool's text to `limit` chars, but instead of the bare
    `…[truncated]` marker emit an ACTIONABLE one that names BOTH recovery paths and the sizes:
    re-call with a larger max_chars, or get_observation(<id>) for the full body. The full body
    is always in the Observation, so a head-truncation can never silently hide a tail sink."""
    s = s or ""
    if len(s) <= limit:
        return s
    full = len(s)
    # Name BOTH tool forms — the in-process agent loop has `get_observation`, the MCP surface
    # advertises `obs_get`; both return the full body uncapped. Suggest a larger max_chars only
    # when it can actually reach the full size (it clamps at _MAX_CEILING); past that, the
    # observation tool is the only way to the full body.
    obs = f"get_observation/obs_get('{obs_id}')" if obs_id else None
    if full <= _MAX_CEILING:
        knob = f"re-call with max_chars\u2265{full}"
        tail = f"{knob}, or {obs} for the full body" if obs else f"{knob} for the full body"
    else:
        tail = f"{obs} for the full body" if obs else "the full body is in the Observation store"
    return s[:limit] + f"\n\u2026[truncated {limit}/{full} chars — {tail}]"


def _callee_names(callees) -> list[str]:
    """Callee names from the decompiler's callee list (entries are bare names or dicts)."""
    out = []
    for c in callees or []:
        n = c.get("name") if isinstance(c, dict) else c
        if n:
            out.append(n)
    return out


def _format_decomp(out: dict, label: str, *, limit: int = _MAX) -> str:
    """Render a focused decompile (decompile_function / decompile_at) result as text:
    the resolved name+address, callees, pseudocode, and any not-yet-promoted callees.

    Truncates the body to `limit` chars with the ACTIONABLE marker (recovery knobs + sizes)
    rather than a bare `…[truncated]`, so a head-truncation can't silently hide a tail sink —
    the marker names both the max_chars re-call and the get_observation full-body path."""
    focus = out.get("focus")
    if not focus:
        defined = out.get("functions", []) or []
        # "defined functions" (not "imports") — the list is the decompiler's DEFINED set, which
        # for a stripped binary or a Ghidra/r2 inventory mismatch may not include the requested
        # focus even though it exists. If the label is a function-NAME miss, point at the
        # address-based path (decompile_at resolves the function CONTAINING a hex address from
        # xrefs/strings, and r2 backs Ghidra when their inventories disagree).
        hint = ("" if label.startswith("address ")
                else " — if you have its address, try re_decompile_at(<addr>)")
        return (f"{label} not found among the {len(defined)} defined functions"
                + (f": {', '.join(defined[:40])}" if defined else "") + hint)
    addr = f" @ {focus['address']}" if focus.get("address") else ""
    name = focus.get("name") or label
    promo = out.get("promotable_callees") or []
    note = ""
    if promo:
        # New callees were NOT added to the graph (no fan-out). Surface them for
        # deliberate promotion — decompile_function one of these to promote it.
        note = ("\n// callees not yet in the graph (promote any by decompiling it): "
                + ", ".join(promo))
    return _clip_body(
        f"// {name}{addr} (callees: {', '.join(_callee_names(focus.get('callees')))})\n"
        f"{focus.get('pseudocode', '')}{note}",
        limit=limit, obs_id=out.get("observation_id"))


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
    from hexgraph.engine.graph.nodes import normalize_symbol_name

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
        # Store a FOCUS-ONLY payload: the decompilation Observation is about THIS one function,
        # but the Ghidra decompiler dict also carries the whole-program `calls` (≤2000) and
        # `structs` (≤200) used by enriched recon — ~33 KB of unrelated noise on every obs_get
        # of a per-function decompile. The decompilation extractor (_extract_functions) and
        # search_decompiled read only `focus` (whole-program calls/structs are enriched from
        # SEPARATE call_graph/structs Observations recorded by enrich_recon), so dropping them
        # here loses nothing — the focus's own callees stay inside `focus`.
        decomp_payload = {"functions": out.get("functions", []), "focus": focus}
        obs, _cached = _record_obs(
            ctx, tool=req_tool, args=req_args,
            result_kind="decompilation", payload=decomp_payload,
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
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.graph.nodes import materialize_function

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
        if name == "floss_strings":
            return _floss(ctx, args)
        if name == "yara_scan":
            return _yara(ctx, args)
        if name == "solve_reaching_input":
            return _solve_input(ctx, args)
        if name == "solve_constraint":
            return _solve_constraint(ctx, args)
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
            # Record the disassembly as a QUERY observation (no graph mutation). Capture the
            # obs id so a truncation marker can point the agent at the full body.
            obs, _cached = _record_obs(ctx, tool="disassemble", args=obs_args,
                                       result_kind="disassembly",
                                       payload={"function": focus.get("name") or subj,
                                                "address": focus.get("address"), "disasm": disasm},
                                       summary=f"disassembled {focus.get('name') or subj}")
            return _clip_body(f"// {focus.get('name') or subj}{at} disassembly\n{disasm}",
                              limit=_effective_limit(args.get("max_chars")),
                              obs_id=obs.id if obs is not None else None)
        if name == "decompile_function":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            out = _decomp(ctx, fn)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"function {fn!r}",
                                  limit=_effective_limit(args.get("max_chars")))
        if name == "decompile_at":
            addr = args.get("address")
            if not addr:
                return "error: 'address' argument is required"
            # Decompile (and PROMOTE) the function CONTAINING this address — analyze-at-address
            # for when you have an address (from xrefs/strings) but not a function name.
            out = _decomp(ctx, None, address=addr)
            if out.get("error"):
                return out["error"]
            return _format_decomp(out, f"address {addr}",
                                  limit=_effective_limit(args.get("max_chars")))
        if name == "reanalyze":
            # Raise the analysis depth and bust the cache so a function/edge the fast pass
            # missed gets a retry. QUERY: re-runs the inventory, mutates no graph.
            out = _decomp(ctx, None, reanalyze=True)
            if out.get("error"):
                return out["error"]
            fns = out.get("functions", [])
            return _clip(f"re-analyzed ({len(fns)} functions):\n" + "\n".join(fns[:300]))
        if name == "check_decompiler":
            from hexgraph.agent.mcp_tools import check_decompiler
            d = check_decompiler()
            ver = f" {d['version']}" if d.get("version") else ""
            mode = f" ({d['mode']})" if d.get("mode") else ""
            status = "WORKING" if d["working"] else "NOT WORKING"
            return _clip(f"decompiler: {d['active']}{ver}{mode} — {status}\n{d['detail']}")
        if name == "check_features":
            from hexgraph.agent.mcp_tools import check_features
            d = check_features()
            lines = [d["summary"]]
            for r in d["features"]:
                line = f"  {r['feature']}: {r['state'].upper()} — {r['detail']}"
                if r.get("remediation"):
                    line += f"  [fix: {r['remediation']}]"
                lines.append(line)
            return _clip("\n".join(lines))
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
            return _search_decompiled(ctx, q, limit=_effective_limit(args.get("max_chars")))
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
        # get_observation is the FULL-body channel (the truncation marker points here),
        # so it must NOT re-clip — return the complete payload uncapped, matching MCP obs_get.
        return _json.dumps(out, default=str) if out else f"observation {oid!r} not found"
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
    from hexgraph.engine.re.binutils import collect_binutils_facts

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


def _floss(ctx: ToolContext, args: dict) -> str:
    """Run the FLOSS deobfuscation probe (the engine helper records the Observation) and
    render the recovered hidden strings as text. QUERY: mutates no graph — the agent
    promotes interesting strings deliberately. Always-on static tool; returns a clean
    error only when the sandbox is down or the artifact isn't analyzable."""
    raw_len = args.get("min_length")
    min_length = None
    if raw_len is not None:
        try:
            min_length = int(raw_len)
        except (TypeError, ValueError):
            return "error: 'min_length' must be an integer"
    from hexgraph.engine.re.floss import collect_floss_strings, effective_min_length

    key = f"floss:{effective_min_length(min_length)}"
    if key in ctx.cache:
        return ctx.cache[key]

    out = collect_floss_strings(ctx.session, ctx.project, ctx.target,
                                min_length=min_length, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {}) or {}
    c = f.get("counts", {}) or {}

    def _vals(rows, n):
        return [r.get("string") for r in (rows or [])[:n] if isinstance(r, dict) and r.get("string")]

    lines = [
        f"// FLOSS strings for {ctx.target.name}" + (" (cached)" if out.get("cached") else ""),
        f"counts: stack={c.get('stack_strings', 0)} tight={c.get('tight_strings', 0)} "
        f"decoded={c.get('decoded_strings', 0)} static={c.get('static_strings', 0)}",
    ]
    if f.get("degraded"):
        lines.append(f"NOTE: {f.get('note') or 'degraded (static-only)'}")
    stack = _vals(f.get("stack_strings"), 80)
    tight = _vals(f.get("tight_strings"), 80)
    decoded = _vals(f.get("decoded_strings"), 80)
    if stack:
        lines.append("stack strings: " + ", ".join(repr(s) for s in stack))
    if tight:
        lines.append("tight strings: " + ", ".join(repr(s) for s in tight))
    if decoded:
        lines.append("decoded strings: " + ", ".join(repr(s) for s in decoded))
    if not (stack or tight or decoded):
        lines.append("(no obfuscated strings recovered; see static_strings in the Observation)")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _yara(ctx: ToolContext, args: dict) -> str:
    """Run the YARA matcher over THIS target (the engine helper records the Observation and
    promotes matched rules to pattern nodes + matches_rule edges) and render the matches as
    text. Always-on static tool; returns a clean error only when the sandbox is down, the
    artifact isn't readable, or the ruleset id is unknown."""
    ruleset = args.get("ruleset")
    if ruleset is not None and not isinstance(ruleset, str):
        return "error: 'ruleset' must be a string (a bundled ruleset id, or 'all')"
    from hexgraph.engine.re.yara import scan_target

    key = f"yara:{ruleset or 'all'}"
    if key in ctx.cache:
        return ctx.cache[key]

    out = scan_target(ctx.session, ctx.project, ctx.target, ruleset=ruleset, source="agent")
    if out.get("error"):
        return out["error"]
    f = out.get("facts", {}) or {}
    matches = f.get("matches") or []
    promoted = out.get("promoted") or []
    lines = [
        f"// YARA matches for {ctx.target.name} [ruleset={out.get('ruleset')}]"
        + (" (cached)" if out.get("cached") else ""),
        f"{len(matches)} rule match(es) over {f.get('rule_file_count', 0)} rule file(s); "
        f"promoted {len(promoted)} pattern node(s) (matches_rule edges).",
    ]
    for m in matches[:40]:
        meta = m.get("meta") or {}
        sev = meta.get("severity")
        cve = meta.get("cve")
        tag = f" [severity={sev}]" if sev else ""
        tag += f" [{cve}]" if cve else ""
        desc = meta.get("description")
        lines.append(f"- {m.get('rule')}{tag}" + (f": {desc}" if desc else ""))
    if not matches:
        lines.append("(no rule matched; see the yara_matches Observation for the rule files swept)")
    ctx.cache[key] = _clip("\n".join(lines))
    return ctx.cache[key]


def _solve_input(ctx: ToolContext, args: dict) -> str:
    """angr-solve for an input reaching a sink (the engine records the Observation, promotes the
    grounded path, and emits the vulnerability finding) and render it as text. Opt-in: refuses
    cleanly if features.angr is off."""
    sink_func = args.get("sink_func")
    if not sink_func or not isinstance(sink_func, str):
        return "error: 'sink_func' (the dangerous callee to reach, e.g. 'system') is required"
    function = args.get("function") if isinstance(args.get("function"), str) else None
    budget = args.get("budget") if isinstance(args.get("budget"), str) else None
    from hexgraph.engine.re.solving import solve_reaching_input

    out = solve_reaching_input(ctx.session, ctx.project, ctx.target,
                               sink_func=sink_func, function=function, budget=budget,
                               source="agent")
    if out.get("error"):
        return out["error"]
    if not out.get("solved"):
        return (f"// angr: no input reaching {sink_func!r} on {ctx.target.name} within the budget "
                f"(unreachable/unsatisfiable, or a step/time/state cap was hit). "
                f"{out.get('reason', '')}")
    return _clip("\n".join([
        f"// angr solved a reaching input for {sink_func!r} on {ctx.target.name}"
        + (" (cached)" if out.get("cached") else ""),
        f"reaching input (hex): {out.get('concrete_input')}",
        f"reaching input (repr): {out.get('concrete_input_repr')}",
        f"emitted vulnerability finding: {out.get('finding_id')} "
        f"(assurance input_reachable/static; the input is the reproducer).",
        f"path basic blocks: {', '.join((out.get('path_addrs') or [])[:12])}",
    ]))


def _solve_constraint(ctx: ToolContext, args: dict) -> str:
    """angr-solve for a value satisfying a check (annotates the function node) and render it as
    text. Opt-in: refuses cleanly if features.angr is off."""
    function = args.get("function") if isinstance(args.get("function"), str) else None
    check_addr = args.get("check_addr") if isinstance(args.get("check_addr"), str) else None
    sink_func = args.get("sink_func") if isinstance(args.get("sink_func"), str) else None
    budget = args.get("budget") if isinstance(args.get("budget"), str) else None
    if not (function or check_addr or sink_func):
        return "error: a check selector is required ('function', 'check_addr', or 'sink_func')"
    from hexgraph.engine.re.solving import solve_constraint

    out = solve_constraint(ctx.session, ctx.project, ctx.target, function=function,
                           check_addr=check_addr, sink_func=sink_func, budget=budget, source="agent")
    if out.get("error"):
        return out["error"]
    if not out.get("solved"):
        return (f"// angr: no satisfying value for {function or check_addr or sink_func} within "
                f"the budget. {out.get('reason', '')}")
    lines = [f"// angr recovered a satisfying value/input on {ctx.target.name}"
             + (" (cached)" if out.get("cached") else "")]
    if out.get("recovered_value") is not None:
        lines.append(f"recovered value: {out.get('recovered_value')} ({out.get('recovered_value_hex')})")
    if out.get("satisfying_input"):
        lines.append(f"satisfying input (hex): {out.get('satisfying_input')}")
    if function:
        lines.append(f"annotated function node {out.get('function_node_id')} "
                     f"(attrs.recovered_value / satisfying_input_hex).")
    return _clip("\n".join(lines))


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


def _recon_function_xrefs(ctx: ToolContext, function: str) -> tuple[list[str], list[str]]:
    """Callers and callees of `function` derived from the program call graph recon already in
    the Observation substrate (the same source `_call_graph_tool` falls back to). Matches by
    NORMALIZED function name (decompiler prefixes stripped) so `sym.foo`/`fcn.foo`/`foo` resolve
    to one identity. Returns `(caller_names, callee_names)`; read-only, promotes nothing."""
    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

    key = _norm(function)
    callers: list[str] = []
    callees: list[str] = []
    for caller, callee in _recon_call_graph_edges(ctx):
        if _norm(callee) == key and caller not in callers:
            callers.append(caller)
        if _norm(caller) == key and callee not in callees:
            callees.append(callee)
    return callers, callees


def _function_xrefs(ctx: ToolContext, function: str) -> str:
    """Callers AND callees of one function (the bidirectional neighbourhood). QUERY.

    Falls back to the program call graph recon in the Observation substrate when the r2 xrefs
    probe errors or comes up empty in BOTH directions — Ghidra's `enrich_recon` may have mapped
    the graph the r2 probe missed (the same fallback `call_graph` uses), so the neighbourhood
    isn't a false `(none)/(none)`."""
    key = f"fxrefs:{function}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, function, "function")
    callers = (out.get("callers") or []) if (not err and not out.get("error")) else []
    callees = (out.get("callees") or []) if (not err and not out.get("error")) else []
    source_note = ""
    if not callers and not callees:
        # The probe errored, the function wasn't in r2's inventory, or it found nothing both
        # ways — surface the recon-substrate neighbourhood instead of a false empty.
        r_callers, r_callees = _recon_function_xrefs(ctx, function)
        if r_callers or r_callees:
            callers = [{"caller": c} for c in r_callers]
            callees = [{"name": c} for c in r_callees]
            out = {"callers": callers, "callees": callees,
                   "total_callers": len(callers), "total_callees": len(callees)}
            source_note = " (from recon substrate)"
        elif err:
            return err
        elif (out or {}).get("error"):
            return f"function {function!r} not found"
    _record_obs(ctx, tool="function_xrefs", args={"function": function},
                result_kind="function_xrefs", payload=out,
                summary=f"{function}: {len(callers)} callers, {len(callees)} callees")
    lines = [f"// {function}: callers (who calls it) and callees (what it calls){source_note}",
             "callers:"]
    lines += [f"- {c['caller']}"
              + (f" (@ {c['caller_addr']})" if c.get("caller_addr") else "")
              + (f" at {c['at']}" if c.get("at") else "") for c in callers] or ["  (none)"]
    more_c = out.get("total_callers", len(callers)) - len(callers)
    if more_c > 0:
        lines.append(f"  … and {more_c} more callers")
    lines.append("callees:")
    lines += [f"- {c.get('name')}"
              + (f" (@ {c['addr']})" if c.get("addr") else "") for c in callees] or ["  (none)"]
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

    from hexgraph.engine.graph.nodes import normalize_symbol_name as _norm

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


def _recon_call_graph_edges(ctx: ToolContext) -> list:
    """The program call graph recon already computed, read back from the Observation
    substrate. Ghidra's `enrich_recon` records the whole-program graph as a `call_graph`
    Observation (`{"functions": [{"name", "callees": [...]}]}`); the radare2 xrefs probe used
    by the QUERY path can come up empty on a binary recon already mapped richly, so this is the
    fallback so the breadth-first 'see the structure' use case isn't blank. Returns `[caller,
    callee]` pairs (read-only; promotes nothing)."""
    from hexgraph.engine import observations as O

    rows = O.list_observations(ctx.session, ctx.target.id, tool="enrich_recon", kind="call_graph")
    if not rows:
        return []
    full = O.get_observation(ctx.session, rows[0]["id"]) or {}
    edges = []
    for rec in (full.get("payload") or {}).get("functions", []) or []:
        caller = rec.get("name")
        for callee in rec.get("callees", []) or []:
            if caller and callee:
                edges.append([caller, callee])
    return edges


def _call_graph_tool(ctx: ToolContext, function: str | None, depth) -> str:
    """The whole-program call graph (or the neighbourhood rooted at `function`). QUERY: records
    a call_graph Observation whose facts SELF-WIRE `calls` edges among already-curated functions
    (both-endpoints-safe); creates no new nodes. Falls back to the recon-computed graph in the
    Observation substrate when the probe path comes up empty."""
    key = f"callgraph:{function or '*'}:{depth or ''}"
    if key in ctx.cache:
        return ctx.cache[key]
    out, err = _run_xrefs_probe(ctx, None, "callgraph")
    edges = (out.get("calls") or []) if not err else []
    source_note = ""
    if not edges:
        # The probe found nothing (radare2 missed the graph, or Docker is down). Surface the
        # program graph recon already computed into the substrate, so breadth-first structure
        # exploration isn't blank until functions are promoted one by one.
        recon_edges = _recon_call_graph_edges(ctx)
        if recon_edges:
            edges = recon_edges
            source_note = " (from recon substrate — promote functions to curate the wired graph)"
        elif err:
            return err
    # Record as a call_graph Observation in the per-caller shape the extractor reads, so the
    # `A calls B` facts wire edges among functions ALREADY promoted (no new nodes). The payload
    # is the whole-program graph regardless of `function` (the root only shapes the returned
    # TEXT), so record under args={} — it dedups to ONE Observation no matter how many rooted
    # views are requested, instead of re-storing the identical graph per root.
    from hexgraph.engine.re.ghidra import _call_graph_records
    _record_obs(ctx, tool="call_graph", args={},
                result_kind="call_graph", payload={"functions": _call_graph_records(edges)},
                summary=f"{len(edges)} call edges")
    if function:
        d = max(1, min(int(depth or 2), 6))
        sub = _bfs_subgraph(edges, function, d)
        if not sub:
            ctx.cache[key] = f"{function!r} not found in the call graph (or it calls nothing)"
            return ctx.cache[key]
        text = f"call graph from {function} (depth {d}, {len(sub)} edges){source_note}:\n" + \
               "\n".join(f"- {a} → {b}" for a, b in sub)
        ctx.cache[key] = _clip(text)
        return ctx.cache[key]
    shown = edges[:200]
    note = f"\n  … and {len(edges) - len(shown)} more edges" if len(edges) > len(shown) else ""
    text = f"call graph ({len(edges)} edges){source_note}:\n" + \
           "\n".join(f"- {p[0]} → {p[1]}" for p in shown if len(p) == 2) + note
    ctx.cache[key] = _clip(text)
    return ctx.cache[key]


def _search_decompiled(ctx: ToolContext, query: str, *, limit: int = _MAX) -> str:
    """Grep already-decompiled function bodies on this target (mines the Observation store —
    no re-decompile). QUERY: records an Observation; adds no graph nodes. Truncates to `limit`
    chars with the actionable marker (the recorded Observation holds the full hit list)."""
    from hexgraph.engine import observations as O

    hits = O.search_decompiled(ctx.session, ctx.target.id, query=query)
    obs, _cached = _record_obs(ctx, tool="search_decompiled", args={"query": query},
                               result_kind="search_decompiled",
                               payload={"query": query, "hits": hits},
                               summary=f"{len(hits)} functions matching {query!r}")
    if not hits:
        return (f"no decompiled body contains {query!r}. search_decompiled mines PRIOR "
                "decompilations — decompile_function the candidates first if nothing's been "
                "decompiled yet (it does not decompile on demand).")
    lines = [f"functions whose decompiled body contains {query!r}:"]
    lines += [f"- {h['function']}: …{h['snippet']}…" for h in hits]
    return _clip_body("\n".join(lines), limit=limit,
                      obs_id=obs.id if obs is not None else None)


def _fuzz(ctx: ToolContext, args: dict) -> str:
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # only reachable when fuzzing is enabled
    import os
    import tempfile

    from hexgraph.engine.fuzz.fuzzing import resolve_harness
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
