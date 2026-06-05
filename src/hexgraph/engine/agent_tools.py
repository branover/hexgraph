"""Agent tools — what an LLM task can call, each executed by HexGraph in the
sandbox (the model never touches the environment).

The registry is the single source for (a) the tool specs advertised to the model
and (b) executing a requested call. Static tools are read-only and need no policy
change; `fuzz_function` is dynamic and offered only when fuzzing is enabled
(policy-gated). Tools return bounded TEXT; errors come back as text so the model
can recover rather than the task failing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.llm.base import ToolSpec

_MAX = 6000  # cap any single tool result so the context stays bounded


@dataclass
class ToolContext:
    session: Session
    project: Project
    target: Target
    cache: dict = field(default_factory=dict)


# --- specs (advertised to the model) ------------------------------------------

_STATIC_SPECS = [
    ToolSpec("list_functions", "List the function names discovered in the target binary.",
             {"type": "object", "properties": {}}),
    ToolSpec("decompile_function", "Decompile one function to pseudo-C and list its callees. "
             "Use this to read the actual code before judging a vulnerability.",
             {"type": "object", "properties": {"function": {"type": "string"}}, "required": ["function"]}),
    ToolSpec("disassemble", "Disassemble one function (when pseudo-C is unclear).",
             {"type": "object", "properties": {"function": {"type": "string"}}, "required": ["function"]}),
    ToolSpec("xrefs", "Find which functions CALL a given symbol/sink (e.g. system, popen, "
             "strcpy) and where. With no symbol, map the binary's dangerous sinks, format-string "
             "sinks, AND network/socket surface (bind/listen/connect/recv) + who reaches each. Use "
             "to trace a sink back to its caller, or to find listen/connect sites for socket nodes.",
             {"type": "object", "properties": {"symbol": {"type": "string"}}}),
    ToolSpec("read_imports", "Return the target's imported symbols, linked libraries, and mitigation flags.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_strings", "List notable strings in the target, optionally filtered by a substring.",
             {"type": "object", "properties": {"pattern": {"type": "string"}}}),
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


def _decomp(ctx: ToolContext, function: str | None):
    """Run the decompiler (cached per function) and, for a focus, grow the graph."""
    key = f"decomp:{function or '*'}"
    if key in ctx.cache:
        return ctx.cache[key]
    from hexgraph.sandbox.decompiler import get_decompiler
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        ctx.cache[key] = {"error": "decompilation unavailable (Docker/sandbox not running)"}
        return ctx.cache[key]
    try:
        out = get_decompiler().decompile(ctx.target.path, function, project=ctx.project)
    except Exception as exc:  # noqa: BLE001
        out = {"error": f"decompiler failed: {exc}"}
    ctx.cache[key] = out
    if function and isinstance(out, dict) and out.get("focus"):
        _materialize(ctx, out["focus"])
    return out


def _materialize(ctx: ToolContext, focus: dict) -> None:
    """Materialize the decompiled focus function + callees into the graph (so the
    agent's exploration is recorded), mirroring the single-pass path."""
    from hexgraph.db.models import EdgeType
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.nodes import materialize_function

    if not focus.get("name"):
        return
    fnode = materialize_function(ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
                                 name=focus["name"], address=focus.get("address"),
                                 pseudocode=focus.get("pseudocode") or None, created_by="agent")
    for callee in focus.get("callees", []) or []:
        cnode = materialize_function(ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
                                     name=callee, created_by="agent")
        add_edge(ctx.session, project_id=ctx.project.id, src=("node", fnode.id), dst=("node", cnode.id),
                 type=EdgeType.calls, origin="tool", confidence=1.0, created_by_tool="agent")


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
            return _clip("strings:\n" + ("\n".join(str(s) for s in strings[:200]) or "(none)"))
        if name == "list_functions":
            out = _decomp(ctx, None)
            if out.get("error"):
                return out["error"]
            return _clip("functions:\n" + "\n".join(out.get("functions", [])[:300]))
        if name == "disassemble":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            # Always disassemble with radare2 — it gives real instruction listings;
            # the Ghidra decompiler path returns empty disasm (it's a decompiler).
            from hexgraph.sandbox.decompiler import R2Decompiler
            from hexgraph.sandbox.runner import docker_available
            if not docker_available():
                return "disassembly unavailable (Docker/sandbox not running)"
            try:
                out = R2Decompiler().decompile(ctx.target.path, fn)  # defaults to get_executor()
            except Exception as exc:  # noqa: BLE001
                return f"disassembly failed: {exc}"
            focus = (out or {}).get("focus")
            disasm = (focus or {}).get("disasm") if focus else None
            if not disasm:
                return f"function {fn!r} not found / no disassembly (functions: " \
                       f"{', '.join((out or {}).get('functions', [])[:40])})"
            return _clip(f"// {fn} disassembly\n{disasm}")
        if name == "decompile_function":
            fn = args.get("function")
            if not fn:
                return "error: 'function' argument is required"
            out = _decomp(ctx, fn)
            if out.get("error"):
                return out["error"]
            focus = out.get("focus")
            if not focus:
                return f"function {fn!r} not found among: {', '.join(out.get('functions', [])[:40])}"
            addr = f" @ {focus['address']}" if focus.get("address") else ""
            return _clip(f"// {fn}{addr} (callees: {', '.join(focus.get('callees', []) or [])})\n"
                         f"{focus.get('pseudocode', '')}")
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
