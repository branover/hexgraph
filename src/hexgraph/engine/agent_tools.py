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
    ToolSpec("read_imports", "Return the target's imported symbols, linked libraries, and mitigation flags.",
             {"type": "object", "properties": {}}),
    ToolSpec("list_strings", "List notable strings in the target, optionally filtered by a substring.",
             {"type": "object", "properties": {"pattern": {"type": "string"}}}),
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
        out = get_decompiler().decompile(ctx.target.path, function)
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
            return _clip("strings:\n" + "\n".join(str(s) for s in strings[:200]) or "(none)")
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
        if name == "fuzz_function":
            return _fuzz(ctx, args)
        return f"error: unknown tool {name!r}"
    except Exception as exc:  # noqa: BLE001 — tools never crash the task
        return f"error running {name}: {exc}"


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
