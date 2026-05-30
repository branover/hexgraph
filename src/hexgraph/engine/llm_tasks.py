"""Execute LLM-backed tasks behind the backend seam (SPEC §5, §6).

`static_analysis`, `reverse_engineering`, `pattern_sweep`, `harness_generation`
all flow through here: gather deterministic facts from the target's recon
metadata (and, for static analysis, decompilation in M3-T5), build a prompt,
ask the selected `LLMBackend` to reason, and persist the resulting findings.

**Backend-agnostic by construction**: this code never branches on which backend
it is — it calls `run_findings(get_backend(...))`. The mock returns canned,
schema-valid findings; real backends return live ones; the path is identical.
Findings' `related_target_refs` become `related_to` edges and
`suggested_followups` are stored for one-click spawning (M4).
"""

from __future__ import annotations

import os

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Project, Target, TargetKind, Task, TaskStatus
from hexgraph.engine.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.nodes import materialize_function
from hexgraph.engine.recon import RISKY_SINKS
from hexgraph.engine.refs import pick_sibling, resolve_target_ref
from hexgraph.engine.tasks import write_trace
from hexgraph.llm.registry import get_backend
from hexgraph.llm.runner import run_findings
from hexgraph.tasks.base import TaskContext

LLM_TASK_TYPES = {"static_analysis", "reverse_engineering", "pattern_sweep", "harness_generation"}
_DECOMPILE_TYPES = {"static_analysis", "reverse_engineering"}
_DECOMPILABLE_KINDS = {TargetKind.executable, TargetKind.shared_library}


def _gather_decompilation(target: Target, ctx: TaskContext) -> dict | None:
    """Best-effort decompilation to enrich the prompt (real backends use it; the
    mock ignores it). Gated on the environment — never on the backend identity —
    so the backend seam stays clean. Silently skipped if the sandbox is absent."""
    if os.environ.get("HEXGRAPH_DISABLE_DECOMPILE") == "1":
        return None
    if ctx.task_type not in _DECOMPILE_TYPES or target.kind not in _DECOMPILABLE_KINDS:
        return None
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None
    try:
        from hexgraph.sandbox.decompiler import get_decompiler

        return get_decompiler().decompile(target.path, ctx.function)
    except Exception:  # noqa: BLE001 — decompilation is best-effort enrichment
        return None


def _build_prompt(target: Target, ctx: TaskContext, decomp: dict | None = None) -> str:
    """A deterministic prompt from recon facts + decompilation. The mock ignores
    it; real backends reason over it. The LLM only ever sees tool output here,
    never raw target bytes."""
    meta = target.metadata_json or {}
    lines = [
        f"Target: {target.name} ({target.format} {target.arch}, {target.kind.value})",
        f"Imports: {', '.join(meta.get('imports', [])[:30])}",
        f"Mitigations: {meta.get('mitigations', {})}",
    ]
    if ctx.objective:
        lines.append(f"Objective: {ctx.objective}")
    if ctx.function:
        lines.append(f"Focus function: {ctx.function}")
    if decomp:
        focus = decomp.get("focus")
        if focus and focus.get("pseudocode"):
            lines.append(f"Decompiled {focus['name']}:\n{focus['pseudocode']}")
        elif decomp.get("functions"):
            lines.append(f"Functions: {', '.join(decomp['functions'][:40])}")
    lines.append(
        f"Emit findings as JSON ({ctx.task_type}). Each finding must match the HexGraph finding schema."
    )
    return "\n".join(lines)


def _build_context(session: Session, project: Project, target: Target, task: Task) -> TaskContext:
    params = task.params_json or {}
    meta = target.metadata_json or {}
    risky = sorted(set(meta.get("imports", [])) & RISKY_SINKS)

    sibling = pick_sibling(session, project.id, target)
    return TaskContext(
        task_id=task.id,
        task_type=task.type,
        project_id=project.id,
        target_id=target.id,
        target_name=target.name,
        objective=task.objective_text,
        function=params.get("function"),
        sink=params.get("sink") or (risky[0] if risky else None),
        sibling_target_id=sibling.id if sibling else None,
        sibling_name=sibling.name if sibling else None,
        target_format=target.format,
        arch=target.arch,
        model=task.model,
        mock_scenario=params.get("mock_scenario"),
    )


def _compile_harnesses(findings) -> None:
    """For harness_generation findings, actually build the emitted source in the
    sandbox and record the real result. Best-effort + env/docker-gated."""
    if os.environ.get("HEXGRAPH_DISABLE_SANDBOX_BUILD") == "1":
        return
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return
    from hexgraph.engine.harness import compile_harness_source

    for finding in findings:
        source = finding.evidence.decompiled_snippet
        if not source:
            continue
        try:
            build = compile_harness_source(source)
        except Exception:  # noqa: BLE001 — best-effort enrichment
            continue
        extra = dict(finding.evidence.extra or {})
        extra["build"] = build
        finding.evidence.extra = extra


def _materialize_decomp_graph(session: Session, project_id: str, target_id: str, decomp: dict) -> None:
    """Turn decompilation into graph: a function node for the focus + its callees,
    joined by `calls` edges (design §3.2 lazy materialization, §3.3 `calls`)."""
    focus = decomp.get("focus")
    if not focus or not focus.get("name"):
        return
    fnode = materialize_function(
        session, project_id=project_id, target_id=target_id, name=focus["name"],
        pseudocode=focus.get("pseudocode") or None, created_by="decompile",
    )
    for callee in focus.get("callees", []):
        cnode = materialize_function(
            session, project_id=project_id, target_id=target_id, name=callee, created_by="decompile",
        )
        add_edge(
            session, project_id=project_id,
            src=("node", fnode.id), dst=("node", cnode.id),
            type=EdgeType.calls, origin="tool", confidence=1.0, created_by_tool="radare2",
        )


def execute_llm_task(session: Session, project: Project, target: Target, task: Task) -> int:
    """Run an LLM-backed task to findings. Returns the number of findings emitted.

    Sets the task status to needs_triage if any finding has low confidence.
    """
    ctx = _build_context(session, project, target, task)
    decomp = _gather_decompilation(target, ctx)
    if decomp:
        ctx.tool_outputs["decompilation"] = decomp
        _materialize_decomp_graph(session, project.id, target.id, decomp)

    # Assemble the content bundle (the frozen, content-addressed input).
    from hexgraph.engine.context import build_context_bundle, estimate_tokens
    from hexgraph.llm.cassette import maybe_wrap_cassette
    from hexgraph.llm.prompting import system_prompt

    bundle = build_context_bundle(session, project, target, task, ctx)
    task.context_bundle_id = bundle.row.id

    backend = get_backend(task.backend if task.backend not in (None, "none") else None)
    backend = maybe_wrap_cassette(backend, project)
    req = ctx.build_request(prompt=bundle.prompt)
    req.cache_key = bundle.row.bundle_sha

    findings, usage = run_findings(backend, req)

    if task.type == "harness_generation":
        _compile_harnesses(findings)

    # Metering seam: log usage per task (BYOK = user's own spend; the hook a future
    # credits sink uses). No-op-ish locally.
    from hexgraph.metering import record_usage

    record_usage(f"task.{task.type}", usage, task_id=task.id)

    write_trace(task, "prompt.txt", bundle.prompt)
    write_trace(task, "system.txt", system_prompt(task.type))
    write_trace(task, "bundle.json", {
        "bundle_sha": bundle.row.bundle_sha, "token_estimate": bundle.row.token_estimate,
        "token_budget": bundle.row.token_budget, "dropped": [d.kind for d in bundle.dropped],
        "items": [{"kind": it.kind, "est_tokens": estimate_tokens(it.text)} for it in bundle.included],
    })
    write_trace(task, "response.json", {
        "findings": [f.to_payload() for f in findings],
        "usage": {"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
                  "cost_source": usage.cost_source, "cost_usd": usage.cost_usd},
    })
    write_trace(task, "usage.json", {
        "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
        "cost_source": usage.cost_source, "cost_usd": usage.cost_usd,
    })
    task.cost_estimate = usage.cost_usd
    task.backend = backend.name

    low_confidence = False
    for finding in findings:
        resolved_refs = [
            r for r in (resolve_target_ref(session, project.id, ref) for ref in finding.related_target_refs or [])
            if r is not None and r.id != target.id
        ]
        # pattern_sweep reports a sibling's issue: home the finding ON that sibling
        # (the graph payoff), while still drawing the seed -> sibling related_to edge.
        home = resolved_refs[0] if (task.type == "pattern_sweep" and resolved_refs) else target
        row = persist_finding(
            session,
            project_id=project.id,
            target_id=home.id,
            task_id=task.id,
            finding=finding,
        )
        if finding.confidence == "low":
            low_confidence = True
        edge_type = EdgeType.instance_of_pattern if task.type == "pattern_sweep" else EdgeType.related_to
        for dst in resolved_refs:
            add_edge(
                session, project_id=project.id,
                src=("target", target.id), dst=("target", dst.id),
                type=edge_type, origin="llm", confidence=finding.confidence,
                created_by_task_id=task.id,
                attrs={"finding_id": row.id, "matched_from_finding_id": row.id},
            )

    if findings and low_confidence:
        task.status = TaskStatus.needs_triage

    # Group this execution as an analysis_run for run-to-run comparison.
    from hexgraph.engine.runs import record_run

    record_run(
        session, project_id=project.id, anchor_kind="target", anchor_id=target.id,
        task=task, bundle_sha=bundle.row.bundle_sha, finding_count=len(findings),
    )
    return len(findings)
