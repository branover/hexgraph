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

from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, EdgeType, FindingStatus, Project, Target, Task, TaskStatus
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.recon import RISKY_SINKS
from hexgraph.engine.tasks import write_trace
from hexgraph.llm.registry import get_backend
from hexgraph.llm.runner import run_findings
from hexgraph.tasks.base import TaskContext

LLM_TASK_TYPES = {"static_analysis", "reverse_engineering", "pattern_sweep", "harness_generation"}


def _build_prompt(target: Target, ctx: TaskContext) -> str:
    """A deterministic prompt from recon facts. The mock ignores it; real
    backends use it. Decompiled pseudocode is added in M3-T5 (decompiler seam)."""
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
    lines.append(
        f"Emit findings as JSON ({ctx.task_type}). Each finding must match the HexGraph finding schema."
    )
    return "\n".join(lines)


def _build_context(session: Session, project: Project, target: Target, task: Task) -> TaskContext:
    params = task.params_json or {}
    meta = target.metadata_json or {}
    risky = sorted(set(meta.get("imports", [])) & RISKY_SINKS)

    sibling = (
        session.query(Target)
        .filter(Target.project_id == project.id, Target.id != target.id)
        .first()
    )
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


def _resolve_target_ref(session: Session, project: Project, ref: str) -> Target | None:
    if not ref:
        return None
    direct = session.get(Target, ref)
    if direct is not None and direct.project_id == project.id:
        return direct
    base = Path(ref).name
    for t in session.query(Target).filter(Target.project_id == project.id).all():
        if Path(t.name).name == base:
            return t
    return None


def execute_llm_task(session: Session, project: Project, target: Target, task: Task) -> int:
    """Run an LLM-backed task to findings. Returns the number of findings emitted.

    Sets the task status to needs_triage if any finding has low confidence.
    """
    ctx = _build_context(session, project, target, task)
    prompt = _build_prompt(target, ctx)
    backend = get_backend(task.backend if task.backend not in (None, "none") else None)

    findings, usage = run_findings(backend, ctx.build_request(prompt=prompt))

    write_trace(task, "prompt.txt", prompt)
    write_trace(task, "usage.json", {
        "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
        "cost_source": usage.cost_source, "cost_usd": usage.cost_usd,
    })
    task.cost_estimate = usage.cost_usd
    task.backend = backend.name

    low_confidence = False
    for finding in findings:
        row = persist_finding(
            session,
            project_id=project.id,
            target_id=target.id,
            task_id=task.id,
            finding=finding,
        )
        if finding.confidence == "low":
            low_confidence = True
        # related_target_refs -> related_to edges
        for ref in finding.related_target_refs or []:
            dst = _resolve_target_ref(session, project, ref)
            if dst is not None and dst.id != target.id:
                session.add(
                    Edge(
                        project_id=project.id,
                        src_target_id=target.id,
                        dst_target_id=dst.id,
                        type=EdgeType.related_to,
                        metadata_json={"finding_id": row.id},
                    )
                )

    if findings and low_confidence:
        task.status = TaskStatus.needs_triage
    return len(findings)
