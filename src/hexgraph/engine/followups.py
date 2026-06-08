"""Spawn a task from a finding's suggested follow-up (SPEC §5, §9 M4).

This is the "spawn the next thing" step that closes the loop. A finding carries
`suggested_followups` (task_type, label, optional target_ref + params); launching
one creates a new task against the resolved target with `parent_finding_id` set,
so the graph records what led to what.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Finding, Project, Task
from hexgraph.engine.graph.refs import resolve_target_ref
from hexgraph.engine.tasks import create_task


def spawn_followup(session: Session, finding_id: str, index: int) -> Task:
    """Create (queued) the task described by finding.suggested_followups[index].

    Resolves `target_ref` (id or name) to a target, defaulting to the finding's
    own target; carries the follow-up's params; sets `parent_finding_id`.
    """
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")

    followups = finding.suggested_followups_json or []
    if index < 0 or index >= len(followups):
        raise IndexError(f"finding has no follow-up at index {index}")
    fu = followups[index]

    project = session.get(Project, finding.project_id)
    target = resolve_target_ref(session, project.id, fu.get("target_ref"))
    target_id = target.id if target is not None else finding.target_id

    params = dict(fu.get("params") or {})
    return create_task(
        session,
        project=project,
        target_id=target_id,
        type=fu["task_type"],
        objective=fu.get("label"),
        backend=project.llm_backend.value,
        params=params,
        parent_finding_id=finding.id,
    )
