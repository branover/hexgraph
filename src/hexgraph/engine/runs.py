"""Analysis runs + run-to-run finding diff (P2-5, design §7).

An `analysis_run` groups one task execution's inputs (bundle/backend/model/params)
and outputs (findings), so runs over the same anchor — e.g. the same function with
a different model — are comparable. The diff is what makes per-task model
selection worth anything.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import AnalysisRun, Finding


def record_run(
    session: Session, *, project_id: str, anchor_kind: str, anchor_id: str, task,
    bundle_sha: str | None, finding_count: int,
) -> AnalysisRun:
    run = AnalysisRun(
        project_id=project_id, anchor_kind=anchor_kind, anchor_id=anchor_id,
        task_id=task.id, task_type=task.type, backend=task.backend, model=task.model,
        params_json=task.params_json or {}, bundle_sha=bundle_sha, finding_count=finding_count,
    )
    session.add(run)
    session.flush()
    return run


def _signature(f: Finding) -> tuple:
    ev = f.evidence_json or {}
    return (f.category, f.title, ev.get("function", ""), ev.get("sink", ""))


def _findings_for_run(session: Session, run: AnalysisRun) -> list[Finding]:
    return session.query(Finding).filter(Finding.task_id == run.task_id).all()


def diff_runs(session: Session, run_a_id: str, run_b_id: str) -> dict:
    """Diff two runs' findings by signature → added / dropped / changed-severity."""
    a, b = session.get(AnalysisRun, run_a_id), session.get(AnalysisRun, run_b_id)
    if a is None or b is None:
        raise ValueError("run not found")
    fa = {_signature(f): f for f in _findings_for_run(session, a)}
    fb = {_signature(f): f for f in _findings_for_run(session, b)}

    added = [b_sig_title(s, fb) for s in fb.keys() - fa.keys()]
    dropped = [b_sig_title(s, fa) for s in fa.keys() - fb.keys()]
    changed = [
        {"title": fb[s].title, "from": fa[s].severity, "to": fb[s].severity}
        for s in fa.keys() & fb.keys()
        if fa[s].severity != fb[s].severity
    ]
    return {"run_a": run_a_id, "run_b": run_b_id, "added": added, "dropped": dropped, "changed": changed}


def b_sig_title(sig: tuple, table: dict) -> dict:
    f = table[sig]
    return {"title": f.title, "severity": f.severity, "category": f.category}
