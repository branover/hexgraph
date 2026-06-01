"""Tasks + analysis runs: launch/preview/status/detail/trace/rerun, run history & diff."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from hexgraph.db.models import AnalysisRun, Finding, Project, Target, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.runs import diff_runs
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import get_worker

from ._shared import TaskCreate, finding_dict, task_dict

router = APIRouter()


@router.post("/api/tasks/preview")
def api_task_preview(body: TaskCreate):
    """Pre-flight: show the exact context bundle (prompt + items + token estimate)
    a task would run on, before spending anything."""
    from hexgraph.engine.llm_tasks import preview_context

    params = dict(body.params or {})
    if body.mock_scenario:
        params["mock_scenario"] = body.mock_scenario
    with session_scope() as s:
        target = s.get(Target, body.target_id)
        if target is None:
            raise HTTPException(404, "target not found")
        preview = preview_context(s, s.get(Project, target.project_id), target,
                                  task_type=body.type, objective=body.objective, params=params)
        preview["backend"] = body.backend or "mock"
        preview["model"] = body.model
        return preview


@router.post("/api/tasks")
async def api_create_task(body: TaskCreate):
    with session_scope() as s:
        target = s.get(Target, body.target_id)
        if target is None:
            raise HTTPException(404, "target not found")
        project = s.get(Project, target.project_id)
        params = dict(body.params or {})
        if body.mock_scenario:
            params["mock_scenario"] = body.mock_scenario
        task = create_task(
            s, project=project, target_id=target.id, type=body.type,
            objective=body.objective, model=body.model,
            backend=body.backend or project.llm_backend.value,
            params=params, parent_finding_id=body.parent_finding_id,
            anchor_kind=body.anchor_kind, anchor_id=body.anchor_id,
        )
        task_id = task.id
    await get_worker().enqueue(task_id)
    return {"task_id": task_id, "status": "queued"}


@router.get("/api/targets/{target_id}/runs")
def api_target_runs(target_id: str):
    with session_scope() as s:
        runs = (
            s.query(AnalysisRun).filter(AnalysisRun.anchor_id == target_id)
            .order_by(AnalysisRun.created_at.desc()).all()
        )
        return [
            {"id": r.id, "task_id": r.task_id, "task_type": r.task_type, "backend": r.backend,
             "model": r.model, "bundle_sha": r.bundle_sha, "finding_count": r.finding_count,
             "created_at": r.created_at}
            for r in runs
        ]


@router.post("/api/runs/diff")
def api_runs_diff(body: dict):
    with session_scope() as s:
        try:
            return diff_runs(s, body["run_a"], body["run_b"])
        except (KeyError, ValueError) as exc:
            raise HTTPException(400, str(exc))


@router.get("/api/tasks/{task_id}")
def api_task(task_id: str):
    with session_scope() as s:
        t = s.get(Task, task_id)
        if t is None:
            raise HTTPException(404, "task not found")
        return {"id": t.id, "type": t.type, "status": t.status.value, "target_id": t.target_id}


# --- P5: task workspace + provenance navigation ---
@router.get("/api/projects/{project_id}/tasks")
def api_project_tasks(project_id: str):
    with session_scope() as s:
        tasks = (
            s.query(Task).filter(Task.project_id == project_id)
            .order_by(Task.created_at.desc()).all()
        )
        counts = {}
        for f in s.query(Finding).filter(Finding.project_id == project_id).all():
            counts[f.task_id] = counts.get(f.task_id, 0) + 1
        return [{**task_dict(t), "finding_count": counts.get(t.id, 0)} for t in tasks]


@router.get("/api/tasks/{task_id}/detail")
def api_task_detail(task_id: str):
    with session_scope() as s:
        t = s.get(Task, task_id)
        if t is None:
            raise HTTPException(404, "task not found")
        findings = s.query(Finding).filter(Finding.task_id == task_id).all()
        trace = []
        error = None
        if t.log_path and Path(t.log_path).is_dir():
            trace = sorted(p.name for p in Path(t.log_path).iterdir() if p.is_file())
            err_path = Path(t.log_path) / "error.txt"
            if err_path.is_file():
                error = err_path.read_text()[:8000]  # surface the failure reason inline
        return {
            "task": task_dict(t),
            "findings": [finding_dict(f) for f in findings],
            "trace_files": trace,
            "error": error,
        }


@router.get("/api/tasks/{task_id}/trace/{name}")
def api_task_trace(task_id: str, name: str):
    """Read one trace artifact's content (error.txt, prompt.txt, fuzz.json, …)."""
    with session_scope() as s:
        t = s.get(Task, task_id)
        if t is None or not t.log_path:
            raise HTTPException(404, "task not found")
        p = Path(t.log_path) / name
        if p.name != name or not p.is_file():  # no path traversal
            raise HTTPException(404, "trace file not found")
        return PlainTextResponse(p.read_text()[:200000])


@router.post("/api/tasks/{task_id}/rerun")
async def api_task_rerun(task_id: str):
    with session_scope() as s:
        t = s.get(Task, task_id)
        if t is None:
            raise HTTPException(404, "task not found")
        project = s.get(Project, t.project_id)
        clone = create_task(
            s, project=project, target_id=t.target_id, type=t.type,
            objective=t.objective_text, model=t.model, backend=t.backend,
            params=dict(t.params_json or {}), parent_finding_id=t.parent_finding_id,
            anchor_kind=t.anchor_kind, anchor_id=t.anchor_id,
        )
        new_id = clone.id
    await get_worker().enqueue(new_id)
    return {"task_id": new_id, "status": "queued"}
