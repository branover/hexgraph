"""Task lifecycle helpers: create rows, mark running/succeeded/failed, log path.

Determinism & evidence (SPEC §6): each task gets a `log_path` under the project
data dir where tool output and prompt/response traces are written, so findings
are auditable and reproducible.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Task, TaskStatus


def _now() -> datetime:
    return datetime.now(timezone.utc)


def task_log_dir(project: Project, task_id: str) -> Path:
    path = Path(project.data_dir) / "tasks" / task_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def create_task(
    session: Session,
    *,
    project: Project,
    target_id: str,
    type: str,
    objective: str | None = None,
    backend: str | None = None,
    model: str | None = None,
    parent_finding_id: str | None = None,
    status: TaskStatus = TaskStatus.queued,
) -> Task:
    task = Task(
        project_id=project.id,
        target_id=target_id,
        type=type,
        objective_text=objective,
        backend=backend,
        model=model,
        parent_finding_id=parent_finding_id,
        status=status,
    )
    session.add(task)
    session.flush()
    task.log_path = str(task_log_dir(project, task.id))
    return task


def mark_running(task: Task) -> None:
    task.status = TaskStatus.running
    task.started_at = _now()


def mark_succeeded(task: Task, *, status: TaskStatus = TaskStatus.succeeded) -> None:
    task.status = status
    task.finished_at = _now()


def mark_failed(task: Task, error: str) -> None:
    task.status = TaskStatus.failed
    task.finished_at = _now()
    if task.log_path:
        (Path(task.log_path) / "error.txt").write_text(error)


def write_trace(task: Task, name: str, data: Any) -> None:
    """Persist a trace artifact (facts, prompt, raw response) under the task log dir."""
    if not task.log_path:
        return
    path = Path(task.log_path) / name
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2, default=str))
    else:
        path.write_text(str(data))
