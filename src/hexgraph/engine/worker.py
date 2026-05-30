"""In-process task worker (SPEC §3).

v1 uses an asyncio queue over the existing `task` table as the job table —
structured so Celery+Redis can drop in later (same enqueue / dispatch seam).
`run_task_sync` executes one queued task; the async `TaskWorker` runs them off
a queue, offloading the blocking sandbox call to a thread.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, Task, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.recon import execute_recon
from hexgraph.engine.tasks import mark_failed, mark_running, mark_succeeded
from hexgraph.sandbox.runner import SandboxRunner


def _dispatch(session: Session, project: Project, target: Target, task: Task) -> None:
    if task.type == "recon":
        execute_recon(session, project, target, task, SandboxRunner())
        return
    # static_analysis / reverse_engineering / pattern_sweep / harness_generation
    # are wired to the LLM backends in M3–M4.
    raise NotImplementedError(f"task type {task.type!r} is available in M3+")


def run_task_sync(task_id: str) -> str:
    """Execute one task to completion. Returns the final status value."""
    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError(f"task {task_id} not found")
        project = session.get(Project, task.project_id)
        target = session.get(Target, task.target_id)
        mark_running(task)
        try:
            _dispatch(session, project, target, task)
            if task.status == TaskStatus.running:
                mark_succeeded(task)
        except Exception as exc:  # noqa: BLE001 — any failure marks the task failed
            mark_failed(task, f"{type(exc).__name__}: {exc}")
        return task.status.value


class TaskWorker:
    """Background consumer of queued task ids."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._runner: asyncio.Task | None = None

    async def start(self) -> None:
        if self._runner is None:
            self._runner = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._runner is not None:
            self._runner.cancel()
            self._runner = None

    async def enqueue(self, task_id: str) -> None:
        await self._queue.put(task_id)

    async def _loop(self) -> None:
        while True:
            task_id = await self._queue.get()
            try:
                await asyncio.to_thread(run_task_sync, task_id)
            except Exception:  # noqa: BLE001 — never let the loop die
                pass
            finally:
                self._queue.task_done()


_worker: TaskWorker | None = None


def get_worker() -> TaskWorker:
    global _worker
    if _worker is None:
        _worker = TaskWorker()
    return _worker
