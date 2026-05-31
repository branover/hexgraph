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
from datetime import datetime, timezone

from hexgraph.engine.llm_tasks import LLM_TASK_TYPES, execute_llm_task
from hexgraph.engine.recon import execute_recon
from hexgraph.engine.tasks import mark_failed, mark_running, mark_succeeded
from hexgraph.sandbox.executor import Executor, get_executor


def _dispatch(session: Session, project: Project, target: Target, task: Task) -> None:
    if task.type == "recon":
        execute_recon(session, project, target, task, get_executor())
        return
    if task.type == "fuzzing":
        from hexgraph.engine.fuzzing import execute_fuzzing

        execute_fuzzing(session, project, target, task, get_executor())
        return
    if task.type == "agent_delegate":
        from hexgraph.engine.agent_delegate import execute_delegate

        execute_delegate(session, project, target, task)
        return
    if task.type in LLM_TASK_TYPES:
        execute_llm_task(session, project, target, task)
        return
    raise NotImplementedError(f"unknown task type {task.type!r}")


def run_task_sync(task_id: str) -> str:
    """Execute one task to completion. Returns the final status value."""
    with session_scope() as session:
        task = session.get(Task, task_id)
        if task is None:
            raise ValueError(f"task {task_id} not found")
        project = session.get(Project, task.project_id)
        target = session.get(Target, task.target_id)
        # Entitlement gate (no-op in the local/BYOK build; the seam for paid features).
        from hexgraph.entitlements import require

        require(f"task.{task.type}")
        mark_running(task)
        try:
            _dispatch(session, project, target, task)
            if task.status == TaskStatus.running:
                mark_succeeded(task)
            elif task.finished_at is None:
                # e.g. a handler set needs_triage; still stamp completion time.
                task.finished_at = datetime.now(timezone.utc)
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
