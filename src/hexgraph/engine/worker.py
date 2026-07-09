"""In-process task worker (SPEC §3).

v1 uses an asyncio queue over the existing `task` table as the job table —
structured so Celery+Redis can drop in later (same enqueue / dispatch seam).
`run_task_sync` executes one queued task; the async `TaskWorker` runs them off
a queue, offloading the blocking sandbox call to a thread.
"""

from __future__ import annotations

import asyncio

from sqlalchemy.orm import Session

from hexgraph.db.models import SURFACE_KINDS, Project, Target, Task, TargetKind, TaskStatus
from hexgraph.db.session import session_scope
from datetime import datetime, timezone

from hexgraph.engine.llm_tasks import LLM_TASK_TYPES, execute_llm_task
from hexgraph.engine.re.recon import execute_recon
from hexgraph.engine.tasks import mark_failed, mark_running, mark_succeeded
from hexgraph.sandbox.executor import get_executor


def _dispatch(session: Session, project: Project, target: Target, task: Task) -> None:
    if task.type == "recon":
        # A SURFACE target (web_app/service/remote) has no bytes at rest — it's reached via
        # a Channel, with `path=""`. Byte recon (recon_probe over a file) would resolve the
        # empty path to the cwd and crash with a confusing "artifact not found". Route the
        # generic `recon` task to the surface-appropriate analysis instead.
        if target.kind in SURFACE_KINDS or not (target.path or "").strip():
            _dispatch_surface_recon(session, project, target, task)
            return
        execute_recon(session, project, target, task, get_executor())
        return
    if task.type == "fuzzing":
        from hexgraph.engine.fuzz.fuzzing import execute_fuzzing

        execute_fuzzing(session, project, target, task, get_executor())
        return
    if task.type == "agent_delegate":
        from hexgraph.agent.agent_delegate import execute_delegate

        execute_delegate(session, project, target, task)
        return
    if task.type == "poc":
        from hexgraph.engine.findings.poc import execute_poc

        execute_poc(session, project, target, task, get_executor())
        return
    if task.type == "surface_recon":
        from hexgraph.engine.targets.surfaces import run_surface_recon

        run_surface_recon(session, project, target, task)
        return
    if task.type == "web_recon":
        from hexgraph.engine.targets.surfaces import run_web_recon

        run_web_recon(session, project, target, task)
        return
    if task.type == "web_discover":
        from hexgraph.engine.targets.surfaces import run_web_discover

        run_web_discover(session, project, target, task)
        return
    if task.type == "target_analyze":
        from hexgraph.engine.pipeline import analyze_target
        from hexgraph.engine.targets.unpack import build_links_against

        analyze_target(session, project, target, get_executor())
        build_links_against(session, project)
        return
    if task.type == "recon_children_batch":
        # analyze_target's large-firmware path (engine.pipeline.CHILD_RECON_DETACH_THRESHOLD):
        # ONE detached process recons every child SEQUENTIALLY — same "one process for the
        # whole batch, not one per item" reasoning as ghidra_enrich_batch below. `target`
        # here is the PARENT (firmware) being analyzed, not any one of the actual children —
        # those travel in params_json.
        from hexgraph.engine.pipeline import _maybe_enrich_ghidra, _record_progress
        from hexgraph.engine.re.recon import run_recon

        child_ids = (task.params_json or {}).get("target_ids", [])
        total = len(child_ids)
        for i, cid in enumerate(child_ids, start=1):
            # _record_progress commits — this doubles as the per-child checkpoint, same as
            # the inline (small-firmware) loop already relied on.
            _record_progress(session, target, "recon_children", done=i - 1, total=total)
            child = session.get(Target, cid)
            if child is None:
                continue
            try:
                child_facts = run_recon(session, project, child, get_executor())
                _maybe_enrich_ghidra(session, project, child, child_facts)
            except Exception:  # noqa: BLE001 — one bad child must not abort the rest
                pass
        _record_progress(session, target, "done", children=total)
        return
    if task.type == "ghidra_enrich":
        from hexgraph.engine.re.ghidra import enrich_target

        result = enrich_target(session, project, target)
        if result.get("ok"):
            # Mark done so _ensure_ghidra_enrichment (engine.targets.reveal) doesn't
            # re-queue this target; a soft failure (ok=False, no exception) leaves it
            # unmarked so a later reveal call retries instead of silently giving up.
            meta = dict(target.metadata_json or {})
            meta["ghidra_enriched"] = True
            target.metadata_json = meta
            from sqlalchemy.orm.attributes import flag_modified

            flag_modified(target, "metadata_json")
        return
    if task.type == "ghidra_enrich_batch":
        # reveal_dir's bulk path (engine.targets.reveal._ensure_batch_ghidra_enrichment):
        # ONE detached process enriches MANY targets SEQUENTIALLY, not one process per
        # target — a directory can have a dozen+ binaries, and a dozen+ CONCURRENT cold
        # headless Ghidra containers would contend hard for host resources. `target` here is
        # the anchor (the firmware passed to reveal_dir), not any one of the actual targets
        # being enriched — those travel in params_json.
        from hexgraph.engine.re.ghidra import enrich_target
        from sqlalchemy.orm.attributes import flag_modified

        for tid in (task.params_json or {}).get("target_ids", []):
            tgt = session.get(Target, tid)
            if tgt is None:
                continue
            try:
                result = enrich_target(session, project, tgt)
            except Exception:  # noqa: BLE001 — one bad target must not abort the rest
                continue
            if result.get("ok"):
                meta = dict(tgt.metadata_json or {})
                meta["ghidra_enriched"] = True
                tgt.metadata_json = meta
                flag_modified(tgt, "metadata_json")
            # Checkpoint per-target: a killed/crashed batch (this can run for a long
            # time — a dozen+ sequential cold Ghidra analyses) keeps whatever it already
            # finished rather than losing all progress on the final commit.
            session.commit()
        return
    if task.type in LLM_TASK_TYPES:
        execute_llm_task(session, project, target, task)
        return
    raise NotImplementedError(f"unknown task type {task.type!r}")


def _dispatch_surface_recon(session: Session, project: Project, target: Target, task: Task) -> None:
    """Route a generic `recon` task on a path-less SURFACE target to the right analysis.

    A `web_app` maps to deterministic, offline `run_surface_recon` (materialise the route
    spec → endpoint/param nodes + routes_to handler edges) — the surface analogue of byte
    recon, no network. A `service`/`remote` surface has no offline deterministic recon
    probe, so we fail with a clear, actionable error rather than crashing on the byte path."""
    from hexgraph.engine.targets.surfaces import run_surface_recon

    if target.kind == TargetKind.web_app:
        run_surface_recon(session, project, target, task)
        return
    kind = target.kind.value if isinstance(target.kind, TargetKind) else str(target.kind)
    if target.kind == TargetKind.service:
        raise NotImplementedError(
            f"target {target.name!r} is a {kind} surface (a live network listener, no bytes "
            "at rest) — 'recon' has no offline probe for it. Use a network fuzzing campaign "
            "or run_tcp_probe (features.network) to assess it.")
    if target.kind == TargetKind.remote:
        raise NotImplementedError(
            f"target {target.name!r} is a {kind} surface (a live device over SSH/telnet, no "
            "bytes at rest) — 'recon' has no offline probe for it. Use the remote read-only "
            "tools (features.remote) to assess it.")
    raise NotImplementedError(
        f"target {target.name!r} has no byte artifact (path is empty) and is a {kind} target; "
        "the 'recon' task only handles byte targets and web_app surfaces.")


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
            # A task records its reusable Observations in their OWN durable commits as it
            # runs (engine.observations.record_observation checkpoints them), so they
            # survive THIS failure — the long task transaction is no longer all-or-nothing.
            # Roll back only the work pending SINCE the last such checkpoint: that clears
            # any failed/pending-rollback transaction state (e.g. when the failure was a DB
            # lock mid-flush) so the mark_failed write below can commit, and discards the
            # half-built synthesized result that SHOULD die with the task. The committed
            # Observations are untouched. Re-fetch the task — rollback expires it.
            session.rollback()
            task = session.get(Task, task_id)
            if task is not None:
                mark_failed(task, f"{type(exc).__name__}: {exc}")
        return task.status.value if task is not None else TaskStatus.failed.value


# How often the reaper polls detached fuzz-campaign containers (seconds). A campaign
# runs for minutes-to-hours but crashes must surface within minutes — so this is short
# enough to stream the first crash quickly, cheap enough to run continuously.
REAPER_INTERVAL = 15


def reap_campaigns_sync() -> int:
    """Run one reaper pass: poll every live campaign's detached container, ingest new
    artifacts → fuzz_crash findings, update stats, finalize completed ones. Crash-safe
    re-attach lives here — the reaper re-binds to running containers by their durable
    `container_name` from the (durable) fuzz_campaign rows, so campaigns survive a
    `serve` restart. Runs in a thread (the docker poll is blocking)."""
    from hexgraph.engine.fuzz import campaigns

    with session_scope() as session:
        # The worker reaper runs in a background thread, so it may take the symbolization
        # backfill path (which EXECUTES the target via the verify replay); the on-read HTTP
        # reaps leave allow_replay_backfill False so they never run the target in a request.
        return campaigns.reap_all(session, allow_replay_backfill=True)


class TaskWorker:
    """Background consumer of queued task ids + the periodic fuzz-campaign reaper."""

    def __init__(self) -> None:
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._runner: asyncio.Task | None = None
        self._reaper: asyncio.Task | None = None

    async def start(self) -> None:
        if self._runner is None:
            self._runner = asyncio.create_task(self._loop())
        if self._reaper is None:
            self._reaper = asyncio.create_task(self._reaper_loop())

    async def stop(self) -> None:
        for attr in ("_runner", "_reaper"):
            t = getattr(self, attr)
            if t is not None:
                t.cancel()
                setattr(self, attr, None)

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

    async def _reaper_loop(self) -> None:
        """Periodically reap detached fuzz campaigns — a SEPARATE task from the queue
        loop so a multi-hour campaign never pins the worker thread (design §5.5: detached
        + reaped, no worker-thread starvation). The first pass on startup is the
        crash-safe re-attach to any container that survived a restart."""
        while True:
            try:
                await asyncio.to_thread(reap_campaigns_sync)
            except Exception:  # noqa: BLE001 — never let the reaper die
                pass
            await asyncio.sleep(REAPER_INTERVAL)


_worker: TaskWorker | None = None


def get_worker() -> TaskWorker:
    global _worker
    if _worker is None:
        _worker = TaskWorker()
    return _worker


def spawn_detached_task(task_id: str) -> int:
    """Run `task_id` to completion in an INDEPENDENT OS process, decoupled from the caller's
    own lifetime.

    Some callers (e.g. `promote_file`) need to kick off work that can legitimately take minutes
    to hours (thousands of sequential sandbox runs for a deeply-nested firmware package) without
    blocking their own request/response cycle. Enqueueing onto `TaskWorker` isn't enough on its
    own: that worker's event loop lives in the `hexgraph serve` process, which may not even be
    running when the caller is an MCP tool invocation (`hexgraph mcp` is a separate, standalone
    process — see CLAUDE.md's worktree/MCP notes). A background THREAD in the calling process
    would have the same problem one level down: if that process exits (a client disconnect, a
    crash, a restart), the thread dies with it and the work is lost mid-flight — exactly the
    failure mode that produced a real incident (a promote_file call whose analysis silently died
    partway through, leaving the manifest permanently marked "promoted" but never analyzed).
    A detached OS process survives all of that; `run_task_sync` re-opens its own DB session and
    the `task` row is the durable, pollable record of progress either way.

    `start_new_session=True` only detaches the SESSION/process group — it does NOT reparent the
    child to init, so the OS still tracks it as a child of THIS process for wait()/reaping
    purposes. Without an explicit wait, a finished child sits as a zombie until this process
    (`hexgraph serve` / `hexgraph mcp`, both long-lived) itself exits — over an engagement that
    promotes many files, that accumulates one zombie per detached analysis. A daemon thread
    blocked on `proc.wait()` reaps it the moment it exits, without making the caller block."""
    import subprocess
    import sys
    import threading

    proc = subprocess.Popen(
        [sys.executable, "-m", "hexgraph.cli", "internal-run-task", task_id],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    threading.Thread(target=proc.wait, daemon=True).start()
    return proc.pid
