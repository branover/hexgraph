"""analyze_target's per-child recon loop must not block the calling ingest for a large
firmware. Real gap found while designing directory-import: promote_file and reveal_dir got
detached tonight, but the INITIAL ingest call site (ingest_and_analyze / `hexgraph ingest` /
`target_ingest`) never routed analyze_target through the detached-task system at all — a
large firmware still blocked the whole ingest call for however long sequential per-child
sandbox recon took. Above CHILD_RECON_DETACH_THRESHOLD children, recon now runs as ONE
detached batch task instead."""

from hexgraph.db.models import Task, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine import pipeline
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.worker import run_task_sync

from conftest import fixture_path


def _fake_facts(session, project, target, runner):
    return {"kind": "firmware_image", "format": "squashfs"}


def test_analyze_target_detaches_large_child_recon(hg_home, monkeypatch):
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    monkeypatch.setattr(pipeline, "run_recon", _fake_facts)

    n = pipeline.CHILD_RECON_DETACH_THRESHOLD + 5
    with session_scope() as s:
        p = create_project(s, name="big-fw")
        root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        children = [ingest_file(s, p, fixture_path("vuln_httpd"), name=f"bin{i}", parent=root, visible=False)
                   for i in range(n)]
        s.flush()
        child_ids = {c.id for c in children}
        monkeypatch.setattr(pipeline, "unpack_firmware", lambda session, project, target, runner: children)

        summary = pipeline.analyze_target(s, p, root, runner=None)
        assert summary["recon_status"] == "queued"
        assert summary["children_count"] == n
        assert len(summary["children"]) == n   # child target rows exist even though unreconned
        assert len(spawned) == 1               # ONE batch task, not one per child

        task = s.get(Task, spawned[0])
        assert task.type == "recon_children_batch" and task.status == TaskStatus.queued
        assert task.target_id == root.id
        assert set(task.params_json["target_ids"]) == child_ids


def test_analyze_target_stays_synchronous_below_threshold(hg_home, monkeypatch):
    """Regression guard: a small firmware (every existing test fixture) must behave exactly
    as before — full synchronous recon, no detached task, recon_status='done'."""
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    monkeypatch.setattr(pipeline, "run_recon", _fake_facts)

    n = pipeline.CHILD_RECON_DETACH_THRESHOLD - 1
    with session_scope() as s:
        p = create_project(s, name="small-fw")
        root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        children = [ingest_file(s, p, fixture_path("vuln_httpd"), name=f"bin{i}", parent=root, visible=False)
                   for i in range(n)]
        s.flush()
        monkeypatch.setattr(pipeline, "unpack_firmware", lambda session, project, target, runner: children)

        summary = pipeline.analyze_target(s, p, root, runner=None)
        assert summary["recon_status"] == "done"
        assert summary["children_count"] == n
        assert len(spawned) == 0
        assert "recon_children_task_id" not in (root.metadata_json or {})


def test_analyze_target_marks_task_failed_on_spawn_error(hg_home, monkeypatch):
    """If spawn_detached_task itself raises, the Task must end up terminal (failed), not
    stuck 'queued' forever — same self-heal reasoning as promote_file/reveal_dir tonight."""
    def _boom(task_id):
        raise OSError("Resource temporarily unavailable")

    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task", _boom)
    monkeypatch.setattr(pipeline, "run_recon", _fake_facts)

    n = pipeline.CHILD_RECON_DETACH_THRESHOLD + 1
    with session_scope() as s:
        p = create_project(s, name="spawn-fails-fw")
        root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        children = [ingest_file(s, p, fixture_path("vuln_httpd"), name=f"bin{i}", parent=root, visible=False)
                   for i in range(n)]
        s.flush()
        monkeypatch.setattr(pipeline, "unpack_firmware", lambda session, project, target, runner: children)

        summary = pipeline.analyze_target(s, p, root, runner=None)
        assert summary["recon_status"] == "failed"
        # No task id is exposed on the target when the spawn itself never got off the
        # ground — look the Task row up directly to confirm it's terminal, not stuck queued.
        assert "recon_children_task_id" not in (root.metadata_json or {})

        task = (
            s.query(Task)
            .filter(Task.target_id == root.id, Task.type == "recon_children_batch")
            .one()
        )
        assert task.status == TaskStatus.failed


def test_recon_children_batch_task_processes_all_children_sequentially(hg_home, monkeypatch):
    """The `recon_children_batch` task type — what the detached spawn runs — must recon
    every target in params_json.target_ids, and a failure on ONE child must not abort the
    rest of the batch."""
    calls = []

    def _fake_run_recon(session, project, target, runner):
        calls.append(target.id)
        if target.name == "bad":
            raise RuntimeError("boom")
        return {"kind": "executable"}

    monkeypatch.setattr("hexgraph.engine.re.recon.run_recon", _fake_run_recon)
    from hexgraph.engine.tasks import create_task

    with session_scope() as s:
        p = create_project(s, name="dispatch-recon-batch")
        root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a", parent=root, visible=False)
        bad = ingest_file(s, p, fixture_path("vuln_httpd"), name="bad", parent=root, visible=False)
        c = ingest_file(s, p, fixture_path("vuln_httpd"), name="c", parent=root, visible=False)
        s.flush()
        task = create_task(s, project=p, target_id=root.id, type="recon_children_batch",
                           params={"target_ids": [a.id, bad.id, c.id]})
        task_id, aid, badid, cid = task.id, a.id, bad.id, c.id

    status = run_task_sync(task_id)
    assert status == "succeeded"          # one bad child doesn't fail the whole batch
    assert calls == [aid, badid, cid]     # processed in order, including past the failure
