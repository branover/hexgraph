"""SQLite write-lock contention under HexGraph's multi-writer model (the web app + a CLI
ingest + a detached recon task all write the same file). A real user hit repeated
"database is locked" crashes importing a large firmware partition while `hexgraph serve`
was running: recon holds the single SQLite write lock across its whole Docker sandbox run,
far longer than the old 5s busy_timeout, so a concurrent writer's very first INSERT failed.

The core discipline these guard: never hold the single SQLite write lock across slow
sandbox/network work. That means (a) a generous busy_timeout, (b) recon/ingest committing
before their Docker phase, and — the broader contention a second user hit running several
agents that decompile in parallel — (c) `release_write_lock` applied at every remaining spot
where a long-lived task session would otherwise pin an uncommitted write across a slow op:
run_task_sync checkpoints the running-status write before dispatch, and the agent loop commits
after each tool call so one function's graph promotion isn't held across the NEXT function's
decompile.
"""

from sqlalchemy import text

from conftest import fixture_path

from hexgraph.db.models import Node, Project, Target, Task, TaskStatus
from hexgraph.db.session import (BUSY_TIMEOUT_MS, get_engine, get_session, release_write_lock,
                                 session_scope)
from hexgraph.engine.re import recon
from hexgraph.engine.tasks import create_task
from hexgraph.engine.targets.dirimport import ingest_directory
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.worker import run_task_sync

ELF = b"\x7fELF\x01\x01\x01" + b"a binary" + b"\x00" * 8


def test_busy_timeout_is_generous(hg_home):
    """The busy_timeout must comfortably exceed a normal slow-but-legitimate write hold
    (a Docker recon, a file copy) so a concurrent writer WAITS rather than crashing. 5s was
    too short; regression-guard the generous value on an actual connection. `hg_home` keeps
    this hermetic — it reads the PRAGMA off the tmp-home engine, never the real ~/.hexgraph."""
    assert BUSY_TIMEOUT_MS >= 30_000
    with get_engine().connect() as conn:
        got = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
    assert got == BUSY_TIMEOUT_MS


def test_execute_recon_releases_write_lock_before_docker_probe(hg_home, tmp_path):
    """The core fix: recon must COMMIT (release the single SQLite write lock) before it runs
    the seconds-to-minutes Docker probe, otherwise every other writer is starved for the whole
    sandbox run. Proven from INSIDE a fake probe: a separate connection must be able to acquire
    the write lock while the probe 'runs' — impossible if recon still held it."""
    f = tmp_path / "bin"
    f.write_bytes(ELF)
    captured = {}

    class _Probe:
        def run_json_probe(self, probe, path, **kw):
            # We are now "inside Docker". A fresh connection must be able to WRITE, which is
            # only true if execute_recon already committed and released the lock.
            conn = get_session()
            try:
                conn.execute(text("UPDATE project SET name = name WHERE id = :i"),
                             {"i": captured["pid"]})
                conn.commit()
                captured["acquired_during_probe"] = True
            except Exception as exc:  # noqa: BLE001
                captured["acquired_during_probe"] = False
                captured["err"] = str(exc)
            finally:
                conn.close()
            return {"kind": "executable", "format": "elf", "imports": [], "strings": []}

    with session_scope() as s:
        p = create_project(s, name="recon-lock")
        captured["pid"] = p.id
        t = ingest_file(s, p, f, name="bin")
        recon.run_recon(s, p, t, _Probe())

    assert captured.get("acquired_during_probe") is True, captured.get("err")


def test_ingest_directory_commits_registration_before_returning(hg_home, tmp_path):
    """Directory-import must release the write lock the moment the tree is registered (root +
    children + manifest committed) rather than holding it open into the caller's recon phase —
    otherwise a concurrent writer waits on the ingest for the entire recon run. Verified by
    reading the children back from an INDEPENDENT session opened after ingest_directory returns
    but before any recon: they must already be committed."""
    src = tmp_path / "rootfs"
    (src / "usr").mkdir(parents=True)
    (src / "usr" / "httpd").write_bytes(ELF)

    with session_scope() as s:
        p = create_project(s, name="dir-commit")
        pid = p.id
        root, children = ingest_directory(s, p, src, name="rootfs")
        root_id = root.id
        assert len(children) == 1

        # A DIFFERENT connection — sees only COMMITTED rows. If ingest_directory hadn't
        # committed, this fresh session would see zero children for the new root.
        with session_scope() as s2:
            seen = s2.query(Target).filter(Target.parent_id == root_id).all()
            assert len(seen) == 1
            assert s2.get(Project, pid) is not None


def test_release_write_lock_hands_off_the_lock(hg_home):
    """The idiom every 'commit before slow work' site relies on: `release_write_lock` commits
    pending work, so a write that was only FLUSHED (lock held) becomes durable and the single
    writer lock is handed off — a FRESH connection can then write. If it did NOT commit, the
    fresh write below would block on the busy_timeout and fail."""
    with session_scope() as s:
        p = create_project(s, name="orig")
        pid = p.id

    held = get_session()
    held.execute(text("UPDATE project SET name = 'held' WHERE id = :i"), {"i": pid})
    held.flush()                     # write FLUSHED -> lock acquired, NOT yet committed
    release_write_lock(held)         # commit -> lock released, 'held' durable
    fresh = get_session()
    try:
        fresh.execute(text("UPDATE project SET name = 'fresh' WHERE id = :i"), {"i": pid})
        fresh.commit()               # succeeds only because the lock was handed off
    finally:
        fresh.close()
        held.close()
    with session_scope() as s:
        assert s.get(Project, pid).name == "fresh"


def test_run_task_sync_checkpoints_running_status_before_dispatch(hg_home, tmp_path, monkeypatch):
    """Fix: run_task_sync must COMMIT the running-status write (mark_running) BEFORE _dispatch,
    so a handler's first sandbox op never inherits a held lock. mark_running only mutates the
    ORM object, so without this the task-row write autoflushes inside the handler and is pinned
    across its first Docker probe/decompile. Proven from INSIDE a monkeypatched _dispatch: a
    FRESH session both sees the task already `running` (committed) AND can itself WRITE."""
    import hexgraph.engine.worker as worker

    f = tmp_path / "bin"
    f.write_bytes(ELF)
    captured = {}

    def spy_dispatch(session, project, target, task):
        conn = get_session()
        try:
            row = conn.get(Task, task.id)
            captured["status"] = row.status if row else None
            conn.execute(text("UPDATE project SET name = name WHERE id = :i"), {"i": project.id})
            conn.commit()            # a fresh writer must be able to proceed — lock released
            captured["fresh_write_ok"] = True
        except Exception as exc:  # noqa: BLE001
            captured["fresh_write_ok"] = False
            captured["err"] = str(exc)
        finally:
            conn.close()

    monkeypatch.setattr(worker, "_dispatch", spy_dispatch)

    with session_scope() as s:
        p = create_project(s, name="fix-markrunning")
        t = ingest_file(s, p, f, name="bin")
        task = create_task(s, project=p, target_id=t.id, type="recon", backend="none")
        tid = task.id

    run_task_sync(tid)
    assert captured.get("status") == TaskStatus.running, captured
    assert captured.get("fresh_write_ok") is True, captured.get("err")


def test_agent_loop_checkpoints_graph_write_between_tool_calls(hg_home, monkeypatch):
    """The reported contention: multiple agents decompiling in parallel hit "database is locked".
    Root cause — the agent loop runs every tool on ONE long-lived task session, and a decompile
    that promotes a function node left that write UNCOMMITTED, so it was pinned across the NEXT
    function's (seconds-long) decompile. Fix: the loop commits after each tool call.

    Drive the REAL execute_llm_task loop with the agentic mock (2 tool calls). The first tool
    promotes a node; the second — from a FRESH session — must both SEE that node committed and be
    able to WRITE. Neither is true if the first tool's write is still held on the task session."""
    import hexgraph.agent.agent_tools as agent_tools
    from hexgraph.engine.graph.nodes import get_or_create_node

    seen = {}
    n = {"i": 0}

    def fake_run_tool(ctx, name, args):
        n["i"] += 1
        if n["i"] == 1:
            # Stand in for a decompile that PROMOTES a function node (write + flush, no commit).
            get_or_create_node(ctx.session, project_id=ctx.project.id, target_id=ctx.target.id,
                               node_type="function", name="loop_marker", created_by="test")
            return "// decompiled void f(){}"
        # Second tool call: from a FRESH session, is the first call's node committed, and can we
        # WRITE? Both require the loop to have checkpointed between the two calls.
        conn = get_session()
        try:
            node = (conn.query(Node)
                    .filter(Node.project_id == ctx.project.id, Node.name == "loop_marker").first())
            seen["committed_between_calls"] = node is not None
            conn.execute(text("UPDATE project SET name = name WHERE id = :i"), {"i": ctx.project.id})
            conn.commit()
            seen["fresh_write_ok"] = True
        except Exception as exc:  # noqa: BLE001
            seen["fresh_write_ok"] = False
            seen["err"] = str(exc)
        finally:
            conn.close()
        return "imports: strcpy"

    monkeypatch.setattr(agent_tools, "run_tool", fake_run_tool)

    with session_scope() as s:
        p = create_project(s, name="fix-agentloop")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}, "strings": []}
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           params={"mock_scenario": "agentic_overflow", "function": "cgi_handler"})
        tid = task.id

    run_task_sync(tid)
    assert n["i"] >= 2, "the agentic scenario should have made at least two tool calls"
    assert seen.get("committed_between_calls") is True, seen
    assert seen.get("fresh_write_ok") is True, seen.get("err")
