"""Write-path resilience under multi-agent fan-out.

WAL + busy_timeout=5000 already live in db/session.py (they make a writer *wait*
for the lock). These tests cover the gaps this change closes:

  1. A bounded retry-with-backoff at the WRITE-UNIT boundary (`with_write_retry` /
     `call_with_write_retry`): a transient SQLite lock (`database is locked`,
     `database is busy`, or SQLITE_LOCKED `database table is locked`) re-runs the
     whole unit a few times, then re-raises if it never clears; a NON-lock
     OperationalError (corruption, schema drift) is never retried or masked.
     Retry must re-run the unit, not just the commit: once commit() raises,
     SQLAlchemy invalidates the transaction and rollback discards the staged work.
  2. The retry is WIRED into the MCP write-group seam (`agent.mcp_server.invoke_tool`):
     a locked WRITE tool re-runs the whole call and ultimately persists; read/run
     tools are NOT wrapped (a multi-minute task must not silently re-run on a lock).
  3. The MCP seam sanitizes DB errors so the raw failing SQL and its bound parameters
     (which `str(OperationalError)` carries) never reach the agent — only a structured
     {"error": ...} — and logs the original non-transient error server-side.
"""

import sqlite3

import pytest
from sqlalchemy.exc import OperationalError

from hexgraph.db import session as db_session
from hexgraph.db.session import call_with_write_retry, with_write_retry


def _lock_error(msg: str = "database is locked") -> OperationalError:
    """An OperationalError shaped exactly like SQLite's busy/locked one: its str()
    carries the failing SQL + bound params (the thing we must NOT leak)."""
    return OperationalError(
        "INSERT INTO finding (title, secret_param) VALUES (?, ?)",
        ("SUPER_SECRET_TITLE", "hunter2"),
        sqlite3.OperationalError(msg),
    )


def _non_lock_error() -> OperationalError:
    return OperationalError(
        "SELECT * FROM finding",
        (),
        sqlite3.OperationalError("no such table: finding"),
    )


# ── _is_lock_error: the full SQLite transient-lock family is retryable ──────────────────

@pytest.mark.parametrize("msg", [
    "database is locked",        # SQLITE_BUSY (busy_timeout elapsed)
    "database is busy",          # alternate wording
    "database table is locked",  # SQLITE_LOCKED — was previously missed (finding #2)
])
def test_is_lock_error_covers_all_transient_locks(msg):
    assert db_session._is_lock_error(_lock_error(msg)) is True


@pytest.mark.parametrize("msg", [
    "no such table: finding",
    "disk I/O error",
    "database disk image is malformed",
])
def test_is_lock_error_excludes_structural_errors(msg):
    assert db_session._is_lock_error(_lock_error(msg)) is False


# ── call_with_write_retry: retry a self-contained unit (manages its own txn) ─────────────

def test_call_with_write_retry_retries_sqlite_locked(monkeypatch):
    """SQLITE_LOCKED ('database table is locked') is transient and must be retried — it used
    to fall through to the non-retryable branch (finding #2)."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)
    calls = {"n": 0}

    def unit():
        calls["n"] += 1
        if calls["n"] == 1:
            raise _lock_error("database table is locked")
        return {"ok": True}

    assert call_with_write_retry(unit) == {"ok": True}
    assert calls["n"] == 2


def test_call_with_write_retry_does_not_open_a_session(monkeypatch):
    """call_with_write_retry must NOT wrap the callable in session_scope — it's for callables
    that already manage their own transaction, so wrapping would nest. Assert session_scope
    is never entered by the helper itself."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)
    entered = {"n": 0}
    import contextlib

    @contextlib.contextmanager
    def spy_scope():
        entered["n"] += 1
        yield object()

    monkeypatch.setattr(db_session, "session_scope", spy_scope)
    call_with_write_retry(lambda: "x")
    assert entered["n"] == 0  # helper opened no scope of its own


# ── with_write_retry: bounded retry of the whole unit on transient lock errors ──────────

def test_with_write_retry_recovers_from_one_lock_error(monkeypatch):
    """The unit's commit raises a lock error once, then succeeds on the re-run: the work
    completes and the value is returned, with no exception escaping."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)  # don't actually wait

    calls = {"n": 0}

    def unit(session):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _lock_error()  # first attempt: simulate a lock at commit
        return "done"

    assert with_write_retry(unit) == "done"
    assert calls["n"] == 2  # ran twice: first locked, second succeeded


def test_with_write_retry_gives_up_after_persistent_lock(monkeypatch):
    """A lock that never clears: retry is BOUNDED — after the configured attempts the
    OperationalError re-raises rather than looping forever."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)
    attempts = db_session._WRITE_RETRY_ATTEMPTS
    calls = {"n": 0}

    def unit(session):
        calls["n"] += 1
        raise _lock_error()

    with pytest.raises(OperationalError):
        with_write_retry(unit)
    assert calls["n"] == attempts  # tried exactly the bound, then re-raised — no infinite loop


def test_with_write_retry_does_not_mask_non_lock_errors(monkeypatch):
    """A non-lock OperationalError (e.g. a real schema/corruption error) must surface
    immediately — never retried, never swallowed."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)
    calls = {"n": 0}

    def unit(session):
        calls["n"] += 1
        raise _non_lock_error()

    with pytest.raises(OperationalError):
        with_write_retry(unit)
    assert calls["n"] == 1  # tried once and gave up; not retried


def test_with_write_retry_real_commit_then_readback(hg_home, monkeypatch):
    """End-to-end against the real engine: monkeypatch Session.commit to raise a lock once
    then defer to the real commit, and confirm the unit re-runs and the row truly lands."""
    from hexgraph.db.models import Project
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project

    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)

    real_commit = db_session.Session.commit
    state = {"failed": False}

    def flaky_commit(self):
        if not state["failed"]:
            state["failed"] = True
            raise _lock_error()
        return real_commit(self)

    monkeypatch.setattr(db_session.Session, "commit", flaky_commit)

    pid = with_write_retry(lambda s: create_project(s, name="resilient").id)

    assert state["failed"]  # the first commit really did hit the simulated lock
    monkeypatch.setattr(db_session.Session, "commit", real_commit)
    with session_scope() as s:
        assert s.get(Project, pid) is not None  # the write committed on retry


# ── the MCP seam: sanitize DB errors, never leak SQL/params ────────────────────────────

def test_mcp_seam_sanitizes_db_lock_error():
    """invoke_tool catches a tool's OperationalError and returns a structured, retryable
    error whose text contains NONE of the raw SQL, bound params, or 'OperationalError'."""
    from hexgraph.agent.mcp_server import invoke_tool

    exc = _lock_error()
    leaky = str(exc)
    # sanity: the raw message really does carry the secrets we must not surface
    assert "SUPER_SECRET_TITLE" in leaky and "hunter2" in leaky and "INSERT INTO finding" in leaky

    spec = {"fn": lambda **kw: (_ for _ in ()).throw(exc)}  # a tool that raises the lock error
    out = invoke_tool(spec, {})

    assert isinstance(out, dict) and "error" in out
    assert "retry" in out["error"].lower()
    # the sanitized payload must not leak SQL, params, or the exception class name
    blob = str(out)
    for secret in ("SUPER_SECRET_TITLE", "hunter2", "INSERT INTO finding",
                   "secret_param", "OperationalError", "sqlite3", "[SQL:", "[parameters:"):
        assert secret not in blob, f"sanitized MCP error leaked {secret!r}: {blob!r}"


def test_mcp_seam_sanitizes_non_lock_operational_error():
    """Even a NON-lock OperationalError (schema/corruption) is sanitized at the seam — the
    point is to never surface raw SQL text, regardless of which OperationalError it is."""
    from hexgraph.agent.mcp_server import invoke_tool

    exc = _non_lock_error()
    spec = {"fn": lambda **kw: (_ for _ in ()).throw(exc)}
    out = invoke_tool(spec, {})
    assert isinstance(out, dict) and "error" in out
    assert "SELECT * FROM finding" not in str(out) and "OperationalError" not in str(out)


def test_mcp_seam_passes_through_success_and_non_db_errors():
    """invoke_tool is transparent for the success path and for non-DB errors: a normal
    result returns unchanged, and a non-OperationalError still propagates (genuine bugs
    must surface, not be hidden behind the retry message)."""
    from hexgraph.agent.mcp_server import invoke_tool

    # success path: identical to calling the function directly
    assert invoke_tool({"fn": lambda **kw: {"id": "abc", "ok": True}}, {}) == {"id": "abc", "ok": True}
    # args are threaded through
    assert invoke_tool({"fn": lambda x: x * 2}, {"x": 21}) == 42

    # a non-DB error is NOT swallowed by the seam
    def boom(**kw):
        raise ValueError("a real bug")

    with pytest.raises(ValueError):
        invoke_tool({"fn": boom}, {})


def test_mcp_seam_logs_non_transient_db_error(caplog):
    """The non-transient `_DB_ERROR` tells the operator to 'see the server log', so the seam
    must actually log the original exception server-side (finding #3) — while still never
    RETURNING the raw SQL to the agent."""
    import logging

    from hexgraph.agent.mcp_server import invoke_tool

    exc = _non_lock_error()
    spec = {"name": "graph_create_node", "group": "write",
            "fn": lambda **kw: (_ for _ in ()).throw(exc)}
    with caplog.at_level(logging.ERROR, logger="hexgraph.agent.mcp_server"):
        out = invoke_tool(spec, {})
    assert out["error"].startswith("database error")
    # the server log carries the real exception (so the "see the server log" hint is true)
    assert caplog.records, "non-transient DB error was not logged server-side"
    logged = "\n".join(r.getMessage() + (r.exc_text or "") for r in caplog.records)
    assert "OperationalError" in logged or "no such table" in logged


# ── the retry is WIRED into the write-group seam (finding #1) ───────────────────────────

def test_mcp_write_seam_retries_locked_write_and_persists(hg_home, monkeypatch):
    """The end-to-end fix for F11: a WRITE tool whose commit loses the lock once is re-run by
    invoke_tool (write group) and the row ultimately PERSISTS — proving the retry is wired in,
    not just defined. Uses the real create_node tool against the real engine."""
    from hexgraph.agent import mcp_tools
    from hexgraph.agent.mcp_server import invoke_tool
    from hexgraph.db.models import Node
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project, ingest_file
    from conftest import fixture_path

    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)

    with session_scope() as s:
        p = create_project(s, name="wired")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id

    real_commit = db_session.Session.commit
    # Arm ONLY around the tool call: the only commit that happens while armed is the tool's
    # own session_scope commit (project/target are already created above). Fail its first
    # commit with a lock, then let every commit through — a retry re-runs the call cleanly.
    state = {"armed": False, "failed": False}

    def flaky_commit(self):
        if state["armed"] and not state["failed"]:
            state["failed"] = True
            raise _lock_error()
        return real_commit(self)

    monkeypatch.setattr(db_session.Session, "commit", flaky_commit)

    spec = {"name": "graph_create_node", "group": "write",
            "fn": lambda **kw: mcp_tools.create_node(**kw)}
    state["armed"] = True
    out = invoke_tool(spec, {"project_id": pid, "node_type": "function",
                             "name": "ssdp_recv", "target_id": tid})
    state["armed"] = False

    assert state["failed"], "the simulated lock never fired — test didn't exercise the retry"
    assert isinstance(out, dict) and out.get("id"), out  # the tool succeeded on retry
    monkeypatch.setattr(db_session.Session, "commit", real_commit)
    with session_scope() as s:
        # exactly one node persisted — re-running after a FAILED (rolled-back) commit can't dupe
        assert s.query(Node).filter(Node.project_id == pid, Node.name == "ssdp_recv").count() == 1


def test_mcp_run_group_tool_is_not_retried(monkeypatch):
    """Only WRITE tools retry. A `run`/task tool that hits a lock must NOT be re-run by the
    seam (retrying a multi-minute task is wrong) — it runs once, then surfaces the sanitized
    retryable error for the agent to decide."""
    monkeypatch.setattr(db_session, "_retry_backoff", lambda _a: None)
    from hexgraph.agent.mcp_server import invoke_tool

    calls = {"n": 0}

    def task(**kw):
        calls["n"] += 1
        raise _lock_error()

    out = invoke_tool({"name": "task_run", "group": "run", "fn": task}, {})
    assert calls["n"] == 1                      # ran once, NOT retried
    assert "retry" in out["error"].lower()      # still sanitized + flagged retryable for the agent
