"""Write-path resilience under multi-agent fan-out.

WAL + busy_timeout=5000 already live in db/session.py (they make a writer *wait*
for the lock). These tests cover the two gaps this change closes:

  1. A bounded retry-with-backoff at the WRITE-UNIT boundary (`with_write_retry`):
     a transient `OperationalError: database is locked` re-runs the whole unit of
     work a few times, then re-raises if it never clears; a NON-lock
     OperationalError (corruption, schema drift) is never retried or masked.
     Retry must re-run the unit, not just the commit: once commit() raises,
     SQLAlchemy invalidates the transaction and rollback discards the staged work.
  2. The MCP seam (`agent.mcp_server.invoke_tool`) sanitizes DB errors so the raw
     failing SQL and its bound parameters (which `str(OperationalError)` carries)
     never reach the agent — only a structured, retryable {"error": ...}.
"""

import sqlite3

import pytest
from sqlalchemy.exc import OperationalError

from hexgraph.db import session as db_session
from hexgraph.db.session import with_write_retry


def _lock_error() -> OperationalError:
    """An OperationalError shaped exactly like SQLite's busy/locked one: its str()
    carries the failing SQL + bound params (the thing we must NOT leak)."""
    return OperationalError(
        "INSERT INTO finding (title, secret_param) VALUES (?, ?)",
        ("SUPER_SECRET_TITLE", "hunter2"),
        sqlite3.OperationalError("database is locked"),
    )


def _non_lock_error() -> OperationalError:
    return OperationalError(
        "SELECT * FROM finding",
        (),
        sqlite3.OperationalError("no such table: finding"),
    )


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
