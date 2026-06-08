"""Engine + session management. SQLite under ~/.hexgraph/hexgraph.db.

v1 uses `create_all` (no Alembic). The DB path can be overridden with
`HEXGRAPH_DB_PATH` (tests point it at a tmp file).
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, TypeVar

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from hexgraph.config import db_path, ensure_dirs
from hexgraph.db.models import Base

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None

_T = TypeVar("_T")

# Bounded retry-with-backoff for write contention. WAL + busy_timeout (the pragmas below)
# already make a writer *wait* for the lock, but under heavy multi-agent fan-out (the web
# app plus one or more MCP servers, all separate processes) the busy_timeout can still
# elapse and SQLite raises a lock error. `call_with_write_retry` / `with_write_retry`
# re-run the whole unit of work a few times with a short, growing sleep before giving up.
# Only lock errors are retried; any other OperationalError (corrupt DB, disk full, schema
# mismatch, …) re-raises immediately, never masked.
_WRITE_RETRY_ATTEMPTS = 5          # total tries, including the first
_WRITE_RETRY_BASE_SLEEP = 0.05     # seconds; doubles each attempt (0.05, 0.1, 0.2, …)
_WRITE_RETRY_MAX_SLEEP = 0.5       # cap per-attempt sleep so total backoff stays bounded


def _is_lock_error(exc: OperationalError) -> bool:
    """True only for the transient lock/busy family — never for structural errors
    (corruption, disk full, schema drift) which must surface immediately, unmasked.

    Covers all three SQLite lock messages: SQLITE_BUSY ('database is locked') from a
    busy_timeout that elapsed; the alternate 'database is busy' wording; and SQLITE_LOCKED
    ('database table is locked'), a table-level lock that's equally transient under fan-out
    and must NOT fall through to the generic non-retryable branch."""
    msg = str(getattr(exc, "orig", exc)).lower()
    return (
        "database is locked" in msg
        or "database is busy" in msg
        or "database table is locked" in msg  # SQLITE_LOCKED
    )


def _retry_backoff(attempt: int) -> None:
    """Sleep a capped, exponentially-growing moment between write-retry attempts."""
    time.sleep(min(_WRITE_RETRY_BASE_SLEEP * (2 ** attempt), _WRITE_RETRY_MAX_SLEEP))


def _resolve_db_path() -> Path:
    override = os.environ.get("HEXGRAPH_DB_PATH")
    return Path(override) if override else db_path()


def resolve_db_path() -> Path:
    """Public: the SQLite file path in effect (honors HEXGRAPH_DB_PATH)."""
    return _resolve_db_path()


def db_url() -> str:
    """SQLAlchemy/Alembic URL for the current DB."""
    return f"sqlite:///{_resolve_db_path()}"


def _apply_sqlite_pragmas(dbapi_conn, _record) -> None:
    """WAL + a busy timeout so the web app and a coding agent's MCP server (separate
    processes) can read/write the same SQLite file concurrently without
    'database is locked'. WAL allows many readers alongside one writer; the busy
    timeout makes a writer wait briefly instead of failing immediately."""
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.execute("PRAGMA synchronous=NORMAL")
    # NB: foreign_keys is intentionally left OFF — edges/annotations reference
    # entities polymorphically by string id (not FKs), and merge/cascade logic
    # reparents rows explicitly; enabling enforcement would break those paths.
    cur.close()


def get_engine() -> Engine:
    global _engine, _Session
    if _engine is None:
        path = _resolve_db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(
            f"sqlite:///{path}", future=True,
            connect_args={"check_same_thread": False, "timeout": 5},
        )
        event.listen(_engine, "connect", _apply_sqlite_pragmas)
        _Session = sessionmaker(bind=_engine, future=True, expire_on_commit=False)
    return _engine


def init_db() -> None:
    """Create tables if they don't exist (idempotent)."""
    ensure_dirs()
    Base.metadata.create_all(get_engine())


def get_session() -> Session:
    get_engine()
    assert _Session is not None
    return _Session()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional session: commit on success, rollback on error.

    The success path is a single `session.commit()`, unchanged. NOTE: a lock that bites
    at commit can't be retried *here* — once `commit()` raises, SQLAlchemy invalidates the
    transaction and the only legal next step is `rollback()`, which discards the staged
    objects, so retrying the commit alone would commit nothing. The unit of work has to be
    re-run from scratch instead; that's what `with_write_retry` does, and write paths that
    want resilience under contention should use it (it wraps this scope)."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def call_with_write_retry(fn: Callable[..., _T], *args, **kwargs) -> _T:
    """Run a SELF-CONTAINED unit of write work — a callable that opens and commits its OWN
    transaction (e.g. an MCP tool function that uses `session_scope` internally) — with
    bounded retry-with-backoff on transient SQLite write contention. On a lock/busy
    `OperationalError` the WHOLE call is retried after a short, growing sleep; after the last
    attempt the error re-raises, and a non-lock OperationalError (or any other exception)
    re-raises at once, never retried or masked.

    Unlike `with_write_retry`, this does NOT open a `session_scope` itself, so it can wrap a
    function that already manages one without nesting transactions.

    Replaying the unit is SAFE against duplicate rows: a retry only fires when the prior
    attempt's commit FAILED on the lock, which means SQLAlchemy already rolled it back and
    NOTHING was persisted — so re-running can't double-insert. (The callable should still be
    free of non-DB side effects that mustn't repeat.)"""
    for attempt in range(_WRITE_RETRY_ATTEMPTS):
        try:
            return fn(*args, **kwargs)
        except OperationalError as exc:
            # Only the lock/busy family is transient; everything else propagates now.
            if not _is_lock_error(exc) or attempt == _WRITE_RETRY_ATTEMPTS - 1:
                raise
            _retry_backoff(attempt)
    # Unreachable: the loop either returns or re-raises on the final attempt.
    raise RuntimeError("call_with_write_retry exhausted without returning or raising")


def with_write_retry(fn: Callable[[Session], _T]) -> _T:
    """Run a unit of write work with bounded retry-with-backoff on transient SQLite write
    contention. `fn(session)` is called inside a fresh `session_scope` (so it commits on
    return, rolls back on error); if the commit — or any statement in `fn` — fails with a
    lock/busy `OperationalError`, the WHOLE unit is re-run on a fresh session after a short
    growing sleep. Re-running (not just re-committing) is mandatory: a rolled-back session
    has dropped its staged objects, so the work must be rebuilt. After the last attempt the
    error re-raises; a non-lock OperationalError (or any other exception) re-raises at once,
    never retried or masked. `fn` MUST be idempotent/replayable — it may run more than once
    (safe by construction: a retry only fires after a FAILED, rolled-back commit, so nothing
    was persisted on the prior attempt).

    Returns whatever `fn` returns (read values back out of `fn`, not detached ORM objects,
    since the session closes when the scope exits)."""
    def _unit() -> _T:
        with session_scope() as session:
            return fn(session)

    return call_with_write_retry(_unit)


def reset_engine_for_tests() -> None:
    """Drop the cached engine so a new HEXGRAPH_DB_PATH takes effect (tests only)."""
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None
