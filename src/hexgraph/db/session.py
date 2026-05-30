"""Engine + session management. SQLite under ~/.hexgraph/hexgraph.db.

v1 uses `create_all` (no Alembic). The DB path can be overridden with
`HEXGRAPH_DB_PATH` (tests point it at a tmp file).
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from hexgraph.config import db_path, ensure_dirs
from hexgraph.db.models import Base

_engine: Engine | None = None
_Session: sessionmaker[Session] | None = None


def _resolve_db_path() -> Path:
    override = os.environ.get("HEXGRAPH_DB_PATH")
    return Path(override) if override else db_path()


def resolve_db_path() -> Path:
    """Public: the SQLite file path in effect (honors HEXGRAPH_DB_PATH)."""
    return _resolve_db_path()


def db_url() -> str:
    """SQLAlchemy/Alembic URL for the current DB."""
    return f"sqlite:///{_resolve_db_path()}"


def get_engine() -> Engine:
    global _engine, _Session
    if _engine is None:
        path = _resolve_db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{path}", future=True)
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
    """Transactional session: commit on success, rollback on error."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_engine_for_tests() -> None:
    """Drop the cached engine so a new HEXGRAPH_DB_PATH takes effect (tests only)."""
    global _engine, _Session
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _Session = None
