"""Migration runner (SPEC v2 ruling #1).

The project DB is durable researcher knowledge — never silently reset. Schema
changes ship as Alembic migrations; `prepare_database()` brings a DB to head,
backing it up first, and adopts a legacy (pre-Alembic, create_all'd) DB by
stamping it rather than re-creating tables.

Discipline going forward: any model/schema change ships an Alembic migration
(`alembic revision --autogenerate -m <msg>`), reviewed and committed. Tests use
`init_db()` (create_all) on throwaway DBs and never migrate them.
"""

from __future__ import annotations

import shutil

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from hexgraph.db.session import db_url, resolve_db_path
from hexgraph.paths import repo_root

CORE_TABLES = {"project", "target", "edge", "task", "finding"}


def _alembic_config() -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(repo_root() / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url())
    return cfg


def current_revision() -> str | None:
    engine = create_engine(db_url())
    try:
        with engine.connect() as conn:
            return MigrationContext.configure(conn).get_current_revision()
    finally:
        engine.dispose()


def prepare_database(*, backup: bool = True) -> dict:
    """Bring the current DB to head. Returns {action, revision, db}.

    - Fresh/empty DB → run migrations from baseline.
    - Legacy create_all'd DB (core tables, no alembic_version) → stamp head
      (adopt in place; safe while baseline == current schema).
    - Versioned DB below head → back up, then upgrade.
    """
    path = resolve_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = _alembic_config()

    engine = create_engine(db_url())
    try:
        existing = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    versioned = "alembic_version" in existing
    has_core = bool(CORE_TABLES & existing)

    if has_core and not versioned:
        command.stamp(cfg, "head")
        action = "stamped"
    else:
        if backup and path.exists() and path.stat().st_size > 0:
            shutil.copy2(path, path.with_name(path.name + ".bak"))
        command.upgrade(cfg, "head")
        action = "upgraded"

    return {"action": action, "revision": current_revision(), "db": str(path)}
