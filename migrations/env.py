"""Alembic environment.

The DB URL is resolved from HexGraph config (HEXGRAPH_DB_PATH or
~/.hexgraph/hexgraph.db) rather than alembic.ini, so the CLI and the programmatic
runner in `hexgraph.db.migrate` agree. `render_as_batch=True` enables SQLite
ALTER support for future migrations.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from hexgraph.db.models import Base
from hexgraph.db.session import db_url

target_metadata = Base.metadata


def _url() -> str:
    # Allow an explicit override set by the programmatic runner.
    configured = context.config.get_main_option("sqlalchemy.url")
    return configured or db_url()


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
