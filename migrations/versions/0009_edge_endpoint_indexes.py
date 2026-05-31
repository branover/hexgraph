"""edge: single-column src_id/dst_id indexes (reconcile migration ↔ models)

Migrated DBs only had the composite ix_edge_src / ix_edge_dst
(project_id, *_kind, *_id), but the models also declare single-column indexes on
src_id and dst_id (via index=True). Those single-column indexes serve
edges_touching(), which filters on an id alone (no project_id) and so cannot use
the composite indexes. Add them so a migrated DB matches a create_all DB (no
schema drift) and endpoint lookups are indexed.

Revision ID: 0009_edge_endpoint_indexes
Revises: 0008_finding_type
Create Date: 2026-05-31
"""
from alembic import op

revision = "0009_edge_endpoint_indexes"
down_revision = "0008_finding_type"
branch_labels = None
depends_on = None


def _existing(name: str) -> bool:
    bind = op.get_bind()
    rows = bind.exec_driver_sql(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='edge'"
    ).fetchall()
    return name in {r[0] for r in rows}


def upgrade() -> None:
    # Idempotent: only create if absent (a create_all DB already has them).
    if not _existing("ix_edge_src_id"):
        op.create_index("ix_edge_src_id", "edge", ["src_id"])
    if not _existing("ix_edge_dst_id"):
        op.create_index("ix_edge_dst_id", "edge", ["dst_id"])


def downgrade() -> None:
    if _existing("ix_edge_dst_id"):
        op.drop_index("ix_edge_dst_id", table_name="edge")
    if _existing("ix_edge_src_id"):
        op.drop_index("ix_edge_src_id", table_name="edge")
