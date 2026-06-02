"""source_tree — managed trees of trusted source (design §4.1/§4.5 D1/D2)

A project holds multiple independent source trees, each optionally linked to a
target via a `built_from` edge. Files live on disk under the project data dir,
indexed by `manifest_json`; `source_file` graph nodes are materialized lazily on
reference (no row per file). This is Phase 1 of the fuzzing+source design —
data-model foundation + read-only IDE browse, NO execution and NO new policy gate.

Node/edge *vocabulary* (`source_file`/`harness` node types; `built_from`/
`located_in`/`harnesses` edge types) is String-column zero-migration; the only
schema change here is this additive table. The `EDGE_KINDS` widening to admit
`source_tree` as a polymorphic endpoint kind is a code change to the constant +
validators (free String columns), not a column-type change.

Revision ID: 0012_source_tree
Revises: 0011_node_archived
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "0012_source_tree"
down_revision = "0011_node_archived"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_tree",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("vcs_rev", sa.String(length=80), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("editable", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("source_tree", schema=None) as batch:
        batch.create_index(batch.f("ix_source_tree_archived"), ["archived"], unique=False)
        batch.create_index(batch.f("ix_source_tree_content_hash"), ["content_hash"], unique=False)
        batch.create_index(batch.f("ix_source_tree_project_id"), ["project_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("source_tree", schema=None) as batch:
        batch.drop_index(batch.f("ix_source_tree_project_id"))
        batch.drop_index(batch.f("ix_source_tree_content_hash"))
        batch.drop_index(batch.f("ix_source_tree_archived"))
    op.drop_table("source_tree")
