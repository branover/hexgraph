"""context bundle + items + analysis_run + task.context_bundle_id

Revision ID: 0003_context_runs
Revises: 0002_typed_graph
Create Date: 2026-05-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_context_runs"
down_revision = "0002_typed_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("task", sa.Column("context_bundle_id", sa.String(length=36), nullable=True))

    op.create_table(
        "context_bundle",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=True),
        sa.Column("bundle_sha", sa.String(length=64), nullable=False),
        sa.Column("assembler_version", sa.String(length=20), nullable=False),
        sa.Column("token_estimate", sa.Integer(), nullable=False),
        sa.Column("token_budget", sa.Integer(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("dropped_count", sa.Integer(), nullable=False),
        sa.Column("deps_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_context_bundle_project_id", "context_bundle", ["project_id"])
    op.create_index("ix_context_bundle_bundle_sha", "context_bundle", ["bundle_sha"])

    op.create_table(
        "context_item",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("bundle_id", sa.String(length=36), nullable=False),
        sa.Column("order_index", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("src_kind", sa.String(length=16), nullable=True),
        sa.Column("src_id", sa.String(length=36), nullable=True),
        sa.Column("content_ref", sa.String(length=64), nullable=True),
        sa.Column("preview", sa.Text(), nullable=True),
        sa.Column("est_tokens", sa.Integer(), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("included", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(["bundle_id"], ["context_bundle.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_context_item_bundle_id", "context_item", ["bundle_id"])

    op.create_table(
        "analysis_run",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("anchor_kind", sa.String(length=16), nullable=False),
        sa.Column("anchor_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("task_type", sa.String(length=50), nullable=False),
        sa.Column("backend", sa.String(length=50), nullable=True),
        sa.Column("model", sa.String(length=100), nullable=True),
        sa.Column("params_json", sa.JSON(), nullable=False),
        sa.Column("bundle_sha", sa.String(length=64), nullable=True),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_analysis_run_project_id", "analysis_run", ["project_id"])
    op.create_index("ix_analysis_run_anchor_id", "analysis_run", ["anchor_id"])


def downgrade() -> None:
    op.drop_table("analysis_run")
    op.drop_table("context_item")
    op.drop_table("context_bundle")
    with op.batch_alter_table("task") as b:
        b.drop_column("context_bundle_id")
