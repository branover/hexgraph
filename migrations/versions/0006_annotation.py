"""annotation table (rename/note/tag) — P6 HITL

Revision ID: 0006_annotation
Revises: 0005_triage_envelope
Create Date: 2026-05-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0006_annotation"
down_revision = "0005_triage_envelope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "annotation",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("node_kind", sa.String(length=16), nullable=False),
        sa.Column("node_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_annotation_project_id", "annotation", ["project_id"])
    op.create_index("ix_annotation_node_id", "annotation", ["node_id"])


def downgrade() -> None:
    op.drop_table("annotation")
