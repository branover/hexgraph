"""task anchor (anchor_kind, anchor_id)

Revision ID: 0004_task_anchor
Revises: 0003_context_runs
Create Date: 2026-05-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_task_anchor"
down_revision = "0003_context_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("task", sa.Column("anchor_kind", sa.String(length=16), nullable=True))
    op.add_column("task", sa.Column("anchor_id", sa.String(length=36), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("task") as b:
        b.drop_column("anchor_id")
        b.drop_column("anchor_kind")
