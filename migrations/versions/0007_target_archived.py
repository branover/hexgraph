"""target.archived — soft removal of targets (reversible)

Revision ID: 0007_target_archived
Revises: 0006_annotation
Create Date: 2026-05-30
"""
from alembic import op
import sqlalchemy as sa

revision = "0007_target_archived"
down_revision = "0006_annotation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("target") as batch:
        batch.add_column(sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_target_archived", "target", ["archived"])


def downgrade() -> None:
    op.drop_index("ix_target_archived", table_name="target")
    with op.batch_alter_table("target") as batch:
        batch.drop_column("archived")
