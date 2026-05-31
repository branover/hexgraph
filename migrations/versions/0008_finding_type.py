"""finding.finding_type — classify findings for sort/filter

Revision ID: 0008_finding_type
Revises: 0007_target_archived
Create Date: 2026-05-31
"""
from alembic import op
import sqlalchemy as sa

revision = "0008_finding_type"
down_revision = "0007_target_archived"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("finding") as batch:
        batch.add_column(sa.Column("finding_type", sa.String(length=24),
                                   nullable=False, server_default="vulnerability"))
    op.create_index("ix_finding_finding_type", "finding", ["finding_type"])
    # Backfill: recon findings are the recon type; the rest stay 'vulnerability'.
    op.execute("UPDATE finding SET finding_type = 'recon' WHERE category = 'recon'")


def downgrade() -> None:
    op.drop_index("ix_finding_finding_type", table_name="finding")
    with op.batch_alter_table("finding") as batch:
        batch.drop_column("finding_type")
