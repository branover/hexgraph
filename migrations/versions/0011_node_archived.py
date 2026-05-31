"""node.archived — soft removal of nodes (hide node + its edges; restore on re-add)

Mirrors target.archived. An archived node and the edges touching it drop out of the
graph/search; re-adding the same node un-archives it and the edges reappear.

Revision ID: 0011_node_archived
Revises: 0010_egress_event
Create Date: 2026-05-31
"""
import sqlalchemy as sa
from alembic import op

revision = "0011_node_archived"
down_revision = "0010_egress_event"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("node") as batch:
        batch.add_column(sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_node_archived", "node", ["archived"])


def downgrade() -> None:
    op.drop_index("ix_node_archived", table_name="node")
    with op.batch_alter_table("node") as batch:
        batch.drop_column("archived")
