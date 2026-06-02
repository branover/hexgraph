"""egress_event — audit log for outbound actions against live targets

The bounded-egress (local-network) tier records every outbound action; this table
is its durable home (docs/design/design-dynamic-surfaces.md).

Revision ID: 0010_egress_event
Revises: 0009_edge_endpoint_indexes
Create Date: 2026-05-31
"""
import sqlalchemy as sa
from alembic import op

revision = "0010_egress_event"
down_revision = "0009_edge_endpoint_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "egress_event",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("project.id"), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("task_id", sa.String(length=36), nullable=True),
        sa.Column("dest", sa.String(length=255), nullable=False),
        sa.Column("allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tool", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_egress_event_project_id", "egress_event", ["project_id"])
    op.create_index("ix_egress_event_target_id", "egress_event", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_egress_event_target_id", table_name="egress_event")
    op.drop_index("ix_egress_event_project_id", table_name="egress_event")
    op.drop_table("egress_event")
