"""index target.parent_id for target-children pagination

Revision ID: 95bb894a0ef6
Revises: 0020_target_visible
Create Date: 2026-07-08 23:22:07.534529

The new GET /api/projects/{id}/target-children endpoint (the Targets sidebar's
lazy per-directory fetch) filters on parent_id — previously unindexed, so
every directory expansion on an 8000+-target project did a full table scan.
"""
from alembic import op
import sqlalchemy as sa


revision = '95bb894a0ef6'
down_revision = '0020_target_visible'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('target', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_target_parent_id'), ['parent_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('target', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_target_parent_id'))
