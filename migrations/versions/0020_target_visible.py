"""add visible flag to target (hidden-by-default firmware children)

Revision ID: 0020_target_visible
Revises: 0019_journal
Create Date: 2026-06-08 18:44:13.077298

Adds `target.visible` (default True, indexed). A hidden target is recorded +
searchable + addressable but contributes nothing to the curated graph until
revealed. Server default 1 so EVERY existing target/project is unaffected
(stays visible); only `unpack_firmware` registers firmware ELF children hidden
going forward.
"""
from alembic import op
import sqlalchemy as sa


revision = '0020_target_visible'
down_revision = '0019_journal'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('target', schema=None) as batch_op:
        # server_default="1" backfills existing rows as visible (the column is NOT NULL);
        # new rows take the model-level default (True) — no app-visible default change.
        batch_op.add_column(sa.Column('visible', sa.Boolean(), nullable=False, server_default='1'))
        batch_op.create_index(batch_op.f('ix_target_visible'), ['visible'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('target', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_target_visible'))
        batch_op.drop_column('visible')
