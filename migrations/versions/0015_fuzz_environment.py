"""fuzz_environment — registered remote fuzz environments (design §5.8b, Phase 6)

A `fuzz_environment` is a place a campaign's container can run: `local` (the host
Docker daemon, always implicit) plus N user-owned REMOTE Docker endpoints reached via
DOCKER_HOST (ssh:// over an SSH control socket, or tcp:// + TLS client certs). A
campaign SELECTS one (defaulting `local`).

This table holds ONLY NON-SECRET metadata: a stable id, a human label, a non-secret
host descriptor, the transport, a per-environment ResourceSpec ceiling, and the cached
last health-check. The SECRET connection details (the full DOCKER_HOST string, SSH
key/password, TLS certs) are NEVER stored here — they are read at connect time from
env/config.toml keyed by the environment id (same discipline as the SSH/telnet remote
creds). Environments are HOST-level (no project_id): a registered box serves every
project. The frozen Finding schema is untouched.

Revision ID: 0015_fuzz_environment
Revises: 0014_fuzz_campaign
Create Date: 2026-06-02
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_fuzz_environment"
down_revision = "0014_fuzz_campaign"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fuzz_environment",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("transport", sa.String(length=8), nullable=False),
        sa.Column("host_descriptor", sa.String(length=255), nullable=True),
        sa.Column("resources_json", sa.JSON(), nullable=False),
        sa.Column("last_health_json", sa.JSON(), nullable=False),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("fuzz_environment", schema=None) as batch:
        batch.create_index(batch.f("ix_fuzz_environment_archived"), ["archived"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("fuzz_environment", schema=None) as batch:
        batch.drop_index(batch.f("ix_fuzz_environment_archived"))
    op.drop_table("fuzz_environment")
