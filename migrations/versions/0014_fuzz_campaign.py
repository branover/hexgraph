"""fuzz_campaign + fuzz_artifact — the detached-campaign lifecycle (design §4.5 D7/D8, Phase 3)

A fuzz campaign is a SEPARATE table, not just a `task` (D7): it outlives a single
task tick, is start/stop/resume-able, and accumulates corpus/coverage/dedup across
runs — the durable identity that makes fuzzing *progressive*. A detached, hardened
sandbox container (owned by `container_name`) runs the fuzzer in continuous mode,
streaming artifacts/stats to a `/out` bind-mount; a periodic reaper polls + ingests
them. Crash-safe: because the container is detached and the row durable, a `serve`
restart re-attaches the reaper by `container_name`.

`fuzz_artifact` is the queryable lifecycle record for one deduplicated crash/hang/
leak/oom/corpus (D8); the reproducer BYTES live in CAS (`content_cas`), not here.
`UNIQUE(campaign_id, dedup_key)` keeps ONE representative per stack-hash bucket.

The fuzz edge vocab (`fuzzed_by`/`produced_artifact`/`reproduces`/`covers`) + the
`fuzz_campaign` polymorphic endpoint kind are String-column zero-migration (a code
change to EdgeType / EDGE_KINDS + the authoring validator), so the only schema change
here is these two tables. `resources_json` carries the per-campaign ResourceSpec — a
RESOURCE knob, never a policy/gate relaxation. The frozen Finding schema is untouched.

Revision ID: 0014_fuzz_campaign
Revises: 0013_build
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "0014_fuzz_campaign"
down_revision = "0013_build"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fuzz_campaign",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("surface", sa.String(length=20), nullable=False),
        sa.Column("engine", sa.String(length=20), nullable=False),
        sa.Column("harness_node_id", sa.String(length=36), nullable=True),
        sa.Column("build_spec_id", sa.String(length=36), nullable=True),
        sa.Column("task_id", sa.String(length=36), nullable=True),
        sa.Column("container_name", sa.String(length=80), nullable=True),
        sa.Column("outdir", sa.Text(), nullable=True),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("resources_json", sa.JSON(), nullable=False),
        sa.Column("corpus_ref", sa.String(length=64), nullable=True),
        sa.Column("dictionary_ref", sa.String(length=64), nullable=True),
        sa.Column("coverage_ref", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("stats_json", sa.JSON(), nullable=False),
        sa.Column("instances", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("fuzz_campaign", schema=None) as batch:
        batch.create_index(batch.f("ix_fuzz_campaign_archived"), ["archived"], unique=False)
        batch.create_index(batch.f("ix_fuzz_campaign_container_name"), ["container_name"], unique=False)
        batch.create_index(batch.f("ix_fuzz_campaign_project_id"), ["project_id"], unique=False)
        batch.create_index(batch.f("ix_fuzz_campaign_status"), ["status"], unique=False)
        batch.create_index(batch.f("ix_fuzz_campaign_target_id"), ["target_id"], unique=False)

    op.create_table(
        "fuzz_artifact",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=36), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("content_cas", sa.String(length=64), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sanitizer", sa.String(length=40), nullable=True),
        sa.Column("dedup_key", sa.String(length=64), nullable=True),
        sa.Column("dupe_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("faulting_function", sa.String(length=300), nullable=True),
        sa.Column("exploitability_json", sa.JSON(), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("fuzz_artifact", schema=None) as batch:
        batch.create_index("ix_fuzz_artifact_campaign_dedup", ["campaign_id", "dedup_key"], unique=True)
        batch.create_index(batch.f("ix_fuzz_artifact_campaign_id"), ["campaign_id"], unique=False)
        batch.create_index(batch.f("ix_fuzz_artifact_dedup_key"), ["dedup_key"], unique=False)
        batch.create_index(batch.f("ix_fuzz_artifact_project_id"), ["project_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("fuzz_artifact", schema=None) as batch:
        batch.drop_index(batch.f("ix_fuzz_artifact_project_id"))
        batch.drop_index(batch.f("ix_fuzz_artifact_dedup_key"))
        batch.drop_index(batch.f("ix_fuzz_artifact_campaign_id"))
        batch.drop_index("ix_fuzz_artifact_campaign_dedup")
    op.drop_table("fuzz_artifact")

    with op.batch_alter_table("fuzz_campaign", schema=None) as batch:
        batch.drop_index(batch.f("ix_fuzz_campaign_target_id"))
        batch.drop_index(batch.f("ix_fuzz_campaign_status"))
        batch.drop_index(batch.f("ix_fuzz_campaign_project_id"))
        batch.drop_index(batch.f("ix_fuzz_campaign_container_name"))
        batch.drop_index(batch.f("ix_fuzz_campaign_archived"))
    op.drop_table("fuzz_campaign")
