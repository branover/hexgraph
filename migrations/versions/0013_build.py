"""build_spec + build — recorded recipe + the build ledger (design §4.5, Phase 2)

The `Builder` seam (engine/build.py) turns a source_tree into an instrumented
artifact via a recorded, reproducible recipe the API/tool layer runs in the
sandbox. The recipe is a `build_spec` row (recipe_sha = hash of {phases, env,
base_image, instrumentation, arch}); every execution is a `build` row — the durable
ledger (status, the reproducibility triple, artifacts as CAS shas, the log in CAS,
timing, error, the derived instrumented target it registered). Both FK-light,
additive, with `archived` soft-removal on the spec. The `instrumented_build_of` /
`builds` edge vocab + the `build_spec` polymorphic endpoint kind are String-column
zero-migration (a code change to EdgeType / EDGE_KINDS + the authoring validator),
so the only schema change here is these two tables.

Vendored/offline only this phase: the build phase runs --network none (the audited
fetch tier is a later phase). The frozen Finding schema is untouched.

Revision ID: 0013_build
Revises: 0012_source_tree
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "0013_build"
down_revision = "0012_source_tree"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "build_spec",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("source_tree_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("system", sa.String(length=20), nullable=False),
        sa.Column("recipe_json", sa.JSON(), nullable=False),
        sa.Column("instrumentation_json", sa.JSON(), nullable=False),
        sa.Column("artifacts_json", sa.JSON(), nullable=False),
        sa.Column("base_image", sa.String(length=120), nullable=False),
        sa.Column("arch", sa.String(length=32), nullable=False),
        sa.Column("network", sa.String(length=8), nullable=False),
        sa.Column("recipe_sha", sa.String(length=64), nullable=True),
        sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("build_spec", schema=None) as batch:
        batch.create_index(batch.f("ix_build_spec_archived"), ["archived"], unique=False)
        batch.create_index(batch.f("ix_build_spec_project_id"), ["project_id"], unique=False)
        batch.create_index(batch.f("ix_build_spec_recipe_sha"), ["recipe_sha"], unique=False)
        batch.create_index(batch.f("ix_build_spec_source_tree_id"), ["source_tree_id"], unique=False)

    op.create_table(
        "build",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("build_spec_id", sa.String(length=36), nullable=False),
        sa.Column("source_tree_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("recipe_sha", sa.String(length=64), nullable=True),
        sa.Column("source_content_hash", sa.String(length=64), nullable=True),
        sa.Column("toolchain_digest", sa.String(length=80), nullable=True),
        sa.Column("artifacts_json", sa.JSON(), nullable=False),
        sa.Column("log_cas", sa.String(length=64), nullable=True),
        sa.Column("instrumentation_json", sa.JSON(), nullable=False),
        sa.Column("returncode", sa.Integer(), nullable=True),
        sa.Column("duration", sa.Float(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("derived_target_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("build", schema=None) as batch:
        batch.create_index(batch.f("ix_build_build_spec_id"), ["build_spec_id"], unique=False)
        batch.create_index(batch.f("ix_build_project_id"), ["project_id"], unique=False)
        batch.create_index(batch.f("ix_build_recipe_sha"), ["recipe_sha"], unique=False)
        batch.create_index(batch.f("ix_build_source_tree_id"), ["source_tree_id"], unique=False)
        batch.create_index(batch.f("ix_build_status"), ["status"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("build", schema=None) as batch:
        batch.drop_index(batch.f("ix_build_status"))
        batch.drop_index(batch.f("ix_build_source_tree_id"))
        batch.drop_index(batch.f("ix_build_recipe_sha"))
        batch.drop_index(batch.f("ix_build_project_id"))
        batch.drop_index(batch.f("ix_build_build_spec_id"))
    op.drop_table("build")

    with op.batch_alter_table("build_spec", schema=None) as batch:
        batch.drop_index(batch.f("ix_build_spec_source_tree_id"))
        batch.drop_index(batch.f("ix_build_spec_recipe_sha"))
        batch.drop_index(batch.f("ix_build_spec_project_id"))
        batch.drop_index(batch.f("ix_build_spec_archived"))
    op.drop_table("build_spec")
