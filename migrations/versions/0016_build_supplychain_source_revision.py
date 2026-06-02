"""build supply-chain provenance + editable-IDE source revisions (design §3.5/§6.2, Phase 7)

Adds:
  - `source_revision` — the editable-IDE revision history (design §6.2 D-edit): a save
    never mutates in place; it writes a new revision (content in CAS + a diff), so edits
    are durable + reversible and a build can be launched rebuild-from-revision. Only
    HexGraph-authored/role-tagged files in an editable tree get revisions.
  - new `build` columns for SUPPLY-CHAIN PROVENANCE + DETERMINISM (the DB envelope, not
    the frozen finding schema): `lockfile_json` (hash-pinned deps from the bounded fetch
    phase), `sbom_json` (fetched dep urls+sha256, SBOM-lite), `reproducible` (the
    reproducibility-badge verdict), `cache_hit` (reused a prior CAS artifact for the same
    key), `source_revision_id` (built from a specific revision), `cache_key` (the
    reproducibility cache key, indexed for artifact reuse).

All ADD COLUMNs carry a server_default so the migration applies cleanly to a populated
`build` table; the model has no default at rest, which a fresh init_db (create_all)
satisfies directly. The frozen Finding schema is untouched.

Revision ID: 0016_build_supplychain_source_revision
Revises: 0015_fuzz_environment
Create Date: 2026-06-02
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_build_supplychain_source_revision"
down_revision = "0015_fuzz_environment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_revision",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("source_tree_id", sa.String(length=36), nullable=False),
        sa.Column("rel", sa.String(length=400), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("content_cas", sa.String(length=64), nullable=True),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("diff", sa.Text(), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("note", sa.String(length=300), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("source_revision", schema=None) as batch:
        batch.create_index(batch.f("ix_source_revision_project_id"), ["project_id"], unique=False)
        batch.create_index(batch.f("ix_source_revision_rel"), ["rel"], unique=False)
        batch.create_index(batch.f("ix_source_revision_source_tree_id"), ["source_tree_id"], unique=False)

    with op.batch_alter_table("build", schema=None) as batch:
        batch.add_column(sa.Column("lockfile_json", sa.JSON(), nullable=False,
                                   server_default=sa.text("'{}'")))
        batch.add_column(sa.Column("sbom_json", sa.JSON(), nullable=False,
                                   server_default=sa.text("'[]'")))
        batch.add_column(sa.Column("reproducible", sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
        batch.add_column(sa.Column("cache_hit", sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
        batch.add_column(sa.Column("source_revision_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("cache_key", sa.String(length=64), nullable=True))
        batch.create_index(batch.f("ix_build_cache_key"), ["cache_key"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("build", schema=None) as batch:
        batch.drop_index(batch.f("ix_build_cache_key"))
        batch.drop_column("cache_key")
        batch.drop_column("source_revision_id")
        batch.drop_column("cache_hit")
        batch.drop_column("reproducible")
        batch.drop_column("sbom_json")
        batch.drop_column("lockfile_json")

    with op.batch_alter_table("source_revision", schema=None) as batch:
        batch.drop_index(batch.f("ix_source_revision_source_tree_id"))
        batch.drop_index(batch.f("ix_source_revision_rel"))
        batch.drop_index(batch.f("ix_source_revision_project_id"))
    op.drop_table("source_revision")
