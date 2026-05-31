"""typed graph: node table + polymorphic attributed edge

Revision ID: 0002_typed_graph
Revises: bbdb1d98bf54
Create Date: 2026-05-30

Creates the `node` table and rewrites `edge` from target-only (src_target_id /
dst_target_id / type-with-CHECK / metadata_json) into a polymorphic, attributed
edge. Existing edges are migrated as target→target with origin derived from type.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_typed_graph"
down_revision = "bbdb1d98bf54"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "node",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("node_type", sa.String(length=32), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=300), nullable=False),
        sa.Column("fq_name", sa.String(length=400), nullable=True),
        sa.Column("address", sa.String(length=64), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("attrs_json", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_node_project_id", "node", ["project_id"])
    op.create_index("ix_node_node_type", "node", ["node_type"])
    op.create_index("ix_node_target_id", "node", ["target_id"])
    op.create_index("ix_node_content_hash", "node", ["content_hash"])

    # Rebuild `edge` (SQLite: create new, copy, swap) to shed the old CHECK
    # constraint and add the polymorphic/attribution columns.
    op.create_table(
        "edge_new",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("src_kind", sa.String(length=16), nullable=False),
        sa.Column("src_id", sa.String(length=36), nullable=False),
        sa.Column("dst_kind", sa.String(length=16), nullable=False),
        sa.Column("dst_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("directed", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("weight", sa.Float(), nullable=True),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("created_by_task_id", sa.String(length=36), nullable=True),
        sa.Column("created_by_tool", sa.String(length=64), nullable=True),
        sa.Column("attrs_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.ForeignKeyConstraint(["created_by_task_id"], ["task.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        """
        INSERT INTO edge_new
            (id, project_id, src_kind, src_id, dst_kind, dst_id, type, directed,
             confidence, weight, origin, created_by_task_id, created_by_tool,
             attrs_json, created_at)
        SELECT id, project_id, 'target', src_target_id, 'target', dst_target_id, type, 1,
               NULL, NULL,
               CASE WHEN type = 'related_to' THEN 'llm' ELSE 'tool' END,
               NULL, NULL,
               COALESCE(metadata_json, '{}'), CURRENT_TIMESTAMP
        FROM edge
        """
    )
    op.drop_table("edge")
    op.rename_table("edge_new", "edge")
    op.create_index("ix_edge_project_id", "edge", ["project_id"])
    op.create_index("ix_edge_src", "edge", ["project_id", "src_kind", "src_id"])
    op.create_index("ix_edge_dst", "edge", ["project_id", "dst_kind", "dst_id"])
    op.create_index("ix_edge_type", "edge", ["type"])


def downgrade() -> None:
    op.drop_table("node")
    op.create_table(
        "edge_old",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("src_target_id", sa.String(length=36), nullable=False),
        sa.Column("dst_target_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=40), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        """
        INSERT INTO edge_old (id, project_id, src_target_id, dst_target_id, type, metadata_json)
        SELECT id, project_id, src_id, dst_id, type, attrs_json
        FROM edge WHERE src_kind='target' AND dst_kind='target'
        """
    )
    op.drop_table("edge")
    op.rename_table("edge_old", "edge")
