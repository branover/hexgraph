"""widen finding.status + HITL envelope (origin, dismissed_reason, supersedes, human_notes)

Revision ID: 0005_triage_envelope
Revises: 0004_task_anchor
Create Date: 2026-05-30

Rebuilds `finding` (SQLite: create/copy/swap) to drop the old status CHECK
constraint (status becomes a plain String so the triage vocabulary can widen
freely) and add the HITL envelope columns. Maps legacy 'accepted' -> 'confirmed'.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005_triage_envelope"
down_revision = "0004_task_anchor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_new",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("task_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("reasoning", sa.Text(), nullable=False),
        sa.Column("evidence_json", sa.JSON(), nullable=False),
        sa.Column("suggested_followups_json", sa.JSON(), nullable=False),
        sa.Column("related_target_refs_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("dismissed_reason", sa.String(length=200), nullable=True),
        sa.Column("supersedes_id", sa.String(length=36), nullable=True),
        sa.Column("human_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["project.id"]),
        sa.ForeignKeyConstraint(["target_id"], ["target.id"]),
        sa.ForeignKeyConstraint(["task_id"], ["task.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.execute(
        """
        INSERT INTO finding_new
            (id, project_id, target_id, task_id, title, severity, confidence, category,
             summary, reasoning, evidence_json, suggested_followups_json, related_target_refs_json,
             status, origin, dismissed_reason, supersedes_id, human_notes, created_at)
        SELECT id, project_id, target_id, task_id, title, severity, confidence, category,
               summary, reasoning, evidence_json, suggested_followups_json, related_target_refs_json,
               CASE status WHEN 'accepted' THEN 'confirmed' ELSE status END,
               'agent', NULL, NULL, NULL, created_at
        FROM finding
        """
    )
    op.drop_table("finding")
    op.rename_table("finding_new", "finding")


def downgrade() -> None:
    op.execute("UPDATE finding SET status='accepted' WHERE status IN ('confirmed','reported','triaging')")
    with op.batch_alter_table("finding") as b:
        b.drop_column("human_notes")
        b.drop_column("supersedes_id")
        b.drop_column("dismissed_reason")
        b.drop_column("origin")
