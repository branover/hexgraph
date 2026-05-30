"""SQLAlchemy models (SPEC §4). The graph is modeled relationally — no Neo4j.

Entities: project, target (self-referential parent_id tree), edge
(contains | links_against | related_to), task, finding. All ids are UUID strings.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# --- enums (mirror SPEC §4) ----------------------------------------------------


class LLMBackendName(str, enum.Enum):
    mock = "mock"
    anthropic = "anthropic"
    claude_code = "claude_code"


class TargetKind(str, enum.Enum):
    firmware_image = "firmware_image"
    executable = "executable"
    shared_library = "shared_library"
    unknown = "unknown"


class EdgeType(str, enum.Enum):
    contains = "contains"
    links_against = "links_against"
    related_to = "related_to"


class TaskStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    needs_triage = "needs_triage"


class FindingStatus(str, enum.Enum):
    new = "new"
    accepted = "accepted"
    dismissed = "dismissed"


# --- tables --------------------------------------------------------------------


class Project(Base):
    __tablename__ = "project"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    llm_backend: Mapped[LLMBackendName] = mapped_column(
        Enum(LLMBackendName), default=LLMBackendName.mock
    )
    model_pref: Mapped[str | None] = mapped_column(String(100), nullable=True)
    data_dir: Mapped[str] = mapped_column(Text)

    targets: Mapped[list["Target"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Target(Base):
    __tablename__ = "target"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("target.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(300))
    path: Mapped[str] = mapped_column(Text)
    kind: Mapped[TargetKind] = mapped_column(Enum(TargetKind), default=TargetKind.unknown)
    format: Mapped[str | None] = mapped_column(String(100), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(100), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="targets")
    children: Mapped[list["Target"]] = relationship()


class Edge(Base):
    __tablename__ = "edge"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    src_target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    dst_target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    type: Mapped[EdgeType] = mapped_column(Enum(EdgeType))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Task(Base):
    __tablename__ = "task"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    type: Mapped[str] = mapped_column(String(50))
    objective_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form task params (e.g. {"mock_scenario": ..., "function": ..., "sink": ...}).
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus), default=TaskStatus.queued)
    backend: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    cost_estimate: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    log_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Set when this task was spawned from a finding's suggested follow-up.
    parent_finding_id: Mapped[str | None] = mapped_column(ForeignKey("finding.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Finding(Base):
    """Persisted finding = the schema payload (evidence/followups/refs as JSON)
    plus the envelope (ids, status, timestamp)."""

    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    task_id: Mapped[str] = mapped_column(ForeignKey("task.id"))

    title: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(40))
    summary: Mapped[str] = mapped_column(Text)
    reasoning: Mapped[str] = mapped_column(Text)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    suggested_followups_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    related_target_refs_json: Mapped[list[Any]] = mapped_column(JSON, default=list)

    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.new)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
