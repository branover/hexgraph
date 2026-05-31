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


class NodeType(str, enum.Enum):
    """Sub-file / conceptual node kinds (P1 materializes function/symbol/string;
    struct/hypothesis/pattern/task arrive in later phases)."""

    function = "function"
    symbol = "symbol"
    string = "string"
    struct = "struct"
    hypothesis = "hypothesis"
    pattern = "pattern"
    input = "input"      # an untrusted-input source (env/arg/recv) for taint paths
    sink = "sink"        # a dangerous operation reached by tainted data
    task = "task"


class EdgeType(str, enum.Enum):
    """Canonical edge vocabulary (design §3.3). Stored as a string column (no DB
    CHECK constraint) so new types are zero-migration."""

    contains = "contains"
    links_against = "links_against"
    imports_symbol = "imports_symbol"
    exports_symbol = "exports_symbol"
    calls = "calls"
    references = "references"
    reads = "reads"
    writes = "writes"
    instance_of_pattern = "instance_of_pattern"
    similar_to = "similar_to"
    duplicate_of = "duplicate_of"
    derived_from = "derived_from"
    produced_by = "produced_by"
    confirms = "confirms"
    refutes = "refutes"
    supports = "supports"
    contradicts = "contradicts"
    about = "about"
    annotates = "annotates"
    dataflow_hint = "dataflow_hint"
    taints = "taints"          # untrusted data flows from src into dst (source→sink)
    related_to = "related_to"  # generic fallback (kept for back-compat)


# Edge endpoint kinds + provenance origins (plain strings in the DB).
EDGE_KINDS = ("target", "node", "finding", "task")
EDGE_ORIGINS = ("tool", "llm", "human", "derived")


class TaskStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    needs_triage = "needs_triage"


class FindingStatus(str, enum.Enum):
    # Single widened triage axis (design ruling #9). Stored as a String column.
    new = "new"
    triaging = "triaging"
    confirmed = "confirmed"
    dismissed = "dismissed"
    reported = "reported"


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
    # Soft removal: archived targets (and their nodes/findings) are hidden from the
    # graph/lists but never deleted (durable knowledge). Re-adding the same bytes
    # restores them. Cascades down the parent_id subtree.
    archived: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="targets")
    children: Mapped[list["Target"]] = relationship()


class Node(Base):
    """A sub-file / conceptual node (function, symbol, string, ...). Distinct from
    `target` (artifacts with bytes). Identity is content-addressed via
    `content_hash` where available; `fq_name`/`address` are locators."""

    __tablename__ = "node"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    node_type: Mapped[str] = mapped_column(String(32), index=True)
    # The artifact this node lives in (nullable for cross-artifact concepts e.g. pattern).
    target_id: Mapped[str | None] = mapped_column(ForeignKey("target.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(300))
    fq_name: Mapped[str | None] = mapped_column(String(400), nullable=True)
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    attrs_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_by: Mapped[str] = mapped_column(String(32), default="recon")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Edge(Base):
    """One polymorphic, typed, attributed relationship between any two graph
    entities (target | node | finding | task)."""

    __tablename__ = "edge"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    # Polymorphic endpoints — kinds in EDGE_KINDS; ids reference target/node/finding/task.
    src_kind: Mapped[str] = mapped_column(String(16))
    src_id: Mapped[str] = mapped_column(String(36), index=True)
    dst_kind: Mapped[str] = mapped_column(String(16))
    dst_id: Mapped[str] = mapped_column(String(36), index=True)
    type: Mapped[str] = mapped_column(String(40), index=True)
    directed: Mapped[bool] = mapped_column(default=True)
    # Typed attribution (queryable; required for server-side filtering).
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    weight: Mapped[float | None] = mapped_column(Float, nullable=True)
    origin: Mapped[str] = mapped_column(String(16), default="tool")  # EDGE_ORIGINS
    created_by_task_id: Mapped[str | None] = mapped_column(ForeignKey("task.id"), nullable=True)
    created_by_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attrs_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Task(Base):
    __tablename__ = "task"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("target.id"))
    type: Mapped[str] = mapped_column(String(50))
    # The thing this task interrogates (P3): NODE|EDGE|SELECTION|HYPOTHESIS|TARGET.
    # `target_id` stays the resolved primary target the sandbox/decompiler operate on.
    anchor_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)  # None == "target"
    anchor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    objective_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form task params (e.g. {"mock_scenario": ..., "function": ..., "sink": ...}).
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # The frozen context this task ran on (P2). Plain id (app-level provenance).
    context_bundle_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
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

    # Classifies the finding for sort/filter (vulnerability | recon | harness |
    # fuzz_crash | poc | annotation | other). DB envelope, not the frozen schema.
    finding_type: Mapped[str] = mapped_column(String(24), default="vulnerability", index=True)
    # String column (no CHECK) so the triage vocabulary can widen without migration pain.
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.new.value)
    # HITL envelope (design §8): provenance + supersession + human edits.
    origin: Mapped[str] = mapped_column(String(16), default="agent")  # agent|human|agent_edited
    dismissed_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    supersedes_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    human_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Annotation(Base):
    """Human/agent annotation on a graph entity (P6): rename | note | tag | type_decl.
    Keyed by (node_kind, node_id) over target|node|finding. Confirmed renames apply
    to the node's display name; confirmed renames/notes feed back into agent context."""

    __tablename__ = "annotation"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    node_kind: Mapped[str] = mapped_column(String(16))   # target | node | finding
    node_id: Mapped[str] = mapped_column(String(36), index=True)
    kind: Mapped[str] = mapped_column(String(16))        # rename | note | tag | type_decl
    value: Mapped[str] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(16), default="human")     # human | agent_proposed
    status: Mapped[str] = mapped_column(String(16), default="confirmed")  # proposed | confirmed | rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContextBundle(Base):
    """A frozen, content-addressed context assembled for one task run (P2)."""

    __tablename__ = "context_bundle"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    task_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    bundle_sha: Mapped[str] = mapped_column(String(64), index=True)
    assembler_version: Mapped[str] = mapped_column(String(20), default="1")
    token_estimate: Mapped[int] = mapped_column(default=0)
    token_budget: Mapped[int] = mapped_column(default=0)
    item_count: Mapped[int] = mapped_column(default=0)
    dropped_count: Mapped[int] = mapped_column(default=0)
    deps_json: Mapped[list[Any]] = mapped_column(JSON, default=list)  # dependency fingerprints (staleness)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ContextItem(Base):
    __tablename__ = "context_item"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    bundle_id: Mapped[str] = mapped_column(ForeignKey("context_bundle.id"), index=True)
    order_index: Mapped[int] = mapped_column(default=0)
    kind: Mapped[str] = mapped_column(String(40))
    src_kind: Mapped[str | None] = mapped_column(String(16), nullable=True)
    src_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    content_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)  # CAS sha
    preview: Mapped[str | None] = mapped_column(Text, nullable=True)
    est_tokens: Mapped[int] = mapped_column(default=0)
    priority: Mapped[int] = mapped_column(default=0)
    included: Mapped[bool] = mapped_column(default=True)


class AnalysisRun(Base):
    """Groups one task execution's inputs + outputs so runs over the same anchor
    are comparable (run-to-run finding diff)."""

    __tablename__ = "analysis_run"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    project_id: Mapped[str] = mapped_column(ForeignKey("project.id"), index=True)
    anchor_kind: Mapped[str] = mapped_column(String(16), default="target")
    anchor_id: Mapped[str] = mapped_column(String(36), index=True)
    task_id: Mapped[str] = mapped_column(String(36))
    task_type: Mapped[str] = mapped_column(String(50))
    backend: Mapped[str | None] = mapped_column(String(50), nullable=True)
    model: Mapped[str | None] = mapped_column(String(100), nullable=True)
    params_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    bundle_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
