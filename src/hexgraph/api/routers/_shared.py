"""Shared request models + response-shaping helpers for the API routers.

These were module-level in the old monolithic `api/app.py`; lifted here so each
router imports them without duplication.
"""

from __future__ import annotations

from pydantic import BaseModel

from hexgraph.db.models import Finding, Project, Target, Task
from hexgraph.engine.findings import is_verified, row_to_payload


# --- Request bodies ---

class StatusUpdate(BaseModel):
    status: str


class AnnotationCreate(BaseModel):
    node_kind: str
    node_id: str
    kind: str  # rename | note | tag | type_decl
    value: str


class HypothesisCreate(BaseModel):
    statement: str
    rationale: str | None = None
    target_id: str | None = None


class EvidenceLink(BaseModel):
    finding_id: str
    relation: str  # supports | refutes


class GhidraImport(BaseModel):
    path: str
    name: str | None = None


class ProjectCreate(BaseModel):
    name: str
    backend: str | None = "mock"


class NodeCreate(BaseModel):
    node_type: str
    name: str
    target_id: str | None = None
    address: str | None = None
    attrs: dict | None = None


class EdgeCreate(BaseModel):
    src_kind: str
    src_id: str
    dst_kind: str
    dst_id: str
    type: str
    attrs: dict | None = None
    merge: bool = False


class EdgeAttrsUpdate(BaseModel):
    attrs: dict
    merge: bool = True


class SocketCreate(BaseModel):
    kind: str = "tcp"
    port: int | str | None = None
    name: str | None = None
    bind_addr: str | None = None
    attrs: dict | None = None


class TaskCreate(BaseModel):
    target_id: str
    type: str = "recon"
    objective: str | None = None
    model: str | None = None
    backend: str | None = None
    mock_scenario: str | None = None
    params: dict | None = None
    parent_finding_id: str | None = None
    anchor_kind: str | None = None
    anchor_id: str | None = None


class BulkStatus(BaseModel):
    ids: list[str]
    status: str


class FindingPatch(BaseModel):
    severity: str | None = None
    confidence: str | None = None
    title: str | None = None
    human_notes: str | None = None
    dismissed_reason: str | None = None
    status: str | None = None
    # Full-field edit (analyst correcting/completing a finding in the UI). Tags are NOT
    # here — they're annotations (kind=tag), edited via the annotations API.
    category: str | None = None
    summary: str | None = None
    reasoning: str | None = None
    evidence: dict | None = None


class NodePatch(BaseModel):
    name: str | None = None
    address: str | None = None
    attrs: dict | None = None


# --- Response shaping ---

def project_dict(p: Project) -> dict:
    return {"id": p.id, "name": p.name, "backend": p.llm_backend.value, "created_at": p.created_at}


def target_dict(t: Target) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "kind": t.kind.value,
        "format": t.format,
        "arch": t.arch,
        "parent_id": t.parent_id,
        "metadata": t.metadata_json or {},
    }


def task_dict(t: Task) -> dict:
    return {
        "id": t.id, "type": t.type, "status": t.status.value, "target_id": t.target_id,
        "anchor_kind": t.anchor_kind, "anchor_id": t.anchor_id,
        "backend": t.backend, "model": t.model, "cost_estimate": t.cost_estimate,
        "objective": t.objective_text, "params": t.params_json or {},
        "parent_finding_id": t.parent_finding_id, "context_bundle_id": t.context_bundle_id,
        "created_at": t.created_at, "finished_at": t.finished_at,
    }


def finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "target_id": f.target_id,
        "task_id": f.task_id,
        "status": f.status,
        "origin": f.origin,
        "finding_type": f.finding_type,
        "verified": is_verified(f.evidence_json),  # a PoC that executed + matched its oracle
        "dismissed_reason": f.dismissed_reason,
        "human_notes": f.human_notes,
        "created_at": f.created_at,
        **row_to_payload(f),
    }


def ann_dict(a) -> dict:
    return {"id": a.id, "node_kind": a.node_kind, "node_id": a.node_id, "kind": a.kind,
            "value": a.value, "origin": a.origin, "status": a.status, "created_at": a.created_at}
