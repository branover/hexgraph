"""Hypotheses: research questions evidenced by findings.

The list endpoint backs the Hypotheses worklist panel; the work-state/pin endpoints
drive the panel's "check off" and "pin to graph" controls. See
docs/design/design-working-memory.md §4 (hypotheses as a task list).
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Node, Project
from hexgraph.db.session import session_scope
from hexgraph.engine.hypotheses import (
    HypothesisError,
    create_hypothesis,
    link_evidence,
    list_hypotheses,
    set_pinned,
    set_status,
    set_work_state,
    summary,
)

from ._shared import (
    EvidenceLink,
    HypothesisCreate,
    HypothesisPin,
    HypothesisWorkState,
    StatusUpdate,
)

router = APIRouter()


@router.post("/api/projects/{project_id}/hypotheses")
def api_create_hypothesis(project_id: str, body: HypothesisCreate):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            node = create_hypothesis(s, project, statement=body.statement,
                                     rationale=body.rationale, target_id=body.target_id)
            return summary(s, node.id)
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))


@router.get("/api/projects/{project_id}/hypotheses")
def api_list_hypotheses(project_id: str, work_state: str | None = None, status: str | None = None):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            return {"hypotheses": list_hypotheses(s, project, work_state=work_state, status=status)}
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))


@router.get("/api/hypotheses/{hypothesis_id}")
def api_hypothesis(hypothesis_id: str):
    with session_scope() as s:
        try:
            return summary(s, hypothesis_id)
        except HypothesisError as exc:
            raise HTTPException(404, str(exc))


@router.post("/api/hypotheses/{hypothesis_id}/evidence")
def api_hypothesis_evidence(hypothesis_id: str, body: EvidenceLink):
    with session_scope() as s:
        node = s.get(Node, hypothesis_id)
        project = s.get(Project, node.project_id) if node is not None else None
        if project is None:
            raise HTTPException(404, "hypothesis not found")
        try:
            link_evidence(s, project, hypothesis_id=hypothesis_id, finding_id=body.finding_id,
                          relation=body.relation)
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))
        return summary(s, hypothesis_id)


@router.post("/api/hypotheses/{hypothesis_id}/status")
def api_hypothesis_status(hypothesis_id: str, body: StatusUpdate):
    with session_scope() as s:
        try:
            set_status(s, hypothesis_id, body.status)
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))
        return summary(s, hypothesis_id)


@router.post("/api/hypotheses/{hypothesis_id}/work-state")
def api_hypothesis_work_state(hypothesis_id: str, body: HypothesisWorkState):
    """Move a hypothesis along the work-state axis (investigating/parked/done). Pass
    `verdict` to also record the evidence outcome when closing (the panel's "check off")."""
    with session_scope() as s:
        try:
            set_work_state(s, hypothesis_id, body.work_state, verdict=body.verdict)
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))
        return summary(s, hypothesis_id)


@router.post("/api/hypotheses/{hypothesis_id}/pin")
def api_hypothesis_pin(hypothesis_id: str, body: HypothesisPin):
    """Pin/unpin a hypothesis to the graph canvas (attrs.pinned_to_graph)."""
    with session_scope() as s:
        try:
            set_pinned(s, hypothesis_id, body.pinned)
        except HypothesisError as exc:
            raise HTTPException(400, str(exc))
        return summary(s, hypothesis_id)
