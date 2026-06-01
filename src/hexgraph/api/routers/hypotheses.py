"""Hypotheses: research questions evidenced by findings."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Node, Project
from hexgraph.db.session import session_scope
from hexgraph.engine.hypotheses import (
    HypothesisError,
    create_hypothesis,
    link_evidence,
    set_status,
    summary,
)

from ._shared import EvidenceLink, HypothesisCreate, StatusUpdate

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
