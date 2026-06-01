"""Annotations: rename/note/tag/type_decl on graph entities."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Annotation, Project
from hexgraph.db.session import session_scope
from hexgraph.engine.annotations import AnnotationError, create_annotation, set_status

from ._shared import AnnotationCreate, StatusUpdate, ann_dict

router = APIRouter()


@router.post("/api/projects/{project_id}/annotations")
def api_create_annotation(project_id: str, body: AnnotationCreate):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        try:
            a = create_annotation(s, project_id, node_kind=body.node_kind, node_id=body.node_id,
                                  kind=body.kind, value=body.value)
        except AnnotationError as exc:
            raise HTTPException(400, str(exc))
        return ann_dict(a)


@router.get("/api/annotations/{node_kind}/{node_id}")
def api_list_annotations(node_kind: str, node_id: str):
    with session_scope() as s:
        anns = s.query(Annotation).filter(Annotation.node_kind == node_kind, Annotation.node_id == node_id).all()
        return [ann_dict(a) for a in anns]


@router.post("/api/annotations/{annotation_id}/status")
def api_annotation_status(annotation_id: str, body: StatusUpdate):
    with session_scope() as s:
        try:
            a = set_status(s, annotation_id, body.status)
        except AnnotationError as exc:
            raise HTTPException(400, str(exc))
        return ann_dict(a)
