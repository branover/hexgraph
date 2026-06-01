"""Ghidra bridge: list open programs, import one as a target."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Project
from hexgraph.db.session import session_scope
from hexgraph.engine.ghidra_bridge import BridgeUnavailable, import_program, list_open_programs

from ._shared import GhidraImport

router = APIRouter()


@router.get("/api/ghidra/programs")
def api_ghidra_programs():
    """List programs open in a connected Ghidra (bridge mode)."""
    try:
        return list_open_programs()
    except BridgeUnavailable as exc:
        raise HTTPException(400, str(exc))


@router.post("/api/projects/{project_id}/ghidra/import")
def api_ghidra_import(project_id: str, body: GhidraImport):
    """Ingest a program Ghidra has open as a target (real on-disk bytes)."""
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            return import_program(s, project, path=body.path, name=body.name)
        except BridgeUnavailable as exc:
            raise HTTPException(400, str(exc))
