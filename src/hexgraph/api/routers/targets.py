"""Targets: ingest/archive/restore, decompile, unpacked-filesystem browsing."""

from __future__ import annotations

import os
import shutil
import tempfile

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from hexgraph.db.models import Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.filesystem import (
    FilesystemError,
    add_file_as_target,
    list_filesystem,
    read_file,
)
from hexgraph.engine.ingest import ingest_file
from hexgraph.engine.pipeline import analyze_target
from hexgraph.engine.targets import archive_target, restore_matching, restore_target
from hexgraph.engine.unpack import build_links_against
# Import the modules (not the names) so tests can monkeypatch runner.docker_available /
# executor.get_executor and have HTTP routes pick up the patched callable.
from hexgraph.sandbox import executor, runner

router = APIRouter()


@router.post("/api/projects/{project_id}/targets")
def api_add_target(
    project_id: str,
    file: UploadFile = File(...),
    name: str | None = Form(None),
    recon: bool = Form(True),
):
    """Upload real bytes → ingest → (sandboxed) recon populates the facts and,
    for firmware, unpacks child targets. Targets only ever come from bytes."""
    fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(file.filename or "")[1])
    with os.fdopen(fd, "wb") as out:
        shutil.copyfileobj(file.file, out)
    try:
        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            if recon and not runner.docker_available():
                raise HTTPException(400, "Docker is required to analyze a target. Start Docker, "
                                         "or upload with recon=false to register bytes only.")
            # Re-adding bytes that were previously removed restores the archived
            # target (and its findings) instead of creating a duplicate.
            restored = restore_matching(s, project, tmp)
            if restored is not None:
                return {"target_id": restored.id, "name": restored.name, "restored": True}
            target = ingest_file(s, project, tmp, name=name or file.filename)
            result = {"target_id": target.id, "name": target.name, "recon": recon}
            if recon:
                summary = analyze_target(s, project, target, executor.get_executor())
                build_links_against(s, project)
                result["children"] = summary.get("children", [])
            return result
    finally:
        os.unlink(tmp)


@router.delete("/api/projects/{project_id}/targets/{target_id}")
def api_remove_target(project_id: str, target_id: str):
    """Soft-remove a target + its subtree (nodes/findings hidden, not deleted).
    Re-adding the same bytes restores them."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        try:
            n = archive_target(s, project_id, target_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        return {"archived": n}


@router.post("/api/projects/{project_id}/targets/{target_id}/restore")
def api_restore_target(project_id: str, target_id: str):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        try:
            return {"restored": restore_target(s, project_id, target_id)}
        except ValueError as exc:
            raise HTTPException(404, str(exc))


@router.post("/api/targets/{target_id}/decompile")
def api_decompile(target_id: str, body: dict):
    """Decompile a function on demand for the in-app viewer (sandboxed). Returns
    {available, focus|detail}. Degrades gracefully when Docker/sandbox is absent."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        if not runner.docker_available():
            return {"available": False, "detail": "Docker/sandbox not running — decompilation needs it."}
        try:
            from hexgraph.sandbox.decompiler import get_decompiler

            out = get_decompiler().decompile(t.path, body.get("function"))
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "detail": f"decompilation failed: {exc}"}
        return {"available": True, "functions": out.get("functions", []), "focus": out.get("focus")}


@router.get("/api/targets/{target_id}/filesystem")
def api_target_filesystem(target_id: str):
    """The unpacked filesystem manifest of a firmware target (browsable tree)."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        return list_filesystem(s.get(Project, t.project_id), t)


@router.get("/api/targets/{target_id}/file")
def api_target_file(target_id: str, rel: str):
    """Read one file from a firmware's unpacked filesystem for the in-UI viewer
    (text or hex, bounded, path-traversal safe)."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        try:
            return read_file(s.get(Project, t.project_id), t, rel)
        except FilesystemError as exc:
            raise HTTPException(400, str(exc))


@router.post("/api/projects/{project_id}/targets/{target_id}/add-from-fs")
def api_add_from_fs(project_id: str, target_id: str, body: dict):
    """Add a file from a firmware's unpacked filesystem as a child target."""
    with session_scope() as s:
        project = s.get(Project, project_id)
        fw = s.get(Target, target_id)
        if project is None or fw is None:
            raise HTTPException(404, "not found")
        try:
            child = add_file_as_target(s, project, fw, body.get("rel", ""))
        except FilesystemError as exc:
            raise HTTPException(400, str(exc))
        return {"target_id": child.id, "name": child.name, "kind": child.kind.value}
