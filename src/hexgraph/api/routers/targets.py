"""Targets: ingest/archive/restore, decompile, unpacked-filesystem browsing."""

from __future__ import annotations

import os
import shutil
import tempfile

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel

from hexgraph.db.models import Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.filesystem import (
    FilesystemError,
    promote_file,
    list_filesystem,
    read_file,
)
from hexgraph.engine.targets.ingest import ingest_file
from hexgraph.engine.pipeline import analyze_target
from hexgraph.engine.targets.targets import archive_target, restore_matching, restore_target
from hexgraph.engine.targets.unpack import build_links_against
# Import the modules (not the names) so tests can monkeypatch runner.docker_available /
# executor.get_executor and have HTTP routes pick up the patched callable.
from hexgraph.sandbox import executor, runner

router = APIRouter()


def _focus_has_body(out: dict) -> bool:
    """Did a decompile/disassemble actually resolve a function (real pseudocode or disasm)?
    An address focus that misses returns a focus with empty bodies — treat that as a miss so
    the caller can fall back to name resolution."""
    focus = (out or {}).get("focus") or {}
    return bool(focus.get("pseudocode") or focus.get("disasm"))


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


class SocketCreate(BaseModel):
    """Register a bare non-HTTP network service (raw TCP/UDP) as a first-class `service`
    target — no bytes, no credentials. Mirrors the target_register_service MCP tool."""
    host: str
    port: int
    name: str | None = None
    transport: str = "tcp"
    proto: str | None = None
    parent_ref: str | None = None


@router.post("/api/projects/{project_id}/targets/service")
def api_register_service(project_id: str, body: SocketCreate):
    """Register a bare non-HTTP network service (a raw TCP/UDP listener) as a `service`
    target, reached via a Channel `{kind: tcp|udp, host, port}` — NO bytes, NO credentials.
    It's then fuzzable directly (start_campaign infers the `network` surface → boofuzz at
    this host:port) and probeable via the raw-TCP tools, all on the EXISTING bounded local-
    network tier (loopback/private only, features.network, audited). The first-class home for
    a bind shell / vendor binary protocol / custom daemon — distinct from `remote` (no shell)."""
    from hexgraph.engine.targets.surfaces import register_service_target

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        parent = None
        net_container = None
        if body.parent_ref:
            parent = s.get(Target, body.parent_ref)
            if parent is None or parent.project_id != project_id:
                raise HTTPException(404, "parent target not found in this project")
            net_container = (((parent.metadata_json or {}).get("channel") or {})
                             .get("rehost") or {}).get("container")
        try:
            t = register_service_target(s, project, body.host, body.port,
                                       transport=body.transport, proto=body.proto,
                                       name=body.name, parent=parent, net_container=net_container)
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return {"target_id": t.id, "name": t.name, "kind": t.kind.value,
                "channel": (t.metadata_json or {}).get("channel")}


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
    """Decompile a function on demand for the in-app viewer (sandboxed). Resolve by
    `function` NAME and/or `address` — prefer the address when given (analyze-at-address
    is reliable even when the name isn't a discoverable symbol: a stripped binary, a
    renamed function, or one the fast analysis didn't flag). Returns {available,
    focus|detail}. Degrades gracefully when Docker/sandbox is absent."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        if not runner.docker_available():
            return {"available": False, "detail": "Docker/sandbox not running — decompilation needs it."}
        try:
            from hexgraph.db.models import Project
            from hexgraph.sandbox.decompiler import get_decompiler

            project = s.get(Project, t.project_id)
            decompiler = get_decompiler()
            function, address = body.get("function"), body.get("address")
            out = decompiler.decompile(t.path, function, address=address, project=project)
            # Address-focus is preferred (resolves a stripped/renamed function), but it can miss
            # — e.g. a Ghidra-recorded address sent to a radare2 base, or simply a wrong address.
            # When it resolves to nothing AND we have a name, fall back to the name so we never
            # regress a function that name-resolution would have found.
            if address and function and not _focus_has_body(out):
                out = decompiler.decompile(t.path, function, project=project)
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "detail": f"decompilation failed: {exc}"}
        return {"available": True, "backend": decompiler.name,
                "functions": out.get("functions", []), "focus": out.get("focus")}


@router.post("/api/targets/{target_id}/disassemble")
def api_disassemble(target_id: str, body: dict):
    """Disassemble a function (by `function` name or `address`) on demand for the in-app
    source viewer (sandboxed). Parallel to /decompile, but ALWAYS via radare2: the
    configured decompiler may be Ghidra, which returns empty disasm (it's a decompiler).
    Returns {available, backend, focus:{name,address,disasm}|null, functions}. Degrades
    gracefully when Docker/sandbox is absent."""
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            raise HTTPException(404, "target not found")
        if not runner.docker_available():
            return {"available": False, "detail": "Docker/sandbox not running — disassembly needs it."}
        function = body.get("function")
        address = body.get("address")
        if not function and not address:
            raise HTTPException(400, "'function' or 'address' is required")
        try:
            from hexgraph.sandbox.decompiler import R2Decompiler

            out = R2Decompiler().decompile(t.path, function, address=address)
            # Prefer the address, but fall back to the name when it resolves to nothing
            # (e.g. a Ghidra-recorded address sent to radare2's base) — see /decompile.
            if address and function and not _focus_has_body(out):
                out = R2Decompiler().decompile(t.path, function)
        except Exception as exc:  # noqa: BLE001
            return {"available": False, "detail": f"disassembly failed: {exc}"}
        return {"available": True, "backend": "radare2",
                "functions": out.get("functions", []), "focus": out.get("focus")}


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


@router.post("/api/projects/{project_id}/targets/{target_id}/promote-file")
def api_promote_file(project_id: str, target_id: str, body: dict):
    """Add a file from a firmware's unpacked filesystem as a child target."""
    with session_scope() as s:
        project = s.get(Project, project_id)
        fw = s.get(Target, target_id)
        if project is None or fw is None:
            raise HTTPException(404, "not found")
        try:
            child = promote_file(s, project, fw, body.get("rel", ""))
        except FilesystemError as exc:
            raise HTTPException(400, str(exc))
        return {"target_id": child.id, "name": child.name, "kind": child.kind.value}
