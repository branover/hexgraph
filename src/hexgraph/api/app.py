"""FastAPI app on loopback (SPEC §3, §8): JSON API + the React SPA (P4).

Endpoints: health, projects/targets/findings reads, graph JSON, capabilities,
suggestions, runs, task launch + status. The built SPA (frontend/, `make ui`) is
served at / with a client-side-routing fallback; all assets are local (offline).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from hexgraph import __version__
from hexgraph.api.loopback import assert_loopback, host_allowed
from hexgraph.config import load_config
from hexgraph.db.models import Finding, FindingStatus, Node, Project, Target, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import is_verified, row_to_payload
from hexgraph.engine.graph import build_graph
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import get_worker

_WEB = Path(__file__).resolve().parent.parent / "web"


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Migrate the persistent DB to head (backs up first; adopts legacy/create_all'd DBs).
    from hexgraph.db.migrate import prepare_database

    prepare_database(backup=True)
    await get_worker().start()
    yield
    await get_worker().stop()


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


def _project_dict(p: Project) -> dict:
    return {"id": p.id, "name": p.name, "backend": p.llm_backend.value, "created_at": p.created_at}


def _target_dict(t: Target) -> dict:
    return {
        "id": t.id,
        "name": t.name,
        "kind": t.kind.value,
        "format": t.format,
        "arch": t.arch,
        "parent_id": t.parent_id,
        "metadata": t.metadata_json or {},
    }


def _task_dict(t: Task) -> dict:
    return {
        "id": t.id, "type": t.type, "status": t.status.value, "target_id": t.target_id,
        "anchor_kind": t.anchor_kind, "anchor_id": t.anchor_id,
        "backend": t.backend, "model": t.model, "cost_estimate": t.cost_estimate,
        "objective": t.objective_text, "params": t.params_json or {},
        "parent_finding_id": t.parent_finding_id, "context_bundle_id": t.context_bundle_id,
        "created_at": t.created_at, "finished_at": t.finished_at,
    }


class BulkStatus(BaseModel):
    ids: list[str]
    status: str


def _finding_dict(f: Finding) -> dict:
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


_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def create_app() -> FastAPI:
    app = FastAPI(title="HexGraph", version=__version__, lifespan=_lifespan)

    # --- Operator-machine trust boundary (loopback API has no auth by design) ---
    # 1) Host-header guard: the PRIMARY anti-DNS-rebinding defense. A malicious page that
    #    DNS-rebinds to 127.0.0.1 still carries the ATTACKER'S Host header, which is not
    #    loopback → rejected here before any handler runs. Implemented in-house (not
    #    Starlette's TrustedHostMiddleware) because that matches on `host.split(':')[0]`,
    #    which mangles a bracketed IPv6 loopback `[::1]:8765` → `[` and would lock out the UI
    #    on systems where localhost resolves to ::1. `host_allowed` parses IPv6 correctly and
    #    respects the deliberate non-loopback bind override (widens to allow-all).
    _bind_host = load_config().host

    @app.middleware("http")
    async def _host_guard(request: Request, call_next):
        if not host_allowed(request.headers.get("host", ""), _bind_host):
            return JSONResponse({"detail": "invalid host header"}, status_code=400)
        return await call_next(request)

    # 2) Same-origin (CSRF) guard on state-changing /api/* requests. Browsers set
    #    `Sec-Fetch-Site` automatically. Allow a mutation ONLY when it is `same-origin` (the
    #    SPA's own fetches) or when the header is ABSENT (non-browser clients — though the
    #    CLI/MCP/tests call the engine in-process, not HTTP, so this is belt-and-suspenders).
    #    Everything else — `cross-site` AND `same-site` AND `none` — is rejected. Rejecting
    #    `same-site` is essential: a page on `evil.localhost` resolves to 127.0.0.1 and is
    #    same-SITE to `localhost`, so it would otherwise pass both this guard and the Host
    #    check and flip the sandbox-relaxing feature gates.
    @app.middleware("http")
    async def _same_origin_guard(request: Request, call_next):
        if request.method not in _SAFE_METHODS and request.url.path.startswith("/api/"):
            sfs = request.headers.get("sec-fetch-site")
            if sfs is not None and sfs != "same-origin":
                return JSONResponse(
                    {"detail": f"cross-origin request rejected (Sec-Fetch-Site: {sfs}); same-origin only"},
                    status_code=403,
                )
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- JSON API ---
    @app.get("/api/projects")
    def api_projects():
        with session_scope() as s:
            return [_project_dict(p) for p in s.query(Project).all()]

    # --- Authoring (web app = no CLI required) ---
    @app.post("/api/projects")
    def api_create_project(body: ProjectCreate):
        from hexgraph.engine.ingest import create_project

        if not (body.name or "").strip():
            raise HTTPException(400, "project name is required")
        with session_scope() as s:
            p = create_project(s, name=body.name.strip(), llm_backend=body.backend or "mock")
            return _project_dict(p)

    @app.delete("/api/projects/{project_id}")
    def api_delete_project(project_id: str):
        """Permanently delete a project: all its rows + its on-disk data dir.
        Destructive and irreversible (unlike target/node archive)."""
        from hexgraph.engine.removal import delete_project

        with session_scope() as s:
            try:
                return delete_project(s, project_id)
            except ValueError as exc:
                raise HTTPException(404, str(exc))

    @app.post("/api/projects/{project_id}/targets")
    def api_add_target(
        project_id: str,
        file: UploadFile = File(...),
        name: str | None = Form(None),
        recon: bool = Form(True),
    ):
        """Upload real bytes → ingest → (sandboxed) recon populates the facts and,
        for firmware, unpacks child targets. Targets only ever come from bytes."""
        import os
        import shutil
        import tempfile

        from hexgraph.engine.ingest import ingest_file
        from hexgraph.engine.pipeline import analyze_target
        from hexgraph.engine.unpack import build_links_against
        from hexgraph.sandbox.executor import get_executor
        from hexgraph.sandbox.runner import docker_available

        fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(file.filename or "")[1])
        with os.fdopen(fd, "wb") as out:
            shutil.copyfileobj(file.file, out)
        try:
            with session_scope() as s:
                project = s.get(Project, project_id)
                if project is None:
                    raise HTTPException(404, "project not found")
                if recon and not docker_available():
                    raise HTTPException(400, "Docker is required to analyze a target. Start Docker, "
                                             "or upload with recon=false to register bytes only.")
                # Re-adding bytes that were previously removed restores the archived
                # target (and its findings) instead of creating a duplicate.
                from hexgraph.engine.targets import restore_matching

                restored = restore_matching(s, project, tmp)
                if restored is not None:
                    return {"target_id": restored.id, "name": restored.name, "restored": True}
                target = ingest_file(s, project, tmp, name=name or file.filename)
                result = {"target_id": target.id, "name": target.name, "recon": recon}
                if recon:
                    summary = analyze_target(s, project, target, get_executor())
                    build_links_against(s, project)
                    result["children"] = summary.get("children", [])
                return result
        finally:
            os.unlink(tmp)

    @app.delete("/api/projects/{project_id}/targets/{target_id}")
    def api_remove_target(project_id: str, target_id: str):
        """Soft-remove a target + its subtree (nodes/findings hidden, not deleted).
        Re-adding the same bytes restores them."""
        from hexgraph.engine.targets import archive_target

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            try:
                n = archive_target(s, project_id, target_id)
            except ValueError as exc:
                raise HTTPException(404, str(exc))
            return {"archived": n}

    @app.post("/api/projects/{project_id}/targets/{target_id}/restore")
    def api_restore_target(project_id: str, target_id: str):
        from hexgraph.engine.targets import restore_target

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            try:
                return {"restored": restore_target(s, project_id, target_id)}
            except ValueError as exc:
                raise HTTPException(404, str(exc))

    @app.post("/api/targets/{target_id}/decompile")
    def api_decompile(target_id: str, body: dict):
        """Decompile a function on demand for the in-app viewer (sandboxed). Returns
        {available, focus|detail}. Degrades gracefully when Docker/sandbox is absent."""
        from hexgraph.sandbox.runner import docker_available

        with session_scope() as s:
            t = s.get(Target, target_id)
            if t is None:
                raise HTTPException(404, "target not found")
            if not docker_available():
                return {"available": False, "detail": "Docker/sandbox not running — decompilation needs it."}
            try:
                from hexgraph.sandbox.decompiler import get_decompiler

                out = get_decompiler().decompile(t.path, body.get("function"))
            except Exception as exc:  # noqa: BLE001
                return {"available": False, "detail": f"decompilation failed: {exc}"}
            return {"available": True, "functions": out.get("functions", []), "focus": out.get("focus")}

    @app.get("/api/targets/{target_id}/filesystem")
    def api_target_filesystem(target_id: str):
        """The unpacked filesystem manifest of a firmware target (browsable tree)."""
        from hexgraph.engine.filesystem import list_filesystem

        with session_scope() as s:
            t = s.get(Target, target_id)
            if t is None:
                raise HTTPException(404, "target not found")
            return list_filesystem(s.get(Project, t.project_id), t)

    @app.get("/api/targets/{target_id}/file")
    def api_target_file(target_id: str, rel: str):
        """Read one file from a firmware's unpacked filesystem for the in-UI viewer
        (text or hex, bounded, path-traversal safe)."""
        from hexgraph.engine.filesystem import FilesystemError, read_file

        with session_scope() as s:
            t = s.get(Target, target_id)
            if t is None:
                raise HTTPException(404, "target not found")
            try:
                return read_file(s.get(Project, t.project_id), t, rel)
            except FilesystemError as exc:
                raise HTTPException(400, str(exc))

    @app.post("/api/projects/{project_id}/targets/{target_id}/add-from-fs")
    def api_add_from_fs(project_id: str, target_id: str, body: dict):
        """Add a file from a firmware's unpacked filesystem as a child target."""
        from hexgraph.engine.filesystem import FilesystemError, add_file_as_target

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

    @app.post("/api/projects/{project_id}/nodes")
    def api_create_node(project_id: str, body: NodeCreate):
        from hexgraph.engine.authoring import InvariantError, create_node

        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            try:
                n = create_node(s, project, node_type=body.node_type, name=body.name,
                                target_id=body.target_id, address=body.address, attrs=body.attrs)
            except InvariantError as exc:
                raise HTTPException(400, str(exc))
            return {"id": n.id, "node_type": n.node_type, "name": n.name, "target_id": n.target_id,
                    "address": n.address, "attrs": n.attrs_json or {}}

    @app.delete("/api/projects/{project_id}/nodes/{node_id}")
    def api_remove_node(project_id: str, node_id: str):
        """Soft-remove a node (REVERSIBLE): hides the node and the edges touching it.
        Re-adding the same node, or POST .../restore, brings it and its edges back."""
        from hexgraph.engine.removal import archive_node

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            try:
                n = archive_node(s, project_id, node_id)
            except ValueError as exc:
                raise HTTPException(404, str(exc))
            return {"archived": n.archived, "id": n.id}

    @app.post("/api/projects/{project_id}/nodes/{node_id}/restore")
    def api_restore_node(project_id: str, node_id: str):
        from hexgraph.engine.removal import restore_node

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            try:
                n = restore_node(s, project_id, node_id)
            except ValueError as exc:
                raise HTTPException(404, str(exc))
            return {"archived": n.archived, "id": n.id}

    @app.post("/api/projects/{project_id}/edges")
    def api_create_edge(project_id: str, body: EdgeCreate):
        from hexgraph.engine.authoring import InvariantError, create_edge

        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            try:
                e = create_edge(s, project, src_kind=body.src_kind, src_id=body.src_id,
                                dst_kind=body.dst_kind, dst_id=body.dst_id, type=body.type,
                                attrs=body.attrs, merge=body.merge)
            except InvariantError as exc:
                raise HTTPException(400, str(exc))
            return {"id": e.id, "type": e.type, "src_id": e.src_id, "dst_id": e.dst_id,
                    "attrs": e.attrs_json or {}}

    @app.patch("/api/edges/{edge_id}")
    def api_update_edge(edge_id: str, body: EdgeAttrsUpdate):
        from hexgraph.db.models import Edge
        from hexgraph.engine.edge_schemas import merge_edge_attrs

        with session_scope() as s:
            e = s.get(Edge, edge_id)
            if e is None:
                raise HTTPException(404, "edge not found")
            e.attrs_json = (merge_edge_attrs(e.type, e.attrs_json, body.attrs)
                            if body.merge else dict(body.attrs or {}))
            return {"id": e.id, "type": e.type, "attrs": e.attrs_json}

    @app.delete("/api/edges/{edge_id}")
    def api_delete_edge(edge_id: str):
        """Permanently delete one edge (hard delete — recreate with POST .../edges to
        restore). To remove a node's edges reversibly, archive the node instead."""
        from hexgraph.engine.removal import delete_edge

        with session_scope() as s:
            if not delete_edge(s, edge_id):
                raise HTTPException(404, "edge not found")
            return {"deleted": True, "id": edge_id}

    @app.post("/api/projects/{project_id}/sockets")
    def api_create_socket(project_id: str, body: SocketCreate):
        from hexgraph.engine.authoring import InvariantError, create_socket

        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            try:
                n = create_socket(s, project, kind=body.kind, port=body.port, name=body.name,
                                  bind_addr=body.bind_addr, attrs=body.attrs)
            except InvariantError as exc:
                raise HTTPException(400, str(exc))
            return {"id": n.id, "node_type": n.node_type, "name": n.name, "attrs": n.attrs_json or {}}

    @app.get("/api/edge-schemas")
    def api_edge_schemas():
        """What attributes are meaningful per edge type + the socket kinds — for the
        UI's edge inspector and for any client populating typed edges."""
        from hexgraph.engine.edge_schemas import SOCKET_KINDS, describe_edges

        return {"edges": describe_edges(), "socket_kinds": list(SOCKET_KINDS)}

    @app.get("/api/node-schemas")
    def api_node_schemas():
        """Per node-type description, when-to-use, and recommended attributes — for the
        Add-node UI help and any client populating nodes consistently."""
        from hexgraph.engine.node_schemas import describe_nodes

        return {"nodes": describe_nodes()}

    @app.get("/api/projects/{project_id}")
    def api_project(project_id: str):
        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            targets = s.query(Target).filter(
                Target.project_id == project_id, Target.archived.is_(False)
            ).all()
            live_ids = {t.id for t in targets}
            findings = [
                f for f in s.query(Finding).filter(Finding.project_id == project_id).all()
                if f.target_id in live_ids  # hide findings under archived (removed) targets
            ]
            tasks = s.query(Task).filter(Task.project_id == project_id).all()
            total_cost = round(sum(t.cost_estimate or 0.0 for t in tasks), 6)
            cost_source = "mock" if project.llm_backend.value == "mock" else project.llm_backend.value
            # tags on findings (annotation kind=tag, node_kind=finding) → filter facet
            from hexgraph.db.models import Annotation

            tags: dict[str, list[str]] = {}
            for a in s.query(Annotation).filter(Annotation.project_id == project_id, Annotation.kind == "tag",
                                                Annotation.node_kind == "finding").all():
                tags.setdefault(a.node_id, []).append(a.value)
            task_types = {t.id: t.type for t in tasks}  # so the UI can spot harness findings
            return {
                "project": _project_dict(project),
                "targets": [_target_dict(t) for t in targets],
                "findings": [{**_finding_dict(f), "tags": tags.get(f.id, []),
                              "task_type": task_types.get(f.task_id)} for f in findings],
                "cost": {
                    "total_usd": total_cost,
                    "cost_source": cost_source,
                    "task_count": len(tasks),
                },
            }

    @app.get("/api/findings/{finding_id}")
    def api_finding(finding_id: str):
        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            task = s.get(Task, f.task_id)
            return {**_finding_dict(f), "task_type": task.type if task else None}

    @app.post("/api/findings/{finding_id}/status")
    def api_set_finding_status(finding_id: str, body: StatusUpdate):
        try:
            new_status = FindingStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"invalid status {body.status!r}")
        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            f.status = new_status.value
            return {"id": f.id, "status": new_status.value}

    @app.patch("/api/findings/{finding_id}")
    def api_patch_finding(finding_id: str, body: FindingPatch):
        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            # Light edit: stash the agent's original severity/confidence, mark edited.
            if (body.severity and body.severity != f.severity) or (body.confidence and body.confidence != f.confidence):
                ev = dict(f.evidence_json or {})
                extra = dict(ev.get("extra") or {})
                extra.setdefault("agent_original", {"severity": f.severity, "confidence": f.confidence})
                ev["extra"] = extra
                f.evidence_json = ev
                f.origin = "agent_edited"
            if body.severity:
                f.severity = body.severity
            if body.confidence:
                f.confidence = body.confidence
            if body.title:
                f.title = body.title
            if body.human_notes is not None:
                f.human_notes = body.human_notes
            if body.dismissed_reason is not None:
                f.dismissed_reason = body.dismissed_reason
            if body.status:
                try:
                    f.status = FindingStatus(body.status).value
                except ValueError:
                    raise HTTPException(400, f"invalid status {body.status!r}")
            if body.category is not None:
                f.category = body.category
            if body.summary is not None:
                f.summary = body.summary
            if body.reasoning is not None:
                f.reasoning = body.reasoning
            if body.evidence is not None:
                # Full evidence replace from the UI editor; the model validates the shape.
                from pydantic import ValidationError

                from hexgraph.models.finding import Evidence
                try:
                    f.evidence_json = Evidence(**body.evidence).model_dump(exclude_none=True)
                except ValidationError as exc:
                    raise HTTPException(400, f"invalid evidence: {exc.errors()[:3]}")
            return _finding_dict(f)

    @app.patch("/api/projects/{project_id}/nodes/{node_id}")
    def api_patch_node(project_id: str, node_id: str, body: NodePatch):
        """Edit a node's fields from the UI (name/address/attrs). Renaming a function/
        symbol/struct also updates its normalized identity so it stays dedupable."""
        from hexgraph.db.models import Node
        from hexgraph.engine.nodes import normalize_symbol_name

        with session_scope() as s:
            n = s.get(Node, node_id)
            if n is None or n.project_id != project_id:
                raise HTTPException(404, "node not found")
            if body.name is not None and body.name.strip():
                name = body.name.strip()
                if n.node_type in ("function", "symbol", "struct"):
                    name = normalize_symbol_name(name) or name
                n.name = name
                n.fq_name = name
            if body.address is not None:
                n.address = body.address or None
            if body.attrs is not None:
                n.attrs_json = body.attrs
            return {"id": n.id, "node_type": n.node_type, "name": n.name,
                    "address": n.address, "attrs": n.attrs_json or {}}

    @app.post("/api/findings/{finding_id}/verify")
    def api_verify_finding(finding_id: str):
        """Re-run a PoC finding's stored spec (evidence.extra.poc) against its target and
        update the finding's verification in place. Lets an analyst confirm a PoC with one
        click — binary PoCs need features.poc, web PoCs need features.network."""
        from hexgraph.engine.poc import verify_poc as _verify
        from hexgraph.policy import PolicyViolation

        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            spec = ((f.evidence_json or {}).get("extra") or {}).get("poc")
            if not spec:
                raise HTTPException(400, "this finding has no stored PoC spec to verify")
            t = s.get(Target, f.target_id)
            try:
                r = _verify(s, s.get(Project, f.project_id), t, spec)
            except PolicyViolation:
                raise HTTPException(403, "enable features.network (web PoC) or features.poc (binary PoC) to verify")
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(400, f"verification failed: {exc}")
            ev = dict(f.evidence_json or {})
            extra = dict(ev.get("extra") or {})
            # Preserve the original spec (with {{NONCE}} intact) so re-verify stays
            # repeatable; r.get("spec") is the nonce-substituted copy.
            extra["poc"] = spec
            extra["verification"] = {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                                     "exit_code": r.get("exit_code"), "nonce": r.get("nonce"),
                                     "output": (r.get("output") or "")[:2000]}
            ev["extra"] = extra
            f.evidence_json = ev
            return {**_finding_dict(f), "verified": bool(r.get("verified")), "detail": r.get("detail")}

    @app.post("/api/projects/{project_id}/dedup")
    def api_dedup(project_id: str):
        from hexgraph.engine.dedup import dedupe_findings

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            removed = dedupe_findings(s, project_id)
            return {"removed": removed}

    @app.get("/api/projects/{project_id}/export")
    def api_export(project_id: str):
        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            findings = s.query(Finding).filter(Finding.project_id == project_id).all()
            return {
                "project": _project_dict(project),
                "graph": build_graph(s, project_id),
                "findings": [_finding_dict(f) for f in findings],
            }

    @app.get("/api/projects/{project_id}/search")
    def api_search(project_id: str, q: str = ""):
        from hexgraph.engine.search import search_project

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            return search_project(s, project_id, q)

    @app.get("/api/projects/{project_id}/report")
    def api_report(project_id: str):
        from fastapi.responses import PlainTextResponse
        from hexgraph.engine.report import build_report_md

        with session_scope() as s:
            try:
                md = build_report_md(s, project_id)
            except ValueError:
                raise HTTPException(404, "project not found")
        return PlainTextResponse(md, media_type="text/markdown")

    @app.post("/api/projects/{project_id}/merge-duplicates")
    def api_merge_duplicates(project_id: str):
        """Collapse duplicate binaries (same bytes) and nodes (same normalized
        identity, e.g. sym.foo == foo) — moving all edges/findings/annotations to
        the keeper so nothing is lost."""
        from hexgraph.engine.nodemerge import merge_duplicates

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            return merge_duplicates(s, project_id)

    @app.post("/api/projects/{project_id}/link-same-code")
    def api_link_same_code(project_id: str):
        from hexgraph.engine.crosstarget import link_same_code

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            return {"created": link_same_code(s, project_id)}

    # --- Annotations (rename/note/tag) ---
    def _ann_dict(a):
        return {"id": a.id, "node_kind": a.node_kind, "node_id": a.node_id, "kind": a.kind,
                "value": a.value, "origin": a.origin, "status": a.status, "created_at": a.created_at}

    @app.post("/api/projects/{project_id}/annotations")
    def api_create_annotation(project_id: str, body: AnnotationCreate):
        from hexgraph.engine.annotations import AnnotationError, create_annotation

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            try:
                a = create_annotation(s, project_id, node_kind=body.node_kind, node_id=body.node_id,
                                      kind=body.kind, value=body.value)
            except AnnotationError as exc:
                raise HTTPException(400, str(exc))
            return _ann_dict(a)

    @app.get("/api/annotations/{node_kind}/{node_id}")
    def api_list_annotations(node_kind: str, node_id: str):
        from hexgraph.db.models import Annotation

        with session_scope() as s:
            anns = s.query(Annotation).filter(Annotation.node_kind == node_kind, Annotation.node_id == node_id).all()
            return [_ann_dict(a) for a in anns]

    @app.post("/api/annotations/{annotation_id}/status")
    def api_annotation_status(annotation_id: str, body: StatusUpdate):
        from hexgraph.engine.annotations import AnnotationError, set_status

        with session_scope() as s:
            try:
                a = set_status(s, annotation_id, body.status)
            except AnnotationError as exc:
                raise HTTPException(400, str(exc))
            return _ann_dict(a)

    # --- Hypotheses (research questions evidenced by findings) ---
    @app.post("/api/projects/{project_id}/hypotheses")
    def api_create_hypothesis(project_id: str, body: HypothesisCreate):
        from hexgraph.engine.hypotheses import HypothesisError, create_hypothesis, summary

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

    @app.get("/api/hypotheses/{hypothesis_id}")
    def api_hypothesis(hypothesis_id: str):
        from hexgraph.engine.hypotheses import HypothesisError, summary

        with session_scope() as s:
            try:
                return summary(s, hypothesis_id)
            except HypothesisError as exc:
                raise HTTPException(404, str(exc))

    @app.post("/api/hypotheses/{hypothesis_id}/evidence")
    def api_hypothesis_evidence(hypothesis_id: str, body: EvidenceLink):
        from hexgraph.engine.hypotheses import HypothesisError, link_evidence, summary

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

    @app.post("/api/hypotheses/{hypothesis_id}/status")
    def api_hypothesis_status(hypothesis_id: str, body: StatusUpdate):
        from hexgraph.engine.hypotheses import HypothesisError, set_status, summary

        with session_scope() as s:
            try:
                set_status(s, hypothesis_id, body.status)
            except HypothesisError as exc:
                raise HTTPException(400, str(exc))
            return summary(s, hypothesis_id)

    # --- Settings (optional features + non-secret prefs; secrets are status-only) ---
    @app.get("/api/settings")
    def api_get_settings():
        from hexgraph import settings as st

        return st.read_settings()

    @app.patch("/api/settings")
    def api_patch_settings(body: dict):
        from hexgraph import settings as st

        try:
            return st.update_settings(body)
        except st.SettingsError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/settings/ghidra/test")
    def api_ghidra_test():
        """Best-effort check of the configured Ghidra integration (no target needed)."""
        from hexgraph.engine.ghidra import check_ghidra

        return check_ghidra()

    @app.get("/api/ghidra/programs")
    def api_ghidra_programs():
        """List programs open in a connected Ghidra (bridge mode)."""
        from hexgraph.engine.ghidra_bridge import BridgeUnavailable, list_open_programs

        try:
            return list_open_programs()
        except BridgeUnavailable as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/projects/{project_id}/ghidra/import")
    def api_ghidra_import(project_id: str, body: GhidraImport):
        """Ingest a program Ghidra has open as a target (real on-disk bytes)."""
        from hexgraph.engine.ghidra_bridge import BridgeUnavailable, import_program

        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            try:
                return import_program(s, project, path=body.path, name=body.name)
            except BridgeUnavailable as exc:
                raise HTTPException(400, str(exc))

    @app.get("/api/capabilities")
    def api_capabilities():
        from hexgraph.engine.capabilities import capability_table

        return capability_table()

    @app.get("/api/findings/{finding_id}/suggestions")
    def api_finding_suggestions(finding_id: str):
        from hexgraph.entitlements import require
        from hexgraph.engine.suggester import suggest_followups

        require("suggest.followups")  # no-op locally; the paid-feature gate
        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            return [fu.model_dump(exclude_none=True) for fu in suggest_followups(f)]

    @app.get("/graph/{project_id}")
    def api_graph(project_id: str):
        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            return build_graph(s, project_id)

    @app.post("/api/tasks/preview")
    def api_task_preview(body: TaskCreate):
        """Pre-flight: show the exact context bundle (prompt + items + token estimate)
        a task would run on, before spending anything."""
        from hexgraph.engine.llm_tasks import preview_context

        params = dict(body.params or {})
        if body.mock_scenario:
            params["mock_scenario"] = body.mock_scenario
        with session_scope() as s:
            target = s.get(Target, body.target_id)
            if target is None:
                raise HTTPException(404, "target not found")
            preview = preview_context(s, s.get(Project, target.project_id), target,
                                      task_type=body.type, objective=body.objective, params=params)
            preview["backend"] = body.backend or "mock"
            preview["model"] = body.model
            return preview

    @app.post("/api/projects/{project_id}/tasks/clear")
    def api_clear_tasks(project_id: str):
        """Remove tasks that produced no findings (recon/empty/failed noise) + their
        analysis_runs and context bundles. Tasks with findings are kept for provenance."""
        from hexgraph.db.models import AnalysisRun, ContextBundle, ContextItem

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            with_findings = {f.task_id for f in s.query(Finding).filter(Finding.project_id == project_id).all()}
            removed = 0
            for t in s.query(Task).filter(Task.project_id == project_id).all():
                if t.id in with_findings:
                    continue
                if t.context_bundle_id:
                    s.query(ContextItem).filter(ContextItem.bundle_id == t.context_bundle_id).delete(synchronize_session=False)
                    cb = s.get(ContextBundle, t.context_bundle_id)
                    if cb:
                        s.delete(cb)
                s.query(AnalysisRun).filter(AnalysisRun.task_id == t.id).delete(synchronize_session=False)
                s.delete(t)
                removed += 1
            return {"removed": removed}

    @app.post("/api/tasks")
    async def api_create_task(body: TaskCreate):
        with session_scope() as s:
            target = s.get(Target, body.target_id)
            if target is None:
                raise HTTPException(404, "target not found")
            project = s.get(Project, target.project_id)
            params = dict(body.params or {})
            if body.mock_scenario:
                params["mock_scenario"] = body.mock_scenario
            task = create_task(
                s, project=project, target_id=target.id, type=body.type,
                objective=body.objective, model=body.model,
                backend=body.backend or project.llm_backend.value,
                params=params, parent_finding_id=body.parent_finding_id,
                anchor_kind=body.anchor_kind, anchor_id=body.anchor_id,
            )
            task_id = task.id
        await get_worker().enqueue(task_id)
        return {"task_id": task_id, "status": "queued"}

    @app.post("/api/findings/{finding_id}/followups/{index}")
    async def api_spawn_followup(finding_id: str, index: int):
        from hexgraph.engine.followups import spawn_followup

        with session_scope() as s:
            try:
                task = spawn_followup(s, finding_id, index)
            except (ValueError, IndexError) as exc:
                raise HTTPException(404, str(exc))
            task_id, target_id = task.id, task.target_id
        await get_worker().enqueue(task_id)
        return {"task_id": task_id, "status": "queued", "target_id": target_id}

    @app.get("/api/targets/{target_id}/runs")
    def api_target_runs(target_id: str):
        from hexgraph.db.models import AnalysisRun

        with session_scope() as s:
            runs = (
                s.query(AnalysisRun).filter(AnalysisRun.anchor_id == target_id)
                .order_by(AnalysisRun.created_at.desc()).all()
            )
            return [
                {"id": r.id, "task_id": r.task_id, "task_type": r.task_type, "backend": r.backend,
                 "model": r.model, "bundle_sha": r.bundle_sha, "finding_count": r.finding_count,
                 "created_at": r.created_at}
                for r in runs
            ]

    @app.post("/api/runs/diff")
    def api_runs_diff(body: dict):
        from hexgraph.engine.runs import diff_runs

        with session_scope() as s:
            try:
                return diff_runs(s, body["run_a"], body["run_b"])
            except (KeyError, ValueError) as exc:
                raise HTTPException(400, str(exc))

    @app.get("/api/tasks/{task_id}")
    def api_task(task_id: str):
        with session_scope() as s:
            t = s.get(Task, task_id)
            if t is None:
                raise HTTPException(404, "task not found")
            return {"id": t.id, "type": t.type, "status": t.status.value, "target_id": t.target_id}

    # --- P5: task workspace + provenance navigation ---
    @app.get("/api/projects/{project_id}/tasks")
    def api_project_tasks(project_id: str):
        with session_scope() as s:
            tasks = (
                s.query(Task).filter(Task.project_id == project_id)
                .order_by(Task.created_at.desc()).all()
            )
            counts = {}
            for f in s.query(Finding).filter(Finding.project_id == project_id).all():
                counts[f.task_id] = counts.get(f.task_id, 0) + 1
            return [{**_task_dict(t), "finding_count": counts.get(t.id, 0)} for t in tasks]

    @app.get("/api/tasks/{task_id}/detail")
    def api_task_detail(task_id: str):
        from pathlib import Path as _P

        with session_scope() as s:
            t = s.get(Task, task_id)
            if t is None:
                raise HTTPException(404, "task not found")
            findings = s.query(Finding).filter(Finding.task_id == task_id).all()
            trace = []
            error = None
            if t.log_path and _P(t.log_path).is_dir():
                trace = sorted(p.name for p in _P(t.log_path).iterdir() if p.is_file())
                err_path = _P(t.log_path) / "error.txt"
                if err_path.is_file():
                    error = err_path.read_text()[:8000]  # surface the failure reason inline
            return {
                "task": _task_dict(t),
                "findings": [_finding_dict(f) for f in findings],
                "trace_files": trace,
                "error": error,
            }

    @app.get("/api/tasks/{task_id}/trace/{name}")
    def api_task_trace(task_id: str, name: str):
        """Read one trace artifact's content (error.txt, prompt.txt, fuzz.json, …)."""
        from pathlib import Path as _P

        from fastapi.responses import PlainTextResponse

        with session_scope() as s:
            t = s.get(Task, task_id)
            if t is None or not t.log_path:
                raise HTTPException(404, "task not found")
            p = _P(t.log_path) / name
            if p.name != name or not p.is_file():  # no path traversal
                raise HTTPException(404, "trace file not found")
            return PlainTextResponse(p.read_text()[:200000])

    @app.post("/api/tasks/{task_id}/rerun")
    async def api_task_rerun(task_id: str):
        with session_scope() as s:
            t = s.get(Task, task_id)
            if t is None:
                raise HTTPException(404, "task not found")
            project = s.get(Project, t.project_id)
            clone = create_task(
                s, project=project, target_id=t.target_id, type=t.type,
                objective=t.objective_text, model=t.model, backend=t.backend,
                params=dict(t.params_json or {}), parent_finding_id=t.parent_finding_id,
                anchor_kind=t.anchor_kind, anchor_id=t.anchor_id,
            )
            new_id = clone.id
        await get_worker().enqueue(new_id)
        return {"task_id": new_id, "status": "queued"}

    @app.get("/api/findings/{finding_id}/components")
    def api_finding_components(finding_id: str):
        """The graph entities this finding is `about` (for highlight/navigation)."""
        from hexgraph.db.models import Edge, Node

        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            out = [{"kind": "target", "id": f.target_id, "role": "target"}]
            edges = s.query(Edge).filter(
                Edge.src_kind == "finding", Edge.src_id == finding_id
            ).all()
            for e in edges:
                entry = {"kind": e.dst_kind, "id": e.dst_id, "role": (e.attrs_json or {}).get("role")}
                if e.dst_kind == "node":
                    n = s.get(Node, e.dst_id)
                    if n is not None:
                        entry["label"] = n.name
                        entry["node_type"] = n.node_type
                out.append(entry)
            return out

    @app.post("/api/findings/bulk-status")
    def api_bulk_status(body: BulkStatus):
        try:
            new_status = FindingStatus(body.status)
        except ValueError:
            raise HTTPException(400, f"invalid status {body.status!r}")
        with session_scope() as s:
            updated = 0
            for fid in body.ids:
                f = s.get(Finding, fid)
                if f is not None:
                    f.status = new_status.value
                    updated += 1
            return {"updated": updated, "status": new_status.value}

    # --- SPA (built by `frontend/`; served at / with client-side routing fallback) ---
    dist = _WEB / "dist"
    if (dist / "index.html").exists():
        if (dist / "assets").is_dir():
            app.mount("/assets", StaticFiles(directory=str(dist / "assets")), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            # All /api, /graph, /health routes are matched above; everything else is
            # the single-page app (so client-side routes like /projects/<id> work).
            return FileResponse(dist / "index.html")

    return app


def run_server(host: str | None = None, port: int | None = None) -> None:
    import uvicorn

    cfg = load_config()
    host = host or cfg.host
    port = port or cfg.port
    assert_loopback(host)  # refuse non-loopback before binding
    print(f"HexGraph serving on http://{host}:{port}  (backend={cfg.llm_backend})")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
