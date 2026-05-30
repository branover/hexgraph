"""FastAPI app on loopback (SPEC §3, §8): JSON API + the React SPA (P4).

Endpoints: health, projects/targets/findings reads, graph JSON, capabilities,
suggestions, runs, task launch + status. The built SPA (frontend/, `make ui`) is
served at / with a client-side-routing fallback; all assets are local (offline).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from hexgraph import __version__
from hexgraph.api.loopback import assert_loopback
from hexgraph.config import load_config
from hexgraph.db.models import Finding, FindingStatus, Project, Target, Task
from hexgraph.db.session import init_db, session_scope
from hexgraph.engine.findings import row_to_payload
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


def create_app() -> FastAPI:
    app = FastAPI(title="HexGraph", version=__version__, lifespan=_lifespan)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- JSON API ---
    @app.get("/api/projects")
    def api_projects():
        with session_scope() as s:
            return [_project_dict(p) for p in s.query(Project).all()]

    @app.get("/api/projects/{project_id}")
    def api_project(project_id: str):
        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            targets = s.query(Target).filter(Target.project_id == project_id).all()
            findings = s.query(Finding).filter(Finding.project_id == project_id).all()
            tasks = s.query(Task).filter(Task.project_id == project_id).all()
            total_cost = round(sum(t.cost_estimate or 0.0 for t in tasks), 6)
            cost_source = "mock" if project.llm_backend.value == "mock" else project.llm_backend.value
            return {
                "project": _project_dict(project),
                "targets": [_target_dict(t) for t in targets],
                "findings": [_finding_dict(f) for f in findings],
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
            return _finding_dict(f)

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
            return _finding_dict(f)

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

    @app.post("/api/projects/{project_id}/link-same-code")
    def api_link_same_code(project_id: str):
        from hexgraph.engine.crosstarget import link_same_code

        with session_scope() as s:
            if s.get(Project, project_id) is None:
                raise HTTPException(404, "project not found")
            return {"created": link_same_code(s, project_id)}

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
            if t.log_path and _P(t.log_path).is_dir():
                trace = sorted(p.name for p in _P(t.log_path).iterdir() if p.is_file())
            return {
                "task": _task_dict(t),
                "findings": [_finding_dict(f) for f in findings],
                "trace_files": trace,
            }

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
