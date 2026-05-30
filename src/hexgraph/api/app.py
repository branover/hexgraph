"""FastAPI app on loopback (SPEC §3, §8): JSON API + HTMX/JS workspace UI.

Endpoints: health, projects/targets/findings reads, graph JSON, task launch +
status. The graph renders offline via a vendored Cytoscape.js (no CDN).
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from hexgraph import __version__
from hexgraph.api.loopback import assert_loopback
from hexgraph.config import load_config
from hexgraph.db.models import Finding, Project, Target, Task
from hexgraph.db.session import init_db, session_scope
from hexgraph.engine.findings import row_to_payload
from hexgraph.engine.graph import build_graph
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import get_worker

_WEB = Path(__file__).resolve().parent.parent / "web"
templates = Jinja2Templates(directory=str(_WEB / "templates"))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    init_db()
    await get_worker().start()
    yield
    await get_worker().stop()


class TaskCreate(BaseModel):
    target_id: str
    type: str = "recon"
    objective: str | None = None
    model: str | None = None
    backend: str | None = None
    mock_scenario: str | None = None
    params: dict | None = None
    parent_finding_id: str | None = None


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


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "target_id": f.target_id,
        "task_id": f.task_id,
        "status": f.status.value,
        "created_at": f.created_at,
        **row_to_payload(f),
    }


def create_app() -> FastAPI:
    app = FastAPI(title="HexGraph", version=__version__, lifespan=_lifespan)
    app.mount("/static", StaticFiles(directory=str(_WEB / "static")), name="static")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    # --- UI ---
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        with session_scope() as s:
            projects = [_project_dict(p) for p in s.query(Project).all()]
        return templates.TemplateResponse(
            request, "index.html", {"projects": projects, "version": __version__}
        )

    @app.get("/projects/{project_id}", response_class=HTMLResponse)
    def workspace(request: Request, project_id: str):
        with session_scope() as s:
            project = s.get(Project, project_id)
            if project is None:
                raise HTTPException(404, "project not found")
            ctx = {"project": _project_dict(project), "version": __version__}
        return templates.TemplateResponse(request, "workspace.html", ctx)

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
            return {
                "project": _project_dict(project),
                "targets": [_target_dict(t) for t in targets],
                "findings": [_finding_dict(f) for f in findings],
            }

    @app.get("/api/findings/{finding_id}")
    def api_finding(finding_id: str):
        with session_scope() as s:
            f = s.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, "finding not found")
            return _finding_dict(f)

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
            )
            task_id = task.id
        await get_worker().enqueue(task_id)
        return {"task_id": task_id, "status": "queued"}

    @app.get("/api/tasks/{task_id}")
    def api_task(task_id: str):
        with session_scope() as s:
            t = s.get(Task, task_id)
            if t is None:
                raise HTTPException(404, "task not found")
            return {"id": t.id, "type": t.type, "status": t.status.value, "target_id": t.target_id}

    return app


def run_server(host: str | None = None, port: int | None = None) -> None:
    import uvicorn

    cfg = load_config()
    host = host or cfg.host
    port = port or cfg.port
    assert_loopback(host)  # refuse non-loopback before binding
    print(f"HexGraph serving on http://{host}:{port}  (backend={cfg.llm_backend})")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
