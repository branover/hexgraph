"""Projects: CRUD + project-scoped maintenance (export/search/report/dedup/merge)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from hexgraph.db.models import (
    AnalysisRun,
    Annotation,
    ContextBundle,
    ContextItem,
    Finding,
    Project,
    Target,
    Task,
)
from hexgraph.db.session import session_scope
from hexgraph.engine.crosstarget import link_same_code
from hexgraph.engine.dedup import dedupe_findings
from hexgraph.engine.graph import build_graph
from hexgraph.engine.ingest import create_project
from hexgraph.engine.nodemerge import merge_duplicates
from hexgraph.engine.removal import delete_project
from hexgraph.engine.report import build_report_md
from hexgraph.engine.search import search_project

from ._shared import ProjectCreate, finding_dict, project_dict, target_dict

router = APIRouter()


@router.get("/api/projects")
def api_projects():
    with session_scope() as s:
        return [project_dict(p) for p in s.query(Project).all()]


# --- Authoring (web app = no CLI required) ---
@router.post("/api/projects")
def api_create_project(body: ProjectCreate):
    if not (body.name or "").strip():
        raise HTTPException(400, "project name is required")
    with session_scope() as s:
        p = create_project(s, name=body.name.strip(), llm_backend=body.backend or "mock")
        return project_dict(p)


@router.delete("/api/projects/{project_id}")
def api_delete_project(project_id: str):
    """Permanently delete a project: all its rows + its on-disk data dir.
    Destructive and irreversible (unlike target/node archive)."""
    with session_scope() as s:
        try:
            return delete_project(s, project_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))


@router.get("/api/projects/{project_id}")
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
        tags: dict[str, list[str]] = {}
        for a in s.query(Annotation).filter(Annotation.project_id == project_id, Annotation.kind == "tag",
                                            Annotation.node_kind == "finding").all():
            tags.setdefault(a.node_id, []).append(a.value)
        task_types = {t.id: t.type for t in tasks}  # so the UI can spot harness findings
        return {
            "project": project_dict(project),
            "targets": [target_dict(t) for t in targets],
            "findings": [{**finding_dict(f), "tags": tags.get(f.id, []),
                          "task_type": task_types.get(f.task_id)} for f in findings],
            "cost": {
                "total_usd": total_cost,
                "cost_source": cost_source,
                "task_count": len(tasks),
            },
        }


@router.post("/api/projects/{project_id}/dedup")
def api_dedup(project_id: str):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        removed = dedupe_findings(s, project_id)
        return {"removed": removed}


@router.get("/api/projects/{project_id}/export")
def api_export(project_id: str):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        findings = s.query(Finding).filter(Finding.project_id == project_id).all()
        return {
            "project": project_dict(project),
            "graph": build_graph(s, project_id),
            "findings": [finding_dict(f) for f in findings],
        }


@router.get("/api/projects/{project_id}/search")
def api_search(project_id: str, q: str = ""):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return search_project(s, project_id, q)


@router.get("/api/projects/{project_id}/egress")
def api_egress(project_id: str, limit: int = 500):
    """The egress audit log — every outbound action (allowed OR denied) against a live
    target/service when the bounded-network/remote tier is in use (boofuzz sends, http
    probes, remote-fuzz launches). Mandatory once egress is enabled: nothing reaches the
    network without an EgressEvent. Read-only; the operator inspects what HexGraph
    contacted and why."""
    from hexgraph.engine.audit import list_egress

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return {"events": list_egress(s, project_id, limit=limit)}


@router.get("/api/projects/{project_id}/report")
def api_report(project_id: str):
    with session_scope() as s:
        try:
            md = build_report_md(s, project_id)
        except ValueError:
            raise HTTPException(404, "project not found")
    return PlainTextResponse(md, media_type="text/markdown")


@router.post("/api/projects/{project_id}/merge-duplicates")
def api_merge_duplicates(project_id: str):
    """Collapse duplicate binaries (same bytes) and nodes (same normalized
    identity, e.g. sym.foo == foo) — moving all edges/findings/annotations to
    the keeper so nothing is lost."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return merge_duplicates(s, project_id)


@router.post("/api/projects/{project_id}/link-same-code")
def api_link_same_code(project_id: str):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return {"created": link_same_code(s, project_id)}


@router.post("/api/projects/{project_id}/tasks/clear")
def api_clear_tasks(project_id: str):
    """Remove tasks that produced no findings (recon/empty/failed noise) + their
    analysis_runs and context bundles. Tasks with findings are kept for provenance."""
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
