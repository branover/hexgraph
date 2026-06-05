"""Observations (Phase O, design §5.6): the "Tool Results" read surface.

Every deterministic tool call writes a durable Observation (`engine/observations.py`)
— the call (tool + normalized args), a short summary, and the FULL payload in CAS,
scoped to the exact analyzed bytes. These endpoints expose that store read-only so
the UI's "Tool Results" panel can browse prior analysis per target, and a node/
finding can show "derived from these tool results" provenance.

Read-only by design: there is NO write endpoint here. Observations are recorded by
the engine when a tool runs; promoting one into the graph is a separate, deliberate
act (the query/enrich/promote contract, §5.3) and is out of scope for this surface.
List/search return row metadata only (bounded); the single-get carries the full CAS
payload. Loopback-only, same trust boundary as every other router."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query

from hexgraph.db.models import Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O

router = APIRouter()

# The list/search ceilings keep a response bounded even when an active target has
# accumulated thousands of tool results — the full payload is fetched only per-row.
_MAX_LIMIT = 500


@router.get("/api/projects/{project_id}/targets/{target_id}/observations")
def api_list_observations(
    project_id: str,
    target_id: str,
    tool: str | None = Query(None, description="filter by tool name"),
    kind: str | None = Query(None, description="filter by result_kind"),
    since: str | None = Query(None, description="ISO-8601 lower bound on created_at"),
    limit: int = Query(100, ge=1, le=_MAX_LIMIT),
):
    """Prior tool results on a target, newest first (the Tool Results panel feed).
    Filter by `tool` / `kind` / `since`; bounded by `limit`. Row metadata only —
    GET /api/observations/{id} for the full CAS payload."""
    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
        except ValueError:
            raise HTTPException(400, f"invalid 'since' timestamp {since!r} (expected ISO-8601)")
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        if s.get(Target, target_id) is None:
            raise HTTPException(404, "target not found")
        rows = O.list_observations(s, target_id, tool=tool, kind=kind, since=since_dt, limit=limit)
        return {"observations": rows}


@router.get("/api/observations/{obs_id}")
def api_get_observation(obs_id: str):
    """One tool result in full, with its payload loaded back from CAS — the raw
    result the panel pretty-prints and the provenance link opens."""
    with session_scope() as s:
        obs = O.get_observation(s, obs_id)
        if obs is None:
            raise HTTPException(404, "observation not found")
        return obs


@router.get("/api/projects/{project_id}/observations/search")
def api_search_observations(
    project_id: str,
    q: str = Query("", description="substring over tool / summary / result_kind"),
    target_id: str | None = Query(None, description="optionally scope to one target"),
    limit: int = Query(100, ge=1, le=_MAX_LIMIT),
):
    """Substring search over a project's tool results (tool / summary / kind),
    newest first. Row metadata only."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        rows = O.search_observations(
            s, project_id=project_id, target_id=target_id, query=q, limit=limit)
        return {"observations": rows}
