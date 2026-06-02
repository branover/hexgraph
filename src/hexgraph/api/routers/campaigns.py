"""Fuzz campaigns: start / list / get / stop / resume + status/stats/artifacts
(design §5.7, Phase 3). Build-as-API: no shell — the client REQUESTS a campaign and
HexGraph spawns + reaps a detached, hardened sandbox container. Gated by the EXISTING
exec policy (features.fuzzing/poc) — no new gate.

A minimal status surface (Phase 3); the rich Campaigns/Artifacts triage UX is Phase 4.
The endpoints already return what Phase 4 will render."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from hexgraph.db.models import FuzzCampaign, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.fuzzers import FuzzCampaignSpec
from hexgraph.policy import PolicyViolation, assert_allows_execution

router = APIRouter()


class CampaignCreate(BaseModel):
    target_id: str
    surface: str | None = None          # auto-inferred from the target if omitted
    engine: str | None = None           # validated against the surface (fail-closed)
    function: str | None = None
    max_total_time: int | None = None
    max_len: int | None = None
    max_crashes: int | None = None
    instances: int | None = None
    seeds: list[str] | None = None
    build_spec_id: str | None = None
    # Per-campaign ResourceSpec override (mem/cpus/pids/tmpfs/timeout/unconstrained).
    resources: dict | None = None


def _resolve_target_inputs(session, project, target):
    """Resolve the harness + target sources for a campaign from the target's metadata /
    a prior harness_generation finding (reuses the fuzzing-task resolvers)."""
    from hexgraph.db.models import Task
    from hexgraph.engine.fuzzing import resolve_harness, resolve_target_sources

    # A throwaway shell task carries no params; the resolvers fall back to the managed
    # harness node / latest harness_generation finding + target.metadata fuzz_target_sources.
    fake = Task(project_id=project.id, target_id=target.id, type="fuzzing", params_json={})
    source, _fid, function = resolve_harness(session, target, fake)
    sources = resolve_target_sources(target, fake)
    return source, function, sources


@router.post("/api/projects/{project_id}/campaigns")
def api_start_campaign(project_id: str, body: CampaignCreate):
    """Start a detached fuzz campaign; returns immediately (status `running`)."""
    try:
        assert_allows_execution()
    except PolicyViolation as exc:
        raise HTTPException(403, str(exc))
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        t = s.get(Target, body.target_id)
        if t is None or t.project_id != project_id:
            raise HTTPException(404, "target not found in this project")
        surface = body.surface or C.infer_surface(t)
        source, function, sources = _resolve_target_inputs(s, p, t)
        spec = FuzzCampaignSpec(
            target_id=t.id, surface=surface, engine=body.engine,
            harness_source=source, function=body.function or function,
            target_sources=sources, seeds=body.seeds or [],
            max_total_time=body.max_total_time or 60, max_len=body.max_len or 4096,
            max_crashes=body.max_crashes or 10, instances=body.instances or 1,
            build_spec_id=body.build_spec_id,
        )
        try:
            row = C.start_campaign(s, p, t, spec=spec, resources=body.resources)
        except C.CampaignError as exc:
            raise HTTPException(400, str(exc))
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return C.campaign_to_dict(row)


@router.get("/api/projects/{project_id}/campaigns")
def api_list_campaigns(project_id: str, target_id: str | None = None):
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        return {"campaigns": C.list_campaigns(s, p, target_id=target_id)}


@router.get("/api/campaigns/{campaign_id}")
def api_get_campaign(campaign_id: str):
    """Status + live stats (execs/s, edges, crash count, coverage). The reaper updates
    these as the campaign runs; poll this for a live view (Phase 4 adds SSE)."""
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        # Reap on read so the surfaced stats are fresh even between reaper ticks.
        try:
            C.reap_campaign(s, c)
        except Exception:  # noqa: BLE001 — a read must never fail on a reap hiccup
            s.rollback()
            c = s.get(FuzzCampaign, campaign_id)
        return C.campaign_to_dict(c)


@router.get("/api/campaigns/{campaign_id}/artifacts")
def api_campaign_artifacts(campaign_id: str):
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        return {"artifacts": C.list_artifacts(s, c)}


@router.post("/api/campaigns/{campaign_id}/stop")
def api_stop_campaign(campaign_id: str):
    """Stop a running campaign (kill the container, preserve the corpus in CAS)."""
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        return C.campaign_to_dict(C.stop_campaign(s, c))


@router.post("/api/campaigns/{campaign_id}/resume")
def api_resume_campaign(campaign_id: str):
    """Resume a stopped campaign, seeded from the preserved corpus."""
    try:
        assert_allows_execution()
    except PolicyViolation as exc:
        raise HTTPException(403, str(exc))
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        try:
            return C.campaign_to_dict(C.resume_campaign(s, c))
        except (C.CampaignError, ValueError) as exc:
            raise HTTPException(400, str(exc))
