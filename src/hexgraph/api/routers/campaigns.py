"""Fuzz campaigns: start / list / get / stop / resume + status/stats/artifacts
(design §5.7, Phase 3). Build-as-API: no shell — the client REQUESTS a campaign and
HexGraph spawns + reaps a detached, hardened sandbox container. Gated by the EXISTING
exec policy (features.fuzzing/poc) — no new gate.

Phase 4 adds the triage surface the UI renders: per-artifact verify / minimize /
promote, line coverage, server-advertised engines, and a live SSE event stream (with a
polling fallback in the SPA)."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from hexgraph.db.models import FuzzArtifact, FuzzCampaign, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine import fuzz_env as FE
from hexgraph.engine.fuzzers import FuzzCampaignSpec
from hexgraph.policy import PolicyViolation

router = APIRouter()


class CampaignNet(BaseModel):
    """Optional network-fuzz overrides (host/port/proto/spec usually inferred from the
    target — a rehosted device IP / a local service)."""
    host: str | None = None
    port: int | None = None
    protocol: str | None = None
    proto_spec: dict | None = None
    # Launch-and-join (§5.8b): for a LOCAL service HexGraph can start itself (a launchable
    # server binary, no externally-reachable host), it starts the service in its OWN
    # hardened container and joins the fuzzer to its netns so 127.0.0.1:port is reachable
    # WITHOUT --network host. `launch` forces it on; None auto-detects (a launchable binary
    # + a loopback/unset host). `launch_binary` overrides the host path to the server ELF.
    launch: bool | None = None
    launch_binary: str | None = None
    launch_command: list[str] | None = None


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
    # Optional fuzzing dictionary tokens (auto-derived from the target's strings when
    # omitted) — mirrors the MCP start_fuzz_campaign param + the Fuzz modal input.
    dictionary: list[str] | None = None
    build_spec_id: str | None = None
    net: CampaignNet | None = None      # network-fuzz overrides (surface=network)
    # Per-campaign ResourceSpec override (mem/cpus/pids/tmpfs/timeout/unconstrained).
    resources: dict | None = None
    # WHERE the campaign runs (design §5.8b): a registered fuzz environment id, or
    # `local`/None for the host daemon. A remote env is gated by features.fuzz_remote.
    environment: str | None = None


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
    """Start a detached fuzz campaign; returns immediately (status `running`). The policy
    gate is applied INSIDE start_campaign by surface (a live-socket boofuzz campaign rides
    features.network + local_tcp_scope; everything else the exec gate) — NO new gate. A
    PolicyViolation surfaces as 403."""
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        t = s.get(Target, body.target_id)
        if t is None or t.project_id != project_id:
            raise HTTPException(404, "target not found in this project")
        surface = body.surface or C.infer_surface(t)
        source, function, sources = _resolve_target_inputs(s, p, t)
        # Fail FAST with a human reason when there is simply nothing to fuzz, BEFORE we
        # spin up a campaign row / container only to fail in the fuzzer's prepare() with
        # a terse internal message. Each surface has its own minimum input:
        #   • source_lib  → an instrumented build's fuzz_target_sources or a harness
        #   • binary_only → a target ELF on disk (target.path or a derived build)
        #   • network     → a live host/port (a rehosted/remote/web surface) — not a file
        if surface in ("source_lib", "file_format") and not source and not sources:
            raise HTTPException(
                400,
                f"Nothing to fuzz on “{t.name}” yet: this target has no fuzz "
                "harness or instrumented build. Generate a harness (run a "
                "harness_generation task on a function), or build it from source with "
                "fuzzing instrumentation, then start the campaign.",
            )
        if surface == "binary_only" and not (body.net and body.net.host) and not (t.path):
            raise HTTPException(
                400,
                f"Nothing to fuzz on “{t.name}” yet: no target binary is on "
                "disk for binary-only fuzzing. Add the executable as a target (or build "
                "one), then start the campaign.",
            )
        net = body.net
        spec = FuzzCampaignSpec(
            target_id=t.id, surface=surface, engine=body.engine,
            harness_source=source, function=body.function or function,
            target_sources=sources, seeds=body.seeds or [],
            dictionary=body.dictionary or [],
            max_total_time=body.max_total_time or 60, max_len=body.max_len or 4096,
            max_crashes=body.max_crashes or 10, instances=body.instances or 1,
            build_spec_id=body.build_spec_id,
            host=net.host if net else None, port=net.port if net else None,
            protocol=(net.protocol if net and net.protocol else "tcp"),
            proto_spec=net.proto_spec if net else None,
            launch=net.launch if net else None,
            launch_binary=net.launch_binary if net else None,
            launch_command=net.launch_command if net else None,
            environment_id=body.environment,
        )
        try:
            row = C.start_campaign(s, p, t, spec=spec, resources=body.resources)
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        except (C.CampaignError, FE.FuzzEnvError) as exc:
            raise HTTPException(400, str(exc))
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        return C.campaign_to_dict(row)


@router.get("/api/projects/{project_id}/campaigns")
def api_list_campaigns(project_id: str, target_id: str | None = None):
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        # Reap NON-TERMINAL campaigns on read (mirrors api_get_campaign) so the SPA's 4s
        # list poll shows fresh execs/edges/crashes even before the per-campaign SSE mounts
        # — without it the card looked idle until completion. Cheap: only running/building
        # rows are polled, and a reap hiccup must never fail the listing.
        live = (s.query(FuzzCampaign)
                .filter(FuzzCampaign.project_id == project_id,
                        FuzzCampaign.status.in_(["running", "building"])).all())
        for row in live:
            try:
                C.reap_campaign(s, row)
            except Exception:  # noqa: BLE001 — a list read must survive a reap hiccup
                s.rollback()
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
    """Resume a stopped campaign, seeded from the preserved corpus. The surface-correct
    policy gate is applied inside start_campaign (exec for binary/source, egress for a
    live-socket network campaign) — NO new gate."""
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        try:
            return C.campaign_to_dict(C.resume_campaign(s, c))
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        except (C.CampaignError, ValueError) as exc:
            raise HTTPException(400, str(exc))


# ── Per-artifact triage actions (verify / minimize / promote) ─────────────────────

def _get_artifact(s, artifact_id: str) -> FuzzArtifact:
    a = s.get(FuzzArtifact, artifact_id)
    if a is None:
        raise HTTPException(404, "artifact not found")
    return a


@router.post("/api/artifacts/{artifact_id}/verify")
def api_verify_artifact(artifact_id: str):
    """Reproduce / re-verify a crash artifact (LLM-free): replay its stored, minimized
    reproducer against the instrumented harness binary and check the unforgeable `crash`
    oracle. Returns {verified, detail, assurance}. (Reproduce and Re-verify are the same
    action — both re-run the stored reproducer.)"""
    with session_scope() as s:
        a = _get_artifact(s, artifact_id)
        if not a.content_cas:
            raise HTTPException(400, "artifact has no stored reproducer to verify")
        try:
            res = C.verify_artifact(s, a)
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        except (C.CampaignError, ValueError) as exc:
            raise HTTPException(400, str(exc))
        return {"artifact_id": artifact_id, "verified": bool(res.get("verified")),
                "detail": res.get("detail"), "assurance": res.get("assurance"),
                "output": res.get("output")}


# `minimize` is, in this codebase, the same LLM-free crash→verify replay (the probe
# already minimizes inline at ingest), so it shares the verify path — kept as a distinct
# endpoint for the UI affordance and future afl-tmin re-minimization.
router.add_api_route("/api/artifacts/{artifact_id}/minimize", api_verify_artifact,
                     methods=["POST"], name="api_minimize_artifact")


class PromoteBody(BaseModel):
    to_poc: bool = False


@router.post("/api/artifacts/{artifact_id}/promote")
def api_promote_artifact(artifact_id: str, body: PromoteBody | None = None):
    """Promote a crash artifact into tracked work: confirm its fuzz_crash finding (so it
    leaves the triage inbox) and — with `to_poc` — seed a reproducer-backed PoC spec AND
    immediately re-run the LLM-free crash verification, returning the outcome
    ({verified, verify_detail, assurance}) so the UI reflects a real verified PoC.

    `to_poc` executes the target, so it is gated by the execution policy: under
    static-only (PoC/fuzzing disabled) it returns 403 with guidance to enable PoC
    verification in Settings, rather than silently seeding a PoC that can never verify."""
    with session_scope() as s:
        a = _get_artifact(s, artifact_id)
        try:
            return C.promote_artifact(s, a, to_poc=bool(body and body.to_poc))
        except PolicyViolation:
            raise HTTPException(
                403,
                "Promoting a crash to a verifiable PoC re-runs it (executes the target), "
                "which is not permitted under the static-only policy. Enable PoC "
                "verification (features.poc) in Settings to promote a crash to a verified "
                "PoC; or use plain Promote to just confirm the finding without re-running it.",
            )
        except C.CampaignError as exc:
            raise HTTPException(400, str(exc))


# ── Coverage (line-level source shading) ──────────────────────────────────────────

@router.get("/api/campaigns/{campaign_id}/coverage")
def api_campaign_coverage(campaign_id: str):
    """Per-file line coverage map for source shading. `{available, percent, files}` —
    `available=False` when the campaign exposed no line map (no shading then)."""
    with session_scope() as s:
        c = s.get(FuzzCampaign, campaign_id)
        if c is None:
            raise HTTPException(404, "campaign not found")
        return C.coverage_for(s, c)


@router.get("/api/campaigns/{campaign_id}/coverage-diff")
def api_campaign_coverage_diff(campaign_id: str, other: str):
    """Run-to-run coverage diff (design §7, Phase 7): what new lines did `other` reach
    that this campaign (`campaign_id`, the base) did not? Returns per-file
    `{base_covered, other_covered, gained, lost}` + project totals; `available=False`
    when either campaign has no line map."""
    with session_scope() as s:
        base = s.get(FuzzCampaign, campaign_id)
        oth = s.get(FuzzCampaign, other)
        if base is None or oth is None:
            raise HTTPException(404, "campaign not found")
        if base.project_id != oth.project_id:
            raise HTTPException(400, "campaigns belong to different projects")
        return C.coverage_diff(s, base, oth)


# ── Server-advertised engines per surface (the Fuzz modal asks the server) ────────

@router.get("/api/fuzz/engines")
def api_fuzz_engines(surface: str | None = None, target_id: str | None = None):
    """The engines HexGraph advertises for an attack surface — the Fuzz modal renders
    these (it NEVER hardcodes the engine list, mirroring the LLM-backend registry). When
    a `target_id` is given, the surface is inferred from the target if not supplied."""
    from hexgraph.engine.fuzzers import SURFACE_ENGINES, SURFACES

    inferred = None
    if surface is None and target_id:
        with session_scope() as s:
            t = s.get(Target, target_id)
            if t is not None:
                inferred = C.infer_surface(t)
    surf = surface or inferred
    if surf is not None and surf not in SURFACES:
        raise HTTPException(400, f"unknown surface {surf!r}")
    if surf is not None:
        engines = list(SURFACE_ENGINES.get(surf, ()))
        return {"surface": surf, "inferred": inferred is not None and surface is None,
                "engines": engines, "default": engines[0] if engines else None}
    # No surface → the whole matrix (so the UI can let the user pick a surface too).
    return {"surfaces": {k: {"engines": list(v), "default": v[0] if v else None}
                         for k, v in SURFACE_ENGINES.items()}}


# ── Live status via SSE (with a polling fallback in the SPA) ──────────────────────

@router.get("/api/campaigns/{campaign_id}/events")
async def api_campaign_events(campaign_id: str):
    """Server-Sent Events stream of a campaign's live status. Each tick reaps on read
    and emits the campaign dict as JSON; the stream ends when the campaign finalizes.
    The SPA prefers this and falls back to interval polling of GET /api/campaigns/{id}
    if the stream errors — so live status is robust either way."""

    async def gen():
        terminal = {"completed", "failed", "stopped", "degraded"}
        last = None
        for _ in range(3600):  # hard cap (~1h at 1s) so a stream can't leak forever
            def snap():
                with session_scope() as s:
                    c = s.get(FuzzCampaign, campaign_id)
                    if c is None:
                        return None
                    try:
                        C.reap_campaign(s, c)
                    except Exception:  # noqa: BLE001
                        s.rollback()
                        c = s.get(FuzzCampaign, campaign_id)
                    return C.campaign_to_dict(c)

            d = await asyncio.to_thread(snap)
            if d is None:
                yield "event: error\ndata: {\"error\": \"campaign not found\"}\n\n"
                return
            payload = json.dumps(d)
            if payload != last:
                yield f"data: {payload}\n\n"
                last = payload
            if d.get("status") in terminal:
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(1.0)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
