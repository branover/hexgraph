"""Remote fuzz environments — register / list / health-check (design §5.8b, Phase 6).

Settings registers environments (`local` + N remote Docker endpoints, each with a
ResourceSpec ceiling); a campaign selects one (defaulting `local`). The control plane
stays loopback; the remote is purely a compute backend. Secrets (the DOCKER_HOST/creds)
are NEVER stored here — they live in env/config.toml keyed by the environment id and are
reported PRESENCE-ONLY. Selecting a remote endpoint / health-checking it is gated by
features.fuzz_remote (the only gate)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from hexgraph.db.models import FuzzEnvironment
from hexgraph.db.session import session_scope
from hexgraph.engine import fuzz_env as FE
from hexgraph.policy import PolicyViolation

router = APIRouter()


class EnvironmentCreate(BaseModel):
    name: str
    transport: str = "ssh"                  # ssh | tcp
    host_descriptor: str | None = None      # NON-secret hint (the connection is a secret)
    resources: dict | None = None           # per-environment ResourceSpec ceiling


@router.get("/api/fuzz/environments")
def api_list_environments():
    """All registered fuzz environments + the implicit `local` default — NON-SECRET only
    (each carries `connection_present` presence-only + the cached health-check)."""
    with session_scope() as s:
        return {"environments": FE.list_environments(s)}


@router.post("/api/fuzz/environments")
def api_register_environment(body: EnvironmentCreate):
    """Register a remote fuzz environment (NON-SECRET metadata only). Configure its secret
    connection SEPARATELY in env/config.toml keyed by the returned id — never sent here."""
    with session_scope() as s:
        try:
            row = FE.register_environment(
                s, name=body.name, transport=body.transport,
                host_descriptor=body.host_descriptor, resources=body.resources)
        except FE.FuzzEnvError as exc:
            raise HTTPException(400, str(exc))
        return FE.environment_to_dict(row)


@router.post("/api/fuzz/environments/{env_id}/health")
def api_health_check(env_id: str):
    """Verify a remote environment is reachable + authorized + has the fuzz image present.
    Gated by features.fuzz_remote (403 when off). Returns a NON-SECRET health dict."""
    with session_scope() as s:
        try:
            return FE.health_check(s, env_id)
        except FE.FuzzEnvError as exc:
            raise HTTPException(404, str(exc))
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))


@router.delete("/api/fuzz/environments/{env_id}")
def api_archive_environment(env_id: str):
    if env_id == FE.LOCAL_ID:
        raise HTTPException(400, "the local environment cannot be removed")
    with session_scope() as s:
        row = s.get(FuzzEnvironment, env_id)
        if row is None:
            raise HTTPException(404, "environment not found")
        FE.archive_environment(s, row)
        return {"id": env_id, "archived": True}
