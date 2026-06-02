"""Fuzz environments — the registered places a campaign's container can run (design
§5.8b, Phase 6).

`local` (the host Docker daemon, always implicit) + N user-owned REMOTE Docker
endpoints. A campaign SELECTS one (defaulting `local`); when it selects a remote
environment, `get_campaign_executor` returns a `RemoteDockerExecutor` pointed at that
environment's DOCKER_HOST — so the Builder/Fuzzer run on the remote with NO code change
(the seam is the entire point). Selecting a remote endpoint is gated by
`features.fuzz_remote` (the ONLY place — `policy.assert_allows_fuzz_remote`), the
SAME sandbox boundary applies on the remote, and every launch is audited.

**Secrets.** A `FuzzEnvironment` row holds ONLY non-secret metadata (label, descriptor,
transport, ResourceSpec ceiling, cached health). The connection details (DOCKER_HOST,
SSH key/password, TLS certs) are read at connect time from env/`config.toml` keyed by
the environment id (`config.fuzz_remote_connection`) — NEVER stored in the DB, NEVER
logged, reported presence-only.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from hexgraph.db.models import FuzzEnvironment, Project
from hexgraph.sandbox.resources import ResourceSpec

LOCAL_ID = "local"


def slug(name: str) -> str:
    """A stable, human-friendly environment id derived from the name (so the secret
    connection env var — HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST — is sane, not a UUID).
    Lowercase alphanumerics + dashes; collapses runs; bounded length."""
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return (s or "env")[:32]


class FuzzEnvError(RuntimeError):
    """A fuzz-environment operation failed (unknown env, no connection, not permitted)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── registration / listing (non-secret metadata only) ──────────────────────────

def register_environment(session: Session, *, name: str, transport: str = "ssh",
                         host_descriptor: str | None = None,
                         resources: dict | None = None) -> FuzzEnvironment:
    """Register a remote fuzz environment (NON-SECRET metadata only). The connection
    details (DOCKER_HOST/creds/certs) are configured SEPARATELY in env/config.toml keyed
    by the returned environment's id — never passed here, never stored.

    `host_descriptor` is a non-secret hint shown in the UI (e.g. 'ssh://fuzzbox'); the
    actual connection string is the secret. `resources` is the per-environment
    ResourceSpec CEILING a campaign on this environment inherits."""
    transport = (transport or "ssh").lower()
    if transport not in ("ssh", "tcp"):
        raise FuzzEnvError("transport must be 'ssh' or 'tcp'")
    if not (name or "").strip():
        raise FuzzEnvError("a fuzz environment needs a name")
    # The id is a SLUG of the name (stable, so the secret connection env var
    # HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST is human-keyable, not a UUID). Reject a clash
    # with `local` or an existing env so the secret keying is unambiguous.
    eid = slug(name)
    if eid == LOCAL_ID:
        raise FuzzEnvError("'local' is reserved")
    if session.get(FuzzEnvironment, eid) is not None:
        raise FuzzEnvError(f"a fuzz environment with id {eid!r} already exists")
    # Normalize the ResourceSpec (drops unknown keys; never a security/policy field).
    res = ResourceSpec.from_dict(resources or {}).to_dict() if resources else {}
    row = FuzzEnvironment(id=eid, name=name.strip(), transport=transport,
                          host_descriptor=(host_descriptor or "").strip() or None,
                          resources_json=res, last_health_json={})
    session.add(row)
    session.flush()
    return row


def list_environments(session: Session) -> list[dict]:
    """All registered environments + the implicit `local` default, each with presence-only
    secret status and the cached health-check. Never returns a connection string."""
    out = [_local_dict()]
    rows = (session.query(FuzzEnvironment)
            .filter(FuzzEnvironment.archived.is_(False))
            .order_by(FuzzEnvironment.created_at.asc()).all())
    out.extend(environment_to_dict(r) for r in rows)
    return out


def _local_dict() -> dict:
    return {"id": LOCAL_ID, "name": "local", "transport": "local",
            "host_descriptor": "the host Docker daemon", "is_local": True,
            "connection_present": True, "resources": {}, "health": {"ok": True},
            "created_at": None}


def environment_to_dict(row: FuzzEnvironment) -> dict:
    """Serialize an environment for the API/UI — NON-SECRET only. `connection_present` is
    presence-only (the secret connection is configured in env/config.toml, never echoed)."""
    from hexgraph import config

    return {
        "id": row.id, "name": row.name, "transport": row.transport,
        "host_descriptor": row.host_descriptor, "is_local": False,
        "connection_present": config.fuzz_remote_has_connection(row.id),
        "resources": row.resources_json or {},
        "health": row.last_health_json or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def archive_environment(session: Session, row: FuzzEnvironment) -> None:
    row.archived = True
    session.flush()


# ── executor selection (the seam) ───────────────────────────────────────────────

def get_campaign_executor(session: Session, env_id: str | None, *, image: str | None = None,
                          timeout: int | None = None):
    """Return the Executor for a campaign's selected environment (the seam — no identity
    branching in engine/task code beyond this single resolution point). `local`/None →
    the local executor; a remote env → a `RemoteDockerExecutor` pointed at its secret
    DOCKER_HOST. Selecting a remote endpoint is GATED here by `features.fuzz_remote`
    (fail-closed) — the ONLY gate. Raises FuzzEnvError if the env is unknown / has no
    configured connection, PolicyViolation if the gate is off."""
    from hexgraph.sandbox.executor import get_executor

    if not env_id or env_id == LOCAL_ID:
        return get_executor()

    from hexgraph import config
    from hexgraph.policy import assert_allows_fuzz_remote
    from hexgraph.sandbox.remote_executor import RemoteDockerExecutor

    row = session.get(FuzzEnvironment, env_id)
    if row is None or row.archived:
        raise FuzzEnvError(f"unknown fuzz environment {env_id!r}")
    # THE gate (fail-closed): running a campaign on a remote endpoint needs features.fuzz_remote.
    assert_allows_fuzz_remote()
    conn = config.fuzz_remote_connection(env_id)
    if not conn:
        raise FuzzEnvError(
            f"fuzz environment {row.name!r} has no configured connection — set "
            f"HEXGRAPH_FUZZ_REMOTE_{env_id.upper().replace('-', '_')}_DOCKER_HOST (or "
            f"config.toml [fuzz_remote.{env_id}]). Connection details are secrets, never stored.")
    fimg = image or _fuzz_image()
    ex = RemoteDockerExecutor(conn["docker_host"], image=fimg,
                              timeout=timeout or _fuzz_timeout(), tls_env=conn.get("tls_env"))
    return ex


def resolve_resources_ceiling(session: Session, env_id: str | None,
                              override: dict | None) -> dict | None:
    """If the selected environment carries a ResourceSpec ceiling, fold it under the
    per-campaign override (the override may RAISE up to the ceiling but the ceiling is the
    environment's stated max). Returns the effective override dict for the campaign. A
    pure resource concern — NEVER touches policy.py."""
    if not env_id or env_id == LOCAL_ID:
        return override
    row = session.get(FuzzEnvironment, env_id)
    if row is None or not row.resources_json:
        return override
    ceiling = dict(row.resources_json)
    # The environment ceiling is the base; a per-campaign override layers on top (the
    # campaign chooses within the box the environment allows). unconstrained from either
    # side wins (a beefy remote box the user said to use fully).
    merged = {**ceiling, **{k: v for k, v in (override or {}).items() if v is not None}}
    return merged


# ── health-check ────────────────────────────────────────────────────────────────

def health_check(session: Session, env_id: str) -> dict:
    """Verify a remote environment is reachable + authorized + has the fuzz image present
    (the one-time-build/pull check), cache the NON-SECRET result on the row, and return it.
    Gated by features.fuzz_remote (you authorize the endpoint to even probe it). The local
    environment is trivially healthy."""
    if env_id == LOCAL_ID:
        return {"ok": True, "reachable": True, "authorized": True, "image_present": True,
                "detail": "local Docker daemon", "checked_at": _now_iso()}
    from hexgraph import config
    from hexgraph.policy import assert_allows_fuzz_remote
    from hexgraph.sandbox.remote_executor import RemoteDockerExecutor

    row = session.get(FuzzEnvironment, env_id)
    if row is None or row.archived:
        raise FuzzEnvError(f"unknown fuzz environment {env_id!r}")
    assert_allows_fuzz_remote()
    conn = config.fuzz_remote_connection(env_id)
    if not conn:
        res = {"ok": False, "reachable": False, "authorized": False, "image_present": False,
               "detail": "no connection configured (set the secret DOCKER_HOST in env/config.toml)",
               "checked_at": _now_iso()}
        row.last_health_json = res
        session.flush()
        return res
    ex = RemoteDockerExecutor(conn["docker_host"], image=_fuzz_image(),
                              tls_env=conn.get("tls_env"))
    res = ex.health()
    res["checked_at"] = _now_iso()
    row.last_health_json = res  # NON-SECRET (the executor scrubs the connection string)
    session.flush()
    return res


def _fuzz_image() -> str:
    import os

    from hexgraph import settings
    return os.environ.get("HEXGRAPH_FUZZ_IMAGE") or settings.get(
        "features.fuzzing.image", "hexgraph-fuzz:latest")


def _fuzz_timeout() -> int:
    from hexgraph import settings
    return int(settings.get("features.fuzzing.timeout", 300) or 300)


def audit_remote_launch(session: Session, *, project: Project, env_id: str,
                        target_id: str | None, task_id: str | None,
                        container_name: str | None) -> None:
    """Audit a campaign launch on a REMOTE fuzz environment to EgressEvent — a durable,
    queryable record that a container was launched on a remote host (design §5.8b: the
    SSH/TLS connection is audited). The descriptor is NON-SECRET (the environment's
    host_descriptor), never the connection string."""
    from hexgraph.engine.audit import record_egress

    row = session.get(FuzzEnvironment, env_id) if env_id and env_id != LOCAL_ID else None
    dest = (row.host_descriptor or row.name) if row else env_id or LOCAL_ID
    record_egress(session, project_id=project.id, target_id=target_id, task_id=task_id,
                  dest=f"fuzz-env:{dest}", allowed=True, tool="fuzz_remote",
                  detail=f"launched campaign container {container_name or '?'} on remote "
                         f"fuzz environment {row.name if row else env_id!r}")
