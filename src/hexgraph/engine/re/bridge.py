"""Persistent per-target Ghidra bridge lifecycle (`re_bridge_*` / `hexgraph ghidra-bridge`).

A bridge is a LONG-LIVED sandbox container running a resident PyGhidra process with the target's
WARM slot opened once (`ghidra_bridge_probe.py` -> `pyghidra_lib.open_target` + `serve_bridge`), kept
resident behind a small line-delimited JSON RPC server. While it's up, decompiles for that target
reuse the resident project instead of re-opening it per call (~15s on a 6GB project). Decompiler
routing (`sandbox/decompiler.get_decompiler`) prefers a live bridge for the target.

Design mirrors `re_analyze` (engine.re.analysis): single-flight by a deterministic container name,
detached via `start_detached`, status by polling. The per-target registry is a `bridge` entry on
`target.metadata_json` ({container, ip, port, status}) — no migration; routing reads it (the target
is already in scope) and confirms liveness, self-healing a dead entry to the headless fallback.

Networking: the bridge container runs with `allow_network=True` (`--network bridge`) and the host
connects to its private bridge IP directly (the simplest routing — no docker-proxy `-p` publish).
Gated on `features.network` (the container IP is RFC1918-private) and audited to `EgressEvent`.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time

log = logging.getLogger(__name__)

CONTAINER_PREFIX = "hexgraph-ghidra-bridge-"
BRIDGE_PORT = 4768
# How long start_bridge blocks waiting for the resident project to finish opening + the server to
# accept before returning 'starting' (poll via bridge_status). A 6 GB project opens in ~tens of s.
_START_WAIT_S = 90


def container_name(content_sha: str) -> str:
    """The single-flight container name for a target's bridge (host-global, like re_analyze)."""
    return f"{CONTAINER_PREFIX}{content_sha[:16]}"


def _ghidra_slot(project, target, *, runner):
    """Resolve `(slot, artifact, sha)` for the target's GHIDRA warm project (the bridge is a Ghidra
    feature), or None when inapplicable. The bridge opens THIS slot via -process."""
    artifact = getattr(target, "path", None)
    data_dir = getattr(project, "data_dir", None)
    if not artifact or not data_dir:
        return None
    try:
        from hexgraph.engine.re import ghidra_project as gp
        from hexgraph.sandbox.runner import sandbox_image

        sha = gp.content_hash(artifact)
        version = gp.ghidra_version_for_image(sandbox_image(), runner=runner)
        return gp.resolve(data_dir, sha, version), artifact, sha
    except Exception:  # noqa: BLE001 — best-effort; a resolve failure reads as inapplicable
        return None


def _container_ip(name: str) -> str | None:
    """The container's private bridge IP (`docker inspect`), or None. The host reaches the bridge
    server here — the simplest routing, no docker-proxy `-p` publish needed."""
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            capture_output=True, text=True, timeout=10)
        ip = (out.stdout or "").strip()
        return ip or None
    except (OSError, subprocess.SubprocessError):
        return None


def _serving(ip: str, port: int, timeout: float = 2.0) -> bool:
    """True if the bridge port accepts a TCP connection (a cheap liveness check; the decompile RPC
    itself fails gracefully to headless if the server isn't actually ready)."""
    import socket

    try:
        socket.create_connection((ip, port), timeout).close()
        return True
    except OSError:
        return False


def bridge_meta(target) -> dict | None:
    """The recorded bridge entry on the target (or None)."""
    return (getattr(target, "metadata_json", None) or {}).get("bridge")


def _record_bridge(session, target, *, container, ip, port, status="running") -> None:
    md = dict(target.metadata_json or {})
    md["bridge"] = {"container": container, "ip": ip, "port": port, "status": status}
    target.metadata_json = md
    session.flush()


def _clear_bridge(session, target) -> None:
    md = dict(target.metadata_json or {})
    if md.pop("bridge", None) is not None:
        target.metadata_json = md
        session.flush()


def _finalize(session, project, target, name, *, runner) -> dict:
    """Poll the container: if it's running AND serving, record the metadata + audit egress and
    return `running`; if it exited, `failed`; if running-but-not-yet-serving, `starting`; if gone,
    `none`. The single source of truth shared by start_bridge (after launch) and bridge_status."""
    ex = runner
    poll = ex.poll_detached(name) or {}
    if not poll.get("exists"):
        _clear_bridge(session, target)
        return {"state": "none", "detail": "no bridge for this target", "container": name}
    if not poll.get("running"):
        _clear_bridge(session, target)
        return {"state": "failed",
                "detail": f"bridge container exited (code {poll.get('exit_code')}) — the warm "
                          "Ghidra slot may be missing (run re_analyze) or the image lacks the "
                          "bridge (rebuild with WITH_GHIDRA=1)", "container": name}
    ip = _container_ip(name)
    if not (ip and _serving(ip, BRIDGE_PORT)):
        return {"state": "starting",
                "detail": "bridge container is up; still opening the project — call bridge_status "
                          "to poll", "container": name, "ip": ip, "port": BRIDGE_PORT}
    # Serving. Gate on features.network (the dest IP is RFC1918-private) + audit, then record.
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import PolicyViolation, assert_allows_egress, local_tcp_scope

    dest = f"{ip}:{BRIDGE_PORT}"
    try:
        scope = local_tcp_scope(ip, BRIDGE_PORT)
        assert_allows_egress(dest, scope)
    except PolicyViolation as exc:
        record_egress(session, project_id=project.id, dest=dest, allowed=False,
                      tool="ghidra_bridge", target_id=target.id, detail=str(exc), durable=True)
        try:
            ex.stop_detached(name, remove=True)
        except Exception:  # noqa: BLE001
            pass
        _clear_bridge(session, target)
        return {"state": "denied", "detail": str(exc), "container": name}
    record_egress(session, project_id=project.id, dest=dest, allowed=True,
                  tool="ghidra_bridge", target_id=target.id, detail=scope.rationale)
    _record_bridge(session, target, container=name, ip=ip, port=BRIDGE_PORT)
    return {"state": "running",
            "detail": "bridge ready — Ghidra ops for this target now reuse the resident project",
            "container": name, "ip": ip, "port": BRIDGE_PORT}


def start_bridge(session, project, target, *, runner=None) -> dict:
    """Start OR attach to the target's persistent Ghidra bridge. Requires a warm Ghidra analysis
    (else points at re_analyze) and `features.network` (the container needs a network). Idempotent +
    single-flight. Blocks up to ~90s for the project to open; returns `starting` if slower (poll via
    bridge_status). On success, decompiler routing prefers the bridge for this target."""
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    ex = runner or get_executor()
    if not docker_available():
        return {"state": "unavailable", "detail": "Docker/sandbox not running"}
    # Coarse network gate up front (refuse before launching if features.network is off).
    from hexgraph.policy import current_policy

    if not current_policy().allow_network:
        return {"state": "denied",
                "detail": "the Ghidra bridge needs a network to serve RPC — enable features.network "
                          "(the bounded local-network tier)"}
    ctx = _ghidra_slot(project, target, runner=ex)
    if ctx is None:
        return {"state": "unavailable", "detail": "this target has no byte artifact / data dir"}
    slot, artifact, sha = ctx
    if not slot.exists():
        return {"state": "needs_analysis",
                "detail": "no warm Ghidra analysis for this target — run re_analyze (with headless "
                          "Ghidra active) first, then start the bridge"}
    name = container_name(sha)
    poll = ex.poll_detached(name) or {}
    if poll.get("running"):
        return _finalize(session, project, target, name, runner=ex)  # attach + (re)record
    if poll.get("exists"):
        try:  # a stale exited container holds the name — reap it
            ex.stop_detached(name, remove=True)
        except Exception:  # noqa: BLE001
            pass

    slot.prepare()
    from hexgraph.sandbox.resources import resource_spec_for_artifact

    outdir = tempfile.mkdtemp(prefix="hexgraph-bridge-out-")  # unused by the harness; API needs one
    try:
        ex.start_detached(
            "ghidra_bridge_probe.py", artifact, name=name, outdir=outdir,
            project_mount=str(slot.root), allow_network=True,
            resources=resource_spec_for_artifact(artifact, "sandbox"),
            extra_env={"GHIDRA_BRIDGE_PORT": str(BRIDGE_PORT)})
    except Exception as exc:  # noqa: BLE001
        msg = str(exc).lower()
        if "already in use" in msg or ("name" in msg and "in use" in msg):
            return _finalize(session, project, target, name, runner=ex)  # single-flight race
        return {"state": "failed", "detail": f"could not start bridge: {exc}", "container": name}

    deadline = time.monotonic() + _START_WAIT_S
    while True:  # always finalize at least once (records + audits when it comes up serving)
        res = _finalize(session, project, target, name, runner=ex)
        if res["state"] in ("running", "failed", "denied"):
            return res
        if time.monotonic() >= deadline:
            break
        time.sleep(3)
    return {"state": "starting",
            "detail": "bridge launched; the project is still opening — call bridge_status to poll",
            "container": name}


def stop_bridge(session, project, target, *, runner=None) -> dict:
    """Stop the target's bridge (if any) and revert its ops to the headless path."""
    from hexgraph.sandbox.executor import get_executor

    ex = runner or get_executor()
    ctx = _ghidra_slot(project, target, runner=ex)
    name = container_name(ctx[2]) if ctx else (bridge_meta(target) or {}).get("container")
    stopped = False
    if name:
        try:
            if (ex.poll_detached(name) or {}).get("exists"):
                ex.stop_detached(name, remove=True)
                stopped = True
        except Exception:  # noqa: BLE001 — best-effort
            pass
    _clear_bridge(session, target)
    return {"state": "stopped" if stopped else "none",
            "detail": "bridge stopped; this target reverts to headless Ghidra" if stopped
                      else "no running bridge for this target", "container": name}


def bridge_status(session, project, target, *, runner=None) -> dict:
    """Read-only: the target's bridge state (running | starting | failed | denied | none). Records
    the metadata when it transitions to running. Starts nothing."""
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return {"state": "unavailable", "detail": "Docker/sandbox not running"}
    ctx = _ghidra_slot(project, target, runner=runner or get_executor())
    if ctx is None:
        return {"state": "none", "detail": "this target has no byte artifact"}
    ex = runner or get_executor()
    return _finalize(session, project, target, container_name(ctx[2]), runner=ex)


def blocking_message(target, op: str = "this operation") -> str | None:
    """When a live bridge holds the target's project, a headless Ghidra op on the SAME slot would
    conflict on Ghidra's project lock. Until the bridge serves that op (the PR2 refactor), the
    op's call site calls this and, on a non-None result, returns it instead of running headless.
    None when no bridge is live (proceed headless as before). re_decompile_* IS served by the
    bridge, so it routes there instead of being blocked."""
    if bridge_endpoint(target) is None:
        return None
    return (f"A resident Ghidra bridge holds this target's project, so {op} can't run headless "
            "right now without conflicting on Ghidra's project lock. Run re_bridge_stop(target) to "
            "use the headless path (decompile is served BY the bridge). Bridge coverage for this op "
            "is coming in a follow-up.")


def bridge_endpoint(target) -> tuple[str, int] | None:
    """For decompiler routing: `(ip, port)` when the target has a LIVE bridge, else None. The common
    no-bridge case (no metadata entry) does NO docker call and returns immediately. When an entry
    exists, re-inspect the container BY NAME for its CURRENT ip — NOT the stored ip: a dead bridge's
    Docker ip can be recycled by another container, which a bare port check alone wouldn't catch. A
    gone container yields no ip → None (caller falls back to headless; bridge_status reaps the entry).
    Never raises."""
    try:
        meta = bridge_meta(target)
        if not meta:
            return None
        port = int(meta.get("port") or BRIDGE_PORT)
        ip = _container_ip(meta.get("container")) if meta.get("container") else meta.get("ip")
        if ip and _serving(ip, port, timeout=1.0):
            return ip, port
    except Exception:  # noqa: BLE001 — routing must never break decompilation
        pass
    return None
