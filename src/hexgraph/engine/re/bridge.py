"""Persistent per-target Ghidra bridge lifecycle (`re_bridge_*` / `hexgraph ghidra-bridge`).

A bridge is a LONG-LIVED sandbox container running a resident PyGhidra process with the target's
WARM slot opened once (`ghidra_bridge_probe.py` -> `pyghidra_lib.open_target` + `serve_bridge`), kept
resident behind a small line-delimited JSON RPC server. While it's up, decompiles for that target
reuse the resident project instead of re-opening it per call — measured ~2.3x on a 938MB image
(~20s/call headless vs ~9s/call resident, with a ~6s one-off boot). Decompiler
routing (`sandbox/decompiler.get_decompiler`) prefers a live bridge for the target.

Design mirrors `re_analyze` (engine.re.analysis): single-flight by a deterministic container name,
detached via `start_detached`, status by polling. The per-target registry is a `bridge` entry on
`target.metadata_json` ({container, ip, port, status}) — no migration; routing reads it (the target
is already in scope). An entry is recorded as soon as the container is up, `starting` included,
because the project lock is taken before the socket binds; routing falls back to headless only on
positive evidence the container is gone (`bridge_route`), never on an unanswered probe.

Networking: the bridge container runs with `allow_network=True` (`--network bridge`) and the host
connects to its private bridge IP directly (the simplest routing — no docker-proxy `-p` publish).
Gated on `features.network` (the container IP is RFC1918-private) and audited to `EgressEvent`.
"""

from __future__ import annotations

import ipaddress
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


def _parse_ip(token: str | None) -> str | None:
    """A docker-rendered address token, or None when it is not actually an address.

    Validating rather than trusting `parts[1]` is the whole point, because both non-address shapes
    docker really produces are TRUTHY — so an unchecked token doesn't merely fail, it SHADOWS the
    caller's fallback to the recorded address (`bridge_route`'s `ip or meta["ip"]`) and becomes the
    destination instead. Captured from Docker 29.6.1:

    * a running container with no usable address renders the empty `.IPAddress` as `invalid IP`
      (docker >= 26 stringifies the zero value), which splits to the token `invalid`;
    * `{{range .NetworkSettings.Networks}}` has no separator, so a container on TWO networks
      concatenates both addresses into `172.18.0.2172.19.0.2`.

    Neither is routable and neither can be split back apart reliably, so both read as "no fresh
    address" and the recorded one wins — which is the safe direction, since `_finalize` only records
    an ip after `_serving` accepted a connection on it."""
    try:
        ipaddress.ip_address(token or "")
    except ValueError:
        return None
    return token


def _container_state(name: str) -> tuple[bool | None, str | None]:
    """`(not_running, ip)` from ONE `docker inspect` — the single probe both routing and the degrade
    path need, so neither pays for the other's question.

    `not_running` is the same tri-state `_container_not_running` documents: True when docker says
    the container isn't running (absent, or present but exited), False when it reports one running,
    None when the inspect couldn't answer. `ip` is the container's CURRENT bridge address, re-read
    rather than trusted from the registry — a dead bridge's Docker IP can be recycled — and VALIDATED
    (`_parse_ip`), because docker's non-address renderings are truthy and would otherwise shadow the
    caller's fallback to the recorded address rather than merely failing.

    One call rather than two matters because routing runs on EVERY Ghidra op, where the degrade path
    runs only after a failure. The old routing paid an inspect for the IP and then a TCP connect for
    liveness; this answers both at once."""
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}} "
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None, None
    if out.returncode != 0:
        err = (out.stderr or "").lower()
        gone = True if ("no such object" in err or "no such container" in err) else None
        return gone, None
    parts = (out.stdout or "").strip().split()
    state = parts[0].lower() if parts else ""
    # VALIDATED, not just present: docker's non-address renderings are truthy (see `_parse_ip`), so
    # a bare `parts[1]` would shadow `bridge_route`'s fallback to the recorded address.
    ip = _parse_ip(parts[1]) if len(parts) > 1 else None
    if state == "true":
        return False, ip
    if state == "false":
        return True, ip
    return None, ip          # zero exit, unrecognised body ⇒ we did NOT get an answer


def bridge_route(target) -> tuple[str, int] | None:
    """`(ip, port)` to send a Ghidra op to when the bridge MIGHT still own `target`'s project, else
    None to use headless.

    Deliberately NOT `bridge_endpoint`, whose "is it answering right now?" is the wrong question for
    routing. A bridge that is registered and not positively dead still HOLDS the Ghidra project — it
    may be mid-startup, or busy inside a long op behind its listen backlog — and a headless open
    behind it fails on the project lock. So route to it unless we have positive evidence it's gone.

    Guessing wrong costs one failed RPC, which `sandbox.decompiler.run_ghidra_op` then resolves with
    the same positive-evidence check before degrading. Guessing wrong the OTHER way costs a second
    opener on a live project, which is the failure this whole line of work exists to prevent."""
    try:
        meta = bridge_meta(target)
        if not meta:
            return None                      # nothing registered — nothing holds the slot
        not_running, ip = _container_state(meta.get("container") or "")
        if not_running is True:
            return None                      # positively gone ⇒ headless is safe
        return ((ip or meta.get("ip")), int(meta.get("port") or BRIDGE_PORT)) \
            if (ip or meta.get("ip")) else None
    except Exception:  # noqa: BLE001 — routing must never break decompilation
        return None


def _container_not_running(name: str) -> bool | None:
    """Tri-state liveness only, for callers that don't need the address. Delegates to
    `_container_state` so there is ONE docker-reply parser: True when docker positively says the
    container is not running (absent, or present but exited), False when it reports one running,
    None when the inspect could not answer at all.

    NOT "absent": an exited container still exists, and this returns True for it — its JVM is dead,
    so it holds no project. Every unknown resolves to None, and a caller that must not guess wrong
    reads None as "assume it IS running"."""
    return _container_state(name)[0]


def bridge_confirmed_gone(target) -> bool:
    """True ONLY on positive evidence that `target`'s bridge is gone; False on ANY uncertainty.

    `bridge_endpoint` answers "can I route there?" and collapses gone-vs-couldn't-tell into None.
    That is right for routing — either way you don't route — and wrong for the one caller that must
    decide whether running a headless op is SAFE, because a live bridge still owns the project and
    a second open collides.

    The asymmetry is what makes this a separate function. The failure that sends a caller here is
    typically a TIMEOUT from a bridge under load, which is precisely when a one-second connect
    probe is most likely to miss and a `docker inspect` is slowest — so a guard that reads
    uncertainty as death is weakest exactly where it matters. Getting it wrong costs one failed op
    in the safe direction, or a second writer on a live Ghidra project in the other."""
    try:
        meta = bridge_meta(target)
        if not meta:
            return True  # nothing registered — bridge_stop clears this, and nothing holds the slot
        name = meta.get("container")
        if not name:
            return False  # can't name it, can't check it ⇒ assume it's alive
        return _container_not_running(name) is True  # None (couldn't tell) ⇒ assume alive
    except Exception:  # noqa: BLE001 — an unanswerable probe must never read as "safe to proceed"
        return False


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
    """Poll the container: if it's running AND serving, record the metadata and return `running`; if
    it exited, `failed`; if running-but-not-yet-serving, record it `starting` (it already holds the
    project lock); if gone, `none`. Whenever the container has an address, the egress gate + audit run
    FIRST, so no entry is ever recorded — and therefore routable — before the policy has approved its
    destination. The single source of truth shared by start_bridge (after launch) and bridge_status."""
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
    # Gate on features.network (the dest IP is RFC1918-private) + audit BEFORE recording ANY entry,
    # `starting` included. A recorded entry is a ROUTABLE endpoint — `bridge_route` hands its address
    # straight to `connect_managed` — so gating only the `running` transition would spend the whole
    # startup window (_START_WAIT_S and beyond) connecting to an address the policy may be about to
    # REFUSE, with no EgressEvent for any of it. Refusing at the first poll instead of at first serve
    # is also the better failure: the container is torn down before anything dials it.
    if ip:
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
    if not (ip and _serving(ip, BRIDGE_PORT)):
        # RECORD it as `starting`, even though it isn't serving yet. The container is running, and
        # `open_target` takes the Ghidra project lock BEFORE it binds the socket — so for up to
        # _START_WAIT_S this bridge OWNS the project while answering nothing. Without an entry,
        # `bridge_route` sees no bridge, sends the op headless, and it fails on that very lock.
        # `bridge_endpoint` still requires serving, so the two questions stay separate: "might it
        # own the project?" (route) vs "can it answer right now?" (the nudge's `_bridge_live`).
        _record_bridge(session, target, container=name, ip=ip, port=BRIDGE_PORT, status="starting")
        return {"state": "starting",
                "detail": "bridge container is up; still opening the project — call bridge_status "
                          "to poll", "container": name, "ip": ip, "port": BRIDGE_PORT}
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
    """Stop the target's bridge (if any) and revert its ops to the headless path.

    Clearing the registry entry is what makes routing fall back: `bridge_route` reads the entry
    first, so a stopped bridge stops being a routing destination immediately rather than waiting for
    a probe to notice."""
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
