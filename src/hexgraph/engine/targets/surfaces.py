"""Web/service attack surfaces — Phase 1 backbone (docs/design/design-dynamic-surfaces.md).

A `web_app` Target is a *reachable surface*, not bytes at rest: it's described by a
**Channel** in `metadata_json` (here, an HTTP base URL) plus the route spec. `surface_recon`
materialises that spec as `endpoint`/`param` nodes and — the differentiator — links each
route to its handler `function` in a sibling firmware binary via a `routes_to` edge, fusing
the dynamic surface with the static binary graph.

Phase 1 is deterministic and **offline**: the route spec is supplied by the caller (e.g. a
parsed OpenAPI/HAR), so there is **no network egress** and the analysis policy stays
static-only. Live crawling/probing arrives in the network phase, gated by the policy seam.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Node, NodeType, Project, Target, TargetKind
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.graph.nodes import get_or_create_node, normalize_symbol_name


def _channel(target: Target) -> dict:
    return (target.metadata_json or {}).get("channel") or {}


def _rehost_container(target: Target) -> str | None:
    """If this surface is a rehosted firmware, the FirmAE container backing it — the probe
    joins its network namespace to reach the emulated device's (private) IP."""
    return (_channel(target).get("rehost") or {}).get("container")


def register_web_surface(
    session: Session, project: Project, base_url: str, *,
    name: str | None = None, parent: Target | None = None,
    endpoints: list[dict] | None = None,
) -> Target:
    """Register an HTTP attack surface as a `web_app` Target. The surface has no bytes;
    its Channel (base URL) + route spec live in `metadata_json`. `endpoints` is an
    optional offline route spec: [{method, path, params?, handler?, auth?}]."""
    if not (base_url or "").strip():
        raise ValueError("a web surface needs a base_url")
    target = Target(
        project_id=project.id,
        parent_id=parent.id if parent else None,
        name=name or base_url,
        path="",  # a dynamic surface is reached via a Channel, not a file
        kind=TargetKind.web_app,
        metadata_json={"channel": {"kind": "http", "base_url": base_url},
                       "endpoints": list(endpoints or [])},
    )
    session.add(target)
    session.flush()
    return target


def register_service_target(
    session: Session, project: Project, host: str, port: int, *,
    transport: str = "tcp", proto: str | None = None,
    name: str | None = None, parent: Target | None = None,
    net_container: str | None = None,
) -> Target:
    """Register a bare non-HTTP network service (a raw TCP/UDP listener) as a `service`
    Target. Like a `web_app`, it has no bytes — it's reached via a Channel
    `{"kind": "tcp"|"udp", "host", "port"}` in `metadata_json`, with `path=""`. Unlike a
    `remote` target there are NO shell/credential semantics: a socket service is a protocol
    endpoint you talk to, not a box you log into.

    This is the first-class home for a bind shell / vendor binary protocol / custom daemon,
    over TCP or UDP (infosvr/9999, SSDP/1900, mDNS/5353, DNS, DHCP, …). `infer_surface`
    resolves it to the `network` surface, so `start_fuzz_campaign` (boofuzz, tcp or udp) and
    the live request/prove path work against it: `run_tcp_probe`/`verify_poc({transport:"tcp"})`
    for a TCP service, `run_udp_probe`/`verify_poc({transport:"udp"})` for a UDP one. All on the
    EXISTING bounded local-network tier (`features.network` + `local_tcp_scope`, audited).
    `net_container` pins the probe to a rehosted device's emulator netns (a service on the
    device's private IP)."""
    transport = (transport or "tcp").lower()
    if transport not in ("tcp", "udp"):
        raise ValueError("transport must be 'tcp' or 'udp'")
    if not (host or "").strip():
        raise ValueError("a socket target needs a host")
    try:
        port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("a socket target needs an integer port") from exc
    if not (0 < port < 65536):
        raise ValueError("port must be in 1..65535")
    channel = {"kind": transport, "host": host, "port": port}
    if net_container:
        channel["net_container"] = net_container
    meta: dict = {"channel": channel}
    if proto:
        meta["proto"] = proto  # an optional app-protocol hint (e.g. "modbus", "mqtt")
    target = Target(
        project_id=project.id, parent_id=parent.id if parent else None,
        name=name or f"{host}:{port} ({transport})",
        path="",  # a service is reached via its Channel, not a file
        kind=TargetKind.service,
        metadata_json=meta,
    )
    session.add(target)
    session.flush()

    # Link the reachable surface (this target) to the SHARED socket NODE — the firmware's
    # network-map endpoint a server `listens_on` and a client `connects_to`. Target (a
    # reachable surface) and node (a graph annotation) stay distinct entities; the
    # `listens_on` edge fuses them so the live service shows up on the same network map a
    # static binary's bind/listen sites do (identity = (project, kind, port), target_id=None).
    from hexgraph.engine.graph.nodes import materialize_socket

    # The socket node is the SHARED abstract endpoint (identity = kind+port); the concrete
    # live host lives on THIS target's Channel (where _device_host reads it), so we don't
    # write `bind_addr`/host onto the shared node — that would clobber a static-recon
    # listen site's recorded bind address (get_or_create_node merges attrs by overwrite).
    sock = materialize_socket(session, project_id=project.id, kind=transport, port=port,
                              created_by="register_service",
                              attrs={"proto": proto} if proto else None)
    add_edge(session, project_id=project.id, src=("target", target.id),
             dst=("node", sock.id), type=EdgeType.listens_on, origin="tool",
             confidence=1.0, created_by_tool="register_service",
             attrs={"port": port})
    return target


def _find_handler(session: Session, project_id: str, handler: str | None) -> Node | None:
    """Resolve a route's handler to an existing function node (in any binary of the
    project), by normalized name — the static↔dynamic bridge."""
    if not handler:
        return None
    norm = normalize_symbol_name(handler) or handler
    return (session.query(Node)
            .filter(Node.project_id == project_id, Node.node_type == NodeType.function.value,
                    Node.name == norm)
            .first())


def _materialize_endpoints(session, project: Project, target: Target, spec: list,
                           created_by: str) -> tuple[int, int]:
    """Materialise a route spec [{method,path,params?,handler?,auth?,status?}] into
    endpoint/param nodes + references edges + routes_to→handler edges. Returns
    (routes, handlers_linked). Shared by surface_recon (offline spec) and web_discover
    (live crawl)."""
    routes = linked = 0
    for ep in spec:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or "/"
        label = f"{method} {path}"
        attrs = {"method": method, "path": path, "auth": ep.get("auth", "unknown")}
        if ep.get("status") is not None:
            attrs["status"] = ep["status"]
        enode = get_or_create_node(
            session, project_id=project.id, node_type=NodeType.endpoint, name=label,
            target_id=target.id, fq_name=label, created_by=created_by, attrs=attrs,
        )
        routes += 1
        for p in ep.get("params", []) or []:
            pname = p if isinstance(p, str) else (p.get("name") or "")
            if not pname:
                continue
            pnode = get_or_create_node(
                session, project_id=project.id, node_type=NodeType.param, name=pname,
                target_id=target.id, fq_name=f"{label}#{pname}", created_by=created_by,
                attrs={"endpoint": label, **({} if isinstance(p, str) else p)},
            )
            add_edge(session, project_id=project.id, src=("node", enode.id), dst=("node", pnode.id),
                     type=EdgeType.references, origin="tool", confidence=1.0, created_by_tool=created_by)
        handler = _find_handler(session, project.id, ep.get("handler"))
        if handler is not None:
            add_edge(session, project_id=project.id, src=("node", enode.id), dst=("node", handler.id),
                     type=EdgeType.routes_to, origin="tool", confidence=1.0,
                     created_by_tool=created_by, attrs={"handler": ep.get("handler")})
            linked += 1
    return routes, linked


def run_surface_recon(session: Session, project: Project, target: Target, task=None) -> dict:
    """Materialise the surface's route spec into endpoint/param nodes + routes_to→handler
    edges, and (when run as a task) emit a recon finding. Deterministic, offline. The spec
    comes from `task.params_json['endpoints']` if given, else `target.metadata_json`."""
    spec = None
    if task is not None and (task.params_json or {}).get("endpoints") is not None:
        spec = task.params_json["endpoints"]
    if spec is None:
        spec = (target.metadata_json or {}).get("endpoints") or []

    routes, linked = _materialize_endpoints(session, project, target, spec, "surface_recon")

    if task is not None:
        from hexgraph.engine.findings.findings import persist_finding
        from hexgraph.models.finding import Evidence, Finding

        base = (target.metadata_json or {}).get("channel", {}).get("base_url", target.name)
        persist_finding(
            session, project_id=project.id, target_id=target.id, task_id=task.id,
            finding=Finding(
                title=f"Web surface mapped: {routes} endpoint(s) at {base}",
                severity="info", confidence="high", category="recon",
                summary=f"Mapped {routes} route(s); {linked} linked to a handler function (routes_to edges).",
                reasoning="Surface recon materialised the route/param graph for dynamic analysis "
                          "and linked routes to their static handlers where present.",
                evidence=Evidence(extra={"base_url": base, "endpoints": routes, "handlers_linked": linked}),
            ),
            finding_type="recon",
        )
    return {"endpoints": routes, "handlers_linked": linked}


def _egress_gate(session, project: Project, target: Target, *, tool: str, task_id=None):
    """Shared bounded-egress gate for live web tools: build the per-target deny-all-but-this
    scope from the surface's base_url, assert the policy permits egress to it, and audit the
    decision (allow OR deny) to EgressEvent. Returns (base_url, scope, dest). Fail-closed."""
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, current_policy,
                                 local_network_scope)

    base_url = _channel(target).get("base_url")
    if not base_url:
        raise ValueError("target has no web channel (base_url)")
    scope = local_network_scope(base_url)  # raises if the host isn't loopback/private
    dest = next(iter(scope.allow))
    try:
        assert_allows_egress(dest, scope, current_policy())
    except PolicyViolation:
        record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                      dest=dest, allowed=False, tool=tool,
                      detail="blocked: network egress not permitted by policy")
        raise
    record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                  dest=dest, allowed=True, tool=tool, detail=scope.rationale)
    return base_url, scope, dest


# Per-session cookie jars for free-form authed exploration via http_request. A fresh
# sandbox container runs each request (no state between calls), so the host keeps the jar
# and re-injects it. Keyed by (target_id, session_id); in-process (single-user local tool),
# reset on server restart — that's fine, the agent just logs in again.
_COOKIE_JARS: dict[tuple[str, str], dict[str, str]] = {}


def _parse_set_cookie(values: list[str]) -> dict[str, str]:
    """Pull name=value from each Set-Cookie header (ignore attributes after the first ';')."""
    out: dict[str, str] = {}
    for raw in values or []:
        first = (raw or "").split(";", 1)[0].strip()
        if "=" in first:
            name, _, val = first.partition("=")
            name = name.strip()
            if name:
                out[name] = val.strip()
    return out


def clear_http_session(target_id: str, session: str) -> None:
    _COOKIE_JARS.pop((target_id, session), None)


def run_http_request(session: Session, project: Project, target: Target, *, request: dict,
                     runner=None, task_id=None, http_session: str | None = None) -> dict:
    """Send ONE crafted HTTP request to a live web surface and return the (bounded) response
    — the agent's hands for dynamic web testing (log in, probe an auth check, fire an
    injection payload, read the response body). Egress is policy + per-target-scope gated
    and audited, exactly like web_recon; the request runs in the sandbox (no redirects, host
    allowlisted, 64 KiB body cap). `request` = {method, path, params?, headers?, body?, json?}.

    Pass `http_session` (any label) to keep a cookie jar across calls: cookies the server
    Set-Cookie's are stored and re-sent on the next call with the same label, so an auth
    flow (log in, then hit protected routes) works across separate http_request calls
    without manually copying the session cookie."""
    from hexgraph import settings
    from hexgraph.sandbox.executor import get_executor

    base_url, scope, dest = _egress_gate(session, project, target, tool="http_request", task_id=task_id)
    runner = runner or get_executor()
    timeout = int(settings.get("features.network.timeout", 30) or 30)

    req = dict(request or {})
    jar = _COOKIE_JARS.setdefault((target.id, http_session), {}) if http_session else None
    if jar:
        # Merge stored cookies into the request's Cookie header (an explicit Cookie the
        # caller set takes precedence per-name).
        headers = {str(k): v for k, v in (req.get("headers") or {}).items()}
        existing = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
        have = {c.split("=", 1)[0].strip() for c in existing.split(";") if "=" in c}
        merged = [existing] if existing else []
        merged += [f"{k}={v}" for k, v in jar.items() if k not in have]
        if merged:
            headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
            headers["Cookie"] = "; ".join(p for p in merged if p)
            req["headers"] = headers

    channel = {"base_url": base_url, "allow": sorted(scope.allow), "timeout": timeout,
               "request": req}
    result = runner.run_channel_probe("http_probe.py", channel=channel,
                                      net_container=_rehost_container(target))
    resp = result.get("response") or result
    if jar is not None and isinstance(resp, dict):
        jar.update(_parse_set_cookie(resp.get("set_cookie") or []))
        resp["session_cookies"] = sorted(jar)  # tell the agent what's in the jar now
    return resp


def run_web_poc(session: Session, project: Project, target: Target, *, steps: list, oracle: dict,
                runner=None, task_id=None) -> dict:
    """Run a multi-step HTTP PoC against a live web surface and evaluate an oracle on the
    final response — the dynamic-web analogue of binary verify_poc. Cookies carry across
    steps (so login→protected-route works in one run). Use {{NONCE}} in a step and a
    `body_contains` oracle for an unforgeable RCE check; use `status_is`/`status_differs`
    (or the target's own secret in the body) for an auth-bypass check. Gated + audited."""
    from hexgraph import settings
    from hexgraph.sandbox.executor import get_executor

    base_url, scope, dest = _egress_gate(session, project, target, tool="web_poc", task_id=task_id)
    runner = runner or get_executor()
    timeout = int(settings.get("features.network.timeout", 30) or 30)
    channel = {"base_url": base_url, "allow": sorted(scope.allow), "timeout": timeout,
               "steps": steps, "oracle": oracle}
    return runner.run_channel_probe("http_probe.py", channel=channel,
                                    net_container=_rehost_container(target))


def _device_host(target: Target) -> str | None:
    """The loopback/private IP of a live device behind this target, for raw-TCP access:
    a rehosted web surface records the device IP under channel.rehost.ip; a `remote` target
    records it as channel.host; otherwise fall back to the web base_url's host."""
    ch = _channel(target)
    rehost = ch.get("rehost") or {}
    if rehost.get("ip"):
        return rehost["ip"]
    if ch.get("host"):
        return ch["host"]
    base = ch.get("base_url")
    if base:
        from urllib.parse import urlparse
        return urlparse(base).hostname
    return None


def _run_socket_probe(session: Session, project: Project, target: Target, *, transport: str,
                      port: int, payload: str | None = None, payload_hex: str | None = None,
                      oracle: dict | None = None, read_bytes: int | None = None, runner=None,
                      task_id=None, host: str | None = None,
                      net_container: str | None = None) -> dict:
    """Shared raw-socket probe driver for the TCP and UDP live paths — identical bounded-egress
    contract (a per-target deny-all-but-this `local_tcp_scope`, loopback/private only, this
    port), policy gate (features.network) and EgressEvent audit; only the `transport` carried
    into the probe channel (and thus the datagram-vs-stream socket it opens) differs."""
    from hexgraph import settings
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, current_policy,
                                 local_tcp_scope)
    from hexgraph.sandbox.executor import get_executor

    tool = "udp_probe" if transport == "udp" else "tcp_probe"
    host = host or _device_host(target)
    if not host:
        raise ValueError("target has no live device host (rehost ip / remote host / base_url)")
    net_container = net_container or _rehost_container(target)
    scope = local_tcp_scope(host, int(port))  # host:port scope; transport-agnostic
    dest = next(iter(scope.allow))
    try:
        assert_allows_egress(dest, scope, current_policy())
    except PolicyViolation:
        record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                      dest=dest, allowed=False, tool=tool,
                      detail="blocked: network egress not permitted by policy")
        raise
    record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                  dest=dest, allowed=True, tool=tool, detail=scope.rationale)

    runner = runner or get_executor()
    timeout = int(settings.get("features.network.timeout", 30) or 30)
    channel = {"host": host, "port": int(port), "allow": sorted(scope.allow), "timeout": timeout}
    if transport == "udp":
        channel["transport"] = "udp"
    if payload_hex is not None:
        channel["payload_hex"] = payload_hex   # byte-exact (binary protocol / fuzz reproducer)
    elif payload is not None:
        channel["payload"] = payload
    if oracle:
        channel["oracle"] = oracle
    if read_bytes is not None:
        channel["read_bytes"] = int(read_bytes)
    return runner.run_channel_probe("tcp_probe.py", channel=channel,
                                    net_container=net_container)


def run_tcp_probe(session: Session, project: Project, target: Target, *, port: int,
                  payload: str | None = None, payload_hex: str | None = None,
                  oracle: dict | None = None,
                  read_bytes: int | None = None, runner=None, task_id=None,
                  host: str | None = None, net_container: str | None = None) -> dict:
    """Talk to a raw TCP service on a live device (the non-HTTP analogue of run_http_request /
    run_web_poc). Reaches `<device_host>:<port>` — the device IP of a rehosted surface or a
    `remote` target — through the emulator netns when applicable. Same bounded-egress contract
    as the web tools: a per-target deny-all-but-this scope (loopback/private only, this port),
    policy-gated (features.network) and audited. With an `oracle`, the probe strips the sent
    payload (reflection) before matching, so a verified result is unforgeable.

    `payload_hex` sends BYTE-EXACT arbitrary bytes (the probe `bytes.fromhex`es it) — use this
    for a binary protocol / a replayed fuzz reproducer, since the `payload` str field is
    re-encoded as utf-8 and is NOT a byte round-trip for non-ASCII bytes.

    `host`/`net_container` override the target-derived device host / emulator netns. The
    launch-and-join verify path (campaigns._verify_network_artifact) uses this to point the
    probe at `127.0.0.1` inside a freshly-relaunched SERVICE container's netns — the service
    container is gone by verify time, so there is no live host on the target to resolve. The
    SAME local_tcp_scope egress gate + audit still applies (the override only changes WHERE,
    not WHETHER, egress is permitted)."""
    return _run_socket_probe(session, project, target, transport="tcp", port=port,
                             payload=payload, payload_hex=payload_hex, oracle=oracle,
                             read_bytes=read_bytes, runner=runner, task_id=task_id,
                             host=host, net_container=net_container)


def run_udp_probe(session: Session, project: Project, target: Target, *, port: int,
                  payload: str | None = None, payload_hex: str | None = None,
                  oracle: dict | None = None,
                  read_bytes: int | None = None, runner=None, task_id=None,
                  host: str | None = None, net_container: str | None = None) -> dict:
    """The datagram analogue of run_tcp_probe — for a UDP service on a live device (infosvr,
    SSDP, mDNS, DNS, DHCP, WS-Discovery, a vendor discovery responder). Sends one datagram to
    `<device_host>:<port>` (omit `payload` to probe with an empty packet) and reads a bounded
    response under the timeout; UDP is connectionless, so a silent service simply yields no
    response (not an error). Same bounded-egress contract, policy gate (features.network) and
    audit as run_tcp_probe — only the transport differs. With an `oracle`, the probe strips the
    sent payload (reflection) before matching, so a verified result is unforgeable.

    `payload_hex` sends BYTE-EXACT arbitrary bytes (a binary discovery packet / a replayed
    fuzz reproducer). `host`/`net_container` override the target-derived device host /
    emulator netns exactly as in run_tcp_probe."""
    return _run_socket_probe(session, project, target, transport="udp", port=port,
                             payload=payload, payload_hex=payload_hex, oracle=oracle,
                             read_bytes=read_bytes, runner=runner, task_id=task_id,
                             host=host, net_container=net_container)


def run_web_recon(session: Session, project: Project, target: Target, task=None, runner=None) -> dict:
    """Phase 2: LIVE, bounded liveness-probe of a web surface's endpoints. Egress is
    gated by the policy seam (`features.network` → bounded local-network tier) and a
    per-target deny-all-but-this `NetworkScope` that **refuses any non-local
    destination**; every outbound decision (allow or deny) is audited (EgressEvent).
    The probe runs in the sandbox with bounded egress and returns only metadata."""
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, current_policy,
                                 local_network_scope)

    base_url = _channel(target).get("base_url")
    if not base_url:
        raise ValueError("target has no web channel (base_url)")
    scope = local_network_scope(base_url)  # raises if the host isn't loopback/private
    dest = next(iter(scope.allow))
    task_id = task.id if task is not None else None

    policy = current_policy()
    try:
        assert_allows_egress(dest, scope, policy)
    except PolicyViolation:
        record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                      dest=dest, allowed=False, tool="web_recon",
                      detail="blocked: network egress not permitted by policy")
        raise
    record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                  dest=dest, allowed=True, tool="web_recon", detail=scope.rationale)

    from hexgraph.sandbox.executor import get_executor
    from hexgraph import settings
    runner = runner or get_executor()
    endpoints = (target.metadata_json or {}).get("endpoints") or []
    timeout = int(settings.get("features.network.timeout", 30) or 30)
    channel = {"base_url": base_url, "allow": sorted(scope.allow),
               "endpoints": [{"method": e.get("method", "GET"), "path": e.get("path", "/")}
                             for e in endpoints],
               "timeout": timeout}
    result = runner.run_channel_probe("surface_probe.py", channel=channel,
                                      net_container=_rehost_container(target))

    alive = 0
    for pr in result.get("probes", []):
        label = pr.get("endpoint")
        if not label:
            continue
        enode = get_or_create_node(session, project_id=project.id, node_type=NodeType.endpoint,
                                   name=label, target_id=target.id, fq_name=label,
                                   created_by="web_recon",
                                   attrs={"alive": bool(pr.get("alive")), "status": pr.get("status"),
                                          "server": pr.get("server")})
        if pr.get("alive"):
            alive += 1
    if task is not None:
        from hexgraph.engine.findings.findings import persist_finding
        from hexgraph.models.finding import Evidence, Finding

        persist_finding(
            session, project_id=project.id, target_id=target.id, task_id=task.id,
            finding=Finding(
                title=f"Web surface probed: {alive}/{len(endpoints)} endpoint(s) live at {base_url}",
                severity="info", confidence="high", category="recon",
                summary=f"Bounded liveness probe reached {dest}; {alive} endpoint(s) responded.",
                reasoning="Dynamic surface_recon (bounded egress, audited) confirmed live endpoints.",
                evidence=Evidence(extra={"base_url": base_url, "dest": dest,
                                         "alive": alive, "probed": len(endpoints)}),
            ),
            finding_type="recon",
        )
    return {"dest": dest, "alive": alive, "probed": len(endpoints)}


def run_web_discover(session: Session, project: Project, target: Target, task=None, runner=None) -> dict:
    """LIVE, bounded route DISCOVERY of a web surface: crawl from `/` + a builtin common-path
    list, follow same-host links/forms, and materialise the discovered endpoint/param nodes
    (so surface_recon isn't limited to a caller-supplied spec). Same bounded-egress gate +
    audit as web_recon (`features.network`, loopback/private only); the probe joins a rehosted
    surface's emulator netns. Emits a recon finding listing what it found."""
    from hexgraph import settings
    from hexgraph.sandbox.executor import get_executor

    base_url, scope, dest = _egress_gate(session, project, target, tool="web_discover",
                                         task_id=task.id if task is not None else None)
    runner = runner or get_executor()
    timeout = int(settings.get("features.network.timeout", 30) or 30)
    max_pages = int((task.params_json or {}).get("max_pages", 40)) if task is not None else 40
    channel = {"base_url": base_url, "allow": sorted(scope.allow), "timeout": timeout,
               "max_pages": max_pages}
    result = runner.run_channel_probe("web_discover_probe.py", channel=channel,
                                      net_container=_rehost_container(target))
    discovered = result.get("endpoints") or []
    routes, linked = _materialize_endpoints(session, project, target, discovered, "web_discover")

    if task is not None:
        from hexgraph.engine.findings.findings import persist_finding
        from hexgraph.models.finding import Evidence, Finding

        live = sum(1 for e in discovered if isinstance(e.get("status"), int) and e["status"] < 400)
        persist_finding(
            session, project_id=project.id, target_id=target.id, task_id=task.id,
            finding=Finding(
                title=f"Web surface crawled: {routes} route(s) discovered at {base_url}",
                severity="info", confidence="high", category="recon",
                summary=f"Bounded crawl of {result.get('pages_fetched', 0)} page(s) found {routes} "
                        f"route(s) ({live} responded <400); {linked} linked to a static handler.",
                reasoning="Live route discovery (bounded egress, audited) mapped the surface's "
                          "endpoints/params from links + forms + a common-path probe.",
                evidence=Evidence(extra={"base_url": base_url, "dest": dest, "endpoints": routes,
                                         "pages_fetched": result.get("pages_fetched", 0)}),
            ),
            finding_type="recon",
        )
    return {"dest": dest, "endpoints": routes, "handlers_linked": linked,
            "pages_fetched": result.get("pages_fetched", 0)}
