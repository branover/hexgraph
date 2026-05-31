"""Web/service attack surfaces — Phase 1 backbone (docs/design-dynamic-surfaces.md).

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
from hexgraph.engine.edges import add_edge
from hexgraph.engine.nodes import get_or_create_node, normalize_symbol_name


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


def run_surface_recon(session: Session, project: Project, target: Target, task=None) -> dict:
    """Materialise the surface's route spec into endpoint/param nodes + routes_to→handler
    edges, and (when run as a task) emit a recon finding. Deterministic, offline. The spec
    comes from `task.params_json['endpoints']` if given, else `target.metadata_json`."""
    spec = None
    if task is not None and (task.params_json or {}).get("endpoints") is not None:
        spec = task.params_json["endpoints"]
    if spec is None:
        spec = (target.metadata_json or {}).get("endpoints") or []

    routes = 0
    linked = 0
    for ep in spec:
        method = (ep.get("method") or "GET").upper()
        path = ep.get("path") or "/"
        label = f"{method} {path}"
        enode = get_or_create_node(
            session, project_id=project.id, node_type=NodeType.endpoint, name=label,
            target_id=target.id, fq_name=label, created_by="surface_recon",
            attrs={"method": method, "path": path, "auth": ep.get("auth", "unknown")},
        )
        routes += 1
        for p in ep.get("params", []) or []:
            pname = p if isinstance(p, str) else (p.get("name") or "")
            if not pname:
                continue
            pnode = get_or_create_node(
                session, project_id=project.id, node_type=NodeType.param, name=pname,
                target_id=target.id, fq_name=f"{label}#{pname}", created_by="surface_recon",
                attrs={"endpoint": label, **({} if isinstance(p, str) else p)},
            )
            add_edge(session, project_id=project.id, src=("node", enode.id), dst=("node", pnode.id),
                     type=EdgeType.references, origin="tool", confidence=1.0,
                     created_by_tool="surface_recon")
        handler = _find_handler(session, project.id, ep.get("handler"))
        if handler is not None:
            add_edge(session, project_id=project.id, src=("node", enode.id), dst=("node", handler.id),
                     type=EdgeType.routes_to, origin="tool", confidence=1.0,
                     created_by_tool="surface_recon", attrs={"handler": ep.get("handler")})
            linked += 1

    if task is not None:
        from hexgraph.engine.findings import persist_finding
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
        from hexgraph.engine.findings import persist_finding
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
