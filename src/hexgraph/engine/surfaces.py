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
