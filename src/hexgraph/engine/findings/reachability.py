"""Standard B, static — a source→sink reachability ARGUMENT over the typed graph
(docs/design/design-verification-oracles.md, Phase 4).

When a service can't be booted to trigger a flaw live (the DIR-823G case: a real cmdi sink, but
FirmAE couldn't boot goahead), HexGraph can still argue the flaw is *input-reachable* by finding a
directed path over the existing typed graph from an **untrusted input source** to the **sink**.
This is honestly an ARGUMENT, never a demonstration — so it records `input_reachable / static`
(strictly weaker than a live trigger), and only UPGRADES a finding that was at the
`code_present / static` floor (never downgrades a dynamic claim — see
`assurance.upgrade_if_stronger`).

Traversal semantics (decided here, documented so it can't FALSELY claim reachability):

  - **Direction.** We search FORWARD from a source toward the sink, following each edge in the
    direction its semantics flow. `taints` (source→sink dataflow), `calls` (caller→callee),
    `routes_to` (route→handler) and `writes` (writer→written) are followed src→dst. `reads`
    (reader→read-from) and `references` (referrer→referent) are followed src→dst too — a reader/
    referrer is "upstream" of what it reads/references. A `bypasses` edge (attacker input defeats a
    control) is also followed src→dst: it advances control reachability AND, wherever it sits on
    the path, signals an auth gate (so the precondition becomes requires_credentials). We DO NOT
    follow an edge backwards: a `calls` edge means src reaches dst, not the reverse, so reversing it
    would invent reachability that isn't there. (`contains` is a structural target→node edge, NOT
    control/data flow, and is deliberately excluded — every node is `contains`-reachable from its
    target, which would make the argument vacuous.)

  - **Strength.** `taints` is the strongest signal (it directly asserts untrusted data reaches the
    sink); a path that uses at least one `taints` edge is flagged `via_taint=True`. A pure
    control-flow path (`calls`/`routes_to`) argues the sink is *reached*, but is a weaker argument
    that the attacker controls the dangerous operand — we still record it, with the path, so a
    triager sees exactly what was (and wasn't) shown.

  - **Sources** = the untrusted boundary: node types `input` / `param` / `endpoint` / `socket`.
    A `function`/`symbol` is accepted as a source ONLY when explicitly marked
    `attrs.entry == True` (or `attrs.is_entry`) — we never treat an arbitrary function as an input
    boundary (that would falsely claim reachability from internal code).

  - **Sinks** = a `sink`-type node, OR any node carrying `attrs.is_sink == True`
    (a dangerous `symbol`/`function`). A finding cites its sink via its `about`→node edge
    (the function/sink it concerns) and/or its `evidence.sink` string.

  - **Bound.** BFS with a visited set (cycle-safe) and a `max_depth` hop cap so it terminates on
    large graphs. The FIRST source→sink path found (shortest, BFS) is recorded.

Precondition (the principal Standard B requires), derived from what the path crosses:
  - `requires_credentials` — the path crosses an auth boundary: an `endpoint`/`param` node whose
    `attrs.auth` is set to something other than none/unknown, OR the path traverses a `bypasses`
    edge / a node attributed as an auth check.
  - `unauthenticated` — the path STARTS at an `endpoint`/`param`/`socket` explicitly marked
    unauthenticated (`attrs.auth in {"none","unauthenticated"}`) and crosses no auth boundary.
  - `unspecified` — neither could be established (the honest default; never overstates).

Everything here is the DB envelope — `evidence.extra` — never the frozen finding schema.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, Finding, Node
from hexgraph.engine.findings import assurance as A

# Edge types we traverse FORWARD (src→dst), with whether the edge is a taint (dataflow) signal.
# A `taints` edge is the strongest argument; the rest argue control/structural reachability.
_FORWARD_EDGES: dict[str, bool] = {
    "taints": True,        # untrusted data flows src→dst — the strongest signal
    "calls": False,        # caller → callee
    "routes_to": False,    # web route → handler function (dynamic→static bridge)
    "writes": False,       # writer → written-to
    "reads": False,        # reader → read-from (the reader is upstream of the data)
    "references": False,   # referrer → referent
    "dataflow_hint": True, # a (weaker) asserted dataflow — still a taint-flavoured signal
    "bypasses": False,     # attacker input defeats a control en route to the sink (control reach)
}

# Node types that ARE the untrusted input boundary (always eligible sources).
_SOURCE_TYPES = frozenset({"input", "param", "endpoint", "socket"})

# Node types that may carry an attacker-facing auth attribute.
_AUTH_BEARING = frozenset({"endpoint", "param", "socket"})

# `attrs.auth` values that mean "no authentication required" (an unauth boundary).
_UNAUTH_VALUES = frozenset({"none", "unauthenticated", "anon", "anonymous", "public", "preauth"})


class ReachabilityError(ValueError):
    """The reachability analysis could not run (bad target / no sink to anchor on)."""


# ── source / sink classification ───────────────────────────────────────────────────────────

def is_source(node: Node) -> bool:
    """A node at the untrusted input boundary. `input`/`param`/`endpoint`/`socket` always
    qualify; a `function`/`symbol` ONLY if explicitly marked an entry point (`attrs.entry`/
    `attrs.is_entry`) — we never treat arbitrary internal code as an input source, which is the
    main false-reachability trap."""
    nt = node.node_type
    if nt in _SOURCE_TYPES:
        return True
    attrs = node.attrs_json or {}
    return nt in ("function", "symbol") and bool(attrs.get("entry") or attrs.get("is_entry"))


def is_sink(node: Node) -> bool:
    """A node that is a dangerous operation: a `sink`-type node, or any node attributed
    `is_sink=True` (a dangerous `symbol`/`function`)."""
    return node.node_type == "sink" or bool((node.attrs_json or {}).get("is_sink"))


def _node_is_unauth(node: Node) -> bool:
    """The node is an explicitly-unauthenticated boundary (an endpoint/param/socket whose
    `attrs.auth` says no auth is required)."""
    if node.node_type not in _AUTH_BEARING:
        return False
    auth = str((node.attrs_json or {}).get("auth") or "").strip().lower()
    return auth in _UNAUTH_VALUES


def _node_is_auth_gate(node: Node) -> bool:
    """The node represents/sits behind an authentication requirement: an endpoint/param/socket
    whose `attrs.auth` is set to something OTHER than none/unknown, or a node flagged as an auth
    check (`attrs.auth_check`/`attrs.is_auth`)."""
    attrs = node.attrs_json or {}
    if attrs.get("auth_check") or attrs.get("is_auth"):
        return True
    if node.node_type in _AUTH_BEARING:
        auth = str(attrs.get("auth") or "").strip().lower()
        if auth and auth not in _UNAUTH_VALUES and auth not in ("unknown", "?"):
            return True
    return False


# ── the graph search ────────────────────────────────────────────────────────────────────────

def _forward_adjacency(session: Session, project_id: str) -> dict[str, list[tuple[str, Edge]]]:
    """Build {node_id: [(neighbor_node_id, edge), ...]} over the FORWARD-traversable edge types,
    restricted to node↔node edges (sources/sinks are nodes). Edges touching archived nodes are
    pruned by the caller's node lookups returning the archived flag; we keep the adjacency cheap
    and let the BFS skip archived endpoints."""
    adj: dict[str, list[tuple[str, Edge]]] = {}
    edges = (
        session.query(Edge)
        .filter(Edge.project_id == project_id, Edge.type.in_(tuple(_FORWARD_EDGES)),
                Edge.src_kind == "node", Edge.dst_kind == "node")
        .all()
    )
    for e in edges:
        adj.setdefault(e.src_id, []).append((e.dst_id, e))
        # An UNDIRECTED edge (rare for these types) is reachable both ways; honor `directed`.
        if not e.directed:
            adj.setdefault(e.dst_id, []).append((e.src_id, e))
    return adj


def _node_index(session: Session, project_id: str) -> dict[str, Node]:
    """Hydrate every node in the project once into {id: Node}, so the BFS / precondition derivation
    look nodes up from memory instead of a per-neighbor `session.get` round-trip."""
    return {n.id: n for n in session.query(Node).filter(Node.project_id == project_id).all()}


def _bfs_path(
    *, source_ids: set[str], sink_id: str, max_depth: int,
    adj: dict[str, list[tuple[str, Edge]]], nodes: dict[str, Node],
) -> list[dict] | None:
    """BFS from any source toward `sink_id` over the forward adjacency. Returns the path as a
    list of step dicts (the node/edge sequence) or None. Cycle-safe (visited set) and depth-bound
    (`max_depth` hops) so it terminates on big/cyclic graphs. `nodes` is the pre-hydrated
    {id: Node} index, so lookups are in-memory (no per-neighbor DB round-trip)."""
    # Multi-source BFS: seed the frontier with every source. Each queue item is
    # (node_id, path_steps) where path_steps is the list of {node, edge?} dicts so far.
    visited: set[str] = set(source_ids)
    queue: deque[tuple[str, list[dict]]] = deque()
    for sid in source_ids:
        snode = nodes.get(sid)
        if snode is None or snode.archived:
            continue
        queue.append((sid, [{"node_id": sid, "node_type": snode.node_type, "name": snode.name}]))
        if sid == sink_id:
            return queue[-1][1]
    while queue:
        cur, path = queue.popleft()
        if len(path) - 1 >= max_depth:  # hop count == edges traversed
            continue
        for (nbr, edge) in adj.get(cur, ()):  # noqa: B007
            if nbr in visited:
                continue
            nbr_node = nodes.get(nbr)
            if nbr_node is None or nbr_node.archived:
                continue
            step = {
                "edge_type": edge.type, "via_taint": _FORWARD_EDGES.get(edge.type, False),
                "edge_attrs": edge.attrs_json or {},
                "node_id": nbr, "node_type": nbr_node.node_type, "name": nbr_node.name,
            }
            new_path = path + [step]
            if nbr == sink_id:
                return new_path
            visited.add(nbr)
            queue.append((nbr, new_path))
    return None


def _derive_precondition(path: list[dict], nodes: dict[str, Node]) -> tuple[str, str]:
    """Derive (precondition, why) from what the recorded path crosses, per the module docstring.
    requires_credentials wins if ANY auth boundary is crossed; else unauthenticated if the path
    STARTS at an explicitly-unauth boundary; else unspecified. `nodes` is the pre-hydrated index."""
    # Any auth gate anywhere on the path (a node flagged as an auth check, an auth-bearing node
    # requiring creds, or a `bypasses` edge) ⇒ the reachability requires credentials.
    for step in path:
        if step.get("edge_type") == "bypasses":
            return A.REQUIRES_CREDENTIALS, "path traverses a `bypasses` (auth/logic-defeat) edge"
        node = nodes.get(step["node_id"])
        if node is not None and _node_is_auth_gate(node):
            return (A.REQUIRES_CREDENTIALS,
                    f"path crosses an auth boundary at {node.node_type} {node.name!r}")
    first = nodes.get(path[0]["node_id"]) if path else None
    if first is not None and _node_is_unauth(first):
        return A.UNAUTHENTICATED, f"reached from unauthenticated {first.node_type} {first.name!r}"
    return A.UNSPECIFIED, "no auth boundary or unauth marker on the path"


def _summarize(path: list[dict]) -> str:
    """A compact 'src → … → sink' one-liner naming each hop (and the edge type used)."""
    parts = [path[0]["name"]]
    for step in path[1:]:
        parts.append(f"--{step['edge_type']}-->")
        parts.append(step["name"])
    return " ".join(parts)


# ── public entry points ───────────────────────────────────────────────────────────────────────

def find_source_to_sink_path(
    session: Session, project_id: str, sink_node_id: str, *, max_depth: int = 12,
    precondition: str | None = None,
) -> dict | None:
    """Search the project graph for a directed source→sink path to `sink_node_id`. Returns
    {path, via_taint, precondition, precondition_why, precondition_inferred, summary} or None if
    no path exists.

    `path` is the ordered node/edge sequence (the argument). `via_taint` is True iff at least one
    `taints`/`dataflow_hint` edge was used (the stronger dataflow argument). `precondition`, when
    given, OVERRIDES the path-derived one — the operator asserting (e.g.) `unauthenticated` when
    the graph lacks the auth markers that would otherwise under-state it as `unspecified`."""
    nodes = _node_index(session, project_id)
    sink = nodes.get(sink_node_id)
    if sink is None:
        raise ReachabilityError(f"sink node {sink_node_id} not found in project")
    if sink.archived:
        raise ReachabilityError("sink node is archived")

    source_ids = {
        nid for nid, n in nodes.items()
        if nid != sink_node_id and not n.archived and is_source(n)
    }
    if not source_ids:
        return None
    adj = _forward_adjacency(session, project_id)
    path = _bfs_path(source_ids=source_ids, sink_id=sink_node_id, max_depth=max_depth,
                     adj=adj, nodes=nodes)
    if path is None:
        return None
    derived, why = _derive_precondition(path, nodes)
    if precondition:
        pre, why, inferred = precondition, "operator-asserted precondition", False
    else:
        pre, inferred = derived, True
    return {
        "path": path,
        "via_taint": any(step.get("via_taint") for step in path),
        "precondition": pre,
        "precondition_why": why,
        "precondition_inferred": inferred,
        "summary": _summarize(path),
    }


def _candidate_sinks_for_finding(session: Session, finding: Finding) -> list[Node]:
    """Resolve the sink node(s) a finding cites: the nodes it `about`-links to that are sinks,
    falling back to a node named like its `evidence.sink`/`evidence.function` string."""
    project_id = finding.project_id
    # 1. Nodes the finding is `about` (its primary function / cited sink).
    about = (
        session.query(Edge)
        .filter(Edge.project_id == project_id, Edge.type == "about",
                Edge.src_kind == "finding", Edge.src_id == finding.id, Edge.dst_kind == "node")
        .all()
    )
    sinks: list[Node] = []
    seen: set[str] = set()
    for e in about:
        n = session.get(Node, e.dst_id)
        if n is not None and not n.archived and is_sink(n) and n.id not in seen:
            sinks.append(n)
            seen.add(n.id)
    if sinks:
        return sinks
    # 2. Fall back to a sink-ish node whose name matches the finding's cited sink/function.
    ev = finding.evidence_json or {}
    names = [v for v in (ev.get("sink"), ev.get("function")) if v]
    from hexgraph.engine.graph.nodes import normalize_symbol_name

    wanted = {normalize_symbol_name(n) or n for n in names}
    if not wanted:
        return []
    for n in session.query(Node).filter(
        Node.project_id == project_id, Node.archived.is_(False)
    ).all():
        if is_sink(n) and (normalize_symbol_name(n.name) or n.name) in wanted and n.id not in seen:
            sinks.append(n)
            seen.add(n.id)
    return sinks


def argue_reachability_for_finding(
    session: Session, finding_id: str, *, max_depth: int = 12, record: bool = True,
    precondition: str | None = None, sink_node_id: str | None = None,
) -> dict:
    """Compute a static source→sink reachability argument for the finding's cited sink and, when
    one exists and `record` is set, UPGRADE the finding's assurance to input_reachable/static
    (only if stronger than what's recorded — never downgrades a dynamic claim). Returns a
    JSON-able result {found, sink_node_id?, path?, precondition?, assurance?, detail}.

    `sink_node_id`, when given, OVERRIDES sink resolution: that node is used as the sink directly
    (it must be a real, non-archived node in the finding's project), bypassing the
    `about`→sink-edge / `evidence.sink`-name lookup. Use it when the caller knows the sink node but
    the finding doesn't cite it via an `about` edge yet — the upgraded assurance + recorded path
    still land on the finding."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise ReachabilityError(f"finding {finding_id} not found")
    if sink_node_id is not None:
        # Explicit override: resolve the one node the caller named (validated here so a bad id is a
        # clear error, not a silent "no sink" — find_source_to_sink_path also re-checks existence).
        override = session.get(Node, sink_node_id)
        if override is None:
            raise ReachabilityError(f"sink node {sink_node_id} not found")
        if override.archived:
            raise ReachabilityError("sink node is archived")
        if override.project_id != finding.project_id:
            raise ReachabilityError("sink node is not in the finding's project")
        sinks = [override]
    else:
        sinks = _candidate_sinks_for_finding(session, finding)
    if not sinks:
        return {"found": False, "detail": "no sink node cited by this finding (no `about`→sink "
                                          "edge and no node matching evidence.sink/function). "
                                          "Either add an `about`→sink edge (graph_create_edge "
                                          "from this finding to the sink node), pass an explicit "
                                          "sink_node_id, or create the sink node first, then re-run."}
    best: dict[str, Any] | None = None
    for sink in sinks:
        res = find_source_to_sink_path(session, finding.project_id, sink.id, max_depth=max_depth,
                                       precondition=precondition)
        if res is None:
            continue
        res["sink_node_id"] = sink.id
        res["sink_name"] = sink.name
        # Prefer a taint-backed path (the strongest argument) over a pure control path.
        if best is None or (res["via_taint"] and not best["via_taint"]):
            best = res
        if best.get("via_taint"):
            break
    if best is None:
        return {"found": False,
                "detail": f"no source→sink path within {max_depth} hops to the cited sink(s) "
                          f"{[s.name for s in sinks]} — code-present but NO input path argued "
                          "(record this honestly; it does not mean unreachable)."}

    cand = A.assurance(
        A.INPUT_REACHABLE, A.STATIC, best["precondition"],
        precondition_inferred=best["precondition_inferred"],
        detail=f"static source→sink path: {best['summary']}"
               f"{' (taint-backed)' if best['via_taint'] else ' (control-flow only)'}; "
               f"precondition: {best['precondition_why']}",
    )
    result = {
        "found": True, "sink_node_id": best["sink_node_id"], "sink_name": best.get("sink_name"),
        "path": best["path"], "via_taint": best["via_taint"],
        "precondition": best["precondition"], "precondition_why": best["precondition_why"],
        "precondition_inferred": best["precondition_inferred"],
        "summary": best["summary"], "assurance": cand,
    }
    if sink_node_id is not None:
        result["operator_asserted"] = True
    if record:
        # Deep-copy so we never mutate the ORM object's nested dicts in place (an in-place nested
        # mutation isn't detected as a column change, so it wouldn't be flushed); we build a fresh
        # evidence dict and assign it wholesale, which SQLAlchemy reliably persists.
        import copy

        ev = copy.deepcopy(finding.evidence_json or {})
        before = A.assurance_of(ev)
        A.upgrade_if_stronger(ev, cand)
        # Also record the path itself under evidence.extra.reachability so a triager can audit it.
        reach = {
            "sink_node_id": best["sink_node_id"], "summary": best["summary"],
            "via_taint": best["via_taint"], "precondition": best["precondition"],
            "precondition_why": best["precondition_why"],
            "precondition_inferred": best["precondition_inferred"], "path": best["path"],
        }
        # Honesty marker: when the sink came from the caller's explicit sink_node_id override, it
        # bypassed sink resolution AND the is_sink check (an operator-asserted sink, not one the
        # graph auto-resolved). Record that so a triager knows the sink was asserted, not derived.
        if sink_node_id is not None:
            reach["operator_asserted"] = True
        ev.setdefault("extra", {})["reachability"] = reach
        finding.evidence_json = ev
        after = A.assurance_of(ev)
        upgraded = (after == cand and before != after)
        # When the assurance actually rose to input_reachable, the finding's `confidence` column
        # should not lag behind it: a recovered source→sink path is concrete evidence the flaw is
        # reachable, so a `medium`-confidence finding reading `input_reachable` assurance looks
        # self-contradictory to a triager. Bump confidence to at least `high` (never DOWNGRADE a
        # finding that was already high). Only bump on a real upgrade to the input_reachable rung.
        if upgraded and cand.get("standard") == A.INPUT_REACHABLE \
                and (finding.confidence or "").strip().lower() != "high":
            finding.confidence = "high"
            result["confidence_bumped"] = "high"
        session.flush()
        result["upgraded"] = upgraded
        result["assurance_recorded"] = after
    return result
