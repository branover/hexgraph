"""Build the project graph as nodes + edges JSON (SPEC §8).

Graph nodes = targets (artifacts) + typed `node` rows (function/symbol/string/...)
+ findings. Edges = the polymorphic, attributed `edge` rows (contains,
links_against, calls, about, instance_of_pattern, related_to, ...). Edge
endpoint ids reference whichever entity the (kind, id) pair points at.

Two scoped serializations sit alongside the full ``build_graph`` for graphs that
are too large to ship whole to the browser (a real rehosted firmware is ~13k
nodes):

* ``build_skeleton`` — the structural SKELETON only: one *room* per byte target
  (with per-room counts + worst-severity rollup), the shared cross-binary
  sockets (the network bus), and the AGGREGATED cross-room meta-edges. NO
  interiors (no functions/strings/per-target findings as nodes). A 13k-node
  firmware collapses to a few hundred countable, labelled rooms.
* ``build_room`` — a SINGLE room's interior on demand: that target's `node`
  rows + its findings + the edges among them (and to the shared sockets), so
  expanding a room in the UI fetches just that binary's interior.

The browser loads the skeleton first and injects a room's interior only when the
user expands it, so it never receives the whole node/edge set at once.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, Finding, Node, Target

# Worst-finding rollup ordering for the skeleton's per-room severity badge.
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Threshold (nodes+edges) above which the client should load skeleton-first
# rather than the full graph. Kept here so the client and any future
# server-side gating agree on one number; surfaced in every payload as `tier`.
SKELETON_THRESHOLD = 1500


def build_graph(session: Session, project_id: str) -> dict:
    targets = session.query(Target).filter(
        Target.project_id == project_id, Target.archived.is_(False)
    ).all()
    live_ids = {t.id for t in targets}
    code_nodes = [
        n for n in session.query(Node).filter(Node.project_id == project_id, Node.archived.is_(False)).all()
        if n.target_id is None or n.target_id in live_ids  # hide archived nodes + nodes under archived targets
    ]
    edges = session.query(Edge).filter(Edge.project_id == project_id).all()
    findings = [
        f for f in session.query(Finding).filter(Finding.project_id == project_id).all()
        if f.target_id in live_ids  # hide findings under archived targets
    ]

    nodes: list[dict] = []
    for t in targets:
        nodes.append(_target_node(t))
    for n in code_nodes:
        nodes.append(_code_node(n))
    for f in findings:
        nodes.append(_finding_node(f))

    rendered = {n["id"] for n in nodes}
    collapsed = _collapse_edges(edges, rendered)
    return {"project_id": project_id, "nodes": nodes, "edges": collapsed}


# --- shared node serializers (kept identical to build_graph so the client's
#     GraphNode shape is the same whether a node arrives via full / skeleton /
#     room — the frontend never branches on which endpoint produced it). ---
def _target_node(t: Target) -> dict:
    return {
        "id": t.id, "type": "target", "label": t.name, "kind": t.kind.value,
        "format": t.format, "arch": t.arch, "parent_id": t.parent_id,
    }


def _code_node(n: Node) -> dict:
    return {
        "id": n.id, "type": "node", "node_type": n.node_type, "label": n.name,
        "target_id": n.target_id, "address": n.address, "attrs": n.attrs_json or {},
    }


def to_graph_node(n: Node) -> dict:
    """The single-node serializer for the GET-by-id endpoint: the same `GraphNode`
    shape `_code_node` produces (so the client never branches on which endpoint a
    node came from), plus the `archived` flag — a node fetched by id may be archived
    (and so absent from the rendered graph), and the caller decides what to do."""
    return {**_code_node(n), "archived": n.archived}


def _finding_node(f: Finding) -> dict:
    return {
        "id": f.id, "type": "finding", "label": f.title, "severity": f.severity,
        "category": f.category, "confidence": f.confidence, "status": f.status,
        "target_id": f.target_id, "finding_type": f.finding_type,
    }


def _collapse_edges(edges: list[Edge], rendered: set[str]) -> list[dict]:
    """Collapse parallel edges of the same type between the same endpoints into a
    single edge (e.g. three findings each relating httpd→libupnp draw one
    related_to edge, not three). Distinct types between the same pair are kept.
    Skip edges that touch a not-rendered (archived/out-of-scope) endpoint."""
    collapsed: dict[tuple, dict] = {}
    for e in edges:
        if e.src_id not in rendered or e.dst_id not in rendered:
            continue
        key = (e.src_id, e.dst_id, e.type)
        existing = collapsed.get(key)
        if existing is None:
            collapsed[key] = {
                "id": e.id, "source": e.src_id, "target": e.dst_id, "type": e.type,
                "src_kind": e.src_kind, "dst_kind": e.dst_kind,
                "origin": e.origin, "confidence": e.confidence, "count": 1,
                "attrs": e.attrs_json or {},
            }
        else:
            existing["count"] += 1
            if e.confidence is not None and (existing["confidence"] is None or e.confidence > existing["confidence"]):
                existing["confidence"] = e.confidence
    return list(collapsed.values())


def graph_size(session: Session, project_id: str) -> dict:
    """Cheap node+edge count for the project's live graph, so the client can pick
    skeleton-first vs full load WITHOUT first fetching ~13k nodes. Counts mirror
    build_graph's liveness rules (archived targets/nodes excluded)."""
    # Live target ids (archived excluded).
    target_ids = [
        t.id for t in session.query(Target).filter(
            Target.project_id == project_id, Target.archived.is_(False)
        ).all()
    ]
    live = set(target_ids)
    n_nodes = sum(
        1 for n in session.query(Node).filter(
            Node.project_id == project_id, Node.archived.is_(False)
        ).all()
        if n.target_id is None or n.target_id in live
    )
    n_findings = sum(
        1 for f in session.query(Finding.target_id).filter(Finding.project_id == project_id).all()
        if f.target_id in live
    )
    n_edges = session.query(Edge).filter(Edge.project_id == project_id).count()
    total = len(target_ids) + n_nodes + n_findings + n_edges
    return {
        "project_id": project_id,
        "targets": len(target_ids),
        "nodes": n_nodes,
        "findings": n_findings,
        "edges": n_edges,
        "total": total,
        "skeleton_recommended": total > SKELETON_THRESHOLD,
        "threshold": SKELETON_THRESHOLD,
    }


def graph_stats(session: Session, project_id: str) -> dict:
    """Per-type node/edge tallies, so a caller can get before/after counts without listing — and
    counting — every node. Node + finding counts honor liveness (archived targets/nodes excluded,
    mirroring graph_size); the edge tally is the project-wide per-type count (as graph_size's edge
    count is). Returns {targets, findings, nodes_by_type{type:count}, edges_by_type{type:count},
    totals{...}}."""
    target_ids = [
        t.id for t in session.query(Target).filter(
            Target.project_id == project_id, Target.archived.is_(False)
        ).all()
    ]
    live = set(target_ids)
    nodes_by_type: dict[str, int] = {}
    for n in session.query(Node).filter(
        Node.project_id == project_id, Node.archived.is_(False)
    ).all():
        if n.target_id is None or n.target_id in live:
            nodes_by_type[n.node_type] = nodes_by_type.get(n.node_type, 0) + 1
    edges_by_type: dict[str, int] = {}
    for (etype,) in session.query(Edge.type).filter(Edge.project_id == project_id).all():
        edges_by_type[etype] = edges_by_type.get(etype, 0) + 1
    n_findings = sum(
        1 for f in session.query(Finding.target_id).filter(Finding.project_id == project_id).all()
        if f.target_id in live
    )
    return {
        "project_id": project_id,
        "targets": len(target_ids),
        "findings": n_findings,
        "nodes_by_type": dict(sorted(nodes_by_type.items())),
        "edges_by_type": dict(sorted(edges_by_type.items())),
        "totals": {
            "nodes": sum(nodes_by_type.values()),
            "edges": sum(edges_by_type.values()),
            "targets": len(target_ids),
            "findings": n_findings,
        },
    }


def build_skeleton(session: Session, project_id: str) -> dict:
    """Serialize the STRUCTURAL SKELETON only — rooms (byte targets) with per-room
    rollups, the shared cross-binary sockets, and aggregated cross-room
    meta-edges. NO interiors (functions/strings/symbols/per-target findings). This
    is what a LARGE/PATHOLOGICAL graph opens to: a few hundred countable rooms,
    never ~13k dots.

    Each room node carries `room: true`, `n_nodes`, `n_findings`, `worst_severity`
    (for the size-by-weight + severity-rollup ring), and `has_interior` (whether
    expanding it will fetch anything). Shared sockets (`target_id = null`) are
    emitted as ordinary `node`s so the client renders the network-bus lane.
    """
    targets = session.query(Target).filter(
        Target.project_id == project_id, Target.archived.is_(False)
    ).all()
    live_ids = {t.id for t in targets}

    nodes = session.query(Node).filter(
        Node.project_id == project_id, Node.archived.is_(False)
    ).all()
    findings = session.query(Finding).filter(Finding.project_id == project_id).all()
    edges = session.query(Edge).filter(Edge.project_id == project_id).all()

    # Per-target rollups: interior node count, finding count, worst severity.
    n_nodes_by_t: dict[str, int] = {tid: 0 for tid in live_ids}
    n_find_by_t: dict[str, int] = {tid: 0 for tid in live_ids}
    worst_by_t: dict[str, int] = {tid: -1 for tid in live_ids}
    # Map a node/finding id → its owning room (target id), used to fold interior
    # edges into cross-room meta-edges and to know which sockets are shared.
    room_of: dict[str, str] = {tid: tid for tid in live_ids}  # a target is its own room

    loose_sockets: list[dict] = []
    for n in nodes:
        if n.target_id is None:
            # cross-binary node (shared socket / pattern) — first-class skeleton node
            loose_sockets.append(_code_node(n))
            continue
        if n.target_id not in live_ids:
            continue
        n_nodes_by_t[n.target_id] += 1
        room_of[n.id] = n.target_id

    for f in findings:
        if f.target_id not in live_ids:
            continue
        n_find_by_t[f.target_id] += 1
        worst_by_t[f.target_id] = max(worst_by_t[f.target_id], _SEV_RANK.get(f.severity, 0))
        room_of[f.id] = f.target_id

    # SUBTREE rollups: a container (firmware) room's card must summarize ALL its
    # descendant binaries (so a collapsed firmware reads "251 · 90⚠ critical"), not just
    # its own (usually empty) interior. Accumulate each target's own counts up its
    # parent_id chain.
    parent_of = {t.id: t.parent_id for t in targets}
    roll_nodes: dict[str, int] = {tid: 0 for tid in live_ids}
    roll_find: dict[str, int] = {tid: 0 for tid in live_ids}
    roll_worst: dict[str, int] = {tid: -1 for tid in live_ids}
    # count each target itself as a "binary" in its ancestors' tally
    roll_bins: dict[str, int] = {tid: 0 for tid in live_ids}
    for t in targets:
        cur: str | None = t.id
        first = True
        while cur in live_ids:
            roll_nodes[cur] += n_nodes_by_t.get(t.id, 0)
            roll_find[cur] += n_find_by_t.get(t.id, 0)
            roll_worst[cur] = max(roll_worst[cur], worst_by_t.get(t.id, -1))
            if not first:
                roll_bins[cur] += 1   # t is a descendant binary of `cur`
            first = False
            cur = parent_of.get(cur)

    rooms: list[dict] = []
    for t in targets:
        worst = worst_by_t.get(t.id, -1)
        worst_name = next((k for k, v in _SEV_RANK.items() if v == worst), None) if worst >= 0 else None
        rworst = roll_worst.get(t.id, -1)
        rworst_name = next((k for k, v in _SEV_RANK.items() if v == rworst), None) if rworst >= 0 else None
        rooms.append({
            "id": t.id, "type": "target", "label": t.name, "kind": t.kind.value,
            "format": t.format, "arch": t.arch, "parent_id": t.parent_id,
            "room": True,
            # OWN interior (drives the expand-fetch decision — /room/<id> serves these).
            "n_nodes": n_nodes_by_t.get(t.id, 0),
            "n_findings": n_find_by_t.get(t.id, 0),
            "worst_severity": worst_name,
            "has_interior": (n_nodes_by_t.get(t.id, 0) + n_find_by_t.get(t.id, 0)) > 0,
            # SUBTREE rollup (own + all descendants) — what a collapsed container card shows.
            "roll_nodes": roll_nodes.get(t.id, 0),
            "roll_findings": roll_find.get(t.id, 0),
            "roll_worst_severity": rworst_name,
            "child_bins": roll_bins.get(t.id, 0),
        })

    skeleton_nodes = rooms + loose_sockets
    socket_ids = {s["id"] for s in loose_sockets}

    # Cross-room meta-edges: any edge whose endpoints resolve to DIFFERENT rooms
    # (or to a shared socket). Aggregate parallel ones into a weighted ribbon with
    # a count, mirroring the client's Phase-3 meta-edge aggregation but done
    # server-side so the browser never sees the ~thousands of interior edges.
    def rep(ident: str) -> str | None:
        # the room a graph id belongs to: a target → itself, a node/finding → its
        # owning target, a shared socket → itself (lives in the bus lane).
        if ident in live_ids:
            return ident
        if ident in socket_ids:
            return ident
        return room_of.get(ident)

    # Parent target of each room, so we can drop a meta-edge that merely re-expresses
    # the firmware→child nesting (the client already draws that as compound containment;
    # a `contains` ribbon from the firmware to each of ~250 children is pure clutter).
    parent_of_target = {t.id: t.parent_id for t in targets}

    def is_nesting(s: str, t: str, etype: str) -> bool:
        if etype not in ("contains", "located_in"):
            return False
        return parent_of_target.get(t) == s or parent_of_target.get(s) == t

    meta: dict[tuple[str, str], dict] = {}
    for e in edges:
        s = rep(e.src_id)
        t = rep(e.dst_id)
        if s is None or t is None or s == t:
            continue  # both ends in one room → interior, not shown in skeleton
        if is_nesting(s, t, e.type):
            continue  # firmware→child containment is shown as nesting, not a ribbon
        key = (s, t, e.type)
        m = meta.get(key)
        if m is None:
            meta[key] = {
                "id": "meta:" + e.id, "source": s, "target": t, "type": e.type,
                "src_kind": "target" if s in live_ids else "node",
                "dst_kind": "target" if t in live_ids else "node",
                "origin": e.origin, "confidence": e.confidence, "count": 1,
                "meta": True, "attrs": {},
            }
        else:
            m["count"] += 1
            if e.confidence is not None and (m["confidence"] is None or e.confidence > m["confidence"]):
                m["confidence"] = e.confidence

    return {
        "project_id": project_id,
        "skeleton": True,
        "nodes": skeleton_nodes,
        "edges": list(meta.values()),
    }


def build_room(session: Session, project_id: str, target_id: str) -> dict:
    """Serialize ONE room's interior on demand: the target's own `node` rows + its
    findings + the edges among them (and the edges connecting them to the shared
    sockets, so a binary's `listens_on`/`connects_to` to the network bus draws).
    The room target itself is included (as the compound parent the client nests
    the interior under). Used when the user expands a room in the skeleton."""
    target = session.query(Target).filter(
        Target.id == target_id, Target.project_id == project_id
    ).one_or_none()
    if target is None:
        return {"project_id": project_id, "target_id": target_id, "nodes": [], "edges": []}

    interior = session.query(Node).filter(
        Node.project_id == project_id, Node.target_id == target_id, Node.archived.is_(False)
    ).all()
    findings = session.query(Finding).filter(
        Finding.project_id == project_id, Finding.target_id == target_id
    ).all()

    # The shared sockets this room's nodes touch — included so the room's edges to
    # the network bus don't dangle (the socket also lives in the skeleton).
    socket_nodes = {
        n.id: n for n in session.query(Node).filter(
            Node.project_id == project_id, Node.target_id.is_(None), Node.archived.is_(False)
        ).all()
    }

    nodes: list[dict] = [_target_node(target)]
    interior_ids = set()
    for n in interior:
        nodes.append(_code_node(n))
        interior_ids.add(n.id)
    for f in findings:
        nodes.append(_finding_node(f))
        interior_ids.add(f.id)

    # Edges with at least one endpoint inside this room. An edge to a shared
    # socket pulls that socket in as a node (so it doesn't dangle); an edge to
    # another room's interior is dropped (that edge is the skeleton's job).
    edges = session.query(Edge).filter(Edge.project_id == project_id).all()
    rendered = set(interior_ids) | {target_id}
    kept: list[Edge] = []
    pulled_sockets: set[str] = set()
    for e in edges:
        s_in = e.src_id in rendered
        d_in = e.dst_id in rendered
        if not (s_in or d_in):
            continue
        # pull in a shared socket if this room's node connects to it
        for end, other_in in ((e.src_id, d_in), (e.dst_id, s_in)):
            if other_in and end in socket_nodes and end not in rendered:
                pulled_sockets.add(end)
        # keep only edges fully inside the room (incl. pulled sockets); skip an
        # edge whose other end is a different room's interior (skeleton handles it).
        if s_in and d_in:
            kept.append(e)
        elif (e.src_id in socket_nodes and d_in) or (e.dst_id in socket_nodes and s_in):
            kept.append(e)

    for sid in pulled_sockets:
        nodes.append(_code_node(socket_nodes[sid]))
        rendered.add(sid)

    collapsed = _collapse_edges(kept, rendered)
    return {
        "project_id": project_id,
        "target_id": target_id,
        "nodes": nodes,
        "edges": collapsed,
    }


def export_graph(session: Session, project_id: str, path: str | Path) -> Path:
    graph = build_graph(session, project_id)
    out = Path(path)
    out.write_text(json.dumps(graph, indent=2))
    return out
