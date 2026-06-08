"""Skeleton-first graph loading (real-firmware scale): the backend serves the
structural SKELETON (rooms + sockets + aggregated cross-room meta-edges) and a
single room's interior on demand, so the browser never receives ~13k nodes at once.

Covers engine/graph/graph.{graph_size, build_skeleton, build_room} and their HTTP wiring.
Offline, mock, no Docker — builds a small synthetic firmware via the authoring API.
"""

from hexgraph.db.models import EdgeType, FindingStatus, NodeType, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.authoring import create_socket
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.graph.graph import (
    SKELETON_THRESHOLD,
    build_graph,
    build_room,
    build_skeleton,
    graph_size,
)
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding

from conftest import fixture_path


def _firmware(s, *, n_bins=4, fns_per_bin=5):
    """A tiny firmware: a firmware_image root with N executable children, each with
    functions + one finding, a shared socket two binaries touch, and a cross-target
    links_against edge. Returns (project, firmware, [child targets], socket)."""
    p = create_project(s, name="fw")
    fw = ingest_file(s, p, fixture_path("vuln_httpd"), name="fw.img")
    fw.kind = TargetKind.firmware_image
    sock = create_socket(s, p, kind="tcp", port=80, name="http", bind_addr="0.0.0.0")
    bins = []
    for b in range(n_bins):
        binr = ingest_file(s, p, fixture_path("vuln_httpd"), name=f"sbin/svc_{b}", parent=fw)
        binr.kind = TargetKind.executable
        fns = [materialize_function(s, project_id=p.id, target_id=binr.id, name=f"fn_{b}_{i}")
               for i in range(fns_per_bin)]
        for x, y in zip(fns, fns[1:]):
            add_edge(s, project_id=p.id, src=("node", x.id), dst=("node", y.id),
                     type=EdgeType.calls, origin="tool")
        if b < 2:  # two binaries listen on the shared socket
            add_edge(s, project_id=p.id, src=("node", fns[0].id), dst=("node", sock.id),
                     type=EdgeType.listens_on, origin="tool")
        t = create_task(s, project=p, target_id=binr.id, type="static_analysis", backend="mock")
        persist_finding(s, project_id=p.id, target_id=binr.id, task_id=t.id,
                        finding=Finding(title=f"vuln {b}", severity=("critical" if b == 0 else "low"),
                                        confidence="high", category="command-injection",
                                        summary="x", reasoning="y", evidence=Evidence(file="/x")),
                        status=FindingStatus.new, finding_type="vulnerability")
        bins.append(binr)
    # a cross-target structural link (becomes a skeleton meta-edge)
    add_edge(s, project_id=p.id, src=("target", bins[0].id), dst=("target", bins[1].id),
             type=EdgeType.links_against, origin="tool")
    s.flush()
    return p, fw, bins, sock


def test_graph_size_counts_and_threshold(hg_home):
    with session_scope() as s:
        p, fw, bins, sock = _firmware(s)
        sz = graph_size(s, p.id)
        full = build_graph(s, p.id)
        assert sz["total"] == len(full["nodes"]) + len(full["edges"])
        assert sz["targets"] == 1 + len(bins)        # firmware + children
        assert sz["threshold"] == SKELETON_THRESHOLD
        # this tiny graph is well under the threshold → full load recommended
        assert sz["skeleton_recommended"] is False


def test_skeleton_has_rooms_not_interiors(hg_home):
    with session_scope() as s:
        p, fw, bins, sock = _firmware(s)
        full = build_graph(s, p.id)
        sk = build_skeleton(s, p.id)
        assert sk["skeleton"] is True

        rooms = [n for n in sk["nodes"] if n.get("room")]
        sockets = [n for n in sk["nodes"] if n["type"] == "node"]
        # one room per target (firmware + children); the shared socket is loose (bus lane).
        assert len(rooms) == 1 + len(bins)
        assert len(sockets) == 1 and sockets[0]["id"] == sock.id
        # NO interior function nodes leak into the skeleton.
        assert not any(n.get("node_type") == "function" for n in sk["nodes"])
        # the skeleton is dramatically smaller than the full graph.
        assert len(sk["nodes"]) < len(full["nodes"])

        by_id = {r["id"]: r for r in rooms}
        # each child room reports its interior counts + worst-severity rollup.
        crit_room = by_id[bins[0].id]
        assert crit_room["n_nodes"] >= 5 and crit_room["n_findings"] == 1
        assert crit_room["worst_severity"] == "critical"
        assert crit_room["has_interior"] is True
        # the firmware root itself has no own interior nodes/findings.
        assert by_id[fw.id]["n_nodes"] == 0


def test_skeleton_meta_edges_aggregate_cross_room(hg_home):
    with session_scope() as s:
        p, fw, bins, sock = _firmware(s)
        sk = build_skeleton(s, p.id)
        # every skeleton edge is a cross-room meta-edge (no interior edges).
        assert sk["edges"] and all(e.get("meta") for e in sk["edges"])
        room_ids = {n["id"] for n in sk["nodes"]}
        for e in sk["edges"]:
            assert e["source"] in room_ids and e["target"] in room_ids
            assert e["source"] != e["target"]
        types = {e["type"] for e in sk["edges"]}
        # the cross-target links_against link AND the two binaries' listens_on to the
        # shared socket are promoted to the skeleton.
        assert "links_against" in types
        assert "listens_on" in types
        # contains edges (firmware→child, child→fn) are interior structure of a room
        # boundary — firmware→child IS cross-room so it appears; fn-level contains do not
        # because fns aren't skeleton nodes.
        listens = [e for e in sk["edges"] if e["type"] == "listens_on"]
        assert all(e["target"] == sock.id for e in listens)


def test_room_interior_round_trips(hg_home):
    with session_scope() as s:
        p, fw, bins, sock = _firmware(s)
        room = build_room(s, p.id, bins[0].id)
        ids = {n["id"] for n in room["nodes"]}
        # the room's own target + its functions + its finding are present.
        assert bins[0].id in ids
        fn_nodes = [n for n in room["nodes"] if n.get("node_type") == "function"]
        find_nodes = [n for n in room["nodes"] if n["type"] == "finding"]
        assert len(fn_nodes) == 5 and len(find_nodes) == 1
        # the shared socket is PULLED IN (bin 0 listens on it) so its edge doesn't dangle.
        assert sock.id in ids
        # interior call edges are present; no edge dangles outside the returned node set.
        for e in room["edges"]:
            assert e["source"] in ids and e["target"] in ids
        assert any(e["type"] == "calls" for e in room["edges"])
        assert any(e["type"] == "listens_on" for e in room["edges"])

        # a room with no shared-socket touch (bin 2) doesn't pull the socket in.
        room2 = build_room(s, p.id, bins[2].id)
        assert sock.id not in {n["id"] for n in room2["nodes"]}


def test_room_unknown_target_is_empty(hg_home):
    with session_scope() as s:
        p, fw, bins, sock = _firmware(s)
        room = build_room(s, p.id, "does-not-exist")
        assert room["nodes"] == [] and room["edges"] == []
