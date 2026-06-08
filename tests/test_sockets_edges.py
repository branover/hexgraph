"""Socket nodes + typed/attributed edges (the network map + edge-attribute model).

Covers: the edge-attribute schema registry, socket identity shared across binaries
(a server listens_on and a client connects_to ONE node), schema-aware attribute
merge (list attrs like a calls edge's call_sites accumulate), and the MCP/API
surface (create_socket, update_edge, list_sockets, /api/edge-schemas)."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Node, NodeType
from hexgraph.db.session import session_scope
from hexgraph.agent import mcp_tools as M
from hexgraph.engine.graph.edge_schemas import describe_edges, merge_edge_attrs
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def test_edge_schema_registry_and_merge():
    desc = describe_edges()
    assert "calls" in desc and "call_sites" in desc["calls"]["attributes"]
    assert "listens_on" in desc and "address" in desc["listens_on"]["attributes"]
    # list attrs accumulate (deduped), scalars overwrite, unknown keys pass through
    a = merge_edge_attrs("calls", {"call_sites": ["0x1"], "count": 1},
                         {"call_sites": ["0x1", "0x2"], "count": 2, "note": "x"})
    assert a["call_sites"] == ["0x1", "0x2"] and a["count"] == 2 and a["note"] == "x"


def test_socket_shared_across_binaries(hg_home):
    """A server listens_on and a client connects_to the SAME socket node."""
    with session_scope() as s:
        p = create_project(s, name="net")
        srv = ingest_file(s, p, fixture_path("vuln_httpd"), name="server")
        cli = ingest_file(s, p, fixture_path("libupnp.so"), name="client")
        pid, srv_id, cli_id = p.id, srv.id, cli.id

    sock = M.create_socket(project_id=pid, kind="tcp", port=8080, bind_addr="0.0.0.0")
    assert sock["name"] == "tcp:8080" and sock["attrs"]["port"] == 8080
    sid = sock["id"]
    # same (kind, port) dedups to the same node
    assert M.create_socket(project_id=pid, kind="tcp", port=8080)["id"] == sid

    M.create_edge(pid, "target", srv_id, "node", sid, "listens_on",
                  attrs={"address": "0x401200", "reachable_preauth": True})
    M.create_edge(pid, "target", cli_id, "node", sid, "connects_to", attrs={"address": "0x401abc"})

    smap = M.list_sockets(pid)
    assert len(smap) == 1
    rels = {p_["relation"] for p_ in smap[0]["peers"]}
    assert rels == {"listens_on", "connects_to"}


def test_calls_edge_attrs_accumulate(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ca")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="b")
        pid, tid = p.id, t.id
    fn = M.create_node(pid, "function", "handler", target_id=tid, address="0x401000")
    fid = fn["id"]
    M.create_edge(pid, "target", tid, "node", fid, "calls", attrs={"call_sites": ["0x401010"]}, merge=True)
    e = M.create_edge(pid, "target", tid, "node", fid, "calls",
                      attrs={"call_sites": ["0x401060"],
                             "arg_constraints": [{"index": 2, "conclusion": "always O_RDONLY"}]}, merge=True)
    assert e["attrs"]["call_sites"] == ["0x401010", "0x401060"]
    assert e["attrs"]["arg_constraints"][0]["conclusion"] == "always O_RDONLY"
    # exactly one calls edge (merge folded the repeat)
    with session_scope() as s:
        n = s.query(Edge).filter(Edge.project_id == pid, Edge.type == "calls").count()
        assert n == 1


def test_update_edge_merges(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ue")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="b")
        pid, tid = p.id, t.id
    sock = M.create_socket(project_id=pid, kind="tcp", port=22)
    e = M.create_edge(pid, "target", tid, "node", sock["id"], "listens_on", attrs={"address": "0x400500"})
    upd = M.update_edge(e["id"], {"backlog": 16})
    assert upd["attrs"]["address"] == "0x400500" and upd["attrs"]["backlog"] == 16


def test_socket_node_type_and_edge_types_registered():
    assert NodeType.socket.value == "socket"
    assert {EdgeType.listens_on.value, EdgeType.connects_to.value} <= {e.value for e in EdgeType}
    schemas = M.get_schemas()
    assert "socket" in schemas["node_types"]
    assert "listens_on" in schemas["edge_types"]
    assert "calls" in schemas["edge_attribute_schemas"]
    assert "tcp" in schemas["socket"]["kinds"]


def test_api_socket_and_edge_schema_endpoints(hg_home):
    with session_scope() as s:
        p = create_project(s, name="api")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="b")
        pid, tid = p.id, t.id

    c = TestClient(create_app())
    r = c.get("/api/edge-schemas")
    assert r.status_code == 200 and "calls" in r.json()["edges"] and "tcp" in r.json()["socket_kinds"]

    r = c.post(f"/api/projects/{pid}/sockets", json={"kind": "tcp", "port": 1900})
    assert r.status_code == 200
    sid = r.json()["id"]
    assert r.json()["attrs"]["port"] == 1900

    r = c.post(f"/api/projects/{pid}/edges",
               json={"src_kind": "target", "src_id": tid, "dst_kind": "node", "dst_id": sid,
                     "type": "listens_on", "attrs": {"address": "0x401500"}})
    assert r.status_code == 200 and r.json()["attrs"]["address"] == "0x401500"
    eid = r.json()["id"]

    r = c.patch(f"/api/edges/{eid}", json={"attrs": {"backlog": 5}})
    assert r.status_code == 200 and r.json()["attrs"]["backlog"] == 5 and r.json()["attrs"]["address"] == "0x401500"

    # socket shows up in the graph as a node with its attrs
    g = c.get(f"/graph/{pid}").json()
    sock_nodes = [n for n in g["nodes"] if n.get("node_type") == "socket"]
    assert sock_nodes and sock_nodes[0]["attrs"]["port"] == 1900
    # the listens_on edge carries its attrs in the graph
    lo = [e for e in g["edges"] if e["type"] == "listens_on"]
    assert lo and lo[0]["attrs"]["address"] == "0x401500"
