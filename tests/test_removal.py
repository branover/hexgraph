"""Removal of graph entities (engine/removal.py + API):
- nodes are soft-archived (node + its edges hidden; re-adding the node, or restore,
  brings them back) — reversible, nothing deleted;
- a single edge is hard-deleted;
- a whole project is hard-deleted (rows + on-disk data dir).
"""

from pathlib import Path

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Finding, Node, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.graph import build_graph
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node, materialize_function
from hexgraph.engine.removal import archive_node, delete_edge, delete_project, restore_node
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _seed(s):
    p = create_project(s, name="rm")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    caller = materialize_function(s, project_id=p.id, target_id=t.id, name="main")
    callee = materialize_function(s, project_id=p.id, target_id=t.id, name="system")
    edge = add_edge(s, project_id=p.id, src=("node", caller.id), dst=("node", callee.id),
                    type=EdgeType.calls, origin="derived", confidence=1.0)
    return p, t, caller, callee, edge


def test_archive_node_hides_node_and_its_edges(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        before = build_graph(s, p.id)
        assert any(n["id"] == callee.id for n in before["nodes"])
        assert any(e["id"] == edge.id for e in before["edges"])

        archive_node(s, p.id, callee.id)
        g = build_graph(s, p.id)
        # the archived node is gone, and so is the calls edge that touched it
        assert not any(n["id"] == callee.id for n in g["nodes"])
        assert not any(e["id"] == edge.id for e in g["edges"])
        # caller is untouched
        assert any(n["id"] == caller.id for n in g["nodes"])
        # row + edge row still exist (soft delete)
        assert s.get(Node, callee.id) is not None
        assert s.get(Edge, edge.id) is not None


def test_restore_node_brings_edges_back(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        archive_node(s, p.id, callee.id)
        restore_node(s, p.id, callee.id)
        g = build_graph(s, p.id)
        assert any(n["id"] == callee.id for n in g["nodes"])
        assert any(e["id"] == edge.id for e in g["edges"])


def test_readding_node_unarchives(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        archive_node(s, p.id, callee.id)
        # re-materializing the same function resolves to the same node and un-archives it
        again = materialize_function(s, project_id=p.id, target_id=t.id, name="system")
        assert again.id == callee.id and again.archived is False
        g = build_graph(s, p.id)
        assert any(e["id"] == edge.id for e in g["edges"])


def test_archive_unknown_node_raises(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        try:
            archive_node(s, p.id, "nope")
        except ValueError:
            pass
        else:
            assert False, "expected ValueError"


def test_delete_edge_is_hard(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        eid = edge.id
        assert delete_edge(s, eid) is True
        assert s.get(Edge, eid) is None
        assert delete_edge(s, eid) is False  # already gone
        # both endpoints survive
        assert s.get(Node, caller.id) is not None and s.get(Node, callee.id) is not None


def test_delete_project_removes_rows_and_data_dir(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="x", severity="high", confidence="high", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="main")))
        pid, data_dir = p.id, p.data_dir
        assert Path(data_dir).exists()

    with session_scope() as s:
        out = delete_project(s, pid)
        assert out["deleted_project"] == pid
        assert s.get(Project, pid) is None
        for model in (Target, Node, Edge, Finding):
            assert s.query(model).filter(model.project_id == pid).count() == 0
    assert not Path(data_dir).exists()


def test_node_removal_via_api(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        pid, nid, eid = p.id, callee.id, edge.id

    c = TestClient(create_app())
    assert c.delete(f"/api/projects/{pid}/nodes/{nid}").json()["archived"] is True
    g = c.get(f"/graph/{pid}").json()
    assert not any(n["id"] == nid for n in g["nodes"])
    assert c.post(f"/api/projects/{pid}/nodes/{nid}/restore").json()["archived"] is False
    g = c.get(f"/graph/{pid}").json()
    assert any(n["id"] == nid for n in g["nodes"])
    # hard edge delete
    assert c.delete(f"/api/edges/{eid}").json()["deleted"] is True
    assert c.delete(f"/api/edges/{eid}").status_code == 404


def test_project_delete_via_api(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        pid = p.id

    c = TestClient(create_app())
    assert c.delete(f"/api/projects/{pid}").json()["deleted_project"] == pid
    assert c.get(f"/api/projects/{pid}").status_code == 404
    assert c.delete(f"/api/projects/{pid}").status_code == 404
