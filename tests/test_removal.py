"""Removal of graph entities (engine/graph/removal.py + API):
- nodes are soft-archived (node + its edges hidden; re-adding the node, or restore,
  brings them back) — reversible, nothing deleted;
- a single edge is hard-deleted;
- a single finding is hard-deleted (the irreversible counterpart to dismissing it);
- a whole project is hard-deleted (rows + on-disk data dir).
"""

from pathlib import Path

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Annotation, Edge, EdgeType, Finding, Node, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.graph.graph import build_graph
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node, materialize_function
from hexgraph.engine.graph.removal import (
    archive_node, delete_edge, delete_finding, delete_project, restore_node,
)
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


def test_archive_socket_node_hides_its_edges(hg_home):
    """A socket has target_id=None (shared across binaries); archiving it must still
    hide the listens_on/connects_to edges resolving to it, and restore-on-re-add."""
    from hexgraph.engine.graph.nodes import materialize_socket

    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        sock = materialize_socket(s, project_id=p.id, kind="tcp", port=8080)
        le = add_edge(s, project_id=p.id, src=("node", caller.id), dst=("node", sock.id),
                      type=EdgeType.listens_on, origin="agent")
        archive_node(s, p.id, sock.id)
        g = build_graph(s, p.id)
        assert not any(n["id"] == sock.id for n in g["nodes"])
        assert not any(e["id"] == le.id for e in g["edges"])
        # re-materializing the same socket un-archives it and the edge returns
        again = materialize_socket(s, project_id=p.id, kind="tcp", port=8080)
        assert again.id == sock.id and again.archived is False
        assert any(e["id"] == le.id for e in build_graph(s, p.id)["edges"])


def test_archive_finding_anchored_node(hg_home):
    """Archiving a node that a finding points at (about edge) hides the node + the
    about edge, but the finding row and the finding graph-node survive."""
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="rce", severity="critical", confidence="high", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence(function="system")))
        archive_node(s, p.id, callee.id)
        g = build_graph(s, p.id)
        assert not any(n["id"] == callee.id for n in g["nodes"])
        # the finding itself is still rendered (it hangs off the target, not the node)
        assert any(n["type"] == "finding" for n in g["nodes"])
        assert s.query(Finding).filter(Finding.project_id == p.id).count() == 1


def test_delete_edge_with_target_endpoint(hg_home):
    """delete_edge works for a structural edge whose endpoint is a target (the
    target ─contains→ function edge), and the target/function both survive."""
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        contains = (s.query(Edge).filter(Edge.project_id == p.id, Edge.type == "contains",
                                         Edge.dst_id == caller.id).first())
        assert contains is not None
        assert delete_edge(s, contains.id) is True
        assert s.get(Target, t.id) is not None and s.get(Node, caller.id) is not None
        assert not any(e["id"] == contains.id for e in build_graph(s, p.id)["edges"])


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


def _persist_a_finding(s, p, t, *, function="system"):
    task = create_task(s, project=p, target_id=t.id, type="static_analysis")
    return persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
        title="rce", severity="critical", confidence="high", category="command-injection",
        summary="s", reasoning="r", evidence=Evidence(function=function)))


def test_delete_finding_removes_finding_and_all_refs(hg_home):
    """Hard delete: the finding row + every polymorphic ref (an `about` edge it owns,
    a `located_in` source-link edge, an annotation keyed to it) are gone, with NO
    dangling references left behind. The endpoints the edges pointed at survive."""
    from hexgraph.engine.graph.annotations import create_annotation
    from hexgraph.engine.build.source import create_source_tree, link_finding_to_source

    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        f = _persist_a_finding(s, p, t)  # persist_finding adds an `about` edge -> node
        fid = f.id
        # an annotation keyed to the finding
        create_annotation(s, p.id, node_kind="finding", node_id=fid, kind="note", value="junk")
        # a source-link (located_in edge + materializes a source_file node)
        tree = create_source_tree(s, p, name="src", origin="scratch")
        from hexgraph.engine.build.source import write_source_file
        write_source_file(s, p, tree, "a.c", "int main(){}\n")
        link_finding_to_source(s, p, finding_id=fid, tree=tree, rel="a.c", line=1)

        # precondition: the finding owns at least the about + located_in edges
        before = (s.query(Edge).filter(
            ((Edge.src_kind == "finding") & (Edge.src_id == fid))
            | ((Edge.dst_kind == "finding") & (Edge.dst_id == fid))).count())
        assert before >= 2
        assert s.query(Annotation).filter(
            Annotation.node_kind == "finding", Annotation.node_id == fid).count() == 1

        out = delete_finding(s, fid)
        assert out["found"] is True and out["deleted_finding"] == fid
        assert out["edges"] >= 2 and out["annotations"] == 1

        # the finding row is gone
        assert s.get(Finding, fid) is None
        # NO dangling edge references the finding either as src or dst
        assert s.query(Edge).filter(
            ((Edge.src_kind == "finding") & (Edge.src_id == fid))
            | ((Edge.dst_kind == "finding") & (Edge.dst_id == fid))).count() == 0
        # NO dangling annotation
        assert s.query(Annotation).filter(
            Annotation.node_kind == "finding", Annotation.node_id == fid).count() == 0
        # the entities the edges pointed at survive (only the finding-touching edges went)
        assert s.get(Node, callee.id) is not None
        # gone from the rendered graph
        g = build_graph(s, p.id)
        assert not any(n["id"] == fid for n in g["nodes"])


def test_delete_finding_detaches_followup_task(hg_home):
    """A task spawned from a finding (parent_finding_id) is NOT deleted — its pointer
    is just nulled so it doesn't reference a removed row."""
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        f = _persist_a_finding(s, p, t)
        child = create_task(s, project=p, target_id=t.id, type="static_analysis")
        child.parent_finding_id = f.id
        s.flush()
        cid = child.id

        out = delete_finding(s, f.id)
        assert out["tasks_detached"] == 1
        from hexgraph.db.models import Task
        s.expire_all()  # bulk UPDATE used synchronize_session=False; refresh from DB
        again = s.get(Task, cid)
        assert again is not None and again.parent_finding_id is None


def test_delete_finding_detaches_fuzz_artifact(hg_home):
    """A fuzz_crash finding is OWNED by its crash artifact via a COLUMN ref
    (FuzzArtifact.finding_id), not an edge. Deleting the finding must NULL that
    pointer (symmetric with the task detach) so the artifact row + crash bytes
    survive with no dangling reference (else triage serializes a stale id and
    promote/verify wedge the inbox)."""
    from hexgraph.db.models import FuzzArtifact
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        f = _persist_a_finding(s, p, t)
        art = FuzzArtifact(project_id=p.id, campaign_id="camp-1", kind="crash",
                           finding_id=f.id)
        s.add(art)
        s.flush()
        aid = art.id

        out = delete_finding(s, f.id)
        assert out["artifacts_detached"] == 1

        s.expire_all()  # bulk UPDATE used synchronize_session=False; refresh from DB
        again = s.get(FuzzArtifact, aid)
        assert again is not None and again.finding_id is None  # row + bytes survive, no dangling ref
        assert s.get(Finding, f.id) is None  # the finding itself is gone


def test_delete_nonexistent_finding_is_safe_noop(hg_home):
    with session_scope() as s:
        out = delete_finding(s, "does-not-exist")
        assert out["found"] is False
        assert out["edges"] == 0 and out["annotations"] == 0


def test_dismiss_still_works_and_is_unchanged(hg_home):
    """The reversible soft path (status='dismissed') keeps the row, untouched by the
    new hard delete."""
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        f = _persist_a_finding(s, p, t)
        fid = f.id

    c = TestClient(create_app())
    r = c.post(f"/api/findings/{fid}/status", json={"status": "dismissed"})
    assert r.status_code == 200 and r.json()["status"] == "dismissed"
    with session_scope() as s:
        row = s.get(Finding, fid)
        assert row is not None and row.status == "dismissed"  # row persists


def test_delete_finding_via_api(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        f = _persist_a_finding(s, p, t)
        fid = f.id

    c = TestClient(create_app())
    r = c.delete(f"/api/findings/{fid}")
    assert r.status_code == 200 and r.json()["deleted_finding"] == fid
    # gone now -> 404, and a second delete is also 404 (idempotent at the API edge)
    assert c.get(f"/api/findings/{fid}").status_code == 404
    assert c.delete(f"/api/findings/{fid}").status_code == 404


def test_project_delete_via_api(hg_home):
    with session_scope() as s:
        p, t, caller, callee, edge = _seed(s)
        pid = p.id

    c = TestClient(create_app())
    assert c.delete(f"/api/projects/{pid}").json()["deleted_project"] == pid
    assert c.get(f"/api/projects/{pid}").status_code == 404
    assert c.delete(f"/api/projects/{pid}").status_code == 404
