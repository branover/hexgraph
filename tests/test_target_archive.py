"""Soft target removal: archiving a target hides its subtree + nodes + findings
from the graph/detail/search, without deleting; re-adding the bytes restores them."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Finding, Node, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.graph.graph import build_graph
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.engine.targets.targets import archive_target, restore_matching, restore_target
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _seed(s):
    p = create_project(s, name="arch")
    parent = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
    child = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    child.parent_id = parent.id
    child.metadata_json = {"sha256": "child-sha"}
    fn = materialize_function(s, project_id=p.id, target_id=child.id, name="cgi_handler")
    task = create_task(s, project=p, target_id=child.id, type="static_analysis")
    persist_finding(s, project_id=p.id, target_id=child.id, task_id=task.id, finding=FModel(
        title="overflow", severity="high", confidence="high", category="memory-safety",
        summary="s", reasoning="r", evidence=Evidence(function="cgi_handler")))
    return p, parent, child, fn


def test_archive_hides_subtree_in_graph(hg_home):
    with session_scope() as s:
        p, parent, child, fn = _seed(s)
        n = archive_target(s, p.id, parent.id)
        assert n == 2  # firmware + child
        g = build_graph(s, p.id)
        assert g["nodes"] == []  # everything under the archived firmware is hidden
        # rows still exist (soft delete)
        assert s.query(Target).filter(Target.project_id == p.id).count() == 2
        assert s.query(Finding).filter(Finding.project_id == p.id).count() == 1


def test_restore_brings_back(hg_home):
    with session_scope() as s:
        p, parent, child, fn = _seed(s)
        archive_target(s, p.id, parent.id)
        restore_target(s, p.id, parent.id)
        g = build_graph(s, p.id)
        kinds = {node["type"] for node in g["nodes"]}
        assert "target" in kinds and "finding" in kinds


def test_readd_same_bytes_restores(hg_home):
    with session_scope() as s:
        p = create_project(s, name="re")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        # give it a known sha (recon normally sets this)
        import hashlib
        with open(fixture_path("vuln_httpd"), "rb") as fh:
            t.metadata_json = {"sha256": hashlib.sha256(fh.read()).hexdigest()}
        tid = t.id
        archive_target(s, p.id, tid)
        restored = restore_matching(s, p, fixture_path("vuln_httpd"))
        assert restored is not None and restored.id == tid


def test_remove_endpoint_and_detail(hg_home):
    with session_scope() as s:
        p, parent, child, fn = _seed(s)
        pid, parent_id = p.id, parent.id

    c = TestClient(create_app())
    r = c.delete(f"/api/projects/{pid}/targets/{parent_id}")
    assert r.status_code == 200 and r.json()["archived"] == 2
    detail = c.get(f"/api/projects/{pid}").json()
    assert detail["targets"] == [] and detail["findings"] == []
    # restore via endpoint
    assert c.post(f"/api/projects/{pid}/targets/{parent_id}/restore").json()["restored"] == 2
    assert len(c.get(f"/api/projects/{pid}").json()["targets"]) == 2
