"""Backend support for the workspace UX requests: function↔binary edge,
context preview, clear-tasks."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Node, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import materialize_function
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def test_function_node_tied_to_binary(hg_home):
    with session_scope() as s:
        p = create_project(s, name="tie")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        fn = materialize_function(s, project_id=p.id, target_id=t.id, name="cgi_handler")
        # a contains edge target -> function exists
        e = s.query(Edge).filter(Edge.type == EdgeType.contains.value, Edge.src_id == t.id,
                                 Edge.dst_kind == "node", Edge.dst_id == fn.id).all()
        assert len(e) == 1


def test_task_preview(hg_home):
    with session_scope() as s:
        p = create_project(s, name="prev")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy", "printf"], "mitigations": {"canary": False},
                           "strings": ["/cgi-bin/"]}
        tid = t.id
    c = TestClient(create_app())
    r = c.post("/api/tasks/preview", json={"target_id": tid, "type": "static_analysis",
                                           "objective": "find the overflow", "backend": "mock"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_estimate"] > 0
    kinds = {i["kind"] for i in body["items"]}
    assert "recon_facts" in kinds and "objective" in kinds
    assert "## objective" in body["prompt"]


def test_clear_tasks_keeps_finding_bearing(hg_home):
    with session_scope() as s:
        p = create_project(s, name="clr")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        empty = create_task(s, project=p, target_id=t.id, type="recon")  # no findings
        keep = create_task(s, project=p, target_id=t.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=keep.id, finding=FModel(
            title="x", severity="high", confidence="medium", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="f")))
        pid, empty_id, keep_id = p.id, empty.id, keep.id

    c = TestClient(create_app())
    r = c.post(f"/api/projects/{pid}/tasks/clear")
    assert r.json()["removed"] == 1
    with session_scope() as s:
        assert s.get(Task, empty_id) is None
        assert s.get(Task, keep_id) is not None
