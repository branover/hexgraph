"""Web-app authoring with enforced invariants (no CLI required)."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Node, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def _client():
    return TestClient(create_app())


def _project(s, name="auth"):
    return create_project(s, name=name)


def test_create_project_via_api(hg_home):
    c = _client()
    r = c.post("/api/projects", json={"name": "  Web Project ", "backend": "mock"})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "Web Project" and body["backend"] == "mock"
    assert any(p["id"] == body["id"] for p in c.get("/api/projects").json())


def test_create_project_requires_name(hg_home):
    assert _client().post("/api/projects", json={"name": "  "}).status_code == 400


def test_upload_target_registers_bytes(hg_home):
    with session_scope() as s:
        pid = _project(s).id
    c = _client()
    with open(fixture_path("vuln_httpd"), "rb") as f:
        r = c.post(f"/api/projects/{pid}/targets", files={"file": ("vuln_httpd", f.read())}, data={"recon": "false"})
    assert r.status_code == 200
    tid = r.json()["target_id"]
    with session_scope() as s:
        t = s.get(Target, tid)
        assert t is not None and t.project_id == pid
        # real bytes were copied into the project
        import os
        assert os.path.isfile(t.path) and os.path.getsize(t.path) > 0


def test_function_node_requires_existing_binary(hg_home):
    with session_scope() as s:
        project = _project(s)
        t = ingest_file(s, project, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = project.id, t.id
    c = _client()
    # missing target_id -> invariant violation
    assert c.post(f"/api/projects/{pid}/nodes", json={"node_type": "function", "name": "f"}).status_code == 400
    # nonexistent target -> violation
    assert c.post(f"/api/projects/{pid}/nodes", json={"node_type": "function", "name": "f", "target_id": "nope"}).status_code == 400
    # valid -> created
    r = c.post(f"/api/projects/{pid}/nodes", json={"node_type": "function", "name": "cgi_handler", "target_id": tid})
    assert r.status_code == 200 and r.json()["node_type"] == "function"


def test_cannot_handcreate_target_or_task_node(hg_home):
    with session_scope() as s:
        pid = _project(s).id
    c = _client()
    for nt in ("target", "task", "bogus"):
        assert c.post(f"/api/projects/{pid}/nodes", json={"node_type": nt, "name": "x"}).status_code == 400


def test_hypothesis_node_allowed_without_target(hg_home):
    with session_scope() as s:
        pid = _project(s).id
    r = _client().post(f"/api/projects/{pid}/nodes", json={"node_type": "hypothesis", "name": "auth bypass via token"})
    assert r.status_code == 200


def test_edge_endpoints_must_exist(hg_home):
    with session_scope() as s:
        project = _project(s)
        t = ingest_file(s, project, fixture_path("vuln_httpd"), name="httpd")
        a = create_app  # noqa
        pid, tid = project.id, t.id
        n = __import__("hexgraph.engine.graph.nodes", fromlist=["materialize_function"]).materialize_function(
            s, project_id=pid, target_id=tid, name="f")
        nid = n.id
    c = _client()
    # dangling endpoint -> 400
    assert c.post(f"/api/projects/{pid}/edges", json={
        "src_kind": "target", "src_id": tid, "dst_kind": "node", "dst_id": "ghost", "type": "calls"}).status_code == 400
    # invalid type -> 400
    assert c.post(f"/api/projects/{pid}/edges", json={
        "src_kind": "target", "src_id": tid, "dst_kind": "node", "dst_id": nid, "type": "nonsense"}).status_code == 400
    # valid -> created
    r = c.post(f"/api/projects/{pid}/edges", json={
        "src_kind": "target", "src_id": tid, "dst_kind": "node", "dst_id": nid, "type": "references"})
    assert r.status_code == 200 and r.json()["type"] == "references"
