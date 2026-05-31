"""M1: FastAPI app boots and serves health on loopback."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app


def test_health(hg_home):
    client = TestClient(create_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


def test_project_payload_includes_cost(hg_home):
    from conftest import fixture_path
    from hexgraph.db.session import session_scope
    from hexgraph.engine.ingest import create_project, ingest_file

    with session_scope() as s:
        project = create_project(s, name="costs")
        ingest_file(s, project, fixture_path("vuln_httpd"), name="httpd")
        pid = project.id

    client = TestClient(create_app())
    body = client.get(f"/api/projects/{pid}").json()
    assert "cost" in body
    assert body["cost"]["cost_source"] == "mock"
    assert body["cost"]["total_usd"] == 0.0
