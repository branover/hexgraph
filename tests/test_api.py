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
