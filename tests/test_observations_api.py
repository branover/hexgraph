"""The Observation REST surface (Phase O UI): list / get / search endpoints that back
the "Tool Results" panel. Mock backend, offline — no Docker, no key."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _seed_with_observations(hg_home):
    """A project + one target carrying a few recorded tool results; returns
    (project_id, target_id, [observation_ids])."""
    with session_scope() as s:
        p = create_project(s, name="obs-api")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "deadbeef"}
        s.flush()
        pid, tid = p.id, t.id
        ids = []
        o1, _ = O.record_observation(
            s, project_id=pid, target_id=tid, source="task-1", tool="list_functions",
            args={}, result_kind="function_list", payload={"functions": ["main", "cgi_handler"]},
            summary="2 functions", content_hash="deadbeef")
        o2, _ = O.record_observation(
            s, project_id=pid, target_id=tid, source="task-1", tool="decompile_function",
            args={"function": "cgi_handler"}, result_kind="decompilation",
            payload={"pseudocode": "void cgi_handler(){ system(x); }"},
            summary="decompiled cgi_handler", content_hash="deadbeef")
        o3, _ = O.record_observation(
            s, project_id=pid, target_id=tid, source="task-2", tool="xrefs", args={},
            result_kind="xrefs", payload={"sinks": {"system": ["cgi_handler"]}},
            summary="xrefs to system", content_hash="deadbeef")
        ids = [o1.id, o2.id, o3.id]
        return pid, tid, ids


def test_list_observations(hg_home):
    pid, tid, ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    r = client.get(f"/api/projects/{pid}/targets/{tid}/observations")
    assert r.status_code == 200
    rows = r.json()["observations"]
    assert len(rows) == 3
    # Newest first, row metadata only (no full payload on the list).
    assert {row["result_kind"] for row in rows} == {"function_list", "decompilation", "xrefs"}
    assert all("payload" not in row for row in rows)
    assert all(row["target_id"] == tid for row in rows)


def test_list_observations_empty(hg_home):
    with session_scope() as s:
        p = create_project(s, name="empty")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        s.flush()
        pid, tid = p.id, t.id
    client = TestClient(create_app())
    r = client.get(f"/api/projects/{pid}/targets/{tid}/observations")
    assert r.status_code == 200
    assert r.json()["observations"] == []


def test_list_observations_filters(hg_home):
    pid, tid, _ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    # filter by tool
    r = client.get(f"/api/projects/{pid}/targets/{tid}/observations", params={"tool": "xrefs"})
    rows = r.json()["observations"]
    assert len(rows) == 1 and rows[0]["tool"] == "xrefs"
    # filter by kind
    r = client.get(f"/api/projects/{pid}/targets/{tid}/observations", params={"kind": "decompilation"})
    rows = r.json()["observations"]
    assert len(rows) == 1 and rows[0]["result_kind"] == "decompilation"


def test_list_observations_bad_since(hg_home):
    pid, tid, _ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    r = client.get(f"/api/projects/{pid}/targets/{tid}/observations", params={"since": "not-a-date"})
    assert r.status_code == 400


def test_list_observations_404s(hg_home):
    pid, tid, _ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    assert client.get(f"/api/projects/nope/targets/{tid}/observations").status_code == 404
    assert client.get(f"/api/projects/{pid}/targets/nope/observations").status_code == 404


def test_get_observation_returns_full_payload(hg_home):
    pid, tid, ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    r = client.get(f"/api/observations/{ids[1]}")
    assert r.status_code == 200
    body = r.json()
    # The single-get carries the full CAS payload, faithfully restored.
    assert body["result_kind"] == "decompilation"
    assert body["payload"] == {"pseudocode": "void cgi_handler(){ system(x); }"}
    assert body["tool"] == "decompile_function"
    assert body["args"] == {"function": "cgi_handler"}


def test_get_observation_404(hg_home):
    _seed_with_observations(hg_home)
    client = TestClient(create_app())
    assert client.get("/api/observations/does-not-exist").status_code == 404


def test_search_observations(hg_home):
    pid, tid, _ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    # substring over tool / summary / kind
    r = client.get(f"/api/projects/{pid}/observations/search", params={"q": "decompil"})
    rows = r.json()["observations"]
    assert len(rows) == 1 and rows[0]["result_kind"] == "decompilation"
    # match on summary text
    r = client.get(f"/api/projects/{pid}/observations/search", params={"q": "system"})
    assert len(r.json()["observations"]) == 1
    # empty query returns all (newest first), bounded
    r = client.get(f"/api/projects/{pid}/observations/search", params={"q": ""})
    assert len(r.json()["observations"]) == 3


def test_search_observations_scoped_to_target(hg_home):
    pid, tid, _ids = _seed_with_observations(hg_home)
    client = TestClient(create_app())
    r = client.get(f"/api/projects/{pid}/observations/search",
                   params={"q": "", "target_id": tid})
    assert len(r.json()["observations"]) == 3
    r = client.get(f"/api/projects/{pid}/observations/search",
                   params={"q": "", "target_id": "other"})
    assert r.json()["observations"] == []


def test_search_observations_project_404(hg_home):
    client = TestClient(create_app())
    assert client.get("/api/projects/nope/observations/search", params={"q": "x"}).status_code == 404
