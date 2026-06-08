"""The JOURNAL REST surface (working-memory layer, design §9): list/create per project,
get/edit/delete one entry, and search. The human/REST path may edit any entry (the
agent-only-own rule is enforced on the MCP path, covered in test_journal.py). Mock
backend, offline — no Docker, no key."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _seed(hg_home):
    with session_scope() as s:
        p = create_project(s, name="jrnl-api")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        return p.id, t.id


def test_create_list_get(hg_home):
    pid, tid = _seed(hg_home)
    client = TestClient(create_app())
    r = client.post(f"/api/projects/{pid}/journal",
                    json={"body": f"on @[httpd](target:{tid})", "author": "human"})
    assert r.status_code == 200, r.text
    eid = r.json()["id"]
    assert r.json()["author"] == "human"
    # the mention resolved
    assert r.json()["mentions"][0]["ref_kind"] == "target"
    assert r.json()["mentions"][0]["dangling"] is False

    rl = client.get(f"/api/projects/{pid}/journal")
    assert rl.status_code == 200 and len(rl.json()["entries"]) == 1

    rg = client.get(f"/api/journal/{eid}")
    assert rg.status_code == 200 and rg.json()["id"] == eid


def test_create_rejects_blank_body(hg_home):
    pid, _ = _seed(hg_home)
    client = TestClient(create_app())
    r = client.post(f"/api/projects/{pid}/journal", json={"body": "  "})
    assert r.status_code == 400


def test_author_filter(hg_home):
    pid, _ = _seed(hg_home)
    client = TestClient(create_app())
    client.post(f"/api/projects/{pid}/journal", json={"body": "a", "author": "agent"})
    client.post(f"/api/projects/{pid}/journal", json={"body": "h", "author": "human"})
    r = client.get(f"/api/projects/{pid}/journal", params={"author": "agent"})
    assert {e["author"] for e in r.json()["entries"]} == {"agent"}


def test_patch_marks_edited_and_reparses(hg_home):
    pid, tid = _seed(hg_home)
    client = TestClient(create_app())
    eid = client.post(f"/api/projects/{pid}/journal", json={"body": "draft"}).json()["id"]
    r = client.patch(f"/api/journal/{eid}", json={"body": f"now mentions @[httpd](target:{tid})"})
    assert r.status_code == 200
    assert r.json()["edited"] is True
    assert any(m["ref_kind"] == "target" for m in r.json()["mentions"])


def test_human_rest_path_may_edit_an_agent_entry(hg_home):
    """The REST surface is the human's workbench — it may edit ANY entry (the
    agent-only-own restriction lives on the MCP path, not here)."""
    pid, _ = _seed(hg_home)
    client = TestClient(create_app())
    eid = client.post(f"/api/projects/{pid}/journal",
                      json={"body": "agent wrote this", "author": "agent"}).json()["id"]
    r = client.patch(f"/api/journal/{eid}", json={"body": "human corrected it"})
    assert r.status_code == 200 and r.json()["body"] == "human corrected it"


def test_delete(hg_home):
    pid, _ = _seed(hg_home)
    client = TestClient(create_app())
    eid = client.post(f"/api/projects/{pid}/journal", json={"body": "scratch"}).json()["id"]
    assert client.delete(f"/api/journal/{eid}").status_code == 200
    assert client.get(f"/api/journal/{eid}").status_code == 404


def test_search(hg_home):
    pid, _ = _seed(hg_home)
    client = TestClient(create_app())
    client.post(f"/api/projects/{pid}/journal", json={"body": "the cgi handler trusts a length"})
    client.post(f"/api/projects/{pid}/journal", json={"body": "unrelated"})
    r = client.get(f"/api/projects/{pid}/journal/search", params={"q": "cgi"})
    assert r.status_code == 200 and len(r.json()["entries"]) == 1


def test_missing_project_and_entry_404(hg_home):
    client = TestClient(create_app())
    assert client.get("/api/projects/nope/journal").status_code == 404
    assert client.get("/api/journal/nope").status_code == 404
    assert client.patch("/api/journal/nope", json={"body": "x"}).status_code == 404
    assert client.delete("/api/journal/nope").status_code == 404
