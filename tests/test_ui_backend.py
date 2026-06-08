"""Backend support for the workspace UX requests: function↔binary edge,
context preview, clear-tasks."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Node, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function
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


def test_reveal_endpoints_and_target_suggestions(hg_home):
    """The REST reveal endpoints flip visibility (and the project listing default-filters
    to visible); the target suggestions endpoint serves the relocated risky-sink follow-up."""
    with session_scope() as s:
        p = create_project(s, name="rev")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        child = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd",
                            parent=fw, visible=False)
        # enrich the hidden child as recon would (so the suggester has imports to act on)
        child.metadata_json = {**(child.metadata_json or {}), "imports": ["strcpy"]}
        child.kind = __import__("hexgraph.db.models", fromlist=["TargetKind"]).TargetKind.executable
        pid, fwid, cid = p.id, fw.id, child.id

    c = TestClient(create_app())
    # default project listing hides the firmware child
    ids = {t["id"] for t in c.get(f"/api/projects/{pid}").json()["targets"]}
    assert fwid in ids and cid not in ids
    # include_hidden surfaces it
    ids_all = {t["id"] for t in c.get(f"/api/projects/{pid}?include_hidden=true").json()["targets"]}
    assert cid in ids_all

    # the relocated risky-sink follow-up surfaces at the target level
    sugg = c.get(f"/api/targets/{cid}/suggestions").json()
    assert sugg and sugg[0]["task_type"] == "static_analysis"

    # reveal one target → it joins the visible listing
    r = c.post(f"/api/projects/{pid}/targets/{cid}/visible", json={"visible": True})
    assert r.status_code == 200 and r.json()["visible"] is True
    assert cid in {t["id"] for t in c.get(f"/api/projects/{pid}").json()["targets"]}

    # re-hide via the same endpoint
    r = c.post(f"/api/projects/{pid}/targets/{cid}/visible", json={"visible": False})
    assert r.json()["visible"] is False


def test_reveal_dir_endpoint(hg_home):
    with session_scope() as s:
        p = create_project(s, name="revd")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd", parent=fw, visible=False)
        ingest_file(s, p, fixture_path("vuln_httpd"), name="bin/busybox", parent=fw, visible=False)
        pid, fwid, aid = p.id, fw.id, a.id

    c = TestClient(create_app())
    r = c.post(f"/api/projects/{pid}/targets/{fwid}/reveal-dir", json={"prefix": "usr/sbin"})
    assert r.status_code == 200 and r.json()["revealed"] == 1
    assert aid in {t["id"] for t in c.get(f"/api/projects/{pid}").json()["targets"]}


def test_decompile_endpoint_degrades_without_docker(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        p = create_project(s, name="dc")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tid = t.id
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/decompile", json={"function": "cgi_handler"})
    assert r.status_code == 200 and r.json()["available"] is False
    assert c.post("/api/targets/nope/decompile", json={"function": "x"}).status_code == 404
