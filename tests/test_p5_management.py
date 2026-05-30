"""P5: task workspace + provenance navigation + bulk triage + re-run."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, FindingStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync

from conftest import fixture_path


def _project_with_finding(s):
    p = create_project(s, name="m5mgmt")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
    task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                       backend="mock", params={"mock_scenario": "critical_overflow", "function": "cgi_handler"})
    return p, t, task


def test_project_tasks_and_task_detail(hg_home):
    with session_scope() as s:
        p, t, task = _project_with_finding(s)
        tid, pid = task.id, p.id
    assert run_task_sync(tid) == "succeeded"

    client = TestClient(create_app())
    tasks = client.get(f"/api/projects/{pid}/tasks").json()
    assert any(x["id"] == tid and x["finding_count"] == 1 for x in tasks)

    detail = client.get(f"/api/tasks/{tid}/detail").json()
    assert detail["task"]["type"] == "static_analysis"
    assert len(detail["findings"]) == 1
    # full replayable trace was written (P2)
    assert "bundle.json" in detail["trace_files"] and "response.json" in detail["trace_files"]


def test_finding_components_navigation(hg_home):
    with session_scope() as s:
        p, t, task = _project_with_finding(s)
        tid, pid = task.id, p.id
    run_task_sync(tid)
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.project_id == pid).one()
        fid = f.id

    client = TestClient(create_app())
    comps = client.get(f"/api/findings/{fid}/components").json()
    # the finding is about the cgi_handler function node + its target
    assert any(c["kind"] == "node" and c.get("label") == "cgi_handler" for c in comps)
    assert any(c["kind"] == "target" for c in comps)


def test_bulk_status(hg_home):
    with session_scope() as s:
        p, t, task = _project_with_finding(s)
        tid, pid = task.id, p.id
    run_task_sync(tid)
    with session_scope() as s:
        ids = [f.id for f in s.query(Finding).filter(Finding.project_id == pid).all()]

    client = TestClient(create_app())
    r = client.post("/api/findings/bulk-status", json={"ids": ids, "status": "dismissed"})
    assert r.json()["updated"] == len(ids)
    with session_scope() as s:
        assert all(f.status == FindingStatus.dismissed
                   for f in s.query(Finding).filter(Finding.project_id == pid).all())


def test_task_rerun_clones(hg_home):
    with session_scope() as s:
        p, t, task = _project_with_finding(s)
        tid = task.id
    run_task_sync(tid)
    client = TestClient(create_app())
    r = client.post(f"/api/tasks/{tid}/rerun").json()
    assert r["task_id"] != tid and r["status"] == "queued"
    # the clone carries the same type/params
    detail = client.get(f"/api/tasks/{r['task_id']}/detail").json()
    assert detail["task"]["type"] == "static_analysis"
    assert detail["task"]["params"].get("mock_scenario") == "critical_overflow"
