"""M5: accept/dismiss status, dedup, export."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, FindingStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.dedup import dedupe_findings
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FindingModel

from conftest import fixture_path


def _seed(s, n_dupes=0):
    project = create_project(s, name="m5")
    target = ingest_file(s, project, fixture_path("vuln_httpd"), name="httpd")
    task = create_task(s, project=project, target_id=target.id, type="static_analysis")
    base = FindingModel(
        title="Overflow in f", severity="high", confidence="medium", category="memory-safety",
        summary="s", reasoning="r", evidence=Evidence(function="f", sink="strcpy"),
    )
    rows = [persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id, finding=base)]
    for _ in range(n_dupes):
        persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id, finding=base)
    return project, target, rows[0]


def test_accept_dismiss_status(hg_home):
    with session_scope() as s:
        project, _t, finding = _seed(s)
        pid, fid = project.id, finding.id

    client = TestClient(create_app())
    r = client.post(f"/api/findings/{fid}/status", json={"status": "confirmed"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed"
    with session_scope() as s:
        assert s.get(Finding, fid).status == FindingStatus.confirmed

    bad = client.post(f"/api/findings/{fid}/status", json={"status": "bogus"})
    assert bad.status_code == 400


def test_dedup_removes_duplicates(hg_home):
    with session_scope() as s:
        project, _t, _f = _seed(s, n_dupes=2)
        pid = project.id
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 3

    with session_scope() as s:
        removed = dedupe_findings(s, pid)
        assert removed == 2
    with session_scope() as s:
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 1


def test_export_endpoint(hg_home):
    with session_scope() as s:
        project, _t, _f = _seed(s)
        pid = project.id

    client = TestClient(create_app())
    body = client.get(f"/api/projects/{pid}/export").json()
    assert set(body.keys()) == {"project", "graph", "findings"}
    assert len(body["findings"]) == 1
    assert body["graph"]["nodes"]
