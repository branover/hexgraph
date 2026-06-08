"""P6: widened triage, human edits (PATCH), feedback-into-context."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _seed(s):
    p = create_project(s, name="hitl")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    task = create_task(s, project=p, target_id=t.id, type="static_analysis")
    f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
        title="overflow", severity="high", confidence="medium", category="memory-safety",
        summary="s", reasoning="r", evidence=Evidence(function="cgi_handler", sink="strcpy"),
    ))
    return p, t, f


def test_widened_status_values(hg_home):
    with session_scope() as s:
        p, t, f = _seed(s)
        fid = f.id
    client = TestClient(create_app())
    for st in ["triaging", "confirmed", "dismissed", "reported", "new"]:
        r = client.post(f"/api/findings/{fid}/status", json={"status": st})
        assert r.status_code == 200 and r.json()["status"] == st


def test_patch_edit_preserves_agent_original(hg_home):
    with session_scope() as s:
        p, t, f = _seed(s)
        fid = f.id
    client = TestClient(create_app())
    r = client.patch(f"/api/findings/{fid}", json={"severity": "critical", "human_notes": "confirmed exploitable"})
    body = r.json()
    assert body["severity"] == "critical"
    assert body["origin"] == "agent_edited"
    assert body["human_notes"] == "confirmed exploitable"
    assert body["evidence"]["extra"]["agent_original"]["severity"] == "high"


def test_confirmed_and_dismissed_feed_context(hg_home):
    """Confirmed findings become authoritative context; dismissed become do-not-report."""
    from hexgraph.engine.context import build_context_bundle
    from hexgraph.db.models import FindingStatus

    with session_scope() as s:
        p, t, f = _seed(s)
        f.status = FindingStatus.confirmed.value
        # a second, dismissed finding
        task2 = create_task(s, project=p, target_id=t.id, type="static_analysis")
        d = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task2.id, finding=FModel(
            title="noise", severity="low", confidence="low", category="other",
            summary="s", reasoning="r", evidence=Evidence(function="x")))
        d.status = FindingStatus.dismissed.value
        s.flush()

        class _Ctx:
            objective = None; tool_outputs = {}; sibling_name = None; sibling_target_id = None

        task3 = create_task(s, project=p, target_id=t.id, type="static_analysis")
        bundle = build_context_bundle(s, p, t, task3, _Ctx())
        kinds = {it.kind for it in bundle.included}
        assert "analyst_confirmed" in kinds
        assert "do_not_report" in kinds
