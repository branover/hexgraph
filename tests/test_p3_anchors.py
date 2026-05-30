"""P3: task anchors, capability table, follow-up suggester seam."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.capabilities import capabilities_for
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.suggester import suggest_followups
from hexgraph.engine.tasks import create_task

from conftest import fixture_path


def test_capability_table():
    assert "static_analysis" in capabilities_for("target", "executable")
    assert "static_analysis" in capabilities_for("node", "function")
    assert capabilities_for("node", "string") == ["pattern_sweep"]
    assert "static_analysis" in capabilities_for("edge", "calls")
    assert capabilities_for("target", "firmware_image") == ["recon", "unpack"]


def test_task_records_anchor(hg_home):
    with session_scope() as s:
        p = create_project(s, name="anc")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           anchor_kind="node", anchor_id="node-123")
        tid = task.id
    with session_scope() as s:
        task = s.get(Task, tid)
        assert task.anchor_kind == "node" and task.anchor_id == "node-123"


def test_default_anchor_is_target(hg_home):
    with session_scope() as s:
        p = create_project(s, name="anc2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="recon")
        assert task.anchor_kind == "target" and task.anchor_id == t.id


def test_rule_based_suggester():
    fake = Finding(
        project_id="p", target_id="t", task_id="k",
        title="Stack overflow in cgi_handler", severity="critical", confidence="high",
        category="memory-safety", summary="s", reasoning="r",
        evidence_json={"function": "cgi_handler", "sink": "strcpy"},
    )
    sugg = suggest_followups(fake)
    types = {s.task_type for s in sugg}
    assert "harness_generation" in types and "pattern_sweep" in types
    assert any("cgi_handler" in s.label for s in sugg)


def test_capabilities_and_suggestions_endpoints(hg_home):
    from hexgraph.engine.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel

    with session_scope() as s:
        p = create_project(s, name="ep")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="overflow in cgi_handler", severity="critical", confidence="high",
            category="memory-safety", summary="s", reasoning="r",
            evidence=Evidence(function="cgi_handler", sink="strcpy"),
        ))
        fid = f.id

    client = TestClient(create_app())
    caps = client.get("/api/capabilities").json()
    assert "target" in caps and "node" in caps and "edge" in caps

    sugg = client.get(f"/api/findings/{fid}/suggestions").json()
    assert any(s["task_type"] == "pattern_sweep" for s in sugg)
