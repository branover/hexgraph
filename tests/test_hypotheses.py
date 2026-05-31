"""P6: hypothesis lifecycle — evidence-derived status, sticky human verdicts,
and open hypotheses feeding the task context."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import NodeType
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.hypotheses import (
    create_hypothesis, link_evidence, recompute_status, set_status, summary,
)
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _finding(s, project, target, task, title, sev="high"):
    return persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id, finding=FModel(
        title=title, severity=sev, confidence="medium", category="memory-safety",
        summary="s", reasoning="r", evidence=Evidence(function="f")))


def test_status_derives_from_evidence(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hyp")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        h = create_hypothesis(s, p, statement="cgi handler trusts a network length", target_id=t.id)
        assert h.node_type == NodeType.hypothesis.value
        assert (h.attrs_json or {})["status"] == "open"

        f1 = _finding(s, p, t, task, "unbounded strcpy in cgi_handler")
        link_evidence(s, p, hypothesis_id=h.id, finding_id=f1.id, relation="supports")
        assert summary(s, h.id)["status"] == "supported"

        f2 = _finding(s, p, t, task, "bounds check present after all")
        link_evidence(s, p, hypothesis_id=h.id, finding_id=f2.id, relation="refutes")
        assert summary(s, h.id)["status"] == "contested"


def test_human_verdict_is_sticky(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hyp2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        h = create_hypothesis(s, p, statement="reachable from network", target_id=t.id)
        set_status(s, h.id, "confirmed")
        # New refuting evidence must NOT override a human's confirmed verdict.
        f = _finding(s, p, t, task, "looks refuted")
        link_evidence(s, p, hypothesis_id=h.id, finding_id=f.id, relation="refutes")
        assert summary(s, h.id)["status"] == "confirmed"
        # Reopening hands control back to the evidence (which is refuting).
        set_status(s, h.id, "open")
        assert recompute_status(s, h) == "refuted"


def test_open_hypothesis_feeds_context(hg_home):
    from hexgraph.engine.context import preview_context

    with session_scope() as s:
        p = create_project(s, name="hyp3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
        create_hypothesis(s, p, statement="parser overruns a fixed buffer", target_id=t.id)
        prev = preview_context(s, p, t, type("C", (), {
            "objective": "verify the buffer claim", "tool_outputs": None,
            "sibling_name": None, "sibling_target_id": None})())
        kinds = {i["kind"] for i in prev["items"]}
        assert "open_hypotheses" in kinds


def test_hypothesis_api_roundtrip(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hyp4")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = _finding(s, p, t, task, "overflow")
        pid, tid, fid = p.id, t.id, f.id

    c = TestClient(create_app())
    r = c.post(f"/api/projects/{pid}/hypotheses",
               json={"statement": "the handler is exploitable", "target_id": tid})
    assert r.status_code == 200
    hid = r.json()["id"]
    assert r.json()["status"] == "open"

    r = c.post(f"/api/hypotheses/{hid}/evidence", json={"finding_id": fid, "relation": "supports"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "supported" and len(body["supports"]) == 1

    r = c.post(f"/api/hypotheses/{hid}/status", json={"status": "confirmed"})
    assert r.json()["status"] == "confirmed" and r.json()["status_origin"] == "human"


def test_invalid_relation_rejected(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hyp5")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = _finding(s, p, t, task, "x")
        from hexgraph.engine.hypotheses import HypothesisError
        h = create_hypothesis(s, p, statement="q")
        import pytest
        with pytest.raises(HypothesisError):
            link_evidence(s, p, hypothesis_id=h.id, finding_id=f.id, relation="maybe")


def test_confirms_alias_supports(hg_home):
    # Agents reach for "confirms" (an advertised edge type) on a verified finding;
    # it must be accepted as a supporting relation, not rejected.
    with session_scope() as s:
        p = create_project(s, name="hyp6")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = _finding(s, p, t, task, "verified command injection")
        h = create_hypothesis(s, p, statement="popen sink is reachable", target_id=t.id)
        link_evidence(s, p, hypothesis_id=h.id, finding_id=f.id, relation="confirms")
        out = summary(s, h.id)
        assert out["status"] == "supported" and len(out["supports"]) == 1


def test_set_status_records_rationale(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hyp7")
        h = create_hypothesis(s, p, statement="exploitable as RCE")
        set_status(s, h.id, "confirmed", rationale="verified PoC echoes the nonce")
        assert (h.attrs_json or {})["status_note"] == "verified PoC echoes the nonce"
