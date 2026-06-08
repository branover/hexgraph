"""P6: hypothesis lifecycle — evidence-derived status, sticky human verdicts,
and open hypotheses feeding the task context."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import NodeType
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.hypotheses import (
    DEFAULT_WORK_STATE, WORK_STATES, create_hypothesis, link_evidence, list_hypotheses,
    recompute_status, set_pinned, set_status, set_work_state, summary,
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


# --- work-state axis + worklist (design-working-memory.md §4) ---------------------------

def test_new_hypothesis_defaults_investigating_unpinned(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ws1")
        h = create_hypothesis(s, p, statement="a fresh open question")
        attrs = h.attrs_json or {}
        assert attrs["work_state"] == DEFAULT_WORK_STATE == "investigating"
        assert attrs["pinned_to_graph"] is False
        out = summary(s, h.id)
        assert out["work_state"] == "investigating" and out["pinned_to_graph"] is False


def test_work_state_is_orthogonal_to_status(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ws2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        h = create_hypothesis(s, p, statement="reachable pre-auth", target_id=t.id)
        f = _finding(s, p, t, task, "taint reaches the sink")
        link_evidence(s, p, hypothesis_id=h.id, finding_id=f.id, relation="supports")
        # park while supported — the evidence verdict is untouched by the work-state move.
        set_work_state(s, h.id, "parked")
        out = summary(s, h.id)
        assert out["status"] == "supported" and out["work_state"] == "parked"


def test_close_sets_done_and_records_verdict(hg_home):
    from hexgraph.agent.mcp_tools import close_hypothesis
    with session_scope() as s:
        p = create_project(s, name="ws3")
        h = create_hypothesis(s, p, statement="the bypass is real")
        hid = h.id
    r = close_hypothesis(hid, verdict="rejected", rationale="ruled out — auth holds")
    assert r["work_state"] == "done" and r["status"] == "rejected"
    assert r["status_origin"] == "human"


def test_invalid_work_state_rejected(hg_home):
    import pytest
    from hexgraph.engine.hypotheses import HypothesisError
    with session_scope() as s:
        p = create_project(s, name="ws4")
        h = create_hypothesis(s, p, statement="q")
        with pytest.raises(HypothesisError):
            set_work_state(s, h.id, "maybe")


def test_list_hypotheses_filters_and_counts(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ws5")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        h1 = create_hypothesis(s, p, statement="chasing one", target_id=t.id)
        f = _finding(s, p, t, task, "supporting evidence")
        link_evidence(s, p, hypothesis_id=h1.id, finding_id=f.id, relation="supports")
        h2 = create_hypothesis(s, p, statement="parked one", target_id=t.id)
        set_work_state(s, h2.id, "parked")

        rows = list_hypotheses(s, p)
        assert len(rows) == 2
        by_id = {r["id"]: r for r in rows}
        assert by_id[h1.id]["supports_count"] == 1 and by_id[h1.id]["work_state"] == "investigating"
        assert by_id[h2.id]["work_state"] == "parked"

        inv = list_hypotheses(s, p, work_state="investigating")
        assert [r["id"] for r in inv] == [h1.id]
        sup = list_hypotheses(s, p, status="supported")
        assert [r["id"] for r in sup] == [h1.id]


def test_set_pinned_toggles_graph_visibility_flag(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ws6")
        h = create_hypothesis(s, p, statement="pin me")
        set_pinned(s, h.id, True)
        assert (h.attrs_json or {})["pinned_to_graph"] is True
        assert summary(s, h.id)["pinned_to_graph"] is True
        set_pinned(s, h.id, False)
        assert summary(s, h.id)["pinned_to_graph"] is False


def test_stale_investigating_feeds_context_nudge(hg_home):
    from hexgraph.engine.context import preview_context

    with session_scope() as s:
        p = create_project(s, name="ws7")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
        create_hypothesis(s, p, statement="unevidenced lead I'm still chasing", target_id=t.id)
        prev = preview_context(s, p, t, type("C", (), {
            "objective": "verify", "tool_outputs": None,
            "sibling_name": None, "sibling_target_id": None})())
        kinds = {i["kind"] for i in prev["items"]}
        assert "stale_hypotheses" in kinds


def test_worklist_api_endpoints(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ws8")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id

    c = TestClient(create_app())
    hid = c.post(f"/api/projects/{pid}/hypotheses",
                 json={"statement": "live question", "target_id": tid}).json()["id"]

    rows = c.get(f"/api/projects/{pid}/hypotheses").json()["hypotheses"]
    assert len(rows) == 1 and rows[0]["work_state"] == "investigating"

    r = c.post(f"/api/hypotheses/{hid}/pin", json={"pinned": True})
    assert r.status_code == 200 and r.json()["pinned_to_graph"] is True

    r = c.post(f"/api/hypotheses/{hid}/work-state", json={"work_state": "done", "verdict": "confirmed"})
    assert r.status_code == 200 and r.json()["work_state"] == "done" and r.json()["status"] == "confirmed"

    # set_hypothesis_status MCP tool now accepts a work_state move too.
    from hexgraph.agent.mcp_tools import set_hypothesis_status
    out = set_hypothesis_status(hid, work_state="parked")
    assert out["work_state"] == "parked"


def test_work_states_constant_shape(hg_home):
    assert WORK_STATES == ("investigating", "parked", "done")
