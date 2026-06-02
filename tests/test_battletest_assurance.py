"""Battle-test PR-2 regressions (poc-tier engagement): the verify-WRITE path must never
DOWNGRADE an already-stronger stored assurance; one-click re-verify must resolve the PoC's
OWN target (not blindly finding.target_id); list_findings + the verify_poc tool return must
expose the assurance triple; import_source_tree must error (not silently no-op) on a wrong
key. These exercise the write/serialize LOGIC offline by stubbing the verify_poc runner —
no Docker."""

import pytest
from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import assurance as A
from hexgraph.engine import mcp_tools
from hexgraph.engine import poc as poc_mod
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.surfaces import register_web_surface
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path

SPEC = {"steps": [{"method": "GET", "path": "/x"}], "oracle": {"type": "body_contains", "value": "{{NONCE}}"}}


def _make_poc_finding(s, p, target, *, assurance, verified=True):
    """A poc-type finding whose evidence carries the given assurance + a re-runnable spec."""
    task = create_task(s, project=p, target_id=target.id, type="poc")
    f = FModel(title="t", severity="critical", confidence="high", category="command-injection",
               summary="s", reasoning="r",
               evidence=Evidence(extra={
                   "poc": SPEC,
                   "poc_target_id": target.id,
                   "assurance": assurance,
                   "verification": {"verified": verified, "assurance": assurance},
               }))
    return persist_finding(s, project_id=p.id, target_id=target.id, task_id=task.id,
                           finding=f, finding_type="poc")


# ── Fix B: the MCP verify_poc write must NOT downgrade a stronger stored rung ───────────
def test_mcp_verify_poc_failed_reverify_does_not_downgrade(hg_home, monkeypatch):
    """A failed/weaker re-verify (unconfirmed) through the MCP verify_poc(finding_id=…) write
    must PRESERVE an already-stored code_present/dynamic rung — not clobber it to unconfirmed."""
    stored = A.assurance(A.CODE_PRESENT, A.DYNAMIC)
    failed = A.assurance(A.UNCONFIRMED, A.DYNAMIC)
    # the verify itself "fails" this time and would compute the weak rung
    monkeypatch.setattr(poc_mod, "verify_poc",
                        lambda *a, **k: {"verified": False, "detail": "no match", "assurance": failed})
    with session_scope() as s:
        p = create_project(s, name="b")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        f = _make_poc_finding(s, p, t, assurance=stored)
        fid, tid = f.id, t.id
    out = mcp_tools.verify_poc(tid, SPEC, finding_id=fid)
    # the RETURN reflects the merged (preserved) rung, not the failed one
    assert out["assurance"]["standard"] == A.CODE_PRESENT and out["assurance"]["method"] == A.DYNAMIC
    with session_scope() as s:
        f = s.get(Finding, fid)
        a = f.evidence_json["extra"]["assurance"]
        assert a["standard"] == A.CODE_PRESENT and a["method"] == A.DYNAMIC  # NOT downgraded
        assert f.evidence_json["extra"]["verification"]["assurance"]["standard"] == A.CODE_PRESENT


def test_mcp_verify_poc_genuine_upgrade_is_adopted(hg_home, monkeypatch):
    """A real re-confirmation at a HIGHER rung still updates (no over-conservatism)."""
    stored = A.assurance(A.CODE_PRESENT, A.STATIC)
    upgraded = A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED)
    monkeypatch.setattr(poc_mod, "verify_poc",
                        lambda *a, **k: {"verified": True, "detail": "ok", "assurance": upgraded})
    with session_scope() as s:
        p = create_project(s, name="up")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        f = _make_poc_finding(s, p, t, assurance=stored, verified=False)
        fid, tid = f.id, t.id
    mcp_tools.verify_poc(tid, SPEC, finding_id=fid)
    with session_scope() as s:
        a = s.get(Finding, fid).evidence_json["extra"]["assurance"]
        assert a["standard"] == A.INPUT_REACHABLE and a["method"] == A.DYNAMIC


# ── Fix E: list_findings + verify_poc return expose the assurance triple ────────────────
def test_list_findings_includes_assurance_triple(hg_home):
    with session_scope() as s:
        p = create_project(s, name="lf")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        _make_poc_finding(s, p, t, assurance=A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED))
        pid = p.id
    rows = mcp_tools.list_findings(pid)
    assert rows and rows[0]["assurance"] == {
        "standard": A.INPUT_REACHABLE, "method": A.DYNAMIC, "precondition": A.UNAUTHENTICATED}


def test_verify_poc_return_includes_assurance(hg_home, monkeypatch):
    a = A.assurance(A.CODE_PRESENT, A.DYNAMIC)
    monkeypatch.setattr(poc_mod, "verify_poc",
                        lambda *args, **k: {"verified": True, "detail": "ok", "assurance": a})
    with session_scope() as s:
        p = create_project(s, name="vr")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        tid = t.id
    out = mcp_tools.verify_poc(tid, SPEC)  # no finding_id → reports this run's rung
    assert out["assurance"] == {"standard": A.CODE_PRESENT, "method": A.DYNAMIC, "precondition": A.UNSPECIFIED}


# ── Fix B (REST): re-verify must not downgrade + must resolve the PoC's OWN target ──────
def test_rest_reverify_does_not_downgrade(hg_home, monkeypatch):
    stored = A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED)
    failed = A.assurance(A.UNCONFIRMED, A.DYNAMIC)
    monkeypatch.setattr(poc_mod, "verify_poc",
                        lambda *a, **k: {"verified": False, "detail": "no match", "assurance": failed})
    with session_scope() as s:
        p = create_project(s, name="rest-dg")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        f = _make_poc_finding(s, p, t, assurance=stored)
        fid = f.id
    c = TestClient(create_app())
    r = c.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 200 and r.json()["verified"] is False
    with session_scope() as s:
        a = s.get(Finding, fid).evidence_json["extra"]["assurance"]
        assert a["standard"] == A.INPUT_REACHABLE and a["method"] == A.DYNAMIC  # preserved


def test_rest_reverify_resolves_poc_own_target(hg_home, monkeypatch):
    """The PoC was authored against a CHILD web surface, but the finding sits on the parent
    binary. Re-verify must run against the PoC's own target (poc_target_id), not the parent."""
    captured = {}

    def _fake_verify(session, project, target, spec, **k):
        captured["target_id"] = target.id
        return {"verified": True, "detail": "ok",
                "assurance": A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED)}

    monkeypatch.setattr(poc_mod, "verify_poc", _fake_verify)
    with session_scope() as s:
        p = create_project(s, name="rest-tgt")
        parent = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        surf = register_web_surface(s, p, "http://127.0.0.1:9", name="live")
        # finding lives on the PARENT binary, but its PoC fires against the child web surface
        task = create_task(s, project=p, target_id=parent.id, type="poc")
        f = FModel(title="t", severity="critical", confidence="high", category="command-injection",
                   summary="s", reasoning="r",
                   evidence=Evidence(extra={"poc": SPEC, "poc_target_id": surf.id,
                                            "assurance": A.assurance(A.CODE_PRESENT, A.STATIC)}))
        row = persist_finding(s, project_id=p.id, target_id=parent.id, task_id=task.id,
                              finding=f, finding_type="poc")
        fid, surf_id, parent_id = row.id, surf.id, parent.id
    c = TestClient(create_app())
    r = c.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 200 and r.json()["verified"] is True
    assert captured["target_id"] == surf_id and captured["target_id"] != parent_id


def test_rest_reverify_falls_back_to_finding_target(hg_home, monkeypatch):
    """No poc_target_id recorded → fall back to finding.target_id (unchanged behavior)."""
    captured = {}

    def _fake_verify(session, project, target, spec, **k):
        captured["target_id"] = target.id
        return {"verified": True, "detail": "ok", "assurance": A.assurance(A.CODE_PRESENT, A.DYNAMIC)}

    monkeypatch.setattr(poc_mod, "verify_poc", _fake_verify)
    with session_scope() as s:
        p = create_project(s, name="rest-fb")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        task = create_task(s, project=p, target_id=t.id, type="poc")
        f = FModel(title="t", severity="high", confidence="low", category="command-injection",
                   summary="s", reasoning="r", evidence=Evidence(extra={"poc": SPEC}))  # no poc_target_id
        row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                              finding=f, finding_type="poc")
        fid, tid = row.id, t.id
    c = TestClient(create_app())
    assert c.post(f"/api/findings/{fid}/verify").status_code == 200
    assert captured["target_id"] == tid


def test_mcp_verify_poc_records_poc_target_id(hg_home, monkeypatch):
    """The MCP write stamps poc_target_id so a later REST re-verify can resolve the PoC target."""
    monkeypatch.setattr(poc_mod, "verify_poc",
                        lambda *a, **k: {"verified": True, "detail": "ok",
                                         "assurance": A.assurance(A.CODE_PRESENT, A.DYNAMIC)})
    with session_scope() as s:
        p = create_project(s, name="rec")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        task = create_task(s, project=p, target_id=t.id, type="poc")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                            finding=FModel(title="t", severity="high", confidence="low",
                                           category="command-injection", summary="s", reasoning="r",
                                           evidence=Evidence()), finding_type="poc")
        fid, tid = f.id, t.id
    mcp_tools.verify_poc(tid, SPEC, finding_id=fid)
    with session_scope() as s:
        assert s.get(Finding, fid).evidence_json["extra"]["poc_target_id"] == tid


# ── Fix K: import_source_tree errors clearly on a wrong key (no silent 0-file success) ──
def test_import_source_tree_errors_on_wrong_key(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        pid = p.id
    # the engagement passed `path` where the tool wanted `rel` — now accepted as an alias
    ok = mcp_tools.import_source_tree(pid, "t1", files=[{"path": "a.c", "content": "x"}])
    assert ok.get("written") == 1 and "error" not in ok
    # a genuinely keyless entry is a CLEAR error, not a silent 0-file "success"
    bad = mcp_tools.import_source_tree(pid, "t2", files=[{"contents": "oops"}])
    assert "error" in bad and "rel" in bad["error"]
    # a non-object entry errors too
    bad2 = mcp_tools.import_source_tree(pid, "t3", files=["a.c"])
    assert "error" in bad2
