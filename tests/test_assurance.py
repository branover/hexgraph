"""The two standards of "verified" (docs/design-verification-oracles.md): the engine computes a
per-PoC assurance triple {standard, method, precondition} and records it on the finding — so
code-present (A) vs input-reachable (B) is differentiated by CODE, not by prose handed to an
agent. Pure-logic tests plus a verify_poc end-to-end with a fake runner (no Docker)."""

import pytest

from hexgraph import settings
from hexgraph.db.session import session_scope
from hexgraph.engine import assurance as A
from hexgraph.engine.ingest import create_project
from hexgraph.engine.poc import _poc_finding, verify_poc
from hexgraph.engine.surfaces import register_web_surface


# ── derive_poc_assurance: the standard/method/precondition matrix ───────────────────────
def test_verified_is_input_reachable_dynamic():
    a = A.derive_poc_assurance({"verified": True}, {"steps": [{"path": "/x"}]}, is_web=True, is_tcp=False)
    assert a["standard"] == A.INPUT_REACHABLE and a["method"] == A.DYNAMIC


def test_unverified_is_unconfirmed():
    a = A.derive_poc_assurance({"verified": False}, {"steps": [{"path": "/x"}]}, is_web=True, is_tcp=False)
    assert a["standard"] == A.UNCONFIRMED and a["method"] == A.DYNAMIC


def test_single_unauth_web_step_infers_unauthenticated():
    a = A.derive_poc_assurance({"verified": True}, {"steps": [{"method": "POST", "path": "/HNAP1"}]},
                               is_web=True, is_tcp=False)
    assert a["precondition"] == A.UNAUTHENTICATED and a.get("precondition_inferred") is True


def test_login_step_or_cookie_infers_requires_credentials():
    # a login-looking path
    a1 = A.derive_poc_assurance({"verified": True},
                                {"steps": [{"path": "/cgi-bin/luci/login"}, {"path": "/admin/cmd"}]},
                                is_web=True, is_tcp=False)
    assert a1["precondition"] == A.REQUIRES_CREDENTIALS
    # a single step that already carries a session cookie
    a2 = A.derive_poc_assurance({"verified": True},
                                {"steps": [{"path": "/admin/cmd", "headers": {"Cookie": "sid=x"}}]},
                                is_web=True, is_tcp=False)
    assert a2["precondition"] == A.REQUIRES_CREDENTIALS


def test_declared_precondition_wins_and_is_not_inferred():
    a = A.derive_poc_assurance({"verified": True},
                               {"precondition": "requires_credentials:root", "steps": [{"path": "/x"}]},
                               is_web=True, is_tcp=False)
    assert a["precondition"] == "requires_credentials:root" and "precondition_inferred" not in a


def test_tcp_infers_unauthenticated_binary_unspecified():
    t = A.derive_poc_assurance({"verified": True}, {"transport": "tcp", "port": 1337}, is_web=False, is_tcp=True)
    assert t["precondition"] == A.UNAUTHENTICATED
    b = A.derive_poc_assurance({"verified": True}, {"argv": ["x"]}, is_web=False, is_tcp=False)
    assert b["precondition"] == A.UNSPECIFIED


# ── lab-confirmed (code_present/dynamic) vs reachable (input_reachable/dynamic) ──────────
def test_isolated_binary_poc_is_lab_confirmed_not_reachable():
    """An extracted binary run in the sandbox proves the CODE is vulnerable (code_present/dynamic),
    but NOT that the deployed system routes user input to it — it must NOT claim input_reachable."""
    b = A.derive_poc_assurance({"verified": True}, {"argv": ["x"]}, is_web=False, is_tcp=False)
    assert b["standard"] == A.CODE_PRESENT and b["method"] == A.DYNAMIC
    assert "lab-confirmed" in (b.get("detail") or "")


def test_live_surface_poc_is_input_reachable():
    """A verified PoC against a live web/tcp surface hit the real deployed input → input_reachable."""
    w = A.derive_poc_assurance({"verified": True}, {"steps": [{"path": "/HNAP1"}]}, is_web=True, is_tcp=False)
    assert w["standard"] == A.INPUT_REACHABLE
    t = A.derive_poc_assurance({"verified": True}, {"transport": "tcp", "port": 1337}, is_web=False, is_tcp=True)
    assert t["standard"] == A.INPUT_REACHABLE


def test_scope_override_both_directions():
    # a binary PoC the agent justifies AS the real entry (e.g. a CGI invoked as the httpd would)
    up = A.derive_poc_assurance({"verified": True}, {"argv": ["x"], "scope": A.ENTRYPOINT},
                                is_web=False, is_tcp=False)
    assert up["standard"] == A.INPUT_REACHABLE
    # a "web" test the agent marks as an isolated harness → stays code_present
    down = A.derive_poc_assurance({"verified": True}, {"steps": [{"path": "/x"}], "scope": A.HARNESS},
                                  is_web=True, is_tcp=False)
    assert down["standard"] == A.CODE_PRESENT


def test_fuzz_assurance_is_code_present_dynamic():
    a = A.derive_fuzz_assurance()
    assert a["standard"] == A.CODE_PRESENT and a["method"] == A.DYNAMIC and "harness" in a["detail"]


# ── the finding records the triple in evidence.extra ────────────────────────────────────
def test_poc_finding_records_assurance_in_evidence():
    verification = {"verified": True, "detail": "body contains nonce", "nonce": "HEXGRAPH_PWNED_x",
                    "assurance": A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED,
                                             precondition_inferred=True)}
    f = _poc_finding({"steps": []}, verification, "handler", "dev", "command-injection")
    rec = f.evidence.extra["verification"]["assurance"]
    assert rec["standard"] == A.INPUT_REACHABLE and rec["precondition"] == A.UNAUTHENTICATED
    assert "input_reachable / dynamic / unauthenticated" in f.reasoning


# ── verify_poc attaches the engine-computed assurance (end-to-end, fake runner) ─────────
class _FakeRunner:
    def __init__(self, response):
        self.response = response
    def run_channel_probe(self, probe, *, channel, net_container=None, **k):
        return self.response


def test_verify_poc_attaches_assurance_web(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p = create_project(s, name="dev")
        surf = register_web_surface(s, p, "http://127.0.0.1:8080", name="dev")
        runner = _FakeRunner({"verified": True, "detail": "ok",
                              "steps": [{"status": 200, "body": "...HEXGRAPH_PWNED..."}]})
        spec = {"steps": [{"method": "POST", "path": "/HNAP1", "body": ";echo {{NONCE}};"}],
                "oracle": {"type": "body_contains", "value": "{{NONCE}}"}}
        out = verify_poc(s, p, surf, spec, runner=runner)
        assert out["verified"] is True
        a = out["assurance"]
        assert a["standard"] == A.INPUT_REACHABLE and a["method"] == A.DYNAMIC
        assert a["precondition"] == A.UNAUTHENTICATED  # single unauth step


# ── persist_finding stamps the FLOOR, never overwrites a stronger claim ─────────────────
def test_persist_finding_floors_static_vuln_and_preserves_stronger(hg_home):
    from conftest import fixture_path
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding as F

    with session_scope() as s:
        p = create_project(s, name="x")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="b")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        # 1. a static vuln finding with no assurance → floored to code_present/static
        f1 = F(title="t", severity="high", confidence="medium", category="memory-safety",
               summary="s", reasoning="r", evidence=Evidence(function="foo"))
        r1 = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f1,
                             finding_type="vulnerability")
        a1 = r1.evidence_json["extra"]["assurance"]
        assert a1["standard"] == A.CODE_PRESENT and a1["method"] == A.STATIC
        # 2. a recon finding makes no vuln claim → no assurance stamped
        f2 = F(title="t", severity="info", confidence="high", category="recon",
               summary="s", reasoning="r", evidence=Evidence())
        r2 = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f2,
                             finding_type="recon")
        assert A.assurance_of(r2.evidence_json) is None
        # 3. an agent-declared stronger assurance is PRESERVED (the floor never overwrites it)
        f3 = F(title="t", severity="high", confidence="medium", category="command-injection",
               summary="s", reasoning="r",
               evidence=Evidence(extra={"assurance": A.assurance(A.INPUT_REACHABLE, A.STATIC,
                                                                 A.UNAUTHENTICATED)}))
        r3 = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f3,
                             finding_type="vulnerability")
        assert r3.evidence_json["extra"]["assurance"]["standard"] == A.INPUT_REACHABLE
