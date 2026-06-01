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
