"""Executable, verifiable PoC findings + finding-type classification. The real
sandbox run is env-gated; here a fake runner stands in for poc_probe so the nonce
substitution, oracle handling, policy gate, and finding wiring are tested offline."""

import json

import pytest

from hexgraph.db.models import Finding, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import classify_finding, persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.poc import execute_poc, verify_poc
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel
from hexgraph.policy import PolicyViolation
from hexgraph import settings as st

from conftest import fixture_path

SPEC = {"env": {"QUERY_STRING": "host=127.0.0.1;echo {{NONCE}}"},
        "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}


class FakeRunner:
    def __init__(self):
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None):
        self.calls.append({"probe": probe, "extra_args": extra_args, "requires_execution": requires_execution})
        spec = json.loads(extra_args[extra_args.index("--spec") + 1])
        # Simulate the sandbox: the injected `echo <nonce>` ran, so the nonce is in output.
        nonce_val = spec.get("oracle", {}).get("value", "")
        verified = bool(nonce_val) and nonce_val in spec["env"]["QUERY_STRING"]
        return {"tool": "poc_probe", "ran": True, "verified": verified, "exit_code": 0,
                "output": f"...{nonce_val}...", "detail": "output contains nonce"}


def _enable():
    st.update_settings({"features.poc.enabled": True})


def test_verify_poc_substitutes_nonce_and_gates(hg_home):
    with session_scope() as s:
        p = create_project(s, name="poc")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        # disabled → policy refuses
        with pytest.raises(PolicyViolation):
            verify_poc(s, p, t, SPEC, runner=FakeRunner())
        _enable()
        runner = FakeRunner()
        r = verify_poc(s, p, t, SPEC, runner=runner)
        assert r["verified"] is True and r["nonce"].startswith("HEXGRAPH_PWNED_")
        # the {{NONCE}} placeholder was replaced before running (unforgeable oracle)
        sent = runner.calls[0]["extra_args"]
        assert "{{NONCE}}" not in json.dumps(sent) and runner.calls[0]["requires_execution"] is True


def test_execute_poc_records_verified_finding(hg_home):
    _enable()
    with session_scope() as s:
        p = create_project(s, name="poc2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        task = create_task(s, project=p, target_id=t.id, type="poc",
                           params={"poc": SPEC, "function": "run_diagnostic"})
        n = execute_poc(s, p, t, task, runner=FakeRunner())
        assert n == 1
        f = s.query(Finding).filter(Finding.task_id == task.id).one()
        assert f.finding_type == "poc"
        v = f.evidence_json["extra"]["verification"]
        assert v["verified"] is True and "HEXGRAPH_PWNED_" in v["nonce"]
        assert f.severity == "critical"


def test_execute_poc_unverified_needs_triage(hg_home):
    _enable()

    class Neg(FakeRunner):
        def run_json_probe(self, *a, **k):
            return {"ran": True, "verified": False, "exit_code": 0, "output": "", "detail": "no match"}

    with session_scope() as s:
        p = create_project(s, name="poc3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        task = create_task(s, project=p, target_id=t.id, type="poc", params={"poc": SPEC})
        execute_poc(s, p, t, task, runner=Neg())
        assert task.status == TaskStatus.needs_triage


def test_finding_type_classification(hg_home):
    assert classify_finding("recon", "recon") == "recon"
    assert classify_finding("harness_generation", "other") == "harness"
    assert classify_finding("fuzzing", "memory-safety") == "fuzz_crash"
    assert classify_finding("poc", "command-injection") == "poc"
    assert classify_finding("static_analysis", "memory-safety") == "vulnerability"


def test_persist_finding_auto_classifies(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ft")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        hg = create_task(s, project=p, target_id=t.id, type="harness_generation")
        row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=hg.id, finding=FModel(
            title="h", severity="info", confidence="low", category="other", summary="s",
            reasoning="r", evidence=Evidence()))
        assert row.finding_type == "harness"


def test_is_tcp_requires_marker_and_port():
    """_is_tcp must require BOTH a tcp marker AND a port, so an incidental/stray `tcp`-looking
    field can't misroute a web/binary spec into the raw-TCP path (review #9)."""
    from hexgraph.engine.poc import _is_tcp

    assert _is_tcp({"transport": "tcp", "port": 1337}) is True
    assert _is_tcp({"tcp": {"port": 1337}}) is True
    # marker without a port → NOT tcp (can't misroute)
    assert _is_tcp({"transport": "tcp"}) is False
    assert _is_tcp({"tcp": {}}) is False
    assert _is_tcp({"tcp": True}) is False
    # a plain web/binary spec is never tcp
    assert _is_tcp({"steps": [{"method": "GET", "path": "/"}], "oracle": {}}) is False
    assert _is_tcp({"env": {}, "oracle": {}}) is False


def test_verify_poc_web_spec_routes_to_web_not_tcp(hg_home, monkeypatch):
    """A web_app target with a normal {steps, oracle} spec must hit the WEB path, never the
    raw-TCP path — even though both are network-tier (review #9)."""
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine import poc as poc_mod
    from hexgraph.engine.surfaces import register_web_surface

    st.update_settings({"features": {"network": {"enabled": True}}})
    web_calls, tcp_calls = [], []
    monkeypatch.setattr(poc_mod, "_verify_web_poc",
                        lambda *a, **k: web_calls.append(a) or {"verified": True, "detail": "web"})
    monkeypatch.setattr(poc_mod, "_verify_tcp_poc",
                        lambda *a, **k: tcp_calls.append(a) or {"verified": False, "detail": "tcp"})

    with session_scope() as s:
        p = create_project(s, name="web-route")
        t = register_web_surface(s, p, "http://192.168.0.1:8080", name="vr")
        spec = {"steps": [{"method": "GET", "path": "/admin/flag"}],
                "oracle": {"type": "body_contains", "value": "{{NONCE}}"}}
        out = verify_poc(s, p, t, spec, runner=FakeRunner())
        assert out["detail"] == "web"
        assert len(web_calls) == 1 and tcp_calls == []  # WEB path, not TCP


def test_verify_poc_binary_spec_with_incidental_tcp_field_still_gates(hg_home):
    """A binary target whose spec carries an incidental tcp-looking field (but no reachable
    port) must STILL hit the execution gate — not get misrouted to the network path and
    bypass assert_allows_execution (review #9)."""
    with session_scope() as s:
        p = create_project(s, name="bin-gate")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        # `transport:"tcp"` is incidental noise; no port → must NOT route to TCP, and the
        # exec gate (features.poc OFF) must raise rather than silently send it to the network.
        spec = {"transport": "tcp", "env": {"QUERY_STRING": "x"},
                "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}
        with pytest.raises(PolicyViolation):
            verify_poc(s, p, t, spec, runner=FakeRunner())


def test_capability_and_mcp_gate(hg_home):
    from hexgraph.engine.capabilities import capabilities_for
    from hexgraph.engine import mcp_tools

    assert "poc" not in capabilities_for("target", "executable")
    _enable()
    assert "poc" in capabilities_for("target", "executable")
    assert "finding_verify_poc" in {x["name"] for x in mcp_tools.catalog({"run"})}
