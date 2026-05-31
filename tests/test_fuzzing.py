"""The fuzzing task (dynamic, opt-in). Logic-level: a fake executor returns
canned fuzz_probe output; the real clang/libFuzzer run is env-gated like Ghidra.
Covers the policy gate, crash→finding mapping, harness resolution, and the ASan
parser."""

import pytest

from hexgraph.db.models import Annotation, Finding, Node, Task, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.fuzzing import execute_fuzzing, resolve_harness
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel
from hexgraph.policy import PolicyViolation
from hexgraph.sandbox.probes.fuzz_probe import parse_asan
from hexgraph import settings as st

from conftest import fixture_path

HARNESS = "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"


class FakeRunner:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None):
        self.calls.append({"probe": probe, "extra_args": extra_args,
                           "requires_execution": requires_execution, "mounts": extra_ro_mounts})
        return self.payload

    def run_probe(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


def _enable_fuzzing():
    st.update_settings({"features.fuzzing.enabled": True})


def _harness_task(s, p, t):
    """Create a harness_generation finding so resolve_harness finds source."""
    hg = create_task(s, project=p, target_id=t.id, type="harness_generation")
    persist_finding(s, project_id=p.id, target_id=t.id, task_id=hg.id, finding=FModel(
        title="harness", severity="info", confidence="low", category="other",
        summary="s", reasoning="r",
        evidence=Evidence(function="cgi_handler", decompiled_snippet=HARNESS)))
    return hg


def test_parse_asan_classifies():
    rpt = ("==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
           "    #0 0x49 in cgi_handler /src/httpd.c:42\n"
           "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/httpd.c:42 in cgi_handler")
    info = parse_asan(rpt)
    assert info["kind"] == "heap-buffer-overflow" and info["function"] == "cgi_handler"
    assert "SUMMARY" in info["summary"]


def test_policy_blocks_when_disabled(hg_home):
    with session_scope() as s:
        p = create_project(s, name="f")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_task(s, p, t)
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        with pytest.raises(PolicyViolation):
            execute_fuzzing(s, p, t, task, FakeRunner({"compiled": True, "crashes": []}))


def test_crashes_become_findings(hg_home):
    _enable_fuzzing()
    payload = {"compiled": True, "ran": True, "executions": 9000, "crashes": [
        {"kind": "heap-buffer-overflow", "function": "cgi_handler", "summary": "SUMMARY: ... overflow",
         "reproducer_sha256": "ab12", "reproducer_size": 24},
        {"kind": "stack-buffer-overflow", "function": "parse", "summary": "SUMMARY: ... stack",
         "reproducer_sha256": "cd34", "reproducer_size": 12},
    ]}
    with session_scope() as s:
        p = create_project(s, name="f2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_task(s, p, t)
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        runner = FakeRunner(payload)
        n = execute_fuzzing(s, p, t, task, runner)
        assert n == 2
        assert runner.calls[0]["requires_execution"] is True  # dynamic gate engaged
        fs = s.query(Finding).filter(Finding.task_id == task.id).all()
        sev = {f.title: f.severity for f in fs}
        assert any("heap-buffer-overflow" in tl and sv == "critical" for tl, sv in sev.items())
        # crash on cgi_handler materialized a function node + an auto-annotation
        node = s.query(Node).filter(Node.fq_name == "cgi_handler").one()
        assert s.query(Annotation).filter(Annotation.node_id == node.id).count() >= 1
        # reproducer hash recorded
        f0 = [f for f in fs if "cgi_handler" in f.title][0]
        assert f0.evidence_json["reproducer"] == "ab12"


def test_no_harness_raises(hg_home):
    _enable_fuzzing()
    with session_scope() as s:
        p = create_project(s, name="f3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        with pytest.raises(ValueError):
            execute_fuzzing(s, p, t, task, FakeRunner({"compiled": True, "crashes": []}))


def test_compile_failure_sets_needs_triage(hg_home):
    _enable_fuzzing()
    with session_scope() as s:
        p = create_project(s, name="f4")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_task(s, p, t)
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        n = execute_fuzzing(s, p, t, task, FakeRunner({"compiled": False, "stderr": "undefined symbol"}))
        assert n == 0 and task.status == TaskStatus.needs_triage


def test_resolve_harness_from_latest_generation(hg_home):
    _enable_fuzzing()
    with session_scope() as s:
        p = create_project(s, name="f5")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_task(s, p, t)
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        source, fid, fn = resolve_harness(s, t, task)
        assert source == HARNESS and fn == "cgi_handler" and fid is not None


def test_capabilities_gate_on_setting(hg_home):
    from hexgraph.engine.capabilities import capabilities_for

    assert "fuzzing" not in capabilities_for("node", "function")
    _enable_fuzzing()
    assert "fuzzing" in capabilities_for("node", "function")
    assert "fuzzing" in capabilities_for("target", "executable")
