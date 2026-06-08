"""The fuzzing task (dynamic, opt-in). Logic-level: a fake executor returns
canned fuzz_probe output; the real clang/libFuzzer run is env-gated like Ghidra.
Covers the policy gate, crash→finding mapping, harness resolution, and the ASan
parser."""

import pytest

from hexgraph.db.models import Annotation, Finding, Node, Task, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.fuzzing import execute_fuzzing, resolve_harness, resolve_target_sources
from hexgraph.engine.targets.ingest import create_project, ingest_file
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


# Canned ASan reports (trimmed to the salient lines) for the normalized-kind check. The
# `sanitizer` label on a fuzz_crash finding is exactly parse_asan(...)["kind"], so these
# pin that the captured type is correct — especially the double-free case whose ERROR line
# reads "attempting double-free …" (where a naive first-token capture yields "attempting").
_HEAP_UAF = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
    "READ of size 4 at 0x602000000010 thread T0\n"
    "    #0 0x4f in use_it /src/uaf.c:12:5\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free /src/uaf.c:12:5 in use_it")
_HEAP_BOF = (
    "==2==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000020\n"
    "WRITE of size 8 at 0x602000000020 thread T0\n"
    "    #0 0x5a in copy /src/bof.c:20:3\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow /src/bof.c:20:3 in copy")
_STACK_BOF = (
    "==3==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd...\n"
    "WRITE of size 16 at 0x7ffd... thread T0\n"
    "    #0 0x6b in parse /src/stack.c:8:1\n"
    "SUMMARY: AddressSanitizer: stack-buffer-overflow /src/stack.c:8:1 in parse")
# A double-free's ERROR line uses the verb "attempting" before the type.
_DOUBLE_FREE = (
    "==4==ERROR: AddressSanitizer: attempting double-free on address 0x602000000030\n"
    "    #0 0x7c in free_twice /src/df.c:30:5\n"
    "SUMMARY: AddressSanitizer: double-free /src/df.c:30:5 in free_twice")
# Same double-free, but with NO SUMMARY line — must still normalize via the ERROR phrasing.
_DOUBLE_FREE_NO_SUMMARY = (
    "==5==ERROR: AddressSanitizer: attempting double-free on address 0x602000000040\n"
    "    #0 0x8d in df2 /src/df2.c:7:3")
# A bare SEGV with no SUMMARY type at all.
_BARE_SEGV = (
    "==6==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x4ee...)\n"
    "    #0 0x9e in deref /src/segv.c:5:9")


@pytest.mark.parametrize("report,expected_kind", [
    (_HEAP_UAF, "heap-use-after-free"),
    (_HEAP_BOF, "heap-buffer-overflow"),
    (_STACK_BOF, "stack-buffer-overflow"),
    (_DOUBLE_FREE, "double-free"),
    (_DOUBLE_FREE_NO_SUMMARY, "double-free"),
])
def test_parse_asan_normalizes_kind(report, expected_kind):
    assert parse_asan(report)["kind"] == expected_kind


def test_parse_asan_double_free_not_attempting():
    """Regression: the 'attempting double-free' ERROR phrasing must NOT label the kind
    'attempting' (the old first-token capture bug → wrong `sanitizer` field)."""
    assert parse_asan(_DOUBLE_FREE)["kind"] != "attempting"
    assert parse_asan(_DOUBLE_FREE_NO_SUMMARY)["kind"] != "attempting"


def test_parse_asan_bare_segv():
    """A SEGV with no SUMMARY type still classifies as an ASan SEGV (not the literal
    'crash' fallback), so the exploitability classifier and label are meaningful."""
    info = parse_asan(_BARE_SEGV)
    assert info["kind"].lower() == "segv"


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


def test_crash_finding_records_fuzz_extra(hg_home):
    """The new evidence.extra.fuzz envelope rides every crash finding (frozen schema
    untouched): dedup_key, exploitability, minimized reproducer, coverage flag."""
    _enable_fuzzing()
    payload = {"compiled": True, "ran": True, "coverage_instrumented": False, "crashes": [
        {"kind": "heap-buffer-overflow", "function": "cgi_handler", "summary": "SUMMARY: ... overflow",
         "reproducer_sha256": "ab12", "reproducer_size": 24, "dedup_key": "deadbeef" * 8,
         "dupe_count": 3, "exploitability": {"rating": "likely_exploitable", "access": "WRITE"},
         "minimized_reproducer_sha256": "f00d" * 16, "minimized_reproducer_size": 8,
         "coverage_instrumented": False},
    ]}
    with session_scope() as s:
        p = create_project(s, name="fx")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_task(s, p, t)
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        n = execute_fuzzing(s, p, t, task, FakeRunner(payload))
        assert n == 1
        f = s.query(Finding).filter(Finding.task_id == task.id).one()
        fz = f.evidence_json["extra"]["fuzz"]
        assert fz["dedup_key"] == "deadbeef" * 8
        assert fz["exploitability"]["rating"] == "likely_exploitable"
        assert fz["minimized_reproducer_sha"] == "f00d" * 16
        assert fz["coverage_instrumented"] is False
        assert fz["dupe_count"] == 3
        # the finding's reproducer points at the MINIMIZED input when present
        assert f.evidence_json["reproducer"] == "f00d" * 16
        # a coverage-blind run is disclosed in the reasoning, never overstated
        assert "coverage-blind" in (f.reasoning or "")


def test_coverage_instrumented_when_source_mounted(hg_home):
    """When target sources are present they are mounted as --target-source (coverage-
    guided), NOT --target-lib, and the finding reports coverage_instrumented=true."""
    import os, tempfile
    _enable_fuzzing()
    fd, src = tempfile.mkstemp(suffix=".c", prefix="tgt-")
    os.write(fd, b"int add(int a,int b){return a+b;}\n"); os.close(fd)
    payload = {"compiled": True, "ran": True, "coverage_instrumented": True, "crashes": [
        {"kind": "stack-buffer-overflow", "function": "add", "summary": "SUMMARY: ... stack",
         "reproducer_sha256": "11", "reproducer_size": 4, "dedup_key": "a" * 64, "dupe_count": 0,
         "exploitability": {"rating": "likely_exploitable", "access": "WRITE"},
         "coverage_instrumented": True},
    ]}
    try:
        with session_scope() as s:
            p = create_project(s, name="fcov")
            t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
            t.metadata_json = {"fuzz_target_sources": [src]}
            _harness_task(s, p, t)
            task = create_task(s, project=p, target_id=t.id, type="fuzzing")
            runner = FakeRunner(payload)
            n = execute_fuzzing(s, p, t, task, runner)
            assert n == 1
            args = runner.calls[0]["extra_args"]
            assert any(a.startswith("--target-source=") for a in args)
            assert not any(a.startswith("--target-lib=") for a in args)
            f = s.query(Finding).filter(Finding.task_id == task.id).one()
            assert f.evidence_json["extra"]["fuzz"]["coverage_instrumented"] is True
            assert "coverage-blind" not in (f.reasoning or "")
    finally:
        os.unlink(src)


def test_seed_corpus_mounted(hg_home):
    """A `seeds` task param mounts each existing seed file and passes --seed= to the probe."""
    import os, tempfile
    _enable_fuzzing()
    fd, s0 = tempfile.mkstemp(prefix="seed-"); os.write(fd, b"FUZZ"); os.close(fd)
    payload = {"compiled": True, "ran": True, "coverage_instrumented": False, "crashes": []}
    try:
        with session_scope() as s:
            p = create_project(s, name="seed")
            t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
            _harness_task(s, p, t)
            task = create_task(s, project=p, target_id=t.id, type="fuzzing",
                               params={"seeds": [s0, "/missing/seed"]})
            runner = FakeRunner(payload)
            execute_fuzzing(s, p, t, task, runner)
            args = runner.calls[0]["extra_args"]
            mounts = runner.calls[0]["mounts"] or []
            assert sum(a.startswith("--seed=") for a in args) == 1  # only the existing seed
            assert any(host == s0 for host, _ in mounts)
    finally:
        os.unlink(s0)


def test_resolve_target_sources(hg_home):
    import os, tempfile
    fd, real = tempfile.mkstemp(suffix=".c"); os.close(fd)
    try:
        with session_scope() as s:
            p = create_project(s, name="rts")
            t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
            task = create_task(s, project=p, target_id=t.id, type="fuzzing",
                               params={"target_sources": [real, "/does/not/exist.c"]})
            # only the existing file survives; the bogus path is dropped (no overstating)
            assert resolve_target_sources(t, task) == [real]
    finally:
        os.unlink(real)


def test_capabilities_gate_on_setting(hg_home):
    from hexgraph.engine.capabilities import capabilities_for

    assert "fuzzing" not in capabilities_for("node", "function")
    _enable_fuzzing()
    assert "fuzzing" in capabilities_for("node", "function")
    assert "fuzzing" in capabilities_for("target", "executable")
