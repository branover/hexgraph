"""Phase 4 PR2 — the deterministic static-analysis core + mock scoping (design §6).

The core turns grounded taint flows into findings derived from the real bytes; the mock
scoping fix makes `static_analysis` with no explicit scenario fabricate nothing, so the
grounded results stand alone instead of a canned, binary-agnostic vuln.
"""

from hexgraph.db.models import Finding
from hexgraph.db.session import session_scope
from hexgraph.engine.re import taint as T
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.re.static_core import _grounded_finding, run_static_core
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync
from hexgraph.llm.base import LLMRequest
from hexgraph.llm.mock import MockLLMBackend

from conftest import fixture_path

# netcfgd (command-exec, partial sanitizer) + keyserv (overflow, no sanitizer) shaped flows.
# Both use a SELF-CONTAINED source (libc_input — the untrusted bytes enter via a buffer-filling
# input call within the same function), so the intra-procedural pass sees the WHOLE flow → high
# confidence (capped to medium only by the partial sanitizer on the first). A param-sourced or
# unattributed flow is deliberately NOT high — see the dedicated calibration tests below.
_FAKE_FLOWS = [
    {"function": "run_probe", "function_addr": "0x1014a4",
     "source": {"kind": "libc_input", "detail": "recv"},
     "sink": {"func": "popen", "category": "command_exec",
              "call_addr": "0x10158b", "arg_index": 1}, "sanitized": ["sanitize"]},
    {"function": "register_license", "function_addr": "0x101252",
     "source": {"kind": "libc_input", "detail": "fgets"},
     "sink": {"func": "strcpy", "category": "buffer_overflow",
              "call_addr": "0x1012b8", "arg_index": 2}, "sanitized": []},
]


class _FakeAnalyzer(T.TaintAnalyzer):
    name = "fake"
    available = True

    def analyze(self, artifact, *, project=None):
        return {"available": True, "flows": _FAKE_FLOWS, "analyzed": 2, "error": None}


# ── mock scoping: static_analysis with no explicit scenario fabricates nothing ───────

def test_resolve_scenario_static_analysis_defaults_to_no_findings(hg_home):
    m = MockLLMBackend()
    assert m._resolve_scenario(LLMRequest(task_type="static_analysis", task_id="t1")) == "no_findings"
    # ... but an explicit scenario still wins (the demo + fidelity tests rely on this).
    assert m._resolve_scenario(
        LLMRequest(task_type="static_analysis", task_id="t1",
                   mock_scenario="critical_overflow")) == "critical_overflow"


def test_resolve_scenario_env_still_wins(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_MOCK_SCENARIO", "agentic_overflow")
    m = MockLLMBackend()
    assert m._resolve_scenario(LLMRequest(task_type="static_analysis", task_id="t1")) == "agentic_overflow"


# ── _grounded_finding: schema-shaped findings from real flows ────────────────────────

def test_grounded_finding_command_injection_flags_partial_sanitizer():
    f = _grounded_finding(_FAKE_FLOWS[0])
    assert f.category == "command-injection" and f.severity == "high"
    assert f.confidence == "medium"  # an incomplete sanitizer is present → don't over-claim
    assert "popen" in f.title and f.evidence.sink == "popen"
    assert f.evidence.extra["grounded"] is True
    assert f.evidence.extra["taint"]["sanitized"] == ["sanitize"]


def test_grounded_finding_overflow_is_high_confidence():
    # A self-contained (libc_input) overflow with no sanitizer — the strongest grounded flow → high.
    f = _grounded_finding(_FAKE_FLOWS[1])
    assert f.category == "memory-safety" and f.confidence == "high"
    assert "strcpy" in f.title and f.evidence.function == "register_license"
    assert f.evidence.extra["taint"]["input_attributed"] is True
    assert f.evidence.extra["taint"]["source_kind"] == "libc_input"


def test_grounded_finding_skips_unsurfaced_category():
    assert _grounded_finding({"function": "x", "function_addr": "0x1",
                              "sink": {"func": "y", "category": "weird"}}) is None


# ── confidence calibration: the deterministic core must NOT over-promote ──────────────────

def test_grounded_finding_self_contained_source_is_high():
    # call_return (getenv) is a self-contained source — the whole input→sink flow lives in one
    # function, so the intra-procedural taint pass sees it end to end → high confidence.
    f = _grounded_finding({"function": "h", "function_addr": "0x1",
                           "source": {"kind": "call_return", "detail": "getenv"},
                           "sink": {"func": "system", "category": "command_exec",
                                    "call_addr": "0x2", "arg_index": 1}, "sanitized": []})
    assert f.confidence == "high"
    assert f.evidence.extra["taint"]["input_attributed"] is True


def test_grounded_finding_param_source_is_only_medium():
    # A PARAMETER source is intra-procedural-only: the flow holds only if the param is actually
    # attacker-controlled, which reachability across the call graph (not this pass) establishes.
    # It must NOT be auto-promoted to high — medium until reachability argues it.
    f = _grounded_finding({"function": "register_license", "function_addr": "0x101252",
                           "source": {"kind": "param", "detail": "key"},
                           "sink": {"func": "strcpy", "category": "buffer_overflow",
                                    "call_addr": "0x1012b8", "arg_index": 2}, "sanitized": []})
    assert f.confidence == "medium", "a param-sourced (intra-procedural-only) flow must not be high"
    assert f.evidence.extra["taint"]["input_attributed"] is True
    assert f.evidence.extra["taint"]["source_kind"] == "param"
    assert "reachability" in f.reasoning.lower()


def test_grounded_finding_unattributed_source_is_low_and_tagged():
    # An UNATTRIBUTED source (kind "unknown" / missing) is the over-broad / input-independent case:
    # taint reached the sink but could not be tied to a real input boundary. The prior code
    # promoted this high/high — a confident false positive. It must now be low, tagged distinctly,
    # but NOT dropped (still surfaced for triage).
    f = _grounded_finding({"function": "h", "function_addr": "0x1",
                           "source": {"kind": "unknown"},
                           "sink": {"func": "system", "category": "command_exec",
                                    "call_addr": "0x2", "arg_index": 1}, "sanitized": []})
    assert f is not None, "an unattributed flow is downgraded, not dropped"
    assert f.confidence == "low", "an unattributed (input-independent) flow must not be high/medium"
    assert f.evidence.extra["taint"]["input_attributed"] is False
    assert "input-independent" in f.reasoning.lower() or "unattributed" in f.reasoning.lower()


def test_grounded_finding_missing_source_is_low():
    # A flow with no source dict at all is treated as unattributed → low (never high).
    f = _grounded_finding({"function": "h", "function_addr": "0x1",
                           "sink": {"func": "system", "category": "command_exec",
                                    "call_addr": "0x2", "arg_index": 1}})
    assert f is not None and f.confidence == "low"
    assert f.evidence.extra["taint"]["input_attributed"] is False


def test_grounded_finding_sanitizer_never_raises_a_low_flow():
    # A sanitizer caps a high flow to medium, but must NEVER raise a sub-medium (low) flow — an
    # unattributed flow with a sanitizer-looking call on the path stays low, not medium.
    f = _grounded_finding({"function": "h", "function_addr": "0x1",
                           "source": {"kind": "unknown"},
                           "sink": {"func": "system", "category": "command_exec",
                                    "call_addr": "0x2", "arg_index": 1}, "sanitized": ["escape"]})
    assert f.confidence == "low"


# ── run_static_core: persists grounded findings + wires sink edges ───────────────────

def test_run_static_core_persists_grounded_findings(hg_home, monkeypatch):
    monkeypatch.setattr(T, "get_taint_analyzer", lambda: _FakeAnalyzer())
    with session_scope() as s:
        p = create_project(s, name="sc")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        ids = run_static_core(s, p, t, task=task)
        assert len(ids) == 2
        fs = s.query(Finding).filter(Finding.id.in_(ids)).all()
        cats = {f.category for f in fs}
        assert cats == {"command-injection", "memory-safety"}
        assert all((f.evidence_json or {}).get("extra", {}).get("grounded") for f in fs)


def test_run_static_core_no_findings_when_unavailable(hg_home, monkeypatch):
    monkeypatch.setattr(T, "get_taint_analyzer", lambda: T.NullTaintAnalyzer())
    with session_scope() as s:
        p = create_project(s, name="sc2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        assert run_static_core(s, p, t, task=task) == []


# ── integration: a static_analysis task emits the grounded findings AND the mock
#    fabricates nothing (no explicit scenario) ──────────────────────────────────────

def test_static_analysis_task_grounded_only_no_fabrication(hg_home, monkeypatch):
    monkeypatch.setattr(T, "get_taint_analyzer", lambda: _FakeAnalyzer())
    with session_scope() as s:
        p = create_project(s, name="int")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        # NO mock_scenario → the LLM synthesis layer must contribute nothing; only the
        # deterministic core's grounded findings remain.
        task = create_task(s, project=p, target_id=t.id, type="static_analysis", backend="mock")
        tid = task.id

    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        fs = s.query(Finding).filter(Finding.task_id == tid).all()
        assert len(fs) == 2, [f.title for f in fs]
        titles = " ".join(f.title for f in fs)
        assert "popen" in titles and "strcpy" in titles
        # The binary-agnostic canned fabrication is GONE.
        assert all("cgi_handler" not in (f.title or "") for f in fs)
        assert all((f.evidence_json or {}).get("extra", {}).get("grounded") for f in fs)
