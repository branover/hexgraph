"""The analysis gate (C3): the whole-program per-call tools require a SAVED analysis for the active
persistent backend — they error → re_analyze on a warm miss instead of silently launching a cold
analysis (the behavior that cascaded an operator's incident). Since C1b, `analysis_state` is
backend-aware, so this gates BOTH headless Ghidra and radare2 (a warm r2 project miss also errors
→ re_analyze). Targeted/store-reading tools are NOT gated. Only a no-persistent-slot backend
(Ghidra bridge) / Docker-down / no-artifact ⇒ `analysis_state` reports `unavailable` ⇒ not gated.
"""

import pytest

from hexgraph.agent import agent_tools as AT
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="gate")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    return ToolContext(session=s, project=p, target=t)


def _fake_state(monkeypatch, state):
    """Force analysis_state (the gate's sole input) to a fixed lifecycle state. Accepts **kw so it
    works for BOTH callers — _analysis_gate (project, target) and analysis_lead (…, runner=…)."""
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target, **kw: {"state": state, "detail": f"({state})"})


# --- the gate helper ----------------------------------------------------------

def test_gate_blocks_on_no_saved_analysis(hg_home, monkeypatch):
    _fake_state(monkeypatch, "none")
    with session_scope() as s:
        gate = AT._analysis_gate(_ctx(s))
        assert gate is not None
        assert "re_analyze" in gate and "No saved analysis" in gate


@pytest.mark.parametrize("state", ["running", "failed"])
def test_gate_blocks_on_running_or_failed(hg_home, monkeypatch, state):
    _fake_state(monkeypatch, state)
    with session_scope() as s:
        assert "re_analyze" in AT._analysis_gate(_ctx(s))


@pytest.mark.parametrize("state", ["analyzed", "unavailable"])
def test_gate_proceeds_when_analyzed_or_unavailable(hg_home, monkeypatch, state):
    """analyzed ⇒ warm, proceed fast; unavailable ⇒ no persistent-slot backend (Ghidra bridge) /
    Docker down / no artifact ⇒ behave as before (not gated)."""
    _fake_state(monkeypatch, state)
    with session_scope() as s:
        assert AT._analysis_gate(_ctx(s)) is None


def test_gate_is_best_effort_on_error(hg_home, monkeypatch):
    """A gate hiccup must never block a tool that could otherwise run."""
    def _boom(project, target):
        raise RuntimeError("state check failed")

    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state", _boom)
    with session_scope() as s:
        assert AT._analysis_gate(_ctx(s)) is None


# --- integration through run_tool --------------------------------------------

def test_run_tool_gates_decompile_on_miss(hg_home, monkeypatch):
    """A gated tool short-circuits to the gate error on a warm miss — the decompiler is NEVER
    reached (it explodes if called)."""
    _fake_state(monkeypatch, "none")

    def _explode(*a, **k):
        raise AssertionError("must not decompile when gated")

    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_decompiler", _explode)
    with session_scope() as s:
        out = run_tool(_ctx(s), "decompile_function", {"function": "cgi_handler"})
        assert "re_analyze" in out


def test_run_tool_does_not_gate_targeted_disassemble(hg_home, monkeypatch):
    """Targeted disassembly needs no whole-program analysis → NOT gated: it runs even with the gate
    reporting `none` (the gate isn't consulted for it)."""
    _fake_state(monkeypatch, "none")
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)

    class _FakeR2:
        def disassemble_func(self, artifact, subject):
            return {"tool": "decompile_probe", "mode": "disasm",
                    "focus": {"name": subject, "address": "0x401000", "disasm_mode": "function",
                              "disasm": "0x401000  nop", "callees": []}}

    monkeypatch.setattr("hexgraph.sandbox.decompiler.R2Decompiler", _FakeR2)
    with session_scope() as s:
        out = run_tool(_ctx(s), "disassemble", {"address": "0x401000"})
        assert "nop" in out and "re_analyze" not in out


def test_gated_set_is_exactly_the_whole_program_tools():
    g = AT._ANALYSIS_GATED_TOOLS
    for t in ("decompile_function", "decompile_at", "list_functions",
              "xrefs", "call_graph", "function_xrefs", "data_xrefs",
              "run_script"):  # re_script is warm-only → gated so a warm miss returns the re_analyze lead
        assert t in g
    for t in ("disassemble", "disassemble_range", "search_decompiled", "reanalyze"):
        assert t not in g  # targeted/raw/store-reading/explicit — not gated


# --- analysis_lead: the host gate for tools that BYPASS run_tool (recover_constant, taint task) ---

def test_analysis_lead_points_at_re_analyze_on_cold_states(hg_home, monkeypatch):
    """analysis_lead is the single host-side gate for the analysis-needing paths that DON'T go
    through run_tool's gate (recover_constant, the static_analysis taint task). On a cold/unfinished
    slot it returns a re_analyze lead; those callers surface it instead of cold-analyzing."""
    from hexgraph.engine.re import analysis as A

    with session_scope() as s:
        p = create_project(s, name="lead")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        for state in ("none", "running", "failed"):
            _fake_state(monkeypatch, state)
            lead = A.analysis_lead(p, t)
            assert lead and "re_analyze" in lead and "warm-only" in lead


@pytest.mark.parametrize("state", ["analyzed", "unavailable"])
def test_analysis_lead_is_none_when_analyzed_or_unavailable(hg_home, monkeypatch, state):
    """analyzed ⇒ proceed warm; unavailable (Ghidra-bridge / Docker down / no artifact) ⇒ those
    paths serve warm anyway or can't be gated ⇒ no lead (never blocks a runnable tool)."""
    from hexgraph.engine.re import analysis as A

    _fake_state(monkeypatch, state)
    with session_scope() as s:
        p = create_project(s, name="lead2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        assert A.analysis_lead(p, t) is None


def test_analysis_lead_is_best_effort_on_error(hg_home, monkeypatch):
    """A gate hiccup returns None (never blocks a tool that could run) — mirrors _analysis_gate."""
    from hexgraph.engine.re import analysis as A

    def _boom(project, target, **kw):
        raise RuntimeError("state check failed")

    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state", _boom)
    with session_scope() as s:
        p = create_project(s, name="lead3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        assert A.analysis_lead(p, t) is None


def test_recover_constant_gates_on_cold_analysis(hg_home, monkeypatch):
    """recover_constant (emulate) bypasses run_tool's gate, so it gates on analysis_lead directly:
    a cold target returns skipped=needs_analysis + a re_analyze lead and NEVER emulates."""
    from hexgraph.engine.re.emulation import emulate_constant
    from hexgraph.sandbox.decompiler import GhidraDecompiler
    from hexgraph import settings as st

    st.update_settings({"features.emulation.enabled": True,
                        "features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    _fake_state(monkeypatch, "none")

    def _explode(self, *a, **k):
        raise AssertionError("must not emulate when the analysis gate is cold")

    monkeypatch.setattr(GhidraDecompiler, "run_emulate", _explode)
    with session_scope() as s:
        p = create_project(s, name="rc-gate")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = emulate_constant(s, p, t, function="derive_key")
        assert out.get("skipped") == "needs_analysis"
        assert "re_analyze" in (out.get("error") or "")


def test_taint_task_gates_on_cold_analysis(hg_home, monkeypatch):
    """analyze_taint (the static_analysis task path) also bypasses run_tool's gate — a cold target
    returns availability False with a re_analyze lead and NEVER runs the Ghidra taint pass."""
    from hexgraph.engine.re import taint as T
    from hexgraph import settings as st

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    _fake_state(monkeypatch, "none")

    class _ExplodingTaint(T.GhidraTaintAnalyzer):
        def analyze(self, artifact, *, project=None):
            raise AssertionError("must not run taint when the analysis gate is cold")

    with session_scope() as s:
        p = create_project(s, name="taint-gate")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = T.analyze_taint(s, p, t, analyzer=_ExplodingTaint())
        assert out["available"] is False
        assert "re_analyze" in (out.get("error") or "")


def test_r2_project_mount_degrades_on_remote_executor(hg_home, monkeypatch):
    """_r2_project_mount returns None when the active executor can't bind-mount the persistent slot
    (the remote executor — run_probe there REFUSES a project_mount). Without this the r2 xref/search
    calls would pass a mount and hard-error on remote; degrading to None lets them fall back (index
    modes → re_analyze lead; search → raw scan) exactly as on a cold local slot."""
    class _Remoteish:
        supports_project_mount = False

    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: _Remoteish())
    with session_scope() as s:
        assert AT._r2_project_mount(_ctx(s)) is None


# --- content_hash memoization (perf enabler for the gate) ---------------------

def test_content_hash_is_memoized_and_invalidates(tmp_path):
    from hexgraph.engine.re import ghidra_project as gp

    gp._HASH_CACHE.clear()
    f = tmp_path / "a"
    f.write_bytes(b"hello")
    h1 = gp.content_hash(str(f))
    stt = f.stat()
    assert (str(f), stt.st_size, stt.st_mtime_ns) in gp._HASH_CACHE   # cached on first call
    assert gp.content_hash(str(f)) == h1                              # served from cache
    f.write_bytes(b"different content, different size")               # size/mtime change
    assert gp.content_hash(str(f)) != h1                              # cache miss → re-hashed
