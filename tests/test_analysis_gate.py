"""The analysis gate (C3): the whole-program per-call tools require a SAVED analysis when headless
Ghidra is active — they error → re_analyze on a warm miss instead of silently launching a cold
analysis (the behavior that cascaded an operator's incident). Targeted/store-reading tools are NOT
gated. radare2 / Docker-down / no-artifact ⇒ `analysis_state` reports `unavailable` ⇒ not gated
(unchanged behavior).
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
    """Force analysis_state (the gate's sole input) to a fixed lifecycle state."""
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": state, "detail": f"({state})"})


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
    """analyzed ⇒ warm, proceed fast; unavailable ⇒ Ghidra off / Docker down / no artifact ⇒
    behave as before (radare2 backend is never gated)."""
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
              "xrefs", "call_graph", "function_xrefs", "data_xrefs"):
        assert t in g
    for t in ("disassemble", "disassemble_range", "search_decompiled", "reanalyze"):
        assert t not in g  # targeted/raw/store-reading/explicit — not gated


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
