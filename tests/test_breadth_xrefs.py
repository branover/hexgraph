"""Phase 2 PR2 — breadth verbs: call_graph + bidirectional/data xrefs (design-re-tooling.md §7).

Engine-layer coverage with a faked xrefs probe (offline, no Docker — the curation/observation
contract, not the sandboxed radare2), plus the call-graph self-wiring property (recording a
call_graph Observation draws `calls` edges among ALREADY-curated functions, both-endpoints-safe,
and creates no new nodes), the rooted-BFS helper, and the probe's mode/injection-safety helpers.
"""

import json
import shutil
import subprocess

import pytest

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent import agent_tools as AT
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node

from conftest import SANDBOX_READY, fixture_path


def _ctx(s):
    p = create_project(s, name="breadth")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


class _FakeExec:
    """Returns a fixed probe result and records how the probe was invoked."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run_json_probe(self, probe, path, extra_args=None, **kw):
        self.calls.append((probe, list(extra_args or [])))
        return self.result


def _wire(monkeypatch, result):
    fake = _FakeExec(result)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


# --- function_xrefs: callers + callees, a QUERY ------------------------------

def test_function_xrefs_records_observation_and_mutates_no_graph(hg_home, monkeypatch):
    result = {"tool": "xrefs_probe", "mode": "function", "subject": "cgi_handler",
              "callers": [{"caller": "main", "caller_addr": "0x400100", "at": "0x400120"}],
              "callees": [{"name": "system", "addr": "0x400500"}],
              "total_callers": 1, "total_callees": 1}
    fake = _wire(monkeypatch, result)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = run_tool(ctx, "function_xrefs", {"function": "cgi_handler"})
        assert "main" in out and "system" in out and "callers" in out and "callees" in out
        # the probe was invoked in function mode
        assert fake.calls[-1] == ("xrefs_probe.py", ["cgi_handler", "--mode", "function"])
        # QUERY: zero graph mutation
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "function_xrefs").all()
        assert len(obs) == 1 and obs[0].content_hash == "abc123"


def test_function_xrefs_requires_function(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "function_xrefs", {})


def test_function_xrefs_falls_back_to_recon_substrate_when_probe_empty(hg_home, monkeypatch):
    """The r2 xrefs probe can come up empty (function absent from r2's inventory, or it found
    no callers/callees) on a binary recon already mapped with Ghidra. function_xrefs then derives
    BOTH directions from the program call graph recon in the Observation substrate (the same
    fallback call_graph uses) instead of a false `(none)/(none)`."""
    # An empty probe result both ways.
    _wire(monkeypatch, {"tool": "xrefs_probe", "mode": "function", "subject": "parse",
                        "callers": [], "callees": [], "total_callers": 0, "total_callees": 0})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _seed_recon_call_graph(s, p, t)  # main → {parse, dispatch}; parse → helper
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = run_tool(ctx, "function_xrefs", {"function": "parse"})
        # caller (main, who calls parse) AND callee (helper, what parse calls) both derived.
        assert "main" in out and "helper" in out
        assert "recon substrate" in out          # the source is labelled honestly
        assert "(none)" not in out               # NOT the false empty neighbourhood
        # QUERY: no graph mutation.
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb


def test_function_xrefs_recon_fallback_normalizes_symbol_names(hg_home, monkeypatch):
    """The fallback matches by NORMALIZED name so a `sym.`-prefixed recon entry and a bare
    requested name resolve to one identity (normalize_symbol_name strips the namespace)."""
    from hexgraph.engine import observations as O

    _wire(monkeypatch, {"tool": "xrefs_probe", "mode": "function", "callers": [], "callees": [],
                        "total_callers": 0, "total_callees": 0})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="ghidra-enrich", tool="enrich_recon",
            args={}, result_kind="call_graph",
            payload={"functions": [{"name": "sym.main", "callees": ["sym.parse"]}]},
            summary="1 call edge", content_hash="abc123")
        out = run_tool(ctx, "function_xrefs", {"function": "parse"})  # bare name
        assert "sym.main" in out                 # caller resolved across the sym. prefix
        assert "recon substrate" in out


def test_function_xrefs_prefers_probe_over_recon_substrate(hg_home, monkeypatch):
    """When the probe DOES return a neighbourhood, it wins — recon is only the fallback."""
    _wire(monkeypatch, {"tool": "xrefs_probe", "mode": "function", "subject": "cgi_handler",
                        "callers": [{"caller": "router", "caller_addr": "0x400100",
                                     "at": "0x400120"}],
                        "callees": [{"name": "system", "addr": "0x400500"}],
                        "total_callers": 1, "total_callees": 1})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _seed_recon_call_graph(s, p, t)
        out = run_tool(ctx, "function_xrefs", {"function": "cgi_handler"})
        assert "router" in out and "system" in out
        assert "recon substrate" not in out and "main" not in out


# --- decompilation Observation stores a FOCUS-ONLY payload -------------------


class _FakeDecompiler:
    """A Ghidra-style decompiler whose dict carries the whole-program calls/structs the
    enriched-recon pass uses, alongside the per-function focus."""

    name = "ghidra"

    def decompile(self, artifact, function=None, *, address=None, reanalyze=False, project=None):
        return {
            "functions": ["cgi_handler", "helper", "system"],
            "focus": {"name": function or "cgi_handler", "address": "0x401200",
                      "pseudocode": "int cgi_handler(){ helper(); }",
                      "callees": [{"name": "helper", "address": "0x401300"}], "disasm": ""},
            # whole-program facts that must NOT bloat THIS per-function observation:
            "calls": [["cgi_handler", "helper"], ["main", "cgi_handler"]],
            "structs": [{"name": "cfg_t", "fields": []}],
        }


def test_decompilation_observation_payload_is_focus_only(hg_home, monkeypatch):
    """obs_get of a per-function decompilation must not return whole-program calls/structs
    noise — the recorded decompilation Observation stores {functions, focus} only. The
    decompilation extractor + search_decompiled read only `focus`; whole-program calls/structs
    enrich from SEPARATE call_graph/structs Observations, so dropping them here loses nothing."""
    from hexgraph.engine import observations as O

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_decompiler",
                        lambda *a, **k: _FakeDecompiler())
    with session_scope() as s:
        ctx, _p, t = _ctx(s)
        run_tool(ctx, "decompile_function", {"function": "cgi_handler"})
        rows = s.query(Observation).filter(Observation.target_id == t.id,
                                           Observation.result_kind == "decompilation").all()
        assert len(rows) == 1
        payload = O.get_observation(s, rows[0].id)["payload"]
        # The per-function facts are preserved …
        assert payload["focus"]["name"] == "cgi_handler"
        assert payload["focus"]["callees"]            # the focus's OWN callees stay
        assert "functions" in payload
        # … but the whole-program noise is gone from THIS observation.
        assert "calls" not in payload
        assert "structs" not in payload


# --- data_xrefs: refs to an address, a QUERY ---------------------------------

def test_data_xrefs_records_observation_and_mutates_no_graph(hg_home, monkeypatch):
    result = {"tool": "xrefs_probe", "mode": "data", "subject": "0x4007a0",
              "data_refs": [{"from_function": "cgi_handler", "at": "0x401230", "kind": "DATA"}],
              "total": 1}
    fake = _wire(monkeypatch, result)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb = s.query(Node).count()
        out = run_tool(ctx, "data_xrefs", {"address": "0x4007a0"})
        assert "cgi_handler" in out and "0x4007a0" in out
        assert fake.calls[-1] == ("xrefs_probe.py", ["0x4007a0", "--mode", "data"])
        assert s.query(Node).count() == nb
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "data_xrefs").all()
        assert len(obs) == 1


def test_data_xrefs_requires_address(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "data_xrefs", {})


# --- call_graph: self-wires edges among curated fns, creates no new nodes -----

def test_call_graph_self_wires_edges_among_curated_functions(hg_home, monkeypatch):
    """Recording a call_graph Observation draws `calls` edges between functions ALREADY
    in the graph (both-endpoints rule) and creates NO new nodes — an uncurated callee is
    neither minted nor wired."""
    result = {"tool": "xrefs_probe", "mode": "callgraph",
              "calls": [["cgi_handler", "helper"], ["cgi_handler", "system"]], "total": 2}
    _wire(monkeypatch, result)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # Pre-curate ONLY cgi_handler and helper (not system).
        get_or_create_node(s, project_id=p.id, node_type="function", name="cgi_handler", target_id=t.id)
        get_or_create_node(s, project_id=p.id, node_type="function", name="helper", target_id=t.id)
        s.flush()
        nb = s.query(Node).filter(Node.node_type == "function").count()

        out = run_tool(ctx, "call_graph", {})
        assert "cgi_handler" in out and "helper" in out

        # No NEW nodes — `system` (uncurated) is neither minted nor wired.
        assert s.query(Node).filter(Node.node_type == "function").count() == nb
        assert s.query(Node).filter(Node.name == "system").count() == 0
        # The calls edge between the two curated functions WAS drawn (both endpoints exist).
        edges = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(edges) == 1
        # And it's recorded as a discoverable call_graph Observation.
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "call_graph").all()
        assert len(obs) == 1


def test_call_graph_rooted_renders_subgraph(hg_home, monkeypatch):
    result = {"tool": "xrefs_probe", "mode": "callgraph",
              "calls": [["a", "b"], ["b", "c"], ["x", "y"]], "total": 3}
    fake = _wire(monkeypatch, result)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "call_graph", {"function": "a", "depth": 2})
        # BFS from a reaches a→b and b→c, but not the disjoint x→y
        assert "a → b" in out and "b → c" in out and "x → y" not in out
        assert fake.calls[-1] == ("xrefs_probe.py", ["--mode", "callgraph"])


def _seed_recon_call_graph(s, p, t):
    """Seed the whole-program graph recon's Ghidra enrich pass records into the substrate."""
    from hexgraph.engine import observations as O

    O.record_observation(
        s, project_id=p.id, target_id=t.id, source="ghidra-enrich", tool="enrich_recon",
        args={}, result_kind="call_graph",
        payload={"functions": [{"name": "main", "callees": ["parse", "dispatch"]},
                               {"name": "parse", "callees": ["helper"]}]},
        summary="3 call edges", content_hash="abc123")


def test_call_graph_falls_back_to_recon_substrate_when_probe_empty(hg_home, monkeypatch):
    """Finding NC: the probe path (radare2 xrefs) can come up empty on a binary recon already
    mapped with Ghidra. The verb then surfaces the program graph recon recorded into the
    Observation substrate, instead of returning nothing — read-only, no graph mutation."""
    _wire(monkeypatch, {"tool": "xrefs_probe", "mode": "callgraph", "calls": [], "total": 0})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _seed_recon_call_graph(s, p, t)
        nb = s.query(Node).count()
        out = run_tool(ctx, "call_graph", {})
        assert "main → parse" in out and "main → dispatch" in out and "parse → helper" in out
        assert "recon substrate" in out  # the source is labelled honestly
        assert s.query(Node).count() == nb  # QUERY: no new nodes
        # Rooted view over the substrate edges respects depth.
        rooted = run_tool(ctx, "call_graph", {"function": "main", "depth": 1})
        assert "main → parse" in rooted and "main → dispatch" in rooted
        assert "parse → helper" not in rooted


def test_call_graph_prefers_probe_edges_over_recon_substrate(hg_home, monkeypatch):
    """When the probe DOES return edges, they win — the recon substrate is only a fallback."""
    _wire(monkeypatch, {"tool": "xrefs_probe", "mode": "callgraph",
                        "calls": [["a", "b"]], "total": 1})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _seed_recon_call_graph(s, p, t)
        out = run_tool(ctx, "call_graph", {})
        assert "a → b" in out
        assert "recon substrate" not in out and "main → parse" not in out


# --- pure helpers (no sandbox) -----------------------------------------------

def test_bfs_subgraph_is_depth_bounded_and_normalized():
    edges = [["sym.a", "b"], ["b", "c"], ["c", "d"], ["x", "y"]]
    # depth 1 from a: only a→b
    assert AT._bfs_subgraph(edges, "a", 1) == [("sym.a", "b")]
    # depth 2 from a: a→b, b→c
    assert set(AT._bfs_subgraph(edges, "a", 2)) == {("sym.a", "b"), ("b", "c")}
    # disjoint component never appears
    assert ("x", "y") not in AT._bfs_subgraph(edges, "a", 6)


def test_probe_mode_and_injection_helpers():
    from hexgraph.sandbox.probes import xrefs_probe as XP

    # strict address regex rejects injection attempts
    assert XP._ADDR.match("0x4007a0")
    assert not XP._ADDR.match("0x4007a0; !sh")
    assert not XP._ADDR.match("sym.foo && rm -rf /")
    # _resolve_seek: a known flag wins; a validated address/name passes; junk is refused
    flagset = {"sym.cgi_handler"}
    assert XP._resolve_seek("cgi_handler", flagset) == "sym.cgi_handler"
    assert XP._resolve_seek("0x401200", set()) == "0x401200"
    assert XP._resolve_seek("plain_name", set()) == "plain_name"  # safe bare name
    assert XP._resolve_seek("bad; name", set()) is None  # refused (unsafe → unfound)


# --- NE: data_xrefs resolves a local/static symbol NAME via the symbol table -----------

class _SymR2:
    """A fake r2 that answers `isj` (the symbol table) — for _symbol_addr unit tests."""

    def __init__(self, syms):
        self._syms = syms

    def cmd(self, c):
        return json.dumps(self._syms) if c == "isj" else ""


def test_symbol_addr_resolves_name_via_symbol_table():
    """A data symbol given by NAME (KEY_ENC) resolves to its address through the symbol table,
    matching either the full r2 name (`main`) or the trailing component (`obj.KEY_ENC` → KEY_ENC)."""
    from hexgraph.sandbox.probes import xrefs_probe as XP

    r2 = _SymR2([
        {"name": "obj.KEY_ENC", "realname": "KEY_ENC", "vaddr": 0x402004},
        {"name": "main", "vaddr": 0x401000},
        {"name": "no_addr", "vaddr": 0},
    ])
    assert XP._symbol_addr(r2, "KEY_ENC") == "0x402004"   # trailing component of obj.KEY_ENC
    assert XP._symbol_addr(r2, "main") == "0x401000"      # full name
    assert XP._symbol_addr(r2, "missing") is None
    assert XP._symbol_addr(r2, "no_addr") is None         # vaddr 0 is not a usable address
    assert XP._symbol_addr(r2, "bad; name") is None       # unsafe name refused (no shell reach)


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_data_xrefs_resolves_named_symbol_end_to_end(hg_home, tmp_path):
    """Finding NE: data_xrefs by a local/static symbol NAME (not just a hex address). The probe
    resolves KEY_ENC through the symbol table to its address and returns the code refs to it."""
    if shutil.which("gcc") is None:
        pytest.skip("gcc unavailable to compile the keytab fixture")
    src = fixture_path("challenges/keytab.c")
    binpath = str(tmp_path / "keytab")
    if subprocess.run(["gcc", "-O0", "-o", binpath, src], capture_output=True).returncode != 0:
        pytest.skip("could not compile keytab")

    from hexgraph.sandbox.executor import get_executor

    out = get_executor().run_json_probe(
        "xrefs_probe.py", binpath, extra_args=["KEY_ENC", "--mode", "data"])
    refs = out.get("data_refs") or []
    assert refs, out  # resolved BY NAME and found at least one reference
    # The reference lives in verify() (which does memcmp(in, KEY_ENC, ...)).
    assert any("verify" in (r.get("from_function") or "") for r in refs), out


# --- warm-project Ghidra xrefs routing ----------------------------------------
# When headless Ghidra is the active backend, the four xrefs tools serve from the warm persistent
# project's reference index (GhidraDecompiler.xrefs) instead of the cold r2 xrefs_probe sweep that
# re-analyzes the whole binary every call. The routing + fallback are unit-tested here with a fake
# warm backend; the Jython reference-index emit itself is exercised by the sandbox/live tier.

class _FakeGhidra:
    """Stands in for GhidraDecompiler: `xrefs` returns a canned per-mode result (the warm
    reference-index probe payload) and records how it was called."""

    def __init__(self, results, calls):
        self._results = results
        self._calls = calls

    def xrefs(self, artifact, *, mode, subject=None, project=None):
        self._calls.append((mode, subject))
        return self._results.get(mode)


class _NoR2Xrefs:
    """A stand-in executor that FAILS the test if the cold r2 xrefs_probe is reached (it must not be
    when the warm Ghidra path served), while tolerating any incidental non-xrefs probe."""

    def run_json_probe(self, probe, artifact, *, extra_args=None, **kw):
        if probe == "xrefs_probe.py":
            raise AssertionError("cold r2 xrefs_probe must NOT run when the warm Ghidra path served")
        return {}


def _wire_ghidra(monkeypatch, results, *, forbid_r2=True):
    """Route xrefs through a fake warm Ghidra backend: force the gate on, Docker up, and swap in a
    _FakeGhidra. With forbid_r2, the r2 executor asserts if reached (proving the warm path served).
    Returns the list that records (mode, subject) per warm call."""
    calls = []
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.GhidraDecompiler",
                        lambda: _FakeGhidra(results, calls))
    if forbid_r2:
        monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: _NoR2Xrefs())
    return calls


def test_gate_reflects_headless_ghidra_setting(hg_home, monkeypatch):
    """The routing gate is ON only for enabled HEADLESS Ghidra — off by default, off for bridge
    mode (which has no persistent-project warm path here)."""
    from hexgraph.engine.re import ghidra as G

    monkeypatch.setattr(G, "ghidra_config", lambda: {"enabled": False, "mode": "headless"})
    assert AT._ghidra_xrefs_active() is False
    monkeypatch.setattr(G, "ghidra_config", lambda: {"enabled": True, "mode": "headless"})
    assert AT._ghidra_xrefs_active() is True
    monkeypatch.setattr(G, "ghidra_config", lambda: {"enabled": True, "mode": "bridge"})
    assert AT._ghidra_xrefs_active() is False


def test_xrefs_symbol_served_from_warm_ghidra(hg_home, monkeypatch):
    calls = _wire_ghidra(monkeypatch, {"callers": {
        "mode": "callers", "symbol": "system",
        "callers": [{"caller": "handle_req", "caller_addr": "0x401000", "at": "0x401040"}],
        "total": 1}})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "xrefs", {"symbol": "system"})
        assert "handle_req" in out and "0x401040" in out
        assert calls == [("callers", "system")]        # served from the warm reference index
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "xrefs").all()
        assert len(obs) == 1                             # still records the QUERY Observation


def test_xrefs_sink_sweep_served_from_warm_ghidra(hg_home, monkeypatch):
    calls = _wire_ghidra(monkeypatch, {"sinks": {
        "mode": "sinks",
        "sinks": {"system": {"callers": [{"caller": "run_cmd"}], "total": 1}},
        "format_sinks": {}, "network": {}}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "xrefs", {})               # no symbol => the sink sweep
        assert "system" in out and "run_cmd" in out
        assert calls == [("sinks", None)]


def test_xrefs_unknown_symbol_fast_fails_without_r2(hg_home, monkeypatch):
    """An unknown symbol comes back EMPTY from the warm index (fast) — the tool reports 'no callers'
    and never falls through to the cold r2 sweep (the 42-minute failure this fix removes)."""
    calls = _wire_ghidra(monkeypatch, {"callers": {"mode": "callers", "symbol": "sub_bogus",
                                                   "callers": [], "total": 0}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "xrefs", {"symbol": "sub_bogus"})
        assert "no callers" in out
        assert calls == [("callers", "sub_bogus")]     # warm path answered; r2 forbidden, never hit


def test_xrefs_falls_back_to_r2_when_ghidra_cannot_run(hg_home, monkeypatch):
    """Ghidra active but unable to run (not built into the image => a top-level `error`) degrades to
    the r2 probe rather than failing."""
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.GhidraDecompiler",
                        lambda: _FakeGhidra({"callers": {"error": "Ghidra not installed"}}, []))
    fake = _wire(monkeypatch, {"tool": "xrefs_probe", "symbol": "system",
                               "callers": [{"caller": "main", "caller_addr": "0x1", "at": "0x2"}],
                               "total": 1})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "xrefs", {"symbol": "system"})
        assert "main" in out                            # the r2 result surfaced
        assert fake.calls[-1] == ("xrefs_probe.py", ["system"])   # r2 probe WAS the fallback


def test_function_xrefs_served_from_warm_ghidra(hg_home, monkeypatch):
    calls = _wire_ghidra(monkeypatch, {"function": {
        "mode": "function", "subject": "cgi_handler",
        "callers": [{"caller": "router", "caller_addr": "0x400100", "at": "0x400120"}],
        "callees": [{"name": "system", "addr": "0x400500"}],
        "total_callers": 1, "total_callees": 1}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "function_xrefs", {"function": "cgi_handler"})
        assert "router" in out and "system" in out
        assert calls == [("function", "cgi_handler")]


def test_function_xrefs_not_found_via_warm_ghidra(hg_home, monkeypatch):
    """A function the warm index doesn't define returns `not_found` (fast) => 'not found', no cold
    r2 retry."""
    _wire_ghidra(monkeypatch, {"function": {"mode": "function", "subject": "nope",
                                            "callers": [], "callees": [],
                                            "total_callers": 0, "total_callees": 0,
                                            "not_found": True}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "function_xrefs", {"function": "nope"})
        assert "not found" in out


def test_data_xrefs_not_found_via_warm_ghidra(hg_home, monkeypatch):
    _wire_ghidra(monkeypatch, {"data": {"mode": "data", "subject": "0xdead",
                                        "data_refs": [], "total": 0, "not_found": True}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "data_xrefs", {"address": "0xdead"})
        assert "no resolvable references" in out


def test_call_graph_served_from_warm_ghidra(hg_home, monkeypatch):
    calls = _wire_ghidra(monkeypatch, {"callgraph": {
        "mode": "callgraph", "calls": [["a", "b"], ["b", "c"]], "total": 2}})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "call_graph", {})
        assert "a → b" in out and "b → c" in out
        assert calls == [("callgraph", None)]
