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
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node

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
