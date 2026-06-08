"""Phase 2 PR1 — address-level access + reanalyze (design-re-tooling.md §7).

Covers the new read verbs (decompile_at / disassemble-by-address / reanalyze) at the
engine layer with a faked decompiler (offline, no Docker — the curation plumbing, not
the sandboxed decompiler), the probe's pure address-resolution helpers, and the
decompiler-seam focus-arg builder. The address path must stay injection-safe and honor
the same query/promote contract as the name path.
"""

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="addr")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


class _FakeDecompiler:
    """Records how it was called and returns a fixed {functions, focus}."""

    def __init__(self, focus=None, functions=None):
        self.focus = focus
        self.functions = functions or []
        self.calls = []

    def decompile(self, artifact, function=None, *, address=None, reanalyze=False, project=None):
        self.calls.append({"function": function, "address": address, "reanalyze": reanalyze})
        return {"functions": list(self.functions), "focus": self.focus}


def _wire(monkeypatch, decompiler):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_decompiler", lambda *a, **k: decompiler)


# --- decompile_at: promote the function CONTAINING an address ------------------

def test_decompile_at_promotes_resolved_function_and_records(hg_home, monkeypatch):
    focus = {"name": "cgi_handler", "address": "0x401200",
             "pseudocode": "void cgi_handler(){ system(x); }", "callees": ["system"]}
    fake = _FakeDecompiler(focus=focus, functions=["cgi_handler", "main"])
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "decompile_at", {"address": "0x401200"})
        assert "cgi_handler" in out and "0x401200" in out

        # PROMOTE: exactly the resolved focus function landed (no callee fan-out).
        fns = s.query(Node).filter(Node.node_type == "function", Node.target_id == t.id).all()
        assert {f.name for f in fns} == {"cgi_handler"}
        # the not-yet-curated callee is surfaced, not minted
        assert "system" in out
        assert s.query(Edge).filter(Edge.type == "calls").count() == 0

        # the decompiler was asked BY ADDRESS, and the Observation is keyed to decompile_at
        assert fake.calls[-1]["address"] == "0x401200"
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.tool == "decompile_at").all()
        assert len(obs) == 1 and obs[0].result_kind == "decompilation"
        assert obs[0].content_hash == "abc123"


def test_decompile_at_address_not_found_records_under_decompile_at(hg_home, monkeypatch):
    fake = _FakeDecompiler(focus=None, functions=["main"])  # nothing contains the address
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "decompile_at", {"address": "0xdeadbeef"})
        assert "not found" in out
        # no graph mutation, and the miss is attributed to the call actually made
        assert s.query(Node).filter(Node.node_type == "function").count() == 0
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.tool == "decompile_at").all()
        assert len(obs) == 1 and obs[0].result_kind == "function_list"


def test_decompile_at_requires_address(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "decompile_at", {})


# --- disassemble by address: a QUERY, no graph mutation -----------------------

def test_disassemble_by_address_records_and_mutates_no_graph(hg_home, monkeypatch):
    focus = {"name": "cgi_handler", "address": "0x401200",
             "disasm": "0x401200  push rbp\n0x401201  mov rbp, rsp", "callees": []}

    class _FakeR2:
        def decompile(self, artifact, function=None, *, address=None, reanalyze=False, project=None):
            assert address == "0x401200"  # routed by address
            return {"functions": ["cgi_handler"], "focus": focus}

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.R2Decompiler", _FakeR2)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = run_tool(ctx, "disassemble", {"address": "0x401200"})
        assert "push rbp" in out and "cgi_handler" in out
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "disassembly").all()
        assert len(obs) == 1 and (obs[0].args_json or {}).get("address") == "0x401200"


def test_disassemble_requires_a_focus(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "disassemble", {})


def test_disassemble_miss_records_observation_for_discoverability(hg_home, monkeypatch):
    """A requested-but-unresolved disassemble still records a discoverable Observation
    (parity with decompile_at's not-found path) and mutates no graph."""
    class _FakeR2:
        def decompile(self, artifact, function=None, *, address=None, reanalyze=False, project=None):
            return {"functions": ["main", "helper"], "focus": None}  # nothing resolved

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.R2Decompiler", _FakeR2)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb = s.query(Node).count()
        out = run_tool(ctx, "disassemble", {"function": "ghost"})
        assert "not found" in out
        assert s.query(Node).count() == nb  # QUERY: no mutation even on a miss
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.tool == "disassemble").all()
        assert len(obs) == 1 and obs[0].result_kind == "function_list"


# --- reanalyze: raise depth, bust cache, QUERY only ---------------------------

def test_reanalyze_raises_depth_busts_cache_and_records(hg_home, monkeypatch):
    fake = _FakeDecompiler(focus=None, functions=["a", "b", "c"])
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # prime the inventory cache with a plain list_functions first
        run_tool(ctx, "list_functions", {})
        nb = s.query(Node).count()
        out = run_tool(ctx, "reanalyze", {})
        assert "re-analyzed" in out and "3 functions" in out
        # QUERY: no graph mutation
        assert s.query(Node).count() == nb
        # the decompiler was actually re-run at depth (cache busted by the distinct key)
        assert fake.calls[-1]["reanalyze"] is True
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.tool == "reanalyze").all()
        assert len(obs) == 1 and obs[0].result_kind == "function_list"


# --- probe + seam unit helpers (pure, no sandbox) -----------------------------

def test_probe_resolves_address_to_containing_function():
    from hexgraph.sandbox.probes import decompile_probe as DP

    funcs = [{"name": "fcn.a", "offset": 0x1000, "size": 0x40},
             {"name": "main", "offset": 0x1040, "size": 0x80}]
    assert DP._containing_function(0x1000, funcs)["name"] == "fcn.a"
    assert DP._containing_function(0x1050, funcs)["name"] == "main"
    assert DP._containing_function(0x9999, funcs) is None  # outside every function


def test_probe_address_regex_is_injection_safe():
    from hexgraph.sandbox.probes import decompile_probe as DP

    assert DP._ADDR.match("0x401200")
    # a command-injection attempt is NOT a valid address, so it never reaches an r2 seek
    assert not DP._ADDR.match("0x401200; !sh")
    assert not DP._ADDR.match("system")
    assert not DP._ADDR.match("0x401200 && rm -rf /")


def test_focus_args_builds_probe_argv():
    from hexgraph.sandbox.decompiler import _focus_args

    assert _focus_args("foo", None, False) == ["foo"]
    assert _focus_args(None, "0x1000", False) == ["0x1000"]
    assert _focus_args("foo", None, True) == ["foo", "--reanalyze"]
    assert _focus_args(None, None, False) is None
    # address wins when both are (defensively) supplied
    assert _focus_args("foo", "0x1000", False) == ["0x1000"]
