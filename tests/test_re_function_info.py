"""re_function_info — lightweight per-function metadata (address, size, prototype, calling
convention, #callers, #callees) by NAME or ADDRESS, WITHOUT a full decompile.

The cheap 'what is this function' triage before deciding to re_decompile_function it. Two substrate
reads, both read-only and free:
  * #callers/#callees from the recon call-graph Observation (`_recon_function_xrefs`, the same
    source re_function_xrefs uses).
  * address from the binutils symbol index (`_symbol_index`).
And, OPPORTUNISTICALLY, prototype/calling_convention/param_count/size from an EXISTING
`decompilation` Observation for the function (if it was already decompiled) — WITHOUT triggering a
new decompile. Fields not recovered are marked 'unknown (decompile to recover)'. PARTIAL by design.
Records a function_info Observation, mutates no graph.

Offline + mock, mirroring test_list_functions / test_re_symbol: monkeypatch the two substrate
sources (`_recon_call_graph_edges` for the counts, `_symbol_index` for address), seed a prior
decompilation Observation for the prototype path, and assert the DECOMPILER IS NEVER INVOKED (it's
stubbed to raise) — the whole point of the 'no full decompile' constraint.
"""

import hexgraph.agent.agent_tools as AT
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool, _record_obs
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


# A synthetic call graph: main -> parse_request, main -> handle, parse_request -> strcpy,
# validate -> parse_request. So parse_request has 2 callers (main, validate) and 1 callee (strcpy).
_EDGES = [["main", "parse_request"], ["main", "handle"],
          ["parse_request", "strcpy"], ["validate", "parse_request"]]

# A symbol index giving parse_request an address (nm rows carry name+addr, no size). `_symbol_index`
# returns ADDRESS-SORTED rows (its contract; the nearest-symbol lookup binary-searches over it), so
# the stub honors that ordering: handle < parse_request < main.
_INDEX = [{"name": "handle", "address": 0x401196},
          {"name": "parse_request", "address": 0x4011e6},
          {"name": "main", "address": 0x401267}]


def _ctx(s):
    p = create_project(s, name="fninfo")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "fi123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


def _stub_substrate(monkeypatch, *, edges=_EDGES, index=_INDEX):
    """Stand in for the two read-only substrate sources, and make the decompiler EXPLODE if ever
    reached — re_function_info must answer without decompiling."""
    monkeypatch.setattr(AT, "_recon_call_graph_edges", lambda ctx: list(edges))
    monkeypatch.setattr(AT, "_symbol_index", lambda ctx: list(index))

    def _explode(*a, **k):
        raise AssertionError("re_function_info must not decompile")

    # Both the seam and the wrapper — belt and suspenders that no decompile is triggered.
    monkeypatch.setattr(AT, "_decomp", _explode)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_decompiler", _explode)


# --- the caller/callee counts come from the recon call graph (no decompile) ---------------

def test_counts_from_recon_call_graph(hg_home, monkeypatch):
    """parse_request has 2 callers (main, validate) and 1 callee (strcpy) per the synthetic graph."""
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "function_info", {"function": "parse_request"})
        assert "callers: 2" in out
        assert "callees: 1" in out
        assert "main" in out and "validate" in out and "strcpy" in out   # the sample listing


def test_address_selector_resolves_the_function(hg_home, monkeypatch):
    """Passed an ADDRESS, the nearest symbol at-or-below names the function (server-side over the
    symbol index — no probe), then its counts come from the call graph."""
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        # 0x4011f0 is just inside parse_request (0x4011e6) and below handle/main -> resolves to it.
        out = run_tool(ctx, "function_info", {"address": "0x4011f0"})
        assert "parse_request" in out
        assert "callers: 2" in out


def test_name_selector_fills_address_from_index(hg_home, monkeypatch):
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "function_info", {"function": "parse_request"})
        assert "0x4011e6" in out                           # address from the symbol index


# --- prototype/conv/size opportunistically from a PRIOR decompilation (no new decompile) ---

def _seed_decompilation(ctx, *, name, prototype, cc, size, addr):
    """Record a `decompilation` Observation whose focus carries the recovered facts — as
    re_decompile_function would, so re_function_info can surface them without re-decompiling."""
    _record_obs(ctx, tool="decompile_function", args={"function": name},
                result_kind="decompilation",
                payload={"focus": {"name": name, "address": addr, "size": size,
                                   "prototype": prototype, "calling_convention": cc,
                                   "param_count": 2}},
                summary=f"decompiled {name}", node_refs=[name])


def test_prototype_from_prior_decompilation(hg_home, monkeypatch):
    """When the function was ALREADY decompiled, re_function_info surfaces its prototype / calling
    convention / size from that Observation — and the decompiler is NEVER called (it raises)."""
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        _seed_decompilation(ctx, name="parse_request",
                            prototype="int parse_request(char *req, int len)",
                            cc="cdecl", size=0x81, addr="0x4011e6")
        s.flush()
        out = run_tool(ctx, "function_info", {"function": "parse_request"})
        assert "int parse_request(char *req, int len)" in out
        assert "cdecl" in out
        assert "129" in out                                # size 0x81 == 129, from the decompile
        assert "prior decompilation" in out
        assert "param_count: 2" in out


def test_prototype_unknown_when_never_decompiled(hg_home, monkeypatch):
    """With no prior decompilation, prototype/size/calling_convention are marked unknown (decompile
    to recover) — never fabricated, and still no decompile is triggered."""
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "function_info", {"function": "parse_request"})
        assert "prototype: unknown (decompile to recover)" in out
        assert "re_decompile_function" in out              # the actionable hint


# --- a nonexistent function -> clean 'not found' with a nearest-name hint ------------------

def test_not_found_gives_nearest_name_hint(hg_home, monkeypatch):
    """A name absent from BOTH the symbol index and the call graph returns a clean 'not found' with
    the nearest matching name as a hint (not a crash)."""
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "function_info", {"function": "parse_XXX"})
        assert "not found" in out
        assert "parse_request" in out                      # nearest-name hint (substring match)


def test_missing_both_selectors_is_an_error(hg_home, monkeypatch):
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "function_info", {})
        assert "error" in out.lower() and "required" in out


# --- QUERY contract: one function_info Observation, zero graph mutation -------------------

def test_records_observation_and_no_graph(hg_home, monkeypatch):
    _stub_substrate(monkeypatch)
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "function_info", {"function": "parse_request"})
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "function_info").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "fi123"
