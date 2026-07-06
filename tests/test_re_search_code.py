"""search_code — search the WHOLE binary's code (code NOT necessarily decompiled yet).

Three sub-capabilities, each honest about its cost:
  • a BYTE/opcode pattern (`bytes`) or an IMMEDIATE constant (`immediate`) scanned across the
    mapped image via the r2 `--mode search` probe (`/xj`//`/vj`), each hit mapped to its function;
  • a decompile-on-demand GREP (`query`) over a BOUNDED candidate set the caller names in
    `functions` — pure orchestration over the existing decompiler, bounded so an UNBOUNDED
    whole-binary decompile (the exact cost the persistent project avoids) is NEVER triggered.
CALLERS of a symbol/sink are re_xrefs' job (whole-program, indexed) — search_code must NOT
duplicate it, and its doc routes there. A full pseudo-C grep over the whole binary is DEFERRED.

Offline + mock: the byte/immediate scan is a probe, so those tests stub the executor (the
_FakeExec pattern from test_breadth_xrefs) — the unit under test is the formatting/pagination/
function-mapping, not the sandboxed r2 run. The grep tests stub `_decomp` to prove ONLY the named
functions get decompiled (the cost bound) and record nothing of their own, so the ONE search_code
Observation asserted is unambiguously search_code's.
"""

import hexgraph.agent.agent_tools as AT
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import SANDBOX_READY, fixture_path


def _ctx(s):
    p = create_project(s, name="searchcode")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "sc123"}
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


def _wire_probe(monkeypatch, result):
    fake = _FakeExec(result)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


# ======================================================================================
# The byte / immediate scan (the genuinely-new capability) — mocked probe
# ======================================================================================

def test_byte_scan_formats_hits_and_maps_to_functions(hg_home, monkeypatch):
    """A byte-pattern scan runs the r2 `--mode search --bytes` probe and formats each hit with the
    function that contains it — the constant/opcode locator re_search_decompiled can't answer."""
    result = {"tool": "xrefs_probe", "mode": "search", "kind": "bytes", "pattern": "deadbeef",
              "hits": [{"addr": "0x401000", "in_function": "cgi_handler"},
                       {"addr": "0x401234", "in_function": None}],
              "total": 2}
    fake = _wire_probe(monkeypatch, result)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "deadbeef"})
        # the probe was invoked in SEARCH mode with the byte pattern
        assert fake.calls[-1] == ("xrefs_probe.py", ["--mode", "search", "--bytes", "deadbeef"])
        assert "0x401000" in out and "in cgi_handler" in out
        assert "0x401234" in out and "(no function)" in out   # a hit with no containing function
        assert "2 hit(s)" in out


def test_immediate_scan_invokes_imm_mode(hg_home, monkeypatch):
    """An immediate/constant scan uses `--imm` (r2 `/vj`)."""
    result = {"tool": "xrefs_probe", "mode": "search", "kind": "immediate", "value": "0x1337",
              "hits": [{"addr": "0x402000", "in_function": "derive_key"}], "total": 1}
    fake = _wire_probe(monkeypatch, result)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"immediate": "0x1337"})
        assert fake.calls[-1] == ("xrefs_probe.py", ["--mode", "search", "--imm", "0x1337"])
        assert "derive_key" in out and "1 hit(s)" in out


def test_scan_paginates_and_reports_next_offset(hg_home, monkeypatch):
    """A scan with many hits is bounded to a page and reports the total + the next offset (no
    silent clip), exactly like the other greps."""
    hits = [{"addr": hex(0x400000 + i), "in_function": f"fn_{i}"} for i in range(250)]
    _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search", "kind": "bytes",
                              "pattern": "90", "hits": hits, "total": 250})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "90", "limit": 10})
        assert "250 hit(s)" in out
        assert "0x400000" in out and "0x400009" in out
        assert "0x40000a" not in out                      # clipped to the page
        assert "240 more" in out and "offset=10" in out

        ctx.cache.clear()
        out2 = run_tool(ctx, "search_code", {"bytes_pattern": "90", "limit": 10, "offset": 10})
        assert "0x40000a" in out2 and "0x400009" not in out2


def test_scan_records_one_observation_and_no_graph(hg_home, monkeypatch):
    _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search", "kind": "bytes",
                              "pattern": "cc", "hits": [{"addr": "0x401000", "in_function": "m"}],
                              "total": 1})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "search_code", {"bytes_pattern": "cc"})
        assert s.query(Node).count() == 0 and s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "search_code").all()
        assert len(obs) == 1 and obs[0].content_hash == "sc123"


def test_scan_surfaces_probe_error(hg_home, monkeypatch):
    """The probe rejects a malformed byte pattern; search_code surfaces that reason, not a crash."""
    _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search",
                              "error": "bytes must be an even-length hex string, e.g. 'deadbeef'"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "xyz"})
        assert "even-length hex" in out


# ======================================================================================
# The decompile-on-demand grep — bounded by `functions` (mocked decompiler)
# ======================================================================================

def _stub_decomp_bodies(monkeypatch, bodies):
    """Stub `_decomp` so ONLY the named functions have a body — records the calls so a test can
    assert exactly which (and how many) functions were decompiled. An unknown name returns a
    no-focus dict (the 'not found' shape)."""
    calls = []

    def _fake(ctx, function, **kw):
        calls.append(function)
        if function in bodies:
            return {"functions": list(bodies), "focus": {"name": function,
                                                         "pseudocode": bodies[function]}}
        return {"functions": list(bodies), "focus": None}

    monkeypatch.setattr(AT, "_decomp", _fake)
    return calls


def test_grep_decompiles_only_named_functions(hg_home, monkeypatch):
    """The whole safety property: the grep decompiles ONLY the functions the caller named (never
    the whole binary) — the call count equals len(functions), and the match is found in the body."""
    bodies = {
        "parse_request": "int parse_request(char *b){ strcpy(dst, b); return 0; }",
        "handle_login": "int handle_login(void){ return check(); }",
    }
    calls = _stub_decomp_bodies(monkeypatch, bodies)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code",
                       {"query": "strcpy", "functions": ["parse_request", "handle_login"]})
        # ONLY the two named functions were decompiled — no whole-binary fan-out.
        assert sorted(calls) == ["handle_login", "parse_request"]
        assert len(calls) == 2
        # the grep found the hit in the one body that contains it
        assert "parse_request" in out and "strcpy(dst, b)" in out
        assert "handle_login" not in out.split("not decompiled")[0]  # no match line for it


def test_grep_empty_functions_refuses_unbounded_run(hg_home, monkeypatch):
    """A `query` with NO `functions` must NOT trigger an unbounded whole-binary decompile — it
    returns a clear 'name candidate functions' message and decompiles nothing."""
    calls = _stub_decomp_bodies(monkeypatch, {"anything": "x"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "strcpy"})
        assert "needs `functions`" in out
        assert "re_search_decompiled" in out          # points at the no-decompile alternative
        assert "re_xrefs" in out                       # ...and at callers-of-symbol
        assert calls == []                             # decompiled NOTHING


def test_grep_also_refuses_empty_list(hg_home, monkeypatch):
    """An explicitly EMPTY functions list is the same refusal (not a silent whole-binary run)."""
    calls = _stub_decomp_bodies(monkeypatch, {"anything": "x"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "strcpy", "functions": []})
        assert "needs `functions`" in out and calls == []


def test_grep_bounds_candidate_count(hg_home, monkeypatch):
    """Even a LARGE `functions` list is bounded — at most _SEARCH_FUNCS_MAX are decompiled, and
    the result says it clipped (the caller's cost stays bounded, the no-silent-caps discipline)."""
    names = [f"fn_{i:03d}" for i in range(AT._SEARCH_FUNCS_MAX + 25)]
    calls = _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{}}" for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "void", "functions": names})
        assert len(calls) == AT._SEARCH_FUNCS_MAX      # clamped to the ceiling
        assert "bounded to the first" in out


def test_grep_reports_undecompilable_functions(hg_home, monkeypatch):
    """A named function with no recoverable body (unresolved / no analysis) is reported under
    'not decompiled' rather than silently dropped."""
    calls = _stub_decomp_bodies(monkeypatch, {"real_fn": "void real_fn(){ log(); }"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code",
                       {"query": "log", "functions": ["real_fn", "ghost_fn"]})
        assert "real_fn" in out
        assert "not decompiled" in out and "ghost_fn" in out


def test_grep_records_one_observation_and_no_graph(hg_home, monkeypatch):
    _stub_decomp_bodies(monkeypatch, {"f": "void f(){ memcpy(a,b,c); }"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "search_code", {"query": "memcpy", "functions": ["f"]})
        assert s.query(Node).count() == 0 and s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "search_code").all()
        assert len(obs) == 1 and obs[0].content_hash == "sc123"


# ======================================================================================
# Contract: no mode given routes to the three modes + re_xrefs (never an unbounded run)
# ======================================================================================

def test_no_mode_points_at_modes_and_routes_callers_to_xrefs(hg_home):
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {})
        assert "bytes" in out and "immediate" in out and "query" in out
        assert "re_xrefs" in out          # callers-of-a-symbol is routed to re_xrefs, not duplicated


def test_catalog_doc_routes_callers_to_xrefs():
    """The advertised description must send callers-of-a-symbol to re_xrefs (the no-overlap rule)."""
    from hexgraph.agent.mcp_catalog import catalog

    doc = {t["name"]: t for t in catalog()}["re_search_code"]["description"]
    assert "re_xrefs" in doc or "xrefs" in doc
    # and it advertises the bounded-cost framing (no unbounded whole-binary decompile)
    assert "functions" in doc


# ======================================================================================
# One non-mocked scan over a real fixture (behind SANDBOX_READY)
# ======================================================================================

import pytest


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_byte_scan_finds_a_known_opcode_end_to_end(hg_home):
    """A byte scan over the real vuln_httpd fixture for a common opcode byte (0x55 = `push rbp`,
    a function-prologue byte present in any x86-64 .text) returns >=1 hit with an address."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "55"})
        assert "hit(s)" in out
        assert "0x" in out            # at least one concrete address (the prologue byte is common)
