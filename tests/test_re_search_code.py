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


def test_scan_bridge_mode_tries_warm_ghidra_then_falls_back_to_r2_raw(hg_home, monkeypatch):
    """The byte/immediate scan's warm gate is `_ghidra_backend_enabled` (any Ghidra mode), NOT the
    headless-only one — so a bridge-mode target isn't wrongly forced onto the cold path. And because
    the r2 fallback is a RAW scan (no warm analysis needed), a researcher-bridge target where warm
    Ghidra can't answer still gets REAL hits from r2, not a 'switch to headless' refusal."""
    from hexgraph.engine.re import ghidra as G

    monkeypatch.setattr(G, "ghidra_config", lambda: {"enabled": True, "mode": "bridge"})
    tried = []
    # Warm Ghidra scan is attempted (proving the broadened gate) but comes up cold => None => r2 raw.
    monkeypatch.setattr(AT, "_ghidra_search",
                        lambda ctx, **kw: (tried.append("ghidra"), None)[1])
    fake = _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search", "kind": "bytes",
                                     "hits": [{"addr": "0x401000", "in_function": "cgi_handler"}],
                                     "total": 1})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "deadbeef"})
        assert tried == ["ghidra"]                              # broadened gate DID try warm Ghidra first
        assert fake.calls[-1][0] == "xrefs_probe.py"            # then the r2 raw scan served it
        assert "0x401000" in out and "cgi_handler" in out       # real hits, not a refusal
        assert "decompile-only" not in out and "headless" not in out


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
    """Even a LARGE `functions` list is bounded — at most _SEARCH_FUNCS_MAX are decompiled per
    call. The overflow is PAGED, not dropped: the result names the remainder and the offset to
    resume from (the no-silent-caps discipline)."""
    names = [f"fn_{i:03d}" for i in range(AT._SEARCH_FUNCS_MAX + 25)]
    calls = _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{}}" for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "void", "functions": names})
        assert len(calls) == AT._SEARCH_FUNCS_MAX      # clamped to the ceiling
        assert "25 more" in out and f"offset={AT._SEARCH_FUNCS_MAX}" in out


def test_grep_pages_over_the_functions_list(hg_home, monkeypatch):
    """offset/limit page over the FUNCTIONS list (not the hits): a grep item can cost a whole
    decompile, so the caller must be able to walk a long candidate list a page at a time."""
    names = [f"fn_{i:02d}" for i in range(10)]
    calls = _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": names, "limit": 4})
        assert calls == names[:4]                      # ONLY the first page was decompiled
        assert "fn_00" in out and "fn_03" in out
        assert "fn_04" not in out                      # the next page was not touched
        assert "6 more" in out and "offset=4" in out


def test_grep_reuses_recorded_bodies_instead_of_re_decompiling(hg_home, monkeypatch):
    """The reuse fix. Ghidra's project database persists the ANALYSIS but never the pseudo-C, so
    the Observation store is the only pseudocode cache — a function already decompiled must be
    grepped from the store for FREE, never re-decompiled (that re-pay is what made a 30-function
    grep a ~10-minute call)."""
    from hexgraph.engine import observations as O

    # Any decompile at all is a failure here, so the stub's body is one the assertions reject.
    calls = _stub_decomp_bodies(monkeypatch, {"parse_request": "void SHOULD_NOT_DECOMPILE(){}"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_function", args={"function": "parse_request"},
            result_kind="decompilation",
            payload={"focus": {"name": "parse_request",
                               "pseudocode": "int parse_request(char *b){ strcpy(dst, b); }"}},
            summary="decompiled parse_request", content_hash=O.content_hash_for(t))
        out = run_tool(ctx, "search_code",
                       {"query": "strcpy", "functions": ["parse_request"]})
        assert calls == []                             # NO decompile — the stored body served it
        assert "strcpy(dst, b)" in out                 # ...and it really grepped that body
        assert "SHOULD_NOT_DECOMPILE" not in out
        assert "reused 1" in out                       # the result says the work was free


def test_grep_decompiles_only_the_functions_with_no_stored_body(hg_home, monkeypatch):
    """Reuse is per-function, not all-or-nothing: a mixed page decompiles ONLY the misses."""
    from hexgraph.engine import observations as O

    calls = _stub_decomp_bodies(monkeypatch, {"cold_fn": "void cold_fn(){ memcpy(a,b,c); }"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_function", args={"function": "warm_fn"},
            result_kind="decompilation",
            payload={"focus": {"name": "warm_fn", "pseudocode": "void warm_fn(){ memcpy(x,y,z); }"}},
            summary="decompiled warm_fn", content_hash=O.content_hash_for(t))
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": ["warm_fn", "cold_fn"]})
        assert calls == ["cold_fn"]                    # the warm one was never re-decompiled
        assert "warm_fn" in out and "cold_fn" in out   # both still matched
        assert "decompiled 1, reused 1" in out


def test_grep_releases_the_write_lock_before_each_decompile(hg_home, monkeypatch):
    """The lock fix. This loop interleaves DB writes (the Observation + the node/edges a decompile
    promotes) with tens-of-seconds sandbox work; under single-writer SQLite, holding the write lock
    across that blocks the web app and every other agent for the whole run. Assert the commit
    happens BEFORE each decompile, not just once."""
    order = []

    def _fake(ctx, function, **kw):
        order.append(f"decompile:{function}")
        return {"focus": {"name": function, "pseudocode": f"void {function}(){{ log(); }}"}}

    monkeypatch.setattr(AT, "_decomp", _fake)
    monkeypatch.setattr("hexgraph.db.session.release_write_lock",
                        lambda sess: order.append("release"))
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "search_code", {"query": "log", "functions": ["a_fn", "b_fn"]})
    assert order == ["release", "decompile:a_fn", "release", "decompile:b_fn"]


def test_grep_stops_on_the_wall_clock_budget_and_reports_the_resume_offset(hg_home, monkeypatch):
    """The budget fix. _SEARCH_FUNCS_MAX bounds how MANY functions a call decompiles but not how
    LONG that takes — with a size-scaled per-decompile timeout up to an hour, a full page could run
    for hours with no output. Once the budget is spent we stop starting new decompiles and report
    the offset to resume from, rather than hanging the caller."""
    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr(AT, "_SEARCH_GREP_BUDGET_S", 300)
    names = [f"fn_{i}" for i in range(10)]
    calls = []

    def _fake(ctx, function, **kw):
        calls.append(function)
        clock["t"] += 100.0        # each decompile burns 100s of the 300s budget
        return {"focus": {"name": function, "pseudocode": f"void {function}(){{ memcpy(a,b,c); }}"}}

    monkeypatch.setattr(AT, "_decomp", _fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": names})
        assert calls == names[:3]                      # stopped once the budget was spent
        assert "stopped after 300s" in out
        assert "offset=3" in out                       # ...and says exactly where to resume
        assert "fn_0" in out and "fn_2" in out         # partial results still returned



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
# observations.decompiled_bodies — the pseudocode cache the grep reads before decompiling
# ======================================================================================

def test_decompiled_bodies_normalizes_names_and_takes_the_newest(hg_home):
    """The helper keys on the NORMALIZED name (so a caller's `foo` matches a focus recorded as
    `sym.foo`), returns only the requested names, and lets the NEWEST decompilation win."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        ctx, p, t = _ctx(s)

        def _rec(name, body, args):
            O.record_observation(
                s, project_id=p.id, target_id=t.id, source="agent",
                tool="decompile_function", args=args, result_kind="decompilation",
                payload={"focus": {"name": name, "pseudocode": body}},
                summary=f"decompiled {name}", content_hash=O.content_hash_for(t))

        _rec("sym.parse_request", "OLD BODY", {"function": "parse_request", "v": 1})
        _rec("sym.parse_request", "NEW BODY", {"function": "parse_request", "v": 2})
        _rec("unwanted_fn", "void unwanted_fn(){}", {"function": "unwanted_fn"})

        got = O.decompiled_bodies(s, t.id, names=["parse_request", "never_decompiled"])
        assert got == {"parse_request": "NEW BODY"}    # normalized key, newest wins, scoped to ask


def test_decompiled_bodies_skips_empty_bodies(hg_home):
    """A recorded decompilation with no pseudocode is NOT a usable cache hit — it must be absent
    so the caller decompiles rather than grepping an empty body and reporting a false miss."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_function", args={"function": "hollow_fn"},
            result_kind="decompilation", payload={"focus": {"name": "hollow_fn", "pseudocode": ""}},
            summary="decompiled hollow_fn", content_hash=O.content_hash_for(t))
        assert O.decompiled_bodies(s, t.id, names=["hollow_fn"]) == {}


def test_decompiled_bodies_empty_when_nothing_asked_or_recorded(hg_home):
    from hexgraph.engine import observations as O

    with session_scope() as s:
        ctx, p, t = _ctx(s)
        assert O.decompiled_bodies(s, t.id, names=[]) == {}
        assert O.decompiled_bodies(s, t.id, names=["anything"]) == {}


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


def test_catalog_doc_states_the_grep_cost_before_the_agent_pays_it():
    """An agent can only choose between the cheap scan and the expensive grep if the description
    PRICES them. The grep costs a real decompile per not-yet-decompiled function, which is what
    turned a 30-function call into a ~10-minute one — that has to be visible up front, not
    discovered by waiting."""
    from hexgraph.agent.mcp_catalog import catalog

    tool = {t["name"]: t for t in catalog()}["re_search_code"]
    doc = tool["description"].lower()
    assert "expensive" in doc and "decompile" in doc
    assert "cheap" in doc                               # ...and which mode is the cheap one
    assert "reused" in doc or "reuse" in doc            # already-decompiled bodies come back free
    # the per-function cost is spelled out on the arg that incurs it
    funcs_desc = tool["schema"]["properties"]["functions"]["description"].lower()
    assert "decompile" in funcs_desc


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


# --- xrefs_probe warm-reload flags: reload a committed project, refuse a cold miss (offline) ---

def test_warm_r2_flags_cold_vs_warm(tmp_path):
    """`_warm_r2_flags` is the WARM-ONLY heart of the xrefs probe: it returns the r2 reload flags
    (`dir.projects` + `-p`) ONLY for a committed project (marker + a non-empty named dir), and None
    for a cold/half-written slot (so the probe returns the re_analyze lead instead of running `aaa`).
    Pure filesystem logic — no r2, no Docker."""
    import json as _json

    from hexgraph.sandbox.probes import xrefs_probe as X

    mount = tmp_path / "gp"
    orig = X._PROJECT_MOUNT
    try:
        X._PROJECT_MOUNT = str(mount)
        assert X._warm_r2_flags() is None                     # mount absent
        mount.mkdir()
        assert X._warm_r2_flags() is None                     # no marker, no project
        (mount / X._META_NAME).write_text(_json.dumps({"content_hash": "x"}))
        assert X._warm_r2_flags() is None                     # marker but named dir missing/empty
        named = mount / X._PROJECT_SUBDIR / X._PROJECT_NAME
        named.mkdir(parents=True)
        (named / "hexgraph.d").write_text("state")            # non-empty named project
        flags = X._warm_r2_flags()
        assert flags and "-p" in flags and X._PROJECT_NAME in flags
        assert any("dir.projects=" in f for f in flags)
    finally:
        X._PROJECT_MOUNT = orig
