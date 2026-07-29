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

import types

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
        # The hint must echo a NON-DEFAULT limit: an agent following it literally would otherwise
        # get the default 50 back — up to 50 decompiles where it deliberately asked for 4.
        assert "limit=4" in out


def test_grep_resume_hint_omits_a_default_limit(hg_home, monkeypatch):
    """...but a DEFAULT limit isn't echoed — noise in the hint the agent doesn't need."""
    names = [f"fn_{i:03d}" for i in range(AT._SEARCH_FUNCS_MAX + 5)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{}}" for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "void", "functions": names})
        assert f"offset={AT._SEARCH_FUNCS_MAX}" in out
        assert "limit=" not in out


def test_grep_offset_past_the_end_is_not_reported_as_a_negative(hg_home, monkeypatch):
    """An out-of-range page searched NOTHING. Reporting that as a clean 'no line contains X' would
    let an agent paging blindly (offset += limit until it runs out) read the boundary page as an
    authoritative negative on its whole candidate set."""
    calls = _stub_decomp_bodies(monkeypatch, {"fn_a": "void fn_a(){ memcpy(a,b,c); }"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": ["fn_a", "fn_b"], "offset": 9})
        assert calls == []                             # nothing decompiled
        assert "past the end" in out and "NOT a negative result" in out
        assert "no line in the searched bodies" not in out   # never the negative phrasing


def test_grep_counter_advances_for_warm_hits_and_miss_paths(hg_home, monkeypatch):
    """The resume contract rests on `searched` counting EVERY name examined — warm hits and the
    two miss paths (decompiler error, no body) included, not just successful decompiles.

    Two regressions this pins: counting only decompiles would make every resume re-do warm work;
    not counting a miss would make a page whose FIRST function persistently errors report an
    unchanged offset, so an agent following the hint loops forever on the same page."""
    from hexgraph.engine import observations as O

    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr(AT, "_SEARCH_GREP_BUDGET_S", 300)

    def _fake(ctx, function, **kw):
        clock["t"] += 200.0            # each decompile burns 200s of the 300s budget
        if function == "ghost_fn":
            return {"functions": [], "focus": None}    # examined, but yields no body
        return {"focus": {"name": function, "pseudocode": f"void {function}(){{ memcpy(a,b,c); }}"}}

    monkeypatch.setattr(AT, "_decomp", _fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_function", args={"function": "warm_fn"},
            result_kind="decompilation",
            payload={"focus": {"name": "warm_fn", "pseudocode": "void warm_fn(){ memcpy(x,y,z); }"}},
            summary="decompiled warm_fn", content_hash=O.content_hash_for(t))

        # warm_fn (free) -> ghost_fn (examined, no body, 200s) -> c1 (200s) -> budget spent.
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy",
                        "functions": ["warm_fn", "ghost_fn", "c1", "c2", "c3"]})
        assert "stopped after" in out
        # 3 examined: the warm hit AND the no-body miss both advanced the counter.
        assert "offset=3" in out
        assert "over 3 of 5" in out
        assert "ghost_fn" in out                       # the miss is reported, not silently dropped


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
    # Two functions is deliberately BELOW _BRIDGE_NUDGE_MIN_COLD, so the nudge branch (which has a
    # release of its own) can't run and this stays a clean per-decompile assertion. Pinned, so the
    # exact sequence below doesn't silently depend on that constant staying above 2.
    assert len(["a_fn", "b_fn"]) < AT._BRIDGE_NUDGE_MIN_COLD
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "search_code", {"query": "log", "functions": ["a_fn", "b_fn"]})
    assert order == ["release", "decompile:a_fn", "release", "decompile:b_fn"]


def test_grep_releases_the_write_lock_before_the_bridge_probe(hg_home, monkeypatch):
    """The nudge branch's own release, which nothing pinned — removing it broke no test.

    `_bridge_live` shells out to `docker inspect` when a bridge entry exists, and this runs inside
    the tool's session_scope, so it is a slow op like the decompiles below it. Every other slow op
    on this path releases first (and test_db_lock_contention pins eleven such sites individually);
    this one was the odd one out."""
    order = []
    monkeypatch.setattr(AT, "_bridge_is_offerable", lambda: True)
    monkeypatch.setattr(AT, "_bridge_live",
                        lambda t: order.append("bridge_probe") or False)
    monkeypatch.setattr(AT, "_decomp",
                        lambda ctx, function, **kw: order.append(f"decompile:{function}") or
                        {"focus": {"name": function, "pseudocode": "void f(){ log(); }"}})
    monkeypatch.setattr("hexgraph.db.session.release_write_lock",
                        lambda sess: order.append("release"))

    names = [f"fn_{i}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "search_code", {"query": "log", "functions": names})

    assert order[:2] == ["release", "bridge_probe"]     # released BEFORE the docker call
    assert order[2] == "release"                        # ...and the per-decompile ones still fire
    assert order[3] == "decompile:fn_0"


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

        # A budget-stopped run is recorded as `partial`, never `ok`: only ok rows dedup, and a
        # wall-clock-bounded result is not the deterministic "analyze once, reuse forever" kind,
        # so an ok row here would shadow a later COMPLETE run of the same args with a short payload.
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "search_code").all()
        assert len(obs) == 1 and obs[0].status == "partial"


def test_budget_stopped_partial_does_not_shadow_a_later_complete_run(hg_home, monkeypatch):
    """The dedup consequence, end to end: re-calling the SAME args after a budget stop must record
    a fresh COMPLETE Observation rather than returning the stale partial one."""
    clock = {"t": 1000.0}
    monkeypatch.setattr("time.monotonic", lambda: clock["t"])
    monkeypatch.setattr(AT, "_SEARCH_GREP_BUDGET_S", 300)
    names = [f"fn_{i}" for i in range(5)]
    burn = {"on": True}

    def _fake(ctx, function, **kw):
        if burn["on"]:
            clock["t"] += 100.0
        return {"focus": {"name": function, "pseudocode": f"void {function}(){{ memcpy(a,b,c); }}"}}

    monkeypatch.setattr(AT, "_decomp", _fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        args = {"query": "memcpy", "functions": names}
        out1 = run_tool(ctx, "search_code", dict(args))
        assert "stopped after" in out1

        # Same args again, this time with budget to spare (and a fresh per-call decompile cache).
        burn["on"] = False
        clock["t"] = 1000.0
        ctx.cache.clear()
        out2 = run_tool(ctx, "search_code", dict(args))
        assert "stopped after" not in out2
        assert "over 5 of 5" in out2                   # the complete run really completed

        rows = s.query(Observation).filter(Observation.target_id == t.id,
                                           Observation.result_kind == "search_code").all()
        statuses = sorted(r.status for r in rows)
        assert statuses == ["ok", "partial"]           # the partial did NOT dedup-shadow the complete run



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


def test_grep_truncation_names_the_observation_holding_every_hit(hg_home, monkeypatch):
    """A grep over a full page can match far more than the inline cap. Truncation must be
    RECOVERABLE, never silent: the marker names obs_get + the full size, because every hit is in
    the Observation and a cut tail must not hide a call site the agent was searching for."""
    # One function whose body matches on thousands of lines — comfortably past the inline cap.
    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(2000))
    _stub_decomp_bodies(monkeypatch, {"huge_fn": body})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": ["huge_fn"]})
        assert len(out) <= AT._MAX + 400              # clipped to the inline cap (+ the marker)
        assert "truncated" in out.lower()
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "search_code").one()
        assert obs.id in out                          # the marker points at the full payload


def test_truncation_marker_only_names_recovery_paths_that_exist(hg_home, monkeypatch):
    """The marker tells the agent how to recover a clipped body. Every path it names must be REAL:
    it advertises `max_chars`, so `max_chars` has to be an advertised param of this tool AND
    accepted by the MCP wrapper. Naming a param the tool doesn't take is a hard TypeError over
    MCP, and — worse because it's silent — a no-op on the in-process agent-loop path."""
    from hexgraph.agent import mcp_tools
    from hexgraph.agent.mcp_catalog import catalog

    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(2000))
    _stub_decomp_bodies(monkeypatch, {"huge_fn": body})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": ["huge_fn"]})
        assert "max_chars" in out                       # the marker advertises it...

    # ...so it must exist on BOTH advertised surfaces and on the callable.
    spec = {sp.name: sp for sp in AT._STATIC_SPECS}["search_code"]
    assert "max_chars" in spec.input_schema["properties"]
    entry = {x["name"]: x for x in catalog()}["re_search_code"]
    assert "max_chars" in entry["schema"]["properties"]
    import inspect
    assert "max_chars" in inspect.signature(mcp_tools.search_code).parameters


def test_max_chars_raises_the_inline_cap_in_both_modes(hg_home, monkeypatch):
    """A param advertised on the tool must WORK in whichever mode the agent used — otherwise a
    scan caller gets it silently ignored, the quiet version of the same defect."""
    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(2000))
    _stub_decomp_bodies(monkeypatch, {"huge_fn": body})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        small = run_tool(ctx, "search_code", {"query": "memcpy", "functions": ["huge_fn"]})
        ctx.cache.clear()
        big = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": ["huge_fn"], "max_chars": 20000})
        assert len(big) > len(small)                    # grep mode honours it

    hits = [{"addr": hex(0x400000 + i), "in_function": f"fn_{i}"} for i in range(400)]
    _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search", "kind": "bytes",
                              "pattern": "90", "hits": hits, "total": 400})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        small = run_tool(ctx, "search_code", {"bytes_pattern": "90", "limit": 400})
        ctx.cache.clear()
        big = run_tool(ctx, "search_code",
                       {"bytes_pattern": "90", "limit": 400, "max_chars": 20000})
        assert len(big) > len(small)                    # scan mode honours it too
        assert "max_chars" in small                     # ...and its marker is the actionable one


def test_truncation_keeps_the_paging_hint_in_both_modes(hg_home, monkeypatch):
    """Clipping must never eat the resume line. Appending the hint and then clipping the whole
    string drops it exactly when the result is big — precisely when the agent most needs to know
    more pages exist. Both surviving recovery paths (a bigger max_chars, obs_get) return only the
    CURRENT page, so losing the line leaves no signal that there IS a next one."""
    # Grep: page 2 of 10 functions, each body long enough to overflow the inline cap.
    names = [f"fn_{i:02d}" for i in range(10)]
    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(400))
    _stub_decomp_bodies(monkeypatch, {n: body for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": names, "limit": 2})
        assert "truncated" in out.lower()               # it really did overflow...
        assert "8 more" in out and "offset=2" in out    # ...and the resume line survived
        assert "limit=2" in out                         # including the non-default page size

    # Scan: a full 500-hit page, likewise past the cap.
    hits = [{"addr": hex(0x400000 + i), "in_function": f"some_longish_function_name_{i}"}
            for i in range(600)]
    _wire_probe(monkeypatch, {"tool": "xrefs_probe", "mode": "search", "kind": "bytes",
                              "pattern": "90", "hits": hits, "total": 600})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"bytes_pattern": "90", "limit": 500})
        assert "truncated" in out.lower()
        assert "100 more" in out and "offset=500" in out
        assert "limit=500" in out


def test_advertised_max_chars_actually_returns_the_untruncated_result(hg_home, monkeypatch):
    """The marker's `max_chars≥N` must be a number that WORKS — follow it once and the result is
    whole. Asserting only that the hint survives a clip is not enough: reserving room for the hint
    makes the advertised N a fixed point unless the clip is told about the reservation (raising
    max_chars raises the reservation by the same amount, so the re-call truncates again and prints
    the identical N — an agent following the instruction loops forever)."""
    import re as _re

    names = [f"fn_{i:02d}" for i in range(10)]
    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(400))
    _stub_decomp_bodies(monkeypatch, {n: body for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        first = run_tool(ctx, "search_code",
                         {"query": "memcpy", "functions": names, "limit": 2})
        assert "truncated" in first.lower()
        m = _re.search(r"max_chars≥(\d+)", first)
        assert m, f"no max_chars knob advertised in: {first[-200:]}"

        ctx.cache.clear()
        second = run_tool(ctx, "search_code",
                          {"query": "memcpy", "functions": names, "limit": 2,
                           "max_chars": int(m.group(1))})
        # ONE follow-up of the advertised size returns the whole thing — hint still attached.
        assert "truncated" not in second.lower()
        assert "8 more" in second and "offset=2" in second


def _bridge_offerable(monkeypatch):
    """Make the managed bridge a REAL option for these tests: headless Ghidra active AND
    features.network on. The nudge is gated on both, so every nudge test — the NEGATIVES most of
    all — has to establish this first, or a "no nudge" assertion passes for the wrong reason: the
    default install is radare2 + no network, where the bridge is never offered whatever the sweep
    looks like. (`_decomp` is stubbed in these tests, so naming a decompiler runs nothing.)"""
    monkeypatch.setenv("HEXGRAPH_DECOMPILER", "ghidra")
    monkeypatch.setattr("hexgraph.policy.current_policy",
                        lambda: types.SimpleNamespace(allow_network=True))


def test_grep_names_the_bridge_when_a_cold_sweep_would_pay_for_it(hg_home, monkeypatch):
    """The grep knows its own cost before it pays it — it counts cold functions before the loop —
    so it can say when a resident bridge is worth starting.

    Measured on a ~940MB image: ~20s/call headless against ~9s/call resident, a ~6s one-off boot.
    So the nudge belongs on a COLD sweep of several functions, and nowhere else: not when the
    bodies are already in the Observation store (those cost nothing), and not when a bridge is
    already up (it's being used)."""
    names = [f"fn_{i:02d}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint", lambda t: None)
    _bridge_offerable(monkeypatch)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": names})
        assert "re_bridge_start" in out
        assert "9s" in out or "20s" in out          # states the measured cost, not a vague "faster"


def test_the_bridge_nudge_keeps_its_provenance_and_its_exceptions(hg_home, monkeypatch):
    """What the nudge SAYS has to survive being shortened, because a short summary of a caveated
    claim is how a helpful line becomes a trap.

    Two things it must not drop. The measurement keeps the target it was taken on (~940MB) — it's
    one datapoint, and an agent can only judge how far it transfers if it's told what it came from.
    And the bridge OWNS the project, so re_script and a COLD re_analyze/re_reanalyze — each of
    which opens the project itself — FAIL while it's up (mcp_catalog's re_bridge_start entry says
    exactly this, and vr_skill repeats it). "It costs no capability" WITHOUT those two named is
    strictly more wrong than the text it summarises."""
    names = [f"fn_{i:02d}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint", lambda t: None)
    _bridge_offerable(monkeypatch)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": names})
        assert "940MB" in out, "the measurement lost the target it was taken on"
        for op in ("re_script", "re_reanalyze", "re_bridge_stop"):
            assert op in out, f"the nudge doesn't name {op}, which the bridge blocks/needs"


def test_grep_does_NOT_nudge_when_the_bridge_is_not_an_option(hg_home, monkeypatch):
    """Advice an agent can't act on is worse than silence: it costs a turn AND teaches a false cost
    model. The managed bridge is headless-Ghidra-only and network-gated, so on the DEFAULT install
    nothing is "re-opening a Ghidra project per call" (radare2 is decompiling, and persists its own
    project) and re_bridge_start would answer denied/unavailable. Three non-offerable installs, one
    reason each — then the same sweep WITH both in place, so these negatives can't pass for some
    unrelated reason the nudge never appears."""
    names = [f"fn_{i:02d}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint", lambda t: None)
    net_on = lambda: types.SimpleNamespace(allow_network=True)          # noqa: E731
    with session_scope() as s:
        ctx, p, t = _ctx(s)

        def _call():
            return run_tool(ctx, "search_code", {"query": "memcpy", "functions": names})

        # the default decompiler: no Ghidra project is being re-opened, so there's nothing to fix
        monkeypatch.setattr("hexgraph.policy.current_policy", net_on)
        monkeypatch.setenv("HEXGRAPH_DECOMPILER", "radare2")
        assert "re_bridge_start" not in _call()

        # ghidra_bridge mode attaches to the researcher's OWN Ghidra — no warm project of ours for
        # a managed bridge to serve, so start_bridge answers 'unavailable'
        monkeypatch.setenv("HEXGRAPH_DECOMPILER", "ghidra_bridge")
        assert "re_bridge_start" not in _call()

        # headless Ghidra, but egress is still gated -> start_bridge answers 'denied'
        monkeypatch.setenv("HEXGRAPH_DECOMPILER", "ghidra")
        monkeypatch.setattr("hexgraph.policy.current_policy",
                            lambda: types.SimpleNamespace(allow_network=False))
        assert "re_bridge_start" not in _call()

        # ...and with both in place the SAME sweep does fire
        monkeypatch.setattr("hexgraph.policy.current_policy", net_on)
        assert "re_bridge_start" in _call()


def test_grep_does_NOT_nudge_when_a_bridge_is_already_live(hg_home, monkeypatch):
    """Telling an agent to start what it already started is noise it pays context for."""
    names = [f"fn_{i:02d}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint",
                        lambda t: ("172.17.0.9", 4768))
    _bridge_offerable(monkeypatch)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "search_code", {"query": "memcpy", "functions": names})
        assert "re_bridge_start" not in out


def test_grep_does_NOT_nudge_for_a_warm_or_small_sweep(hg_home, monkeypatch):
    """No nudge when there's nothing to save: bodies already in the store are free, and a couple of
    cold functions don't repay a container."""
    from hexgraph.engine import observations as O

    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint", lambda t: None)
    _bridge_offerable(monkeypatch)
    names = [f"fn_{i:02d}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # all warm -> nothing to speed up
        for n in names:
            O.record_observation(
                s, project_id=p.id, target_id=t.id, source="agent",
                tool="decompile_function", args={"function": n}, result_kind="decompilation",
                payload={"focus": {"name": n, "pseudocode": f"void {n}(){{ memcpy(a,b,c); }}"}},
                summary=f"decompiled {n}", content_hash=O.content_hash_for(t), node_refs=[n])
        assert "re_bridge_start" not in run_tool(
            ctx, "search_code", {"query": "memcpy", "functions": names})

        # a cold sweep BELOW the threshold -> not worth a container
        few = [f"cold_{i}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD - 1)]
        _stub_decomp_bodies(monkeypatch, {n: f"void {n}(){{ memcpy(a,b,c); }}" for n in few})
        assert "re_bridge_start" not in run_tool(
            ctx, "search_code", {"query": "memcpy", "functions": few})


def test_nudge_counts_only_the_COLD_functions_and_survives_a_clip(hg_home, monkeypatch):
    """Two gaps the first pass left.

    The printed count must be the COLD subset, not the whole sweep — every earlier test used an
    all-cold or all-warm set, so `{cold_total}` -> `{total}` passed all of them. Warm bodies cost
    nothing, so quoting the total would overstate what a bridge saves.

    And the nudge must survive truncation. It is worth most on a big cold sweep, which is exactly
    the result that overflows the inline cap, so it rides in the reserved tail with the paging hint
    rather than in the clippable body."""
    from hexgraph.engine import observations as O

    monkeypatch.setattr("hexgraph.engine.re.bridge.bridge_endpoint", lambda t: None)
    monkeypatch.setattr(AT, "_bridge_is_offerable", lambda: True)
    warm_names = [f"warm_{i}" for i in range(4)]
    cold_names = [f"cold_{i}" for i in range(AT._BRIDGE_NUDGE_MIN_COLD)]
    # long bodies so the rendered result overflows the inline cap
    body = "\n".join(f"  memcpy(dst_{i}, src, n);" for i in range(400))
    _stub_decomp_bodies(monkeypatch, {n: body for n in warm_names + cold_names})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        for n in warm_names:
            O.record_observation(
                s, project_id=p.id, target_id=t.id, source="agent",
                tool="decompile_function", args={"function": n}, result_kind="decompilation",
                payload={"focus": {"name": n, "pseudocode": body}},
                summary=f"decompiled {n}", content_hash=O.content_hash_for(t), node_refs=[n])
        out = run_tool(ctx, "search_code",
                       {"query": "memcpy", "functions": warm_names + cold_names})

    assert "truncated" in out.lower()                    # it really did overflow...
    assert "re_bridge_start" in out                      # ...and the nudge survived the clip
    n_cold = AT._BRIDGE_NUDGE_MIN_COLD
    assert f"[{n_cold} of these need a real decompile" in out   # the COLD count...
    assert f"[{n_cold + len(warm_names)} of these" not in out   # ...not the whole sweep


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


def test_decompiled_bodies_does_not_scan_the_whole_store_for_a_cold_name(hg_home, monkeypatch):
    """The pre-filter that makes this helper cheap in the case it actually runs in.

    Resolving every name lets the loop exit early, but a MIXED warm/cold candidate set — the grep's
    normal input — never resolves everything. Without gating the CAS read on the row's stored
    `node_refs`/args, one never-decompiled name makes the helper read and JSON-parse every
    decompilation blob on the target, and a paged walk re-pays that per page over a store it is
    itself growing. Pin the read count, not just the answer."""
    from hexgraph.engine import cas as _cas
    from hexgraph.engine import observations as O

    with session_scope() as s:
        ctx, p, t = _ctx(s)
        for i in range(25):
            O.record_observation(
                s, project_id=p.id, target_id=t.id, source="agent",
                tool="decompile_function", args={"function": f"other_{i}"},
                result_kind="decompilation",
                payload={"focus": {"name": f"other_{i}", "pseudocode": f"void other_{i}(){{}}"}},
                summary=f"decompiled other_{i}", content_hash=O.content_hash_for(t),
                node_refs=[f"other_{i}"])
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_function", args={"function": "warm_fn"},
            result_kind="decompilation",
            payload={"focus": {"name": "warm_fn", "pseudocode": "void warm_fn(){ memcpy(x,y,z); }"}},
            summary="decompiled warm_fn", content_hash=O.content_hash_for(t),
            node_refs=["warm_fn"])

        reads = []
        real = _cas.get_text
        monkeypatch.setattr(_cas, "get_text",
                            lambda proj, ref: (reads.append(ref), real(proj, ref))[1])

        # One warm name + one that was never decompiled: the early exit CANNOT fire.
        got = O.decompiled_bodies(s, t.id, names=["warm_fn", "never_decompiled"])
        assert set(got) == {"warm_fn"}                 # correct answer...
        assert len(reads) == 1                         # ...for ONE blob read, not all 26


def test_decompiled_bodies_still_reads_a_row_with_no_name_hint(hg_home):
    """The pre-filter's strict-superset guarantee: a row whose columns carry NO usable name hint
    must still be opened, because an empty candidate set means "can't tell", never "doesn't match".

    Every producer today writes the focus name into node_refs, so this guards a future one that
    doesn't — exactly the case where tightening `if cands and …` into `if not (cands & …)` would
    start silently losing bodies while the rest of the suite stayed green."""
    from hexgraph.engine import observations as O

    with session_scope() as s:
        ctx, p, t = _ctx(s)
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="agent",
            tool="decompile_at", args={"address": "0x401000"},   # no `function` arg...
            result_kind="decompilation",
            payload={"focus": {"name": "hintless_fn", "pseudocode": "void hintless_fn(){ x(); }"}},
            summary="decompiled 0x401000", content_hash=O.content_hash_for(t),
            node_refs=[])                                        # ...and no node_refs either
        got = O.decompiled_bodies(s, t.id, names=["hintless_fn"])
        assert got == {"hintless_fn": "void hintless_fn(){ x(); }"}


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
