"""list_functions GREPs the FULL discovered function list with offset/limit pagination.

The old `list_functions` branch did `'\n'.join(functions[:300])` — a hard truncation with no
filter/paging, so on a large binary the function you wanted could be past index 300 and invisible.
Now it mirrors `list_strings`: a server-side substring/regex grep over the decompiler's whole-
program name list, paginated (default 200, max 1000), reporting the total + the next offset — and
recording the returned PAGE as a discoverable function_list_page Observation. Zero graph mutation.

Offline + mock: the whole-program name list comes from the sandboxed decompiler, so these
monkeypatch `_decomp` to stand in for it — the unit under test is the grep/pagination in
`_list_functions`, not the sandboxed decompile itself (mirrors how test_list_strings stubs the
binutils probe). Stubbing `_decomp` also means it records NO Observation of its own, so the ONE
function_list_page Observation the test asserts is unambiguously `_list_functions`' page.
"""

import hexgraph.agent.agent_tools as AT
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


# A large synthetic inventory: 500 `sub_*` noise names + a couple of real ones to grep for.
_FUNCS = [f"sub_{i:04d}" for i in range(500)] + ["parse_http", "wrap_strcpy"]


def _ctx(s):
    p = create_project(s, name="listfn")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "fn123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


def _stub_decomp(monkeypatch, functions):
    """Stand in for the sandboxed decompiler inventory — return a fixed function-name list and
    record NOTHING (so _list_functions owns the sole Observation).

    list_functions is (correctly) in _ANALYSIS_GATED_TOOLS, and since #263 the analysis gate is
    backend-aware, so run_tool short-circuits to the re_analyze lead BEFORE _list_functions runs
    unless a saved analysis exists. The grep/pagination unit under test is the tool body, not the
    gate — so satisfy the gate the same way test_analysis_gate / test_breadth_xrefs do: force
    analysis_state to 'analyzed'. (The gate itself is asserted separately by
    test_analysis_gate_precedes_work_on_ghidra_miss, which does NOT call this helper.)"""
    monkeypatch.setattr(AT, "_decomp", lambda ctx, function, **kw: {"functions": list(functions)})
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})


# --- the grep: a pattern filters by name, the noise is excluded --------------------------

def test_pattern_filters_by_name(hg_home, monkeypatch):
    """`parse` returns parse_http and NOT the sub_* noise — the whole point of the name grep."""
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {"pattern": "parse"})
        assert "parse_http" in out
        assert "sub_0000" not in out and "sub_0100" not in out
        assert "1 total" in out


def test_no_pattern_pages_the_whole_list(hg_home, monkeypatch):
    """With no pattern it pages the WHOLE inventory (502 names), page-1 of the default 200."""
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {})
        assert "502 total" in out
        assert "sub_0000" in out
        assert "302 more" in out and "offset=200" in out   # 502 - 200 = 302 remaining


# --- pagination over a large match set ---------------------------------------------------

def test_pagination_bounds_and_reports_next_offset(hg_home, monkeypatch):
    """A broad grep is bounded to a page and reports the total + next offset (no silent clip)."""
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {"pattern": "sub_", "limit": 10})
        assert "500 total" in out
        assert "sub_0000" in out and "sub_0009" in out
        assert "sub_0010" not in out                       # clipped to the page
        assert "490 more" in out and "offset=10" in out

        ctx.cache.clear()
        out2 = run_tool(ctx, "list_functions", {"pattern": "sub_", "limit": 10, "offset": 10})
        assert "sub_0010" in out2 and "sub_0019" in out2
        assert "sub_0009" not in out2


def test_reports_true_total_when_inventory_capped(hg_home, monkeypatch):
    """When the decompiler returns a bounded slice of a larger inventory (functions_total exceeds the
    returned list), the tool reports the TRUE total — the fix for a large firmware reading as 'only
    400 functions' — and notes how many functions are beyond the returned inventory."""
    monkeypatch.setattr(
        AT, "_decomp",
        lambda ctx, function, **kw: {"functions": [f"sub_{i:04d}" for i in range(300)],
                                     "functions_total": 8000})
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {})
        assert "8000 total" in out                 # the TRUE count, not 300 (the returned slice)
        assert "8000 functions defined" in out      # the capping note names the true inventory size
        assert "7700 are beyond" in out             # 8000 - 300 withheld from the returned inventory


def test_limit_is_clamped_to_ceiling(hg_home, monkeypatch):
    """An over-large limit clamps to the 1000 ceiling and still says there's more."""
    big = [f"fn_{i:05d}" for i in range(2500)]
    _stub_decomp(monkeypatch, big)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {"pattern": "fn_", "limit": 99999})
        assert "2500 total" in out
        assert "showing 0-1000" in out                     # clamped to the ceiling, not 99999
        assert "1500 more" in out and "offset=1000" in out


# --- regex is a guarded bonus: a bad regex FALLS BACK to substring (no crash) ------------

def test_regex_matches_when_valid(hg_home, monkeypatch):
    """A valid regex greps the names (case-insensitive)."""
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {"pattern": r"^parse_.*", "regex": True})
        assert "parse_http" in out and "sub_0000" not in out


def test_bad_regex_falls_back_to_substring(hg_home, monkeypatch):
    """A pattern that doesn't compile as a regex must NOT crash — it degrades to a substring
    test. '[' is an unterminated character class; as a literal substring it matches nothing here,
    so the tool returns cleanly with 0 total rather than raising."""
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "list_functions", {"pattern": "[", "regex": True})
        assert "error" not in out.lower()
        assert "0 total" in out


# --- QUERY contract: exactly one function_list Observation, zero graph mutation ----------

def test_records_one_observation_and_no_graph(hg_home, monkeypatch):
    _stub_decomp(monkeypatch, _FUNCS)
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "list_functions", {"pattern": "parse"})
        # Pure QUERY: no nodes, no edges.
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        # Exactly one function_list_page Observation (the page), scoped to the analyzed bytes.
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "function_list_page").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "fn123"


# --- the analysis gate still fronts list_functions (Ghidra-active warm miss) -------------

def test_analysis_gate_precedes_work_on_ghidra_miss(hg_home, monkeypatch):
    """list_functions is analysis-gated: on a Ghidra-active warm MISS the re_analyze lead is
    returned BEFORE any decompiler work (the decompiler is never reached — it explodes if called)."""
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target, **kw: {"state": "none", "detail": "(none)"})

    def _explode(ctx, function, **kw):
        raise AssertionError("must not decompile when gated")

    monkeypatch.setattr(AT, "_decomp", _explode)
    with session_scope() as s:
        out = run_tool(_ctx(s), "list_functions", {"pattern": "parse"})
        assert "re_analyze" in out and "No saved analysis" in out


def test_list_functions_is_analysis_gated():
    """The engine name stays in the gated set (unchanged from the old branch)."""
    assert "list_functions" in AT._ANALYSIS_GATED_TOOLS


# ======================================================================================
# Truncation markers: one implementation, and each names only recovery paths that EXIST
# ======================================================================================

def _huge_strings(n=400, width=200):
    return [f"S{i:03d}_" + "x" * width for i in range(n)]


def test_paginated_listers_name_the_observation_id_not_a_max_chars_they_lack(hg_home, monkeypatch):
    """The three paginated listers hand-rolled their own clip budget. Consolidating them onto
    `_clip_with_hint` must NOT hand them `_clip_body`'s default marker, because that advertises
    `max_chars` — a param re_list_strings / re_list_functions / re_symbol do not accept, so
    following it is a hard TypeError over MCP (the #299 finding-9 defect, three more times).

    Their real recovery is the Observation, so the marker must carry its ID — today it says a bare
    "obs_get" with no id, leaving the agent to go and find it."""
    import hexgraph.agent.agent_tools as AT
    from hexgraph.agent.mcp_catalog import catalog
    from hexgraph.db.models import Observation

    props = {x["name"]: (x["schema"].get("properties") or {}) for x in catalog()}
    for name in ("re_list_strings", "re_list_functions", "re_symbol"):
        assert "max_chars" not in props[name], f"{name} grew max_chars — revisit this test"

    monkeypatch.setattr(AT, "_scan_artifact_strings",
                        lambda path, pat: (_huge_strings(), False))
    with session_scope() as s:
        ctx = _ctx(s)
        t = ctx.target
        # a page that leaves a remainder, so the paging tail exists to be preserved
        out = run_tool(ctx, "list_strings", {"limit": 200})
        assert "truncated" in out.lower()
        assert "max_chars" not in out          # never advertise what the tool can't take
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "strings").all()
        assert obs and obs[0].id in out        # the ID, so the agent can act without a lookup
        assert "200 more" in out and "offset=200" in out   # paging hint survived the clip


def test_decompile_keeps_its_promotable_callees_note_through_a_clip(hg_home, monkeypatch):
    """Finding 12 from the #298 review. `note` — the not-yet-promoted callees an agent may want to
    decompile next — was concatenated LAST, after the pseudocode, so a long function clipped it away
    first. It's the actionable half of the result: the pseudocode is what you read, the note is what
    you do next."""
    import hexgraph.agent.agent_tools as AT

    body = "\n".join(f"  int v{i} = compute_{i}();" for i in range(2000))
    monkeypatch.setattr(AT, "_decomp", lambda ctx, function, **kw: {
        "focus": {"name": function, "pseudocode": body,
                  "callees": [{"name": "helper_a"}, {"name": "helper_b"}]},
        "promotable_callees": ["helper_a", "helper_b"],
        "observation_id": "obs-123",
    })
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})
    with session_scope() as s:
        out = run_tool(_ctx(s), "decompile_function", {"function": "big_fn"})
    assert "truncated" in out.lower()
    # Assert the NOTE's own text, not the callee names — those also appear in the header's
    # "(callees: …)" list, so matching on them passes whether or not the note survived.
    assert "callees not yet in the graph" in out
    assert out.index("callees not yet in the graph") > out.index("truncated")  # after the clip
