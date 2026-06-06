"""Phase 2 PR3 — search_decompiled + discoverability wiring (design-re-tooling.md §7).

search_decompiled mines the Observation store (the recorded decompilation BODIES) rather
than re-decompiling, so it's pure-offline: record a couple of decompilation Observations,
then grep across them. Also pins the discoverability wiring (catalog + get_schemas advertise
the verb) and the curation contract (a search is a QUERY — no graph mutation).
"""

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.engine import mcp_tools as M
from hexgraph.engine import observations as O
from hexgraph.engine.agent_tools import ToolContext, run_tool
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="search")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


def _record_decomp(ctx, name, pseudocode):
    O.record_observation(
        ctx.session, project_id=ctx.project.id, target_id=ctx.target.id, source="test",
        tool="decompile_function", args={"function": name}, result_kind="decompilation",
        payload={"focus": {"name": name, "pseudocode": pseudocode, "callees": []}},
        summary=f"decompiled {name}", content_hash="abc123")


def test_search_decompiled_finds_substring_across_bodies(hg_home):
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _record_decomp(ctx, "cgi_handler", 'void cgi_handler(){ system(getenv("QUERY_STRING")); }')
        _record_decomp(ctx, "helper", "int helper(){ return 0; }")
        s.flush()
        nb, eb = s.query(Node).count(), s.query(Edge).count()

        out = run_tool(ctx, "search_decompiled", {"query": "getenv"})
        assert "cgi_handler" in out and "helper" not in out
        assert "getenv" in out  # the snippet shows the match

        # QUERY: zero graph mutation
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        # records its own discoverable Observation
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "search_decompiled").all()
        assert len(obs) == 1


def test_search_decompiled_no_match_hints_to_decompile_first(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        # nothing decompiled yet
        out = run_tool(ctx, "search_decompiled", {"query": "anything"})
        assert "no decompiled body" in out and "decompile_function" in out


def test_search_decompiled_requires_query(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "search_decompiled", {})


def test_search_decompiled_helper_dedups_by_function(hg_home):
    """Two decompilations of the same function → one hit (newest wins)."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _record_decomp(ctx, "f", "old body with TOKEN_A")
        # a second decompilation of the same function (different bytes-era) also matching
        O.record_observation(
            ctx.session, project_id=p.id, target_id=t.id, source="test",
            tool="decompile_function", args={"function": "f"}, result_kind="decompilation",
            payload={"focus": {"name": "f", "pseudocode": "new body with TOKEN_A", "callees": []}},
            summary="decompiled f again", content_hash="def456")
        s.flush()
        hits = O.search_decompiled(s, t.id, query="TOKEN_A")
        assert [h["function"] for h in hits] == ["f"]  # deduped to one


def test_catalog_and_schema_advertise_search_decompiled(hg_home):
    names = {sp["name"] for sp in M.catalog()}
    assert "re_search_decompiled" in names
    gs = M.get_schemas()
    # the observations block names the new grep-the-bodies verb
    assert "search_decompiled" in gs["observations"]["what"]
