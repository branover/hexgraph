"""Curation invariants for the tool layer (Phase O, PR 3, design §5.3 / §9).

This is where the query/enrich/promote contract actually FIRES in production: the
real tools record Observations and the graph stays a curated result set. Covers:

- a QUERY verb creates no nodes/edges AND records an Observation,
- the both-endpoints-exist rule: a `calls` edge is never drawn to a callee that isn't
  already a node (no fan-out); decompiling F promotes F but not its callees,
- the per-call promotion budget caps and REPORTS overflow (no silent truncation),
- producers pass content_hash_for(target) so extract-at-write enrichment fires.

Mock backend, offline — no Docker, no key (these exercise the curation plumbing
directly, not the sandboxed decompiler).
"""

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent import agent_tools as AT
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="curate")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123",
                       "strings": ["/cgi-bin/admin", "token=secret"]}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


# --- a query verb creates no nodes/edges and records an Observation -----------

def test_query_verb_records_observation_and_mutates_no_graph(hg_home):
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nodes_before = s.query(Node).count()
        edges_before = s.query(Edge).count()

        out = run_tool(ctx, "list_strings", {"pattern": "cgi"})
        assert "/cgi-bin/admin" in out

        # ZERO graph mutation — an enumeration is an answer, not a graph object.
        assert s.query(Node).count() == nodes_before
        assert s.query(Edge).count() == edges_before
        # But it IS recorded as a discoverable Observation, scoped to the target's bytes.
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "strings").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "abc123"  # content_hash_for(target) was passed


def test_query_observation_dedups_on_rerun(hg_home):
    """A repeat identical query reuses the prior Observation (analyze once) — no second row."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        run_tool(ctx, "list_strings", {})
        ctx.cache.clear()  # force the tool to actually run again, not hit the in-call cache
        run_tool(ctx, "list_strings", {})
        assert s.query(Observation).filter(Observation.target_id == t.id,
                                           Observation.result_kind == "strings").count() == 1


# --- _materialize: promote F, never mass-create its callees -------------------

def test_materialize_promotes_focus_only_not_callees(hg_home):
    """Decompiling F adds F (+ enrichment) but NOT its callees; uncurated callees
    surface as promotable; edges appear only to already-present callees."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        focus = {"name": "cgi_handler", "address": "0x401200",
                 "pseudocode": "void cgi_handler(){ system(x); helper(); }",
                 "callees": ["system", "helper", "strcpy"]}
        promotable = AT._materialize(ctx, focus)

        fns = s.query(Node).filter(Node.node_type == "function", Node.target_id == t.id).all()
        # Only the FOCUS function was promoted — none of the three callees.
        assert {f.name for f in fns} == {"cgi_handler"}
        # All callees surface as promotable (none were already curated).
        assert set(promotable) == {"system", "helper", "strcpy"}
        # No `calls` edge to a non-existent endpoint.
        assert s.query(Edge).filter(Edge.type == "calls").count() == 0


def test_materialize_draws_edge_only_to_existing_callee(hg_home):
    """The both-endpoints-exist rule: a `calls` edge materializes for a callee already
    in the graph, while a not-yet-curated callee is reported instead of spawned."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # Pre-curate ONE callee.
        get_or_create_node(s, project_id=p.id, node_type="function", name="helper", target_id=t.id)
        focus = {"name": "cgi_handler", "address": "0x401200",
                 "pseudocode": "x", "callees": ["helper", "ghost"]}
        promotable = AT._materialize(ctx, focus)

        # ghost was NOT minted; helper got an edge.
        assert promotable == ["ghost"]
        names = {f.name for f in s.query(Node).filter(Node.node_type == "function").all()}
        assert "ghost" not in names and {"cgi_handler", "helper"} <= names
        edges = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(edges) == 1


# --- producers pass content_hash so enrichment fires on the promoted focus ---

def test_decompile_records_then_promotes_enriched_focus(hg_home):
    """Mirrors _decomp's real ordering (record the decompilation Observation, THEN
    promote the focus): because the producer passes content_hash_for(target), the
    extract-at-write facts are indexed under the right hash, so the freshly-promoted
    focus node pulls its recovered prototype/calling_convention at create."""
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        focus = {"name": "cgi_handler", "address": "0x401200",
                 "prototype": "int cgi_handler(char*)", "calling_convention": "cdecl",
                 "pseudocode": "x", "callees": []}
        # 1) record (what _decomp does first) — content_hash_for(target) is passed inside.
        obs, _cached = AT._record_obs(
            ctx, tool="decompile_function", args={"function": "cgi_handler"},
            result_kind="decompilation", payload={"focus": focus}, summary="cgi_handler")
        assert obs is not None and obs.content_hash == "abc123"
        # 2) promote the focus — join-at-create enriches it from the just-indexed facts.
        AT._materialize(ctx, focus)
        node = s.query(Node).filter(Node.node_type == "function",
                                    Node.fq_name == "cgi_handler").one()
        a = node.attrs_json or {}
        assert a.get("prototype") == "int cgi_handler(char*)"
        assert a.get("calling_convention") == "cdecl"
        assert a.get("provenance")  # the source Observation was recorded on the node


# --- per-call promotion budget caps and REPORTS overflow ---------------------

def test_promote_budget_caps_and_reports_overflow(hg_home, monkeypatch):
    """A single call adds at most the budget; the overflow is REPORTED as promotable
    (never silently truncated)."""
    monkeypatch.setattr(AT, "_PROMOTE_BUDGET", 3)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        # Pre-curate 5 callees so each WOULD get an edge if the budget allowed.
        callees = [f"c{i}" for i in range(5)]
        for c in callees:
            get_or_create_node(s, project_id=p.id, node_type="function", name=c, target_id=t.id)
        focus = {"name": "root", "address": "0x1", "pseudocode": "x", "callees": callees}
        promotable = AT._materialize(ctx, focus)

        # Budget 3 = 1 focus node + 2 edges; the remaining 3 callees overflow and are reported.
        edges = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(edges) == 2
        assert len(promotable) == 3  # reported, not dropped
        assert set(promotable) <= set(callees)
