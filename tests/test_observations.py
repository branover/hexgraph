"""The Observation store (Phase O, PR 1): storage + discoverability.

Covers record/dedup/CAS, the read verbs (list/get/search), the provenance helpers,
the context-bundle observation index, the MCP verb registration + an agent-loop
round-trip, and the curation invariant (recording an Observation creates NO graph
nodes/edges). Mock backend, offline — no Docker, no key."""

import json

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.engine import cas, observations as O
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def _seed():
    """A project + one target; returns (project_id, target_id)."""
    with session_scope() as s:
        p = create_project(s, name="obs")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "deadbeef"}
        s.flush()
        return p.id, t.id


# --- record / dedup / CAS -----------------------------------------------------

def test_record_writes_cas_and_sets_fields(hg_home):
    pid, tid = _seed()
    payload = {"functions": ["main", "cgi_handler"], "count": 2}
    with session_scope() as s:
        obs, cached = O.record_observation(
            s, project_id=pid, target_id=tid, source="task-1", tool="list_functions",
            args={}, result_kind="function_list", payload=payload,
            summary="2 functions", content_hash="deadbeef")
        assert cached is False
        assert obs.result_cas and obs.size > 0
        assert obs.status == "ok" and obs.result_kind == "function_list"
        # The full payload really landed in CAS, byte-faithful.
        from hexgraph.db.models import Project
        raw = cas.get_text(s.get(Project, pid), obs.result_cas)
        assert json.loads(raw) == payload


def test_identical_rerun_is_cached_no_duplicate(hg_home):
    pid, tid = _seed()
    payload = {"pseudocode": "void f(){}"}
    with session_scope() as s:
        o1, c1 = O.record_observation(
            s, project_id=pid, target_id=tid, source="a", tool="decompile_function",
            args={"function": "f"}, result_kind="decompilation", payload=payload,
            summary="f", content_hash="deadbeef")
        # Same tool + args (order-insensitive) + content_hash + kind ⇒ cached.
        o2, c2 = O.record_observation(
            s, project_id=pid, target_id=tid, source="b", tool="decompile_function",
            args={"function": "f"}, result_kind="decompilation", payload=payload,
            summary="f again", content_hash="deadbeef")
        assert c1 is False and c2 is True
        assert o1.id == o2.id
        assert s.query(Observation).count() == 1


def test_explicit_none_arg_dedups_with_omitted(hg_home):
    pid, tid = _seed()
    payload = {"pseudocode": "void f(){}"}
    with session_scope() as s:
        o1, c1 = O.record_observation(
            s, project_id=pid, target_id=tid, source="a", tool="decompile_function",
            args={"function": "f"}, result_kind="decompilation", payload=payload,
            summary="f", content_hash="deadbeef")
        # An explicit None for an optional arg is the same call as omitting it ⇒ cached.
        o2, c2 = O.record_observation(
            s, project_id=pid, target_id=tid, source="b", tool="decompile_function",
            args={"function": "f", "depth": None}, result_kind="decompilation",
            payload=payload, summary="f", content_hash="deadbeef")
        assert c1 is False and c2 is True
        assert o1.id == o2.id
        assert s.query(Observation).count() == 1


def test_different_bytes_not_cached(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        _o1, c1 = O.record_observation(
            s, project_id=pid, target_id=tid, source="a", tool="xrefs", args={},
            result_kind="xrefs", payload={"sinks": {}}, summary="x", content_hash="aaa")
        # Re-analyzing CHANGED bytes (new content_hash) must record a fresh row.
        _o2, c2 = O.record_observation(
            s, project_id=pid, target_id=tid, source="a", tool="xrefs", args={},
            result_kind="xrefs", payload={"sinks": {}}, summary="x", content_hash="bbb")
        assert c1 is False and c2 is False
        assert s.query(Observation).count() == 2


def test_error_status_is_not_deduped(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        O.record_observation(s, project_id=pid, target_id=tid, source="a", tool="t",
                             args={}, result_kind="k", payload={}, summary="boom",
                             status="error", content_hash="z")
        O.record_observation(s, project_id=pid, target_id=tid, source="a", tool="t",
                             args={}, result_kind="k", payload={}, summary="boom",
                             status="error", content_hash="z")
        # Errors must be retryable — never collapsed.
        assert s.query(Observation).count() == 2


# --- read verbs ---------------------------------------------------------------

def test_list_get_search(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        a, _ = O.record_observation(s, project_id=pid, target_id=tid, source="x",
                                    tool="decompile_function", args={"function": "f"},
                                    result_kind="decompilation", payload={"pc": "x"},
                                    summary="decompiled f", content_hash="h")
        O.record_observation(s, project_id=pid, target_id=tid, source="x", tool="xrefs",
                             args={}, result_kind="xrefs", payload={"sinks": {"system": 1}},
                             summary="xref sinks", content_hash="h")
        aid = a.id

        rows = O.list_observations(s, tid)
        assert len(rows) == 2
        only = O.list_observations(s, tid, kind="xrefs")
        assert len(only) == 1 and only[0]["result_kind"] == "xrefs"

        full = O.get_observation(s, aid)
        assert full["payload"] == {"pc": "x"} and full["id"] == aid

        hits = O.search_observations(s, target_id=tid, query="sinks")
        assert len(hits) == 1 and hits[0]["tool"] == "xrefs"
        assert O.get_observation(s, "nope") is None


# --- provenance helpers -------------------------------------------------------

def test_provenance_helpers_attach_and_dedup(hg_home):
    attrs = {"summary": "f"}
    O.add_provenance(attrs, "obs-1")
    O.add_provenance(attrs, "obs-2")
    O.add_provenance(attrs, "obs-1")  # dup is a no-op
    assert attrs["provenance"] == ["obs-1", "obs-2"]

    pid, tid = _seed()
    with session_scope() as s:
        obs, _ = O.record_observation(s, project_id=pid, target_id=tid, source="x",
                                      tool="t", args={}, result_kind="k", payload={},
                                      summary="s", content_hash="h")
        O.add_node_ref(obs, "node-1")
        O.add_node_ref(obs, "node-1")  # dup is a no-op
        O.add_node_ref(obs, "node-2")
        assert obs.node_refs == ["node-1", "node-2"]


# --- curation invariant: zero graph mutation ---------------------------------

def test_recording_creates_no_graph_nodes_or_edges(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        before_n = s.query(Node).count()
        before_e = s.query(Edge).count()
        for i in range(3):
            O.record_observation(s, project_id=pid, target_id=tid, source="x", tool="t",
                                 args={"i": i}, result_kind="k", payload={"i": i},
                                 summary=f"o{i}", content_hash="h")
        assert s.query(Observation).count() == 3
        assert s.query(Node).count() == before_n
        assert s.query(Edge).count() == before_e


# --- context-bundle observation index ----------------------------------------

def test_context_includes_observation_index(hg_home):
    from hexgraph.db.models import Project, Target
    from hexgraph.engine.context import _gather_items

    pid, tid = _seed()
    with session_scope() as s:
        O.record_observation(s, project_id=pid, target_id=tid, source="x",
                             tool="decompile_function", args={"function": "f"},
                             result_kind="decompilation", payload={"pc": "x"},
                             summary="f", content_hash="h")
        p, t = s.get(Project, pid), s.get(Target, tid)

        class _Ctx:
            objective = None
            tool_outputs = {}
            sibling_name = None
            sibling_target_id = None

        items = _gather_items(s, p, t, None, _Ctx())
        idx = [it for it in items if it.kind == "observation_index"]
        assert idx, "observation index missing from context bundle"
        assert "decompilation×1" in idx[0].text

    # And it's absent when there are no observations.
    pid2, tid2 = _seed()
    with session_scope() as s:
        p, t = s.get(Project, pid2), s.get(Target, tid2)

        class _Ctx2:
            objective = None
            tool_outputs = {}
            sibling_name = None
            sibling_target_id = None

        items = _gather_items(s, p, t, None, _Ctx2())
        assert not [it for it in items if it.kind == "observation_index"]


# --- MCP verbs + agent-loop round-trip ---------------------------------------

def test_mcp_verbs_registered_and_callable(hg_home):
    from hexgraph.engine import mcp_tools

    names = {t["name"] for t in mcp_tools.catalog()}
    assert {"list_observations", "get_observation", "search_observations"} <= names

    pid, tid = _seed()
    with session_scope() as s:
        obs, _ = O.record_observation(s, project_id=pid, target_id=tid, source="x",
                                      tool="xrefs", args={}, result_kind="xrefs",
                                      payload={"sinks": {"system": 1}}, summary="xref",
                                      content_hash="h")
        oid = obs.id

    listed = mcp_tools.list_observations(tid)
    assert listed["count"] == 1 and listed["reuse_hint"]
    got = mcp_tools.get_observation(oid)
    assert got["observation_id"] == oid and got["payload"] == {"sinks": {"system": 1}}
    found = mcp_tools.search_observations("xref", target_id=tid)
    assert found["count"] == 1
    assert mcp_tools.list_observations("missing-target").get("error")


def test_get_schemas_advertises_observation_contract(hg_home):
    from hexgraph.engine.mcp_tools import get_schemas

    sch = get_schemas()
    assert "observations" in sch and "substrate_vs_graph" in sch
    assert "do NOT auto-populate" in sch["observations"]["contract"] or \
           "do NOT" in sch["observations"]["contract"]


def test_agent_loop_can_query_observations(hg_home):
    """The in-process agent loop's mirrored verbs reach the same store."""
    from hexgraph.db.models import Project, Target
    from hexgraph.engine.agent_tools import ToolContext, available_tools, run_tool

    pid, tid = _seed()
    with session_scope() as s:
        obs, _ = O.record_observation(s, project_id=pid, target_id=tid, source="x",
                                      tool="decompile_function", args={"function": "f"},
                                      result_kind="decompilation", payload={"pc": "void f(){}"},
                                      summary="decompiled f", content_hash="h")
        oid = obs.id
        p, t = s.get(Project, pid), s.get(Target, tid)
        ctx = ToolContext(session=s, project=p, target=t)

        spec_names = {sp.name for sp in available_tools(ctx)}
        assert {"list_observations", "get_observation", "search_observations"} <= spec_names

        listed = run_tool(ctx, "list_observations", {})
        assert oid in listed and "decompilation" in listed
        got = run_tool(ctx, "get_observation", {"observation_id": oid})
        assert "void f(){}" in got
        found = run_tool(ctx, "search_observations", {"query": "decompiled"})
        assert oid in found
