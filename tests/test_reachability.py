"""Standard B, static — source→sink reachability argument over the typed graph
(docs/design/design-verification-oracles.md, Phase 4).

These tests pin the honesty guarantees the reviewer must trust:
  - a real source→sink path stamps `input_reachable/static` with the right precondition;
  - NO path leaves the finding at the `code_present/static` floor (never upgraded);
  - the precedence/`upgrade_if_stronger` rule UPGRADES the floor but NEVER downgrades a dynamic
    claim, and treats the two incomparable middle rungs as a non-upgrade;
  - the bounded search terminates on a cyclic graph;
  - it can't FALSELY claim reachability: a non-source isn't a source, and an edge isn't followed
    backwards.
"""

from hexgraph.db.session import session_scope
from hexgraph.engine.findings import assurance as A
from hexgraph.engine.graph.authoring import create_edge, create_node
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import get_or_create_node
from hexgraph.engine.findings.reachability import (argue_reachability_for_finding,
                                          find_source_to_sink_path, is_source)
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as F

from conftest import fixture_path


def _project_with_binary(s, name="r"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    return p, t


def _vuln_finding(s, p, t, *, sink_node, function="cgi_handler"):
    """Persist a code_present/static vuln finding `about`→ the given sink node."""
    task = create_task(s, project=p, target_id=t.id, type="static_analysis")
    f = F(title="cmdi", severity="high", confidence="medium", category="command-injection",
          summary="s", reasoning="r", evidence=Evidence(function=function, sink=sink_node.name))
    row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f,
                          finding_type="vulnerability")
    # Wire the finding `about`→ the sink node so reachability resolves it.
    create_edge(s, p, src_kind="finding", src_id=row.id, dst_kind="node", dst_id=sink_node.id,
                type="about")
    return row


# ── a real source→sink path is found and stamped ────────────────────────────────────────────

def test_taints_path_unauth_endpoint_stamps_input_reachable_static(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        # endpoint (unauth) --taints--> sink(system, is_sink)
        ep = create_node(s, p, node_type="endpoint", name="/cgi-bin/cmd", target_id=t.id,
                         attrs={"auth": "none"})
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=ep.id, dst_kind="node", dst_id=sink.id,
                    type="taints")
        row = _vuln_finding(s, p, t, sink_node=sink)

        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is True
        assert res["via_taint"] is True
        assert res["precondition"] == A.UNAUTHENTICATED
        a = res["assurance_recorded"]
        assert a["standard"] == A.INPUT_REACHABLE and a["method"] == A.STATIC
        assert a["precondition"] == A.UNAUTHENTICATED
        assert res["upgraded"] is True
        # The path is recorded under evidence.extra.reachability for the triager to audit.
        s.refresh(row)
        rec = row.evidence_json["extra"]["reachability"]
        assert rec["sink_node_id"] == sink.id and rec["via_taint"] is True
        assert len(rec["path"]) == 2  # endpoint -> sink


def test_auth_on_path_yields_requires_credentials(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        # param (auth=session) --taints--> sink
        param = create_node(s, p, node_type="param", name="host", target_id=t.id,
                            attrs={"auth": "session"})
        sink = create_node(s, p, node_type="symbol", name="popen", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=param.id, dst_kind="node", dst_id=sink.id,
                    type="taints")
        row = _vuln_finding(s, p, t, sink_node=sink)

        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is True
        assert res["precondition"] == A.REQUIRES_CREDENTIALS
        assert res["assurance_recorded"]["precondition"] == A.REQUIRES_CREDENTIALS


def test_bypasses_edge_on_path_yields_requires_credentials(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        # input --calls--> auth_check --bypasses--> sink: crossing a bypasses edge ⇒ creds
        inp = create_node(s, p, node_type="input", name="recv_buf", target_id=t.id,
                          attrs={"source": "socket recv"})
        mid = create_node(s, p, node_type="function", name="check_auth", target_id=t.id)
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=inp.id, dst_kind="node", dst_id=mid.id,
                    type="calls")
        create_edge(s, p, src_kind="node", src_id=mid.id, dst_kind="node", dst_id=sink.id,
                    type="bypasses")
        row = _vuln_finding(s, p, t, sink_node=sink)
        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is True
        assert res["precondition"] == A.REQUIRES_CREDENTIALS


def test_control_flow_only_path_is_not_taint_backed(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        # endpoint --routes_to--> handler --calls--> sink (no taints edge)
        ep = create_node(s, p, node_type="endpoint", name="/run", target_id=t.id,
                         attrs={"auth": "none"})
        handler = create_node(s, p, node_type="function", name="do_run", target_id=t.id)
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=ep.id, dst_kind="node", dst_id=handler.id,
                    type="routes_to")
        create_edge(s, p, src_kind="node", src_id=handler.id, dst_kind="node", dst_id=sink.id,
                    type="calls")
        row = _vuln_finding(s, p, t, sink_node=sink)
        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is True
        assert res["via_taint"] is False  # pure control-flow argument
        assert res["assurance_recorded"]["standard"] == A.INPUT_REACHABLE


# ── NO path ⇒ stays at the floor ─────────────────────────────────────────────────────────────

def test_no_path_stays_code_present_static(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        # A sink with NO incoming source path. A lone internal function is NOT a source.
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        internal = create_node(s, p, node_type="function", name="helper", target_id=t.id)
        create_edge(s, p, src_kind="node", src_id=internal.id, dst_kind="node", dst_id=sink.id,
                    type="calls")
        row = _vuln_finding(s, p, t, sink_node=sink)
        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is False
        # The finding is untouched at the floor.
        s.refresh(row)
        a = A.assurance_of(row.evidence_json)
        assert a["standard"] == A.CODE_PRESENT and a["method"] == A.STATIC
        assert "reachability" not in (row.evidence_json.get("extra") or {})


def test_internal_function_is_not_a_source_unless_marked_entry(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        plain = get_or_create_node(s, project_id=p.id, node_type="function", name="parse",
                                   target_id=t.id)
        marked = get_or_create_node(s, project_id=p.id, node_type="function", name="main_loop",
                                    target_id=t.id, attrs={"entry": True})
        assert is_source(plain) is False
        assert is_source(marked) is True


def test_edge_not_followed_backwards(hg_home):
    """A `calls` edge sink→source must NOT make the sink reachable: reversing edge direction
    would invent reachability that isn't there (a key false-claim guard)."""
    with session_scope() as s:
        p, t = _project_with_binary(s)
        ep = create_node(s, p, node_type="endpoint", name="/x", target_id=t.id,
                         attrs={"auth": "none"})
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        # WRONG direction: sink --calls--> endpoint. There is no source→sink path.
        create_edge(s, p, src_kind="node", src_id=sink.id, dst_kind="node", dst_id=ep.id,
                    type="calls")
        res = find_source_to_sink_path(s, p.id, sink.id)
        assert res is None


def test_contains_edge_is_not_traversed(hg_home):
    """The structural target→node `contains` edge must not count as reachability (every node is
    contains-reachable from its target, which would make the argument vacuous)."""
    with session_scope() as s:
        p, t = _project_with_binary(s)
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        # The only thing touching the sink is its auto-created target→node `contains` edge.
        res = find_source_to_sink_path(s, p.id, sink.id)
        assert res is None


# ── precedence / upgrade_if_stronger ─────────────────────────────────────────────────────────

def test_upgrade_floors_static_but_not_dynamic():
    # code_present/static floor → upgraded by input_reachable/static
    floor = {"extra": {"assurance": A.assurance(A.CODE_PRESENT, A.STATIC)}}
    A.upgrade_if_stronger(floor, A.assurance(A.INPUT_REACHABLE, A.STATIC, A.UNAUTHENTICATED))
    assert A.assurance_of(floor)["standard"] == A.INPUT_REACHABLE
    assert A.assurance_of(floor)["method"] == A.STATIC

    # input_reachable/dynamic must NOT be downgraded by input_reachable/static
    dyn = {"extra": {"assurance": A.assurance(A.INPUT_REACHABLE, A.DYNAMIC, A.UNAUTHENTICATED)}}
    A.upgrade_if_stronger(dyn, A.assurance(A.INPUT_REACHABLE, A.STATIC, A.REQUIRES_CREDENTIALS))
    assert A.assurance_of(dyn)["method"] == A.DYNAMIC

    # code_present/dynamic (lab-confirmed) is INCOMPARABLE to input_reachable/static (same tier) —
    # the static argument must NOT displace the dynamic lab-confirmation.
    lab = {"extra": {"assurance": A.assurance(A.CODE_PRESENT, A.DYNAMIC)}}
    A.upgrade_if_stronger(lab, A.assurance(A.INPUT_REACHABLE, A.STATIC, A.UNAUTHENTICATED))
    assert A.assurance_of(lab) == A.assurance(A.CODE_PRESENT, A.DYNAMIC)

    # no current assurance → candidate is recorded
    empty: dict = {}
    A.upgrade_if_stronger(empty, A.assurance(A.INPUT_REACHABLE, A.STATIC))
    assert A.assurance_of(empty)["standard"] == A.INPUT_REACHABLE


def test_rank_partial_order():
    assert A.rank(A.assurance(A.CODE_PRESENT, A.STATIC)) == 0
    assert A.rank(A.assurance(A.CODE_PRESENT, A.DYNAMIC)) == 1
    assert A.rank(A.assurance(A.INPUT_REACHABLE, A.STATIC)) == 1
    assert A.rank(A.assurance(A.INPUT_REACHABLE, A.DYNAMIC)) == 2
    assert A.rank(None) == -1
    assert A.rank({"standard": "unconfirmed", "method": "dynamic"}) == -1


def test_argue_does_not_downgrade_dynamic_finding(hg_home):
    """End-to-end: a finding already at input_reachable/dynamic is NOT downgraded even though a
    static source→sink path exists."""
    with session_scope() as s:
        p, t = _project_with_binary(s)
        ep = create_node(s, p, node_type="endpoint", name="/x", target_id=t.id,
                         attrs={"auth": "session"})  # would argue requires_credentials, weaker
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=ep.id, dst_kind="node", dst_id=sink.id,
                    type="taints")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = F(title="cmdi", severity="critical", confidence="high", category="command-injection",
              summary="s", reasoning="r",
              evidence=Evidence(function="cgi_handler", sink="system",
                                extra={"assurance": A.assurance(A.INPUT_REACHABLE, A.DYNAMIC,
                                                               A.UNAUTHENTICATED)}))
        row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f,
                              finding_type="poc")
        create_edge(s, p, src_kind="finding", src_id=row.id, dst_kind="node", dst_id=sink.id,
                    type="about")
        res = argue_reachability_for_finding(s, row.id)
        assert res["found"] is True
        # The recorded assurance stays the strong dynamic claim.
        assert res["assurance_recorded"]["method"] == A.DYNAMIC
        assert res.get("upgraded") is False


# ── bounded search terminates on a cycle ─────────────────────────────────────────────────────

def test_cyclic_graph_terminates(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        a = create_node(s, p, node_type="function", name="a", target_id=t.id)
        b = create_node(s, p, node_type="function", name="b", target_id=t.id)
        c = create_node(s, p, node_type="function", name="c", target_id=t.id)
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        # A cycle a->b->c->a, none of which is a source, plus an unreachable sink.
        for src, dst in ((a, b), (b, c), (c, a)):
            create_edge(s, p, src_kind="node", src_id=src.id, dst_kind="node", dst_id=dst.id,
                        type="calls")
        # Terminates (returns None) rather than hanging on the cycle.
        assert find_source_to_sink_path(s, p.id, sink.id) is None

        # And a cycle ON the path to a reachable sink still terminates and finds the sink.
        ep = create_node(s, p, node_type="endpoint", name="/e", target_id=t.id,
                         attrs={"auth": "none"})
        create_edge(s, p, src_kind="node", src_id=ep.id, dst_kind="node", dst_id=a.id,
                    type="taints")
        create_edge(s, p, src_kind="node", src_id=c.id, dst_kind="node", dst_id=sink.id,
                    type="calls")
        res = find_source_to_sink_path(s, p.id, sink.id)
        assert res is not None and res["summary"].startswith("/e")


def test_max_depth_bounds_the_search(hg_home):
    with session_scope() as s:
        p, t = _project_with_binary(s)
        ep = create_node(s, p, node_type="endpoint", name="/deep", target_id=t.id,
                         attrs={"auth": "none"})
        prev = ep
        chain = []
        for i in range(5):
            n = create_node(s, p, node_type="function", name=f"f{i}", target_id=t.id)
            create_edge(s, p, src_kind="node", src_id=prev.id, dst_kind="node", dst_id=n.id,
                        type="calls")
            chain.append(n)
            prev = n
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=prev.id, dst_kind="node", dst_id=sink.id,
                    type="calls")
        # The path is 6 hops (endpoint -> f0..f4 -> sink). max_depth=3 can't reach it.
        assert find_source_to_sink_path(s, p.id, sink.id, max_depth=3) is None
        # A generous bound finds it.
        assert find_source_to_sink_path(s, p.id, sink.id, max_depth=12) is not None
