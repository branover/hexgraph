"""The graph-API / finding-envelope batch (Phase 5 eval): graph_stats counts verb,
graph_set_node_attr, the first-class CWE envelope on findings, and the finding_reachability
unauthenticated precondition override. Mock, offline — no Docker, no key."""

from hexgraph.db.session import session_scope
from hexgraph.engine import assurance as A
from hexgraph.agent import mcp_tools as T
from hexgraph.engine.graph.authoring import create_edge, create_node
from hexgraph.engine.findings import normalize_cwe, persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.reachability import argue_reachability_for_finding
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as F

from conftest import fixture_path


def _proj(s, name="ga"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    return p, t


# ── graph_stats: per-type tallies ───────────────────────────────────────────────────────────

def test_graph_stats_tallies_by_type(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        create_node(s, p, node_type="function", name="cgi_handler", target_id=t.id)
        create_node(s, p, node_type="function", name="parse_request", target_id=t.id)
        sym = create_node(s, p, node_type="symbol", name="system", target_id=t.id)
        fn = create_node(s, p, node_type="function", name="main", target_id=t.id)
        create_edge(s, p, src_kind="node", src_id=fn.id, dst_kind="node", dst_id=sym.id, type="calls")
        pid = p.id
    out = T.graph_stats(pid)
    assert out["nodes_by_type"]["function"] == 3
    assert out["nodes_by_type"]["symbol"] == 1
    # each function auto-links to its target via a `contains` edge + the one `calls` we added.
    assert out["edges_by_type"]["calls"] == 1
    assert out["edges_by_type"]["contains"] == 4
    assert out["totals"]["nodes"] == 4
    assert out["targets"] == 1


def test_graph_stats_unknown_project(hg_home):
    assert "error" in T.graph_stats("nope")


# ── graph_set_node_attr: set one attribute in place ─────────────────────────────────────────

def test_set_node_attr_sets_one_key(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        n = create_node(s, p, node_type="symbol", name="strcpy", target_id=t.id,
                        attrs={"kind": "import"})
        nid = n.id
    out = T.set_node_attr(nid, "is_sink", True)
    assert out["attrs"]["is_sink"] is True
    assert out["attrs"]["kind"] == "import"  # other attrs untouched
    assert T.get_node(nid)["attrs"]["is_sink"] is True


def test_set_node_attr_unknown_node(hg_home):
    assert "error" in T.set_node_attr("nope", "is_sink", True)


# ── first-class CWE envelope ─────────────────────────────────────────────────────────────────

def test_normalize_cwe_variants():
    assert normalize_cwe("CWE-787") == "CWE-787"
    assert normalize_cwe("787") == "CWE-787"
    assert normalize_cwe(787) == "CWE-787"
    assert normalize_cwe("cwe_787") == "CWE-787"
    assert normalize_cwe("CWE 787") == "CWE-787"
    assert normalize_cwe(None) is None
    assert normalize_cwe("n/a") is None
    # a stray-digit string must NOT mint a bogus CWE — only a bare number or a "cwe"-anchored ref.
    assert normalize_cwe("version 3") is None
    assert normalize_cwe("CWE-787: stack overflow") == "CWE-787"  # extracts from a labeled ref


def _vuln_with_cwe(s, p, t, cwe):
    task = create_task(s, project=p, target_id=t.id, type="static_analysis")
    f = F(title="oob", severity="high", confidence="medium", category="memory-safety",
          summary="s", reasoning="r",
          evidence=Evidence(function="cgi_handler", extra={"cwe": cwe}))
    return persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f,
                           finding_type="vulnerability")


def test_cwe_lifted_from_evidence_extra_on_persist(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        row = _vuln_with_cwe(s, p, t, "CWE-787")
        assert row.cwe == "CWE-787"
        fid = row.id
    # surfaced by the MCP read tools …
    assert T.get_finding(fid)["cwe"] == "CWE-787"
    assert any(r["cwe"] == "CWE-787" for r in T.list_findings(p.id))


def test_cwe_normalized_when_lifted(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        row = _vuln_with_cwe(s, p, t, 121)  # bare int
        assert row.cwe == "CWE-121"


def test_finding_update_sets_cwe(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        row = _vuln_with_cwe(s, p, t, None)  # no cwe on record
        assert row.cwe is None
        fid = row.id
    out = T.update_finding(fid, cwe="416")
    assert out["cwe"] == "CWE-416"
    assert T.get_finding(fid)["cwe"] == "CWE-416"


# ── finding_reachability precondition override ──────────────────────────────────────────────

def test_reachability_precondition_override(hg_home):
    with session_scope() as s:
        p, t = _proj(s)
        # a plain `input` source (no auth marker) → the derived precondition is `unspecified`.
        src = create_node(s, p, node_type="input", name="argv1", target_id=t.id)
        sink = create_node(s, p, node_type="symbol", name="system", target_id=t.id,
                           attrs={"is_sink": True})
        create_edge(s, p, src_kind="node", src_id=src.id, dst_kind="node", dst_id=sink.id, type="taints")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = F(title="cmdi", severity="high", confidence="medium", category="command-injection",
              summary="s", reasoning="r", evidence=Evidence(function="cgi_handler", sink="system"))
        row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f,
                              finding_type="vulnerability")
        create_edge(s, p, src_kind="finding", src_id=row.id, dst_kind="node", dst_id=sink.id, type="about")

        # default: derived precondition is `unspecified`, inferred.
        base = argue_reachability_for_finding(s, row.id, record=False)
        assert base["found"] and base["precondition"] == A.UNSPECIFIED
        assert base["precondition_inferred"] is True

        # override: caller asserts `unauthenticated`; recorded as NOT inferred.
        over = argue_reachability_for_finding(s, row.id, precondition=A.UNAUTHENTICATED)
        assert over["precondition"] == A.UNAUTHENTICATED
        assert over["precondition_inferred"] is False
        assert over["assurance_recorded"]["precondition"] == A.UNAUTHENTICATED
        assert "precondition_inferred" not in over["assurance_recorded"]


def test_reachability_rejects_bad_precondition(hg_home):
    # the MCP wrapper validates against the closed vocabulary.
    out = T.reachability(sink_node_id="whatever", precondition="bogus")
    assert "error" in out and "precondition" in out["error"]
