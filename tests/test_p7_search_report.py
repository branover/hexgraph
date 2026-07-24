"""P7: search (coverage-honest), report export, cross-target same-code linking."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, FindingStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.crosstarget import link_same_code
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.engine.findings.report import build_report_md
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _seed_finding(s, status="confirmed"):
    p = create_project(s, name="p7")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    task = create_task(s, project=p, target_id=t.id, type="static_analysis", backend="mock")
    f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
        title="Stack overflow in cgi_handler", severity="critical", confidence="high",
        category="memory-safety", summary="unbounded strcpy", reasoning="copies token into buf",
        evidence=Evidence(function="cgi_handler", sink="strcpy", decompiled_snippet="strcpy(buf, t);")))
    f.status = FindingStatus[status].value if hasattr(FindingStatus, status) else status
    return p, t, f


def test_search_finds_finding_and_reports_coverage(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s)
        pid = p.id
    client = TestClient(create_app())
    r = client.get(f"/api/projects/{pid}/search", params={"q": "overflow"}).json()
    assert any("overflow" in x["title"].lower() for x in r["findings"])
    assert "note" in r["coverage"]  # coverage honesty present


def test_report_includes_confirmed_with_provenance(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s, status="confirmed")
        pid = p.id
    with session_scope() as s:
        md = build_report_md(s, pid)
    assert "Stack overflow in cgi_handler" in md
    assert "Provenance" in md and "memory-safety" in md
    assert "strcpy(buf, t);" in md  # decompiled snippet embedded


def test_report_excludes_unconfirmed(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s, status="new")
        pid = p.id
    with session_scope() as s:
        md = build_report_md(s, pid)
    assert "No confirmed findings" in md


def test_cross_target_same_code(hg_home):
    """Two function nodes in different targets sharing a content hash get a similar_to edge."""
    with session_scope() as s:
        p = create_project(s, name="xc")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("libupnp.so"), name="b")
        # same pseudocode in both -> same content_hash
        body = "void f(){ strcpy(buf, x); }"
        materialize_function(s, project_id=p.id, target_id=a.id, name="f", pseudocode=body)
        materialize_function(s, project_id=p.id, target_id=b.id, name="f", pseudocode=body)
        pid = p.id
        created = link_same_code(s, pid)
        assert created == 1
        # idempotent
        assert link_same_code(s, pid) == 0
        edges = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.similar_to.value).all()
        assert len(edges) == 1 and edges[0].origin == "derived"


def test_link_same_code_preloads_edges_once_not_per_pair(hg_home):
    """Regression: link_same_code must pre-load the existing similar_to edges ONCE, not run a
    per-pair `query(Edge).first()` — that was an O(pairs) scan held under the write lock across a
    large same-content clique. On an idempotent re-run over a K-node clique the edge SELECT count
    must stay a small constant, not grow with the K*(K-1)/2 pairs."""
    import re

    from sqlalchemy import event

    from hexgraph.db.models import Target, TargetKind
    from hexgraph.db.session import get_engine

    K = 6
    body = "void f(){ strcpy(buf, x); }"
    with session_scope() as s:
        p = create_project(s, name="clique")
        pid = p.id
        for i in range(K):
            t = Target(project_id=pid, name=f"t{i}", path=f"/tmp/t{i}",
                       kind=TargetKind.executable, metadata_json={})
            s.add(t)
            s.flush()
            materialize_function(s, project_id=pid, target_id=t.id, name="f", pseudocode=body)
        assert link_same_code(s, pid) == K * (K - 1) // 2      # full clique across K targets

        # SECOND (idempotent) run: every pair already exists, so add_edge is never called; the ONLY
        # edge SELECT is the one pre-load. The old per-pair existence check would be K*(K-1)/2 = 15.
        count = {"edge_selects": 0}
        _from_edge = re.compile(r"\bfrom edge\b")

        def _before(conn, cur, stmt, params, ctx, many):
            low = stmt.lstrip().lower()
            if low.startswith("select") and _from_edge.search(low):
                count["edge_selects"] += 1

        eng = get_engine()
        event.listen(eng, "before_cursor_execute", _before)
        try:
            assert link_same_code(s, pid) == 0
        finally:
            event.remove(eng, "before_cursor_execute", _before)
        assert count["edge_selects"] <= 2, count               # one pre-load, NOT O(pairs)


def test_nday_propagate_flow(hg_home):
    """The n-day MCP flow: link_same_code flags which side has a finding, and
    propagate_finding clones it onto the bare sibling wired derived_from→ source."""
    from hexgraph.agent import mcp_tools as M
    from hexgraph.engine.graph.edges import add_edge

    with session_scope() as s:
        p = create_project(s, name="nday")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("libupnp.so"), name="b")
        body = "void f(){ strcpy(buf, x); }"
        na = materialize_function(s, project_id=p.id, target_id=a.id, name="f", pseudocode=body)
        nb = materialize_function(s, project_id=p.id, target_id=b.id, name="f", pseudocode=body)
        task = create_task(s, project=p, target_id=a.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=a.id, task_id=task.id, finding=FModel(
            title="overflow in f", severity="critical", confidence="high", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="f", sink="strcpy")),
            finding_type="vulnerability")
        add_edge(s, project_id=p.id, src=("finding", f.id), dst=("node", na.id),
                 type=EdgeType.about, origin="agent", confidence=1.0)
        pid, src_fid, bid, naid, nbid = p.id, f.id, b.id, na.id, nb.id

    res = M.link_same_code(pid)
    match = res["matches"][0]
    sides = {match["a"]["node_id"]: match["a"], match["b"]["node_id"]: match["b"]}
    assert sides[naid]["has_findings"] and not sides[nbid]["has_findings"]

    prop = M.propagate_finding(finding_id=src_fid, target_id=bid, function="f")
    assert prop["target_id"] == bid and prop["derived_from"] == src_fid
    assert prop["status"] == "new"

    # The propagated finding is wired derived_from→ the source.
    with session_scope() as s:
        e = (s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.derived_from.value,
                                  Edge.src_id == prop["id"], Edge.dst_id == src_fid).first())
        assert e is not None
        ev = s.get(__import__("hexgraph.db.models", fromlist=["Finding"]).Finding, prop["id"]).evidence_json
        assert ev["extra"]["propagated_from"] == src_fid
