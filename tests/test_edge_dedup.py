"""Duplicate relationship edges collapse: one edge per (src,dst,type), both at
creation (merge=True) and in the graph render (belt-and-suspenders)."""

from hexgraph.db.models import Edge, EdgeType
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.graph.graph import build_graph
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def test_merge_collapses_at_creation(hg_home):
    with session_scope() as s:
        p = create_project(s, name="e")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("libupnp.so"), name="b")
        for fid in ("f1", "f2", "f3"):
            add_edge(s, project_id=p.id, src=("target", a.id), dst=("target", b.id),
                     type=EdgeType.related_to, origin="llm", confidence="high",
                     merge=True, attrs={"finding_id": fid})
        rels = s.query(Edge).filter(Edge.project_id == p.id, Edge.type == EdgeType.related_to.value).all()
        assert len(rels) == 1
        assert sorted(rels[0].attrs_json["finding_ids"]) == ["f1", "f2", "f3"]


def test_graph_render_collapses_existing_duplicates(hg_home):
    with session_scope() as s:
        p = create_project(s, name="e2")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("libupnp.so"), name="b")
        # simulate legacy duplicates (no merge) already in the DB
        for _ in range(3):
            add_edge(s, project_id=p.id, src=("target", a.id), dst=("target", b.id),
                     type=EdgeType.related_to, origin="llm", confidence="medium")
        g = build_graph(s, p.id)
        rel = [e for e in g["edges"] if e["type"] == "related_to"]
        assert len(rel) == 1 and rel[0]["count"] == 3


def test_distinct_types_are_not_merged(hg_home):
    with session_scope() as s:
        p = create_project(s, name="e3")
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("libupnp.so"), name="b")
        add_edge(s, project_id=p.id, src=("target", a.id), dst=("target", b.id), type=EdgeType.related_to)
        add_edge(s, project_id=p.id, src=("target", a.id), dst=("target", b.id), type=EdgeType.links_against)
        g = build_graph(s, p.id)
        between = [e for e in g["edges"] if e["source"] == a.id and e["target"] == b.id]
        assert {e["type"] for e in between} == {"related_to", "links_against"}
