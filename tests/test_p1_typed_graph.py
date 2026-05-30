"""P1: typed graph — node materialization, polymorphic edges, findings-as-about."""

from hexgraph.db.models import Edge, EdgeType, Node, NodeType
from hexgraph.db.session import session_scope
from hexgraph.engine.edges import add_edge, delete_node_cascade
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import materialize_function, materialize_symbol
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync

from conftest import fixture_path


def test_node_content_hash_dedups(hg_home):
    with session_scope() as s:
        p = create_project(s, name="n")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        a = materialize_function(s, project_id=p.id, target_id=t.id, name="cgi_handler")
        b = materialize_function(s, project_id=p.id, target_id=t.id, name="cgi_handler")
        assert a.id == b.id  # same (target, name) -> one node
        assert s.query(Node).filter(Node.node_type == NodeType.function.value).count() == 1


def test_polymorphic_edge_and_cascade(hg_home):
    with session_scope() as s:
        p = create_project(s, name="e")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        f1 = materialize_function(s, project_id=p.id, target_id=t.id, name="a")
        f2 = materialize_function(s, project_id=p.id, target_id=t.id, name="b")
        add_edge(s, project_id=p.id, src=("node", f1.id), dst=("node", f2.id),
                 type=EdgeType.calls, origin="tool")
        assert s.query(Edge).filter(Edge.type == EdgeType.calls.value).count() == 1
        # deleting a node cascades its edges
        removed = delete_node_cascade(s, f1.id)
        assert removed == 1
        assert s.query(Edge).filter(Edge.type == EdgeType.calls.value).count() == 0


def test_finding_attaches_to_function_via_about_edge(hg_home):
    """A static_analysis finding on cgi_handler materializes the function node and
    links to it with an `about` edge (mock backend; no Docker needed)."""
    with session_scope() as s:
        p = create_project(s, name="a")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           backend="mock", params={"mock_scenario": "critical_overflow", "function": "cgi_handler"})
        tid, pid = task.id, p.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        fn = s.query(Node).filter(Node.node_type == NodeType.function.value,
                                  Node.fq_name == "cgi_handler").one()
        about = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.about.value,
                                     Edge.dst_kind == "node", Edge.dst_id == fn.id).all()
        assert len(about) == 1 and about[0].src_kind == "finding"


def test_recon_materializes_symbol_nodes(hg_home, sandbox):
    """Real recon (sandbox) emits a bounded symbol/string node set including strcpy."""
    from hexgraph.engine.pipeline import ingest_and_analyze

    with session_scope() as s:
        p = create_project(s, name="r")
        ingest_and_analyze(s, p, fixture_path("vuln_httpd"), runner=sandbox)
        pid = p.id
    with session_scope() as s:
        syms = s.query(Node).filter(Node.project_id == pid, Node.node_type == NodeType.symbol.value).all()
        names = {n.name for n in syms}
        assert "strcpy" in names
        assert any(n.attrs_json.get("is_sink") for n in syms)


def test_decompile_materializes_calls_edges(hg_home, sandbox, monkeypatch):
    """static_analysis on a real ELF decompiles cgi_handler → function node + calls
    edges to its callees (e.g. strcpy)."""
    monkeypatch.delenv("HEXGRAPH_DISABLE_DECOMPILE", raising=False)
    from hexgraph.engine.pipeline import ingest_and_analyze

    with session_scope() as s:
        p = create_project(s, name="d")
        summary = ingest_and_analyze(s, p, fixture_path("vuln_httpd"), runner=sandbox)
        tid_target = summary["root_target_id"]
        task = create_task(s, project=p, target_id=tid_target, type="static_analysis",
                           backend="mock", params={"mock_scenario": "critical_overflow", "function": "cgi_handler"})
        task_id, pid = task.id, p.id
    assert run_task_sync(task_id) == "succeeded"
    with session_scope() as s:
        calls = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.calls.value).all()
        assert calls, "expected calls edges from decompiled cgi_handler"
        # the focus function node exists
        assert s.query(Node).filter(Node.node_type == NodeType.function.value,
                                    Node.fq_name == "cgi_handler").count() >= 1
