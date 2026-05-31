"""Duplicate-node/target merge: collapse by canonical identity (sym.foo == foo,
same-bytes binaries) without losing edges, findings, annotations, or attrs."""

from hexgraph.db.models import Edge, EdgeType, Finding, Node, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.annotations import create_annotation
from hexgraph.engine.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node, materialize_function, normalize_symbol_name
from hexgraph.engine.nodemerge import merge_duplicate_nodes, merge_duplicate_targets
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def test_normalize_strips_decompiler_prefixes():
    assert normalize_symbol_name("sym.get_param") == "get_param"
    assert normalize_symbol_name("sym.imp.system") == "system"
    assert normalize_symbol_name("imp.strcpy") == "strcpy"
    assert normalize_symbol_name("get_param") == "get_param"
    assert normalize_symbol_name("fcn.00401a20") == "fcn.00401a20"  # unnamed → unchanged
    assert normalize_symbol_name("main") == "main"


def test_creation_normalizes_so_no_dup(hg_home):
    with session_scope() as s:
        p = create_project(s, name="n")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        a = materialize_function(s, project_id=p.id, target_id=t.id, name="get_param")
        b = materialize_function(s, project_id=p.id, target_id=t.id, name="sym.get_param")
        assert a.id == b.id  # same node — prefix normalized at creation
        assert a.name == "get_param" and (a.attrs_json or {}).get("name_raw") == "sym.get_param"


def test_merge_collapses_existing_dupes_keeping_everything(hg_home):
    with session_scope() as s:
        p = create_project(s, name="m")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        # Two nodes for the same function created via different paths/names. Force the
        # prefixed one in directly (simulating legacy/cross-tool data) by bypassing
        # normalization is hard, so build one clean + one with a divergent fq.
        clean = get_or_create_node(s, project_id=p.id, node_type="function", name="get_param", target_id=t.id)
        # craft a duplicate row with the raw prefixed name persisted (legacy)
        dup = Node(project_id=p.id, node_type="function", target_id=t.id,
                   name="sym.get_param", fq_name="sym.get_param", created_by="radare2")
        s.add(dup); s.flush()
        # attach edges/annotations/findings to BOTH so we can prove nothing is lost
        callee = get_or_create_node(s, project_id=p.id, node_type="function", name="system", target_id=t.id)
        add_edge(s, project_id=p.id, src=("node", dup.id), dst=("node", callee.id), type=EdgeType.calls)
        create_annotation(s, p.id, node_kind="node", node_id=dup.id, kind="note", value="reachable pre-auth")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="overflow", severity="high", confidence="high", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="sym.get_param")))  # about → dup
        pid, clean_id, dup_id, callee_id = p.id, clean.id, dup.id, callee.id

        removed = merge_duplicate_nodes(s, pid)
        assert removed == 1
        assert s.get(Node, dup_id) is None and s.get(Node, clean_id) is not None
        keeper = s.get(Node, clean_id)
        assert "sym.get_param" in (keeper.attrs_json.get("name_history") or [])
        # the dup's calls edge now points from the keeper
        assert s.query(Edge).filter(EdgeType.calls.value == Edge.type, Edge.src_id == clean_id,
                                    Edge.dst_id == callee_id).count() == 1
        # the dup's annotation moved onto the keeper (none orphaned on the dup)
        from hexgraph.db.models import Annotation
        kept = s.query(Annotation).filter(Annotation.node_id == clean_id).all()
        assert any(a.value == "reachable pre-auth" for a in kept)
        assert s.query(Annotation).filter(Annotation.node_id == dup_id).count() == 0
        # the finding's `about` edge re-homed onto the keeper (no finding lost)
        about = s.query(Edge).filter(Edge.type == EdgeType.about.value, Edge.dst_kind == "node").all()
        assert about and all(e.dst_id == clean_id for e in about)
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 1


def test_merge_targets_same_bytes(hg_home):
    import hashlib
    with session_scope() as s:
        p = create_project(s, name="t")
        sha = hashlib.sha256(open(fixture_path("vuln_httpd"), "rb").read()).hexdigest()
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="a")
        b = ingest_file(s, p, fixture_path("vuln_httpd"), name="b")
        a.metadata_json = {"sha256": sha}
        b.metadata_json = {"sha256": sha}
        # findings + a function node on each
        for tgt in (a, b):
            task = create_task(s, project=p, target_id=tgt.id, type="static_analysis")
            persist_finding(s, project_id=p.id, target_id=tgt.id, task_id=task.id, finding=FModel(
                title=f"f-{tgt.name}", severity="low", confidence="low", category="other",
                summary="s", reasoning="r", evidence=Evidence()))
        pid, a_id, b_id = p.id, a.id, b.id

        removed = merge_duplicate_targets(s, pid)
        assert removed == 1
        survivors = s.query(Target).filter(Target.project_id == pid).all()
        assert len(survivors) == 1
        keeper = survivors[0].id
        # both findings re-homed onto the keeper (none lost)
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 2
        assert all(f.target_id == keeper for f in s.query(Finding).filter(Finding.project_id == pid))
