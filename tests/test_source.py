"""Phase 1 source-tree foundation: the source_tree entity, lazy source_file node
materialization + dedup, the new edges (built_from/located_in/harnesses) incl. the
EDGE_KINDS endpoint-validator widening, the harness backfill + back-compat read
path, path-traversal safety, and the API/MCP read tools."""

import pytest
from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import (
    EDGE_KINDS, Edge, EdgeType, Finding, Node, NodeType, SourceTree, Task,
)
from hexgraph.db.session import session_scope
from hexgraph.engine.build import source as src
from hexgraph.engine.authoring import InvariantError, create_edge
from hexgraph.engine.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.harness_promote import (
    backfill_harnesses, get_or_create_harness_tree, promote_harness,
)
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodemerge import merge_duplicates
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path

HARNESS = "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"


# --- model + migration vocabulary ---------------------------------------------

def test_edge_kinds_widened_to_source_tree():
    assert "source_tree" in EDGE_KINDS
    # the new vocab is String-column zero-migration
    assert NodeType.source_file.value == "source_file"
    assert NodeType.harness.value == "harness"
    for e in ("built_from", "located_in", "harnesses"):
        assert EdgeType(e).value == e


def test_create_source_tree_persists_and_lists(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="libfoo", origin="upload", editable=False)
        assert tree.id and tree.origin == "upload" and tree.editable is False
        # round-trips as a row
        row = s.get(SourceTree, tree.id)
        assert row is not None and row.name == "libfoo"
        listed = src.list_source_trees(s, p)
        assert len(listed) == 1 and listed[0]["id"] == tree.id and listed[0]["file_count"] == 0


def test_can_edit_surfaced_per_tree(hg_home):
    """list_source_trees / list_source_files report a per-tree `can_edit` folding the
    SCOPED source-edit gate: scratch trees editable by default, read-only trees never,
    other authored trees only with features.source.edit. The SPA keys edit UI off this."""
    from hexgraph import settings as _settings
    with session_scope() as s:
        p = create_project(s, name="canedit")
        scratch = src.create_source_tree(s, p, name="scratch", origin="scratch")  # editable=True
        ro = src.create_source_tree(s, p, name="vendor", origin="git", editable=False)
        authored = src.create_source_tree(s, p, name="imported", origin="git", editable=True)
        by_id = {t["id"]: t for t in src.list_source_trees(s, p)}
        # flag OFF: scratch yes, read-only no, other-authored no
        assert by_id[scratch.id]["can_edit"] is True
        assert by_id[ro.id]["can_edit"] is False
        assert by_id[authored.id]["can_edit"] is False
        assert src.list_source_files(s, p, scratch)["can_edit"] is True
        assert src.list_source_files(s, p, authored)["can_edit"] is False
        # flag ON: other-authored flips to editable; read-only still no
        _settings.update_settings({"features.source.edit": True})
        by_id = {t["id"]: t for t in src.list_source_trees(s, p)}
        assert by_id[authored.id]["can_edit"] is True
        assert by_id[ro.id]["can_edit"] is False


def test_bad_origin_rejected(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        with pytest.raises(src.SourceError):
            src.create_source_tree(s, p, name="x", origin="nonsense")


# --- write + read + path-traversal safety -------------------------------------

def test_write_then_read_source_file(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="scratch", origin="scratch")
        src.write_source_file(s, p, tree, "a/b/foo.c", "int main(){}\n", role="code")
        files = src.list_source_files(s, p, tree)["files"]
        assert any(f["rel"] == "a/b/foo.c" for f in files)
        read = src.read_source_file(p, tree, "a/b/foo.c")
        assert read["encoding"] == "text" and "int main" in read["content"]
        assert read["origin"] == "scratch"


def test_read_only_tree_refuses_write(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="vendor", origin="upload", editable=False)
        with pytest.raises(src.SourceError):
            src.write_source_file(s, p, tree, "x.c", "data")


def test_path_traversal_refused(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="scratch", origin="scratch")
        # a traversal write is refused before touching disk
        with pytest.raises(src.SourceError):
            src.write_source_file(s, p, tree, "../../etc/escape", "x")
        # and a traversal read is refused even when manifest is bypassed
        src.write_source_file(s, p, tree, "ok.c", "x")
        tree.manifest_json = {"files": [{"rel": "../../../etc/passwd", "size": 1, "role": "code"}]}
        with pytest.raises(src.SourceError):
            src.read_source_file(p, tree, "../../../etc/passwd")


def test_read_missing_file(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="scratch", origin="scratch")
        with pytest.raises(src.SourceError):
            src.read_source_file(p, tree, "nope.c")


# --- lazy node materialization + dedup ----------------------------------------

def test_lazy_source_file_node_materialization_and_dedup(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="scratch", origin="scratch")
        src.write_source_file(s, p, tree, "foo.c", "x")
        # NOTHING materialized eagerly
        assert s.query(Node).filter(Node.node_type == "source_file").count() == 0
        n1 = src.materialize_source_file(s, p, tree, "foo.c")
        n2 = src.materialize_source_file(s, p, tree, "foo.c")
        assert n1.id == n2.id  # same file → same node (lazy + idempotent)
        assert n1.target_id is None and (n1.attrs_json or {}).get("rel") == "foo.c"
        assert s.query(Node).filter(Node.node_type == "source_file").count() == 1


def test_merge_duplicates_folds_source_file_dupes(hg_home):
    """nodemerge must cope with source_file nodes: its default key is (type,
    target_id=None, fq_name) and our fq_name=`tree:rel` is a stable identity, so two
    rows for the same file fold into one keeping their edges."""
    with session_scope() as s:
        p = create_project(s, name="src")
        tree = src.create_source_tree(s, p, name="scratch", origin="scratch")
        src.write_source_file(s, p, tree, "foo.c", "x")
        keeper = src.materialize_source_file(s, p, tree, "foo.c")
        # forge a duplicate row with the SAME fq_name (simulating two code paths)
        dup = Node(project_id=p.id, node_type="source_file", target_id=None,
                   name="foo.c", fq_name=f"{tree.id}:foo.c", attrs_json={"tree_id": tree.id, "rel": "foo.c"})
        s.add(dup)
        s.flush()
        assert s.query(Node).filter(Node.node_type == "source_file").count() == 2
        merge_duplicates(s, p.id)
        remaining = s.query(Node).filter(Node.node_type == "source_file").all()
        assert len(remaining) == 1 and remaining[0].id == keeper.id


# --- the new edges + endpoint-validator widening ------------------------------

def test_built_from_edge_to_source_tree(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tree = src.create_source_tree(s, p, name="httpd-src", origin="upload")
        # add_edge accepts source_tree as a polymorphic endpoint kind now
        e = add_edge(s, project_id=p.id, src=("target", t.id), dst=("source_tree", tree.id),
                     type=EdgeType.built_from, origin="human")
        assert e.dst_kind == "source_tree" and e.dst_id == tree.id
        # surfaced in list_source_trees as a linked target
        listed = {x["id"]: x for x in src.list_source_trees(s, p)}
        assert t.id in listed[tree.id]["target_ids"]


def test_authoring_create_edge_validates_source_tree_endpoint(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tree = src.create_source_tree(s, p, name="httpd-src", origin="upload")
        # valid: target -> source_tree
        e = create_edge(s, p, src_kind="target", src_id=t.id, dst_kind="source_tree",
                        dst_id=tree.id, type="built_from")
        assert e.id
        # a nonexistent source_tree endpoint is rejected by the existence check
        with pytest.raises(InvariantError):
            create_edge(s, p, src_kind="target", src_id=t.id, dst_kind="source_tree",
                        dst_id="does-not-exist", type="built_from")


def test_located_in_edge_finding_to_source(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tree = src.create_source_tree(s, p, name="httpd-src", origin="scratch")
        src.write_source_file(s, p, tree, "httpd.c", "void cgi(){strcpy(b,t);}\n")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="overflow", severity="high", confidence="high", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="cgi")))
        node = src.link_finding_to_source(s, p, finding_id=f.id, tree=tree, rel="httpd.c", line=1)
        # located_in edge exists finding -> source_file node
        e = (s.query(Edge).filter(Edge.type == "located_in", Edge.src_id == f.id,
                                  Edge.dst_id == node.id).one())
        assert e.attrs_json.get("line") == 1
        # evidence.extra.source_ref mirrors it (frozen schema untouched)
        ref = (s.get(Finding, f.id).evidence_json or {})["extra"]["source_ref"]
        assert ref["tree_id"] == tree.id and ref["rel"] == "httpd.c" and ref["line"] == 1


# --- harness promotion + backfill + back-compat read --------------------------

def _harness_finding(s, p, t):
    hg = create_task(s, project=p, target_id=t.id, type="harness_generation")
    f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=hg.id, finding=FModel(
        title="harness", severity="info", confidence="low", category="other",
        summary="s", reasoning="r", evidence=Evidence(function="cgi_handler", decompiled_snippet=HARNESS)))
    return f


def test_promote_harness_creates_source_file_and_harness_node(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        f = _harness_finding(s, p, t)
        hnode, fnode = promote_harness(s, p, t.id, HARNESS, function="cgi_handler", finding_id=f.id)
        assert hnode.node_type == "harness" and fnode.node_type == "source_file"
        assert (fnode.attrs_json or {}).get("role") == "harness"
        # harnesses edge harness -> target
        assert s.query(Edge).filter(Edge.type == "harnesses", Edge.src_id == hnode.id,
                                    Edge.dst_kind == "target", Edge.dst_id == t.id).count() == 1
        # the source is readable host-side from the managed tree
        tree = get_or_create_harness_tree(s, p)
        rel = (hnode.attrs_json or {})["rel"]
        assert HARNESS in src.read_source_file(p, tree, rel)["content"]


def test_backfill_is_idempotent(hg_home):
    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        _harness_finding(s, p, t)
        r1 = backfill_harnesses(s, p)
        assert r1 == {"promoted": 1, "scanned": 1}
        before = s.query(Node).filter(Node.node_type == "source_file").count()
        r2 = backfill_harnesses(s, p)  # idempotent — no new files/nodes
        after = s.query(Node).filter(Node.node_type == "source_file").count()
        assert r2["promoted"] == 1 and before == after


def test_resolve_harness_prefers_managed_then_falls_back(hg_home):
    from hexgraph.engine.fuzzing import resolve_harness

    with session_scope() as s:
        p = create_project(s, name="src")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        f = _harness_finding(s, p, t)
        # BEFORE backfill: legacy back-compat read path still finds the snippet
        fuzz_task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        source, _fid, fn = resolve_harness(s, t, fuzz_task)
        assert source == HARNESS
        # AFTER backfill: the managed source_file is preferred (same bytes)
        backfill_harnesses(s, p)
        source2, _fid2, _fn2 = resolve_harness(s, t, fuzz_task)
        assert source2 == HARNESS


# --- API + MCP read tools -----------------------------------------------------

def test_api_source_tree_endpoints(hg_home):
    with session_scope() as s:
        p = create_project(s, name="api")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id
    client = TestClient(create_app())
    # create a tree linked to the target
    r = client.post(f"/api/projects/{pid}/source-trees",
                    json={"name": "lib", "origin": "scratch", "target_id": tid})
    assert r.status_code == 200, r.text
    tree_id = r.json()["id"]
    # list
    trees = client.get(f"/api/projects/{pid}/source-trees").json()["source_trees"]
    assert any(x["id"] == tree_id and tid in x["target_ids"] for x in trees)
    # write a file then read it back
    client.post(f"/api/source-trees/{tree_id}/files",
                json={"rel": "main.c", "content": "int main(){return 0;}", "role": "code"})
    listing = client.get(f"/api/source-trees/{tree_id}/files").json()
    assert any(f["rel"] == "main.c" for f in listing["files"])
    got = client.get(f"/api/source-trees/{tree_id}/file", params={"rel": "main.c"}).json()
    assert got["encoding"] == "text" and "int main" in got["content"]
    # traversal is rejected with a 400
    bad = client.get(f"/api/source-trees/{tree_id}/file", params={"rel": "../../escape"})
    assert bad.status_code == 400


def test_api_backfill_and_link(hg_home):
    with session_scope() as s:
        p = create_project(s, name="api")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        f = _harness_finding(s, p, t)
        pid, fid = p.id, f.id
    client = TestClient(create_app())
    r = client.post(f"/api/projects/{pid}/backfill-harnesses").json()
    assert r["promoted"] == 1


def test_mcp_read_tools(hg_home):
    from hexgraph.agent import mcp_tools as mt

    with session_scope() as s:
        p = create_project(s, name="mcp")
        tree = src.create_source_tree(s, p, name="lib", origin="scratch")
        src.write_source_file(s, p, tree, "x.c", "int x;")
        pid, tree_id = p.id, tree.id
    listed = mt.list_source_trees(pid)["source_trees"]
    assert any(x["id"] == tree_id for x in listed)
    files = mt.read_source_file(tree_id)  # no rel → listing
    assert any(f["rel"] == "x.c" for f in files["files"])
    content = mt.read_source_file(tree_id, "x.c")
    assert content["encoding"] == "text" and "int x" in content["content"]
    # traversal returns an error dict (not a raise) through the MCP boundary
    assert "error" in mt.read_source_file(tree_id, "../../etc/passwd")


def test_mcp_import_and_link_tools(hg_home):
    from hexgraph.agent import mcp_tools as mt

    with session_scope() as s:
        p = create_project(s, name="mcp")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="bug", severity="high", confidence="high", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="cgi")))
        pid, fid = p.id, f.id
    res = mt.import_source_tree(pid, "authored",
                                files=[{"rel": "h.c", "content": HARNESS, "role": "harness"}])
    assert res["written"] == 1
    tree_id = res["id"]
    link = mt.link_finding_to_source(fid, tree_id, "h.c", line=1)
    assert link["node_id"] and link["rel"] == "h.c"
