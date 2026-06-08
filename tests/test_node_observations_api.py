"""A node's full result-set: GET /api/projects/{id}/nodes/{nodeId}/observations returns
every tool result that references the node via node_refs (a superset of attrs.provenance),
backing the NodeInspector "Tool Results" section. Mock, offline — no Docker, no key."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function

from conftest import fixture_path


def _seed(hg_home):
    """A target with a function node; two observations reference the node and one does not."""
    with session_scope() as s:
        p = create_project(s, name="node-obs")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        s.flush()
        fn = materialize_function(s, project_id=p.id, target_id=t.id, name="cgi_handler")
        other = materialize_function(s, project_id=p.id, target_id=t.id, name="parse_request")
        # Two results reference cgi_handler …
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="task-1", tool="decompile_function",
            args={"function": "cgi_handler"}, result_kind="decompilation",
            payload={"pseudocode": "void cgi_handler(){}"}, summary="decompiled cgi_handler",
            content_hash="aa", node_refs=[fn.id])
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="task-1", tool="disassemble",
            args={"function": "cgi_handler"}, result_kind="disassembly",
            payload={"disasm": "push rbp"}, summary="disassembled cgi_handler",
            content_hash="bb", node_refs=[fn.id])
        # … and one references a DIFFERENT node only.
        O.record_observation(
            s, project_id=p.id, target_id=t.id, source="task-2", tool="decompile_function",
            args={"function": "parse_request"}, result_kind="decompilation",
            payload={"pseudocode": "int parse_request(){}"}, summary="decompiled parse_request",
            content_hash="cc", node_refs=[other.id])
        return p.id, t.id, fn.id, other.id


def test_node_observations_returns_only_referencing_results(hg_home):
    pid, _tid, fid, _other = _seed(hg_home)
    c = TestClient(create_app())
    r = c.get(f"/api/projects/{pid}/nodes/{fid}/observations")
    assert r.status_code == 200
    rows = r.json()["observations"]
    assert {row["result_kind"] for row in rows} == {"decompilation", "disassembly"}
    assert all(fid in (row["node_refs"] or []) for row in rows)
    assert all("payload" not in row for row in rows)  # row metadata only


def test_node_observations_excludes_other_nodes(hg_home):
    pid, _tid, _fid, other = _seed(hg_home)
    c = TestClient(create_app())
    rows = c.get(f"/api/projects/{pid}/nodes/{other}/observations").json()["observations"]
    assert len(rows) == 1
    assert rows[0]["summary"] == "decompiled parse_request"


def test_node_observations_empty_when_unreferenced(hg_home):
    with session_scope() as s:
        p = create_project(s, name="node-obs-empty")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        s.flush()
        fn = materialize_function(s, project_id=p.id, target_id=t.id, name="lonely")
        pid, fid = p.id, fn.id
    c = TestClient(create_app())
    r = c.get(f"/api/projects/{pid}/nodes/{fid}/observations")
    assert r.status_code == 200 and r.json()["observations"] == []


def test_node_observations_404_for_unknown_node(hg_home):
    with session_scope() as s:
        p = create_project(s, name="node-obs-404")
        pid = p.id
    c = TestClient(create_app())
    assert c.get(f"/api/projects/{pid}/nodes/nope/observations").status_code == 404
