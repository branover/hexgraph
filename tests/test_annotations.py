"""P6 annotations: notes/tags/renames, confirm/reject, rename-applies, context feedback."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Node
from hexgraph.db.session import session_scope
from hexgraph.engine.annotations import confirmed_facts, create_annotation, set_status
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import materialize_function

from conftest import fixture_path


def _project_with_fn(s):
    p = create_project(s, name="ann")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    fn = materialize_function(s, project_id=p.id, target_id=t.id, name="FUN_00401abc")
    return p, t, fn


def test_human_rename_applies_and_keeps_identity(hg_home):
    with session_scope() as s:
        p, t, fn = _project_with_fn(s)
        fq, nid = fn.fq_name, fn.id
        create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="rename", value="parse_request")
        n = s.get(Node, nid)
        assert n.name == "parse_request"            # display updated
        assert n.fq_name == fq                       # durable identity preserved
        assert "FUN_00401abc" in (n.attrs_json.get("name_history") or [])


def test_agent_proposed_rename_needs_confirm(hg_home):
    with session_scope() as s:
        p, t, fn = _project_with_fn(s)
        a = create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="rename",
                              value="cgi_handler", origin="agent_proposed")
        assert a.status == "proposed"
        assert s.get(Node, fn.id).name == "FUN_00401abc"  # not applied yet
        set_status(s, a.id, "confirmed")
        assert s.get(Node, fn.id).name == "cgi_handler"   # applied on confirm


def test_confirmed_facts_feed_context(hg_home):
    with session_scope() as s:
        p, t, fn = _project_with_fn(s)
        create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="note", value="parses CGI form fields")
        facts = confirmed_facts(s, p.id, t.id)
        assert any("parses CGI form fields" in f for f in facts)


def test_tag_on_finding_via_api(hg_home):
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding as FModel

    with session_scope() as s:
        p = create_project(s, name="tagp")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="overflow", severity="high", confidence="medium", category="memory-safety",
            summary="s", reasoning="r", evidence=Evidence(function="f")))
        pid, fid = p.id, f.id

    c = TestClient(create_app())
    r = c.post(f"/api/projects/{pid}/annotations", json={"node_kind": "finding", "node_id": fid, "kind": "tag", "value": "exploitable"})
    assert r.status_code == 200
    body = c.get(f"/api/projects/{pid}").json()
    tagged = next(x for x in body["findings"] if x["id"] == fid)
    assert "exploitable" in tagged["tags"]


def test_invalid_annotations_rejected(hg_home):
    with session_scope() as s:
        p, t, fn = _project_with_fn(s)
        pid = p.id
    c = TestClient(create_app())
    # rename on a target (not a node) is invalid
    assert c.post(f"/api/projects/{pid}/annotations", json={"node_kind": "target", "node_id": t_id(pid), "kind": "rename", "value": "x"}).status_code in (400, 404)


def t_id(pid):  # helper: first target id of a project
    from hexgraph.db.models import Target
    with session_scope() as s:
        return s.query(Target).filter(Target.project_id == pid).first().id
