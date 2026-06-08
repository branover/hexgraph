"""P6 annotations: notes/tags/renames, confirm/reject, rename-applies, context feedback."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Node
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.annotations import confirmed_facts, create_annotation, set_status
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import is_placeholder_name, materialize_function

from conftest import fixture_path


def _project_with_fn(s, name="FUN_00401abc"):
    p = create_project(s, name="ann")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    fn = materialize_function(s, project_id=p.id, target_id=t.id, name=name)
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


def test_agent_rename_of_real_name_needs_confirm(hg_home):
    # An agent renaming a node that ALREADY has a real (analyst-meaningful) name is
    # higher-stakes: it stays `proposed` and is not applied until a human confirms.
    with session_scope() as s:
        p, t, fn = _project_with_fn(s, name="parse_config")
        a = create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="rename",
                              value="cgi_handler", origin="agent")
        assert a.status == "proposed"
        assert a.origin == "agent"
        assert s.get(Node, fn.id).name == "parse_config"  # not applied yet
        set_status(s, a.id, "confirmed")
        assert s.get(Node, fn.id).name == "cgi_handler"   # applied on confirm


def test_agent_naming_placeholder_auto_confirms(hg_home):
    # Naming a genuinely-unnamed object (a decompiler placeholder) is pure value-add,
    # so an agent's rename auto-confirms and applies immediately — no human click —
    # while staying audited (annotation row origin=agent, status=confirmed) and
    # reversible (the old placeholder is recorded in name_history).
    with session_scope() as s:
        p, t, fn = _project_with_fn(s, name="fcn.00401234")
        nid = fn.id
        a = create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="rename",
                              value="parse_request", origin="agent")
        assert a.status == "confirmed"
        assert a.origin == "agent"                          # auditable: still an agent action
        n = s.get(Node, nid)
        assert n.name == "parse_request"                    # applied immediately
        assert "fcn.00401234" in (n.attrs_json.get("name_history") or [])  # reversible


def test_confirmed_facts_feed_context(hg_home):
    with session_scope() as s:
        p, t, fn = _project_with_fn(s)
        create_annotation(s, p.id, node_kind="node", node_id=fn.id, kind="note", value="parses CGI form fields")
        facts = confirmed_facts(s, p.id, t.id)
        assert any("parses CGI form fields" in f for f in facts)


def test_tag_on_finding_via_api(hg_home):
    from hexgraph.engine.findings.findings import persist_finding
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


def test_is_placeholder_name_unit():
    # Genuinely-unnamed: decompiler-synthesized placeholders + empty/None.
    placeholders = [
        None, "", "   ", "\t",
        "fcn.00401234", "fcn.0000abcd",
        "sub_401234", "sub_DEADBEEF",
        "FUN_00401abc", "fun_401000",
        "loc_804a010", "loc.804a010",
        "off_12ab", "unk_4001", "byte_8049f00",
        "nullsub_3", "locret_401050",
        "sym.fcn.00401234",                 # namespace-prefixed placeholder still detected
    ]
    for name in placeholders:
        assert is_placeholder_name(name) is True, name

    # Real, analyst-meaningful names — conservative: anything not a known placeholder
    # pattern is treated as a real name.
    real = [
        "parse_config", "main", "handle_request", "system",
        "sym.get_param",                    # a prefixed REAL name (normalizes to get_param)
        "sub_handler",                      # has a real word, not a bare hex tail
        "function_table",                   # 'fun'/'fcn' substrings but not the pattern
        "loc_handler", "fcn_dispatch",
        "sym.deadbeef", "sym.cafe",         # prefixed REAL names that are all-hex (must NOT auto-confirm)
        "deadbeef", "cafe", "facade",       # bare all-hex real names
        "a", "x1",
    ]
    for name in real:
        assert is_placeholder_name(name) is False, name
