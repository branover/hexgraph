"""Phase 1 of dynamic surfaces (docs/design/design-dynamic-surfaces.md): the web-surface
abstraction + mock/offline surface_recon + the static↔dynamic `routes_to` cross-link,
and the additive policy-tier scaffolding (no egress is permitted yet)."""

import pytest

from hexgraph.db.models import Edge, EdgeType, Node, NodeType, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine import mcp_tools as M
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import materialize_function
from hexgraph.engine.surfaces import register_web_surface, run_surface_recon
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync
from hexgraph import policy

from conftest import fixture_path

SPEC = [
    {"method": "POST", "path": "/cgi-bin/login", "params": ["user", "pass"],
     "handler": "cgi_handler", "auth": "none"},
    {"method": "GET", "path": "/admin/status", "params": ["token"], "auth": "required"},
]


def test_vocab_present():
    assert TargetKind.web_app.value == "web_app"
    assert {"endpoint", "param"} <= {t.value for t in NodeType}
    assert EdgeType.routes_to.value == "routes_to"


def test_register_web_surface(hg_home):
    with session_scope() as s:
        p = create_project(s, name="surf")
        t = register_web_surface(s, p, "http://192.168.1.1", name="router-ui", endpoints=SPEC)
        assert t.kind == TargetKind.web_app
        assert t.path == ""  # a surface has no bytes at rest
        ch = (t.metadata_json or {})["channel"]
        assert ch["kind"] == "http" and ch["base_url"] == "http://192.168.1.1"
        assert len(t.metadata_json["endpoints"]) == 2
    with pytest.raises(ValueError):
        with session_scope() as s:
            register_web_surface(s, create_project(s, name="x"), "")


def test_surface_recon_materialises_routes_params_and_handler_crosslink(hg_home):
    """The differentiator: a discovered route links to its handler function in the
    firmware binary via routes_to."""
    with session_scope() as s:
        p = create_project(s, name="surf2")
        fw = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        # the binary has the handler the web route dispatches to
        handler = materialize_function(s, project_id=p.id, target_id=fw.id, name="cgi_handler")
        surface = register_web_surface(s, p, "http://10.0.0.1", parent=fw, endpoints=SPEC)
        pid, surf_id, handler_id = p.id, surface.id, handler.id

        out = run_surface_recon(s, p, surface)
        assert out == {"endpoints": 2, "handlers_linked": 1}

        endpoints = s.query(Node).filter(Node.project_id == pid,
                                         Node.node_type == NodeType.endpoint.value).all()
        labels = {e.name for e in endpoints}
        assert labels == {"POST /cgi-bin/login", "GET /admin/status"}
        login = next(e for e in endpoints if e.name == "POST /cgi-bin/login")
        assert login.attrs_json["method"] == "POST" and login.attrs_json["auth"] == "none"

        params = s.query(Node).filter(Node.project_id == pid,
                                      Node.node_type == NodeType.param.value).all()
        assert {p_.name for p_ in params} == {"user", "pass", "token"}

        # the routes_to cross-link: login endpoint → cgi_handler function
        rt = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.routes_to.value).all()
        assert len(rt) == 1
        assert rt[0].src_id == login.id and rt[0].dst_id == handler_id

        # idempotent — re-running doesn't duplicate
        run_surface_recon(s, p, surface)
        assert s.query(Node).filter(Node.project_id == pid,
                                    Node.node_type == NodeType.endpoint.value).count() == 2


def test_surface_recon_via_worker_task(hg_home):
    with session_scope() as s:
        p = create_project(s, name="surf3")
        surface = register_web_surface(s, p, "http://10.0.0.2", endpoints=SPEC)
        task = create_task(s, project=p, target_id=surface.id, type="surface_recon")
        tid, pid = task.id, p.id

    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        findings = s.query(__import__("hexgraph.db.models", fromlist=["Finding"]).Finding).filter_by(
            project_id=pid).all()
        recon = [f for f in findings if f.finding_type == "recon"]
        assert recon and "Web surface mapped: 2 endpoint(s)" in recon[0].title


def test_generic_recon_on_web_app_routes_to_surface_recon(hg_home):
    """Regression: running the GENERIC byte `recon` task on a path-less web_app surface
    must route to surface recon (materialise the route spec), NOT crash on the byte path
    with `SandboxError: artifact not found: <cwd>` (Path("").resolve() == cwd)."""
    from hexgraph.db.models import Finding, Node, NodeType

    with session_scope() as s:
        p = create_project(s, name="surf-recon-route")
        surface = register_web_surface(s, p, "http://10.0.0.9", endpoints=SPEC)
        task = create_task(s, project=p, target_id=surface.id, type="recon")
        tid, pid = task.id, p.id

    # Must succeed via surface recon — no executor/Docker, no artifact-not-found.
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        eps = s.query(Node).filter(Node.project_id == pid,
                                   Node.node_type == NodeType.endpoint.value).count()
        assert eps == 2  # the route spec was materialised
        recon = [f for f in s.query(Finding).filter_by(project_id=pid).all()
                 if f.finding_type == "recon"]
        assert recon and "Web surface mapped" in recon[0].title


def test_generic_recon_on_socket_surface_fails_cleanly(hg_home):
    """A `service`/`remote` surface has no offline recon probe — the generic `recon` task
    must fail with a CLEAR error (not byte recon's confusing artifact-not-found)."""
    from hexgraph.db.models import Project, Task, TaskStatus
    from hexgraph.engine.surfaces import register_socket_target
    from hexgraph.engine.worker import _dispatch

    with session_scope() as s:
        p = create_project(s, name="surf-recon-sock")
        sock = register_socket_target(s, p, "127.0.0.1", 9000)
        task = create_task(s, project=p, target_id=sock.id, type="recon")
        tid = task.id

    # The full task path marks the task failed (no Docker, no artifact-not-found crash).
    assert run_task_sync(tid) == "failed"
    with session_scope() as s:
        assert s.get(Task, tid).status == TaskStatus.failed

    # The dispatch raises a clear, actionable error naming the surface kind.
    with session_scope() as s:
        t = s.get(Task, tid)
        proj = s.get(Project, t.project_id)
        tgt = s.get(Target, t.target_id)
        with pytest.raises(NotImplementedError) as ei:
            _dispatch(s, proj, tgt, t)
        msg = str(ei.value)
        assert "service surface" in msg and "artifact not found" not in msg


def test_byte_sandbox_refuses_empty_artifact(hg_home):
    """Defense-in-depth: the byte sandbox runner refuses an empty/path-less artifact with a
    clear surface error instead of resolving '' → cwd → 'artifact not found: <repo root>'."""
    from hexgraph.sandbox.runner import SandboxError, SandboxRunner

    runner = SandboxRunner()
    for empty in ("", "   "):
        with pytest.raises(SandboxError) as ei:
            runner.run_probe("recon_probe.py", empty)
        msg = str(ei.value)
        assert "no byte artifact" in msg and "surface" in msg
        assert "artifact not found" not in msg


def test_endpoint_and_param_are_hand_authorable(hg_home):
    """A4/A3 UX: endpoint and param are first-class, target-bound, hand-authorable
    node types (an analyst can add a route/field the same way as a function node)."""
    from hexgraph.engine.authoring import MANUAL_NODE_TYPES, TARGET_BOUND
    assert {"endpoint", "param"} <= MANUAL_NODE_TYPES
    assert {"endpoint", "param"} <= TARGET_BOUND
    with session_scope() as s:
        p = create_project(s, name="auth")
        surface = register_web_surface(s, p, "http://127.0.0.1", endpoints=[])
        pid, sid = p.id, surface.id
    ep = M.create_node(pid, "endpoint", "POST /api/login", target_id=sid)
    pm = M.create_node(pid, "param", "token", target_id=sid)
    assert ep.get("id") and pm.get("id")
    # they require a target (target-bound) — refused without one
    assert M.create_node(pid, "endpoint", "GET /x").get("error")
    with session_scope() as s:
        kinds = {n.node_type for n in s.query(Node).filter(Node.project_id == pid).all()}
        assert {"endpoint", "param"} <= kinds


def test_mcp_register_and_recon_drive_path(hg_home):
    with session_scope() as s:
        p = create_project(s, name="surf4")
        pid = p.id
    reg = M.register_surface(pid, "http://10.0.0.3", name="ui", endpoints=SPEC)
    assert reg["kind"] == "web_app" and reg["endpoints"] == 2
    res = M.run_task(reg["id"], "surface_recon")
    assert res.get("status") == "succeeded"
    # the new edge type + endpoint nodes are visible through the read tools
    nodes = M.list_nodes(pid, node_type="endpoint")
    assert len(nodes) == 2
    assert "routes_to" in M.get_schemas()["edge_attribute_schemas"]


def test_policy_tier_scaffolding_denies_egress(hg_home):
    pol = policy.current_policy()
    assert pol.tier == policy.TIER_STATIC_ONLY and pol.network is None
    # execution gate unchanged (static-only default)
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_execution()
    # egress is always denied — no tier grants it yet (fail closed)
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("10.0.0.1:80")
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress()
    assert policy.egress_scope() is None
