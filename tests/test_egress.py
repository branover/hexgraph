"""Phase 2 of dynamic surfaces (docs/design-dynamic-surfaces.md): the bounded-egress
machinery — the network policy tier, the loopback/private-only NetworkScope, the
egress audit, the runner's gated network mode, and web_recon's denial-by-default +
audit behaviour (the live probe itself is Docker/feature-gated and not run here)."""

import pytest

from hexgraph import policy, settings
from hexgraph.db.models import EgressEvent
from hexgraph.db.session import session_scope
from hexgraph.engine import mcp_tools as M
from hexgraph.engine.audit import list_egress, record_egress
from hexgraph.engine.ingest import create_project
from hexgraph.engine.surfaces import register_web_surface
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync


def test_network_tier_off_by_default_and_opt_in(hg_home):
    pol = policy.current_policy()
    assert pol.tier == policy.TIER_STATIC_ONLY and pol.allow_network is False
    settings.update_settings({"features": {"network": {"enabled": True}}})
    pol = policy.current_policy()
    assert pol.tier == policy.TIER_LOCAL_NETWORK and pol.allow_network is True
    # execution stays independent — network alone does not permit running the target
    assert pol.allow_execution is False


def test_local_network_scope_refuses_public_hosts():
    for ok in ("http://127.0.0.1:8080", "http://192.168.1.1", "http://10.0.0.5:8443",
               "http://localhost", "http://[::1]:80"):
        scope = policy.local_network_scope(ok)
        assert len(scope.allow) == 1
    for public in ("http://example.com", "http://8.8.8.8", "https://1.1.1.1", "http://93.184.216.34"):
        with pytest.raises(policy.PolicyViolation):
            policy.local_network_scope(public)


def test_local_network_scope_dest_format():
    assert policy.local_network_scope("http://192.168.1.1").allow == frozenset({"192.168.1.1:80"})
    assert policy.local_network_scope("https://127.0.0.1").allow == frozenset({"127.0.0.1:443"})
    assert policy.local_network_scope("http://10.0.0.1:8080").allow == frozenset({"10.0.0.1:8080"})


def test_assert_allows_egress_two_independent_gates(hg_home):
    scope = policy.NetworkScope(allow=frozenset({"127.0.0.1:80"}))
    # gate 1: network off → deny even an allowlisted dest
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("127.0.0.1:80", scope)
    settings.update_settings({"features": {"network": {"enabled": True}}})
    # gate 2: network on, but dest must be in the scope allowlist
    policy.assert_allows_egress("127.0.0.1:80", scope)              # ok
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("10.0.0.9:80", scope)          # not allowlisted
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("127.0.0.1:80", None)          # no scope → deny


def test_record_and_list_egress(hg_home):
    with session_scope() as s:
        p = create_project(s, name="aud")
        record_egress(s, project_id=p.id, dest="127.0.0.1:80", allowed=True, tool="web_recon")
        record_egress(s, project_id=p.id, dest="10.0.0.1:80", allowed=False, tool="web_recon",
                      detail="blocked")
        pid = p.id
    log = list_egress_via_mcp(pid)
    assert len(log) == 2
    assert {e["allowed"] for e in log} == {True, False}


def list_egress_via_mcp(pid):  # exercises the MCP read tool too
    return M.list_egress(pid)


def test_runner_network_mode_requires_policy(hg_home):
    from hexgraph.sandbox.runner import SandboxRunner
    # allow_network=True while the policy forbids network → refuse BEFORE any docker call
    with pytest.raises(policy.PolicyViolation):
        SandboxRunner().run_probe("surface_probe.py", None, allow_network=True)


def test_web_recon_denied_by_default_and_audited(hg_home):
    """With features.network OFF (the default), web_recon must NOT reach out: the task
    fails on the egress gate and a DENIED EgressEvent is logged (offline, no Docker)."""
    with session_scope() as s:
        p = create_project(s, name="wr")
        surface = register_web_surface(s, p, "http://127.0.0.1:8080",
                                       endpoints=[{"method": "GET", "path": "/"}])
        task = create_task(s, project=p, target_id=surface.id, type="web_recon")
        tid, pid = task.id, p.id

    assert run_task_sync(tid) == "failed"          # blocked by the egress gate
    with session_scope() as s:
        events = s.query(EgressEvent).filter(EgressEvent.project_id == pid).all()
        assert len(events) == 1
        assert events[0].allowed is False and events[0].dest == "127.0.0.1:8080"


def test_web_recon_refuses_public_target(hg_home):
    # even with network enabled, a public target is refused by the scope guard
    settings.update_settings({"features": {"network": {"enabled": True}}})
    from hexgraph.engine.surfaces import run_web_recon
    with session_scope() as s:
        p = create_project(s, name="pub")
        surface = register_web_surface(s, p, "http://example.com", endpoints=[{"path": "/"}])
        with pytest.raises(policy.PolicyViolation):
            run_web_recon(s, p, surface, task=None)
