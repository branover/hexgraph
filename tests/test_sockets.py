"""First-class raw-TCP / socket live targets (`TargetKind.service`).

A bare non-HTTP network service (bind shell / vendor binary protocol / custom daemon) is
registered DIRECTLY — no misusing register_remote(transport="telnet"), which carries
SSH/telnet shell-credential semantics a protocol endpoint doesn't have. Covers:
  • register_service_target → a `service` target + the tcp/udp Channel (no creds) + the
    linked shared `socket` NODE (listens_on edge) — target (surface) vs node (annotation);
  • infer_surface → `network` (so it's fuzzable directly);
  • a (mock) network campaign on a socket target launches via the EXISTING bounded local-
    network tier — egress-gated, audited — and REFUSES a non-local host (local_tcp_scope);
  • the REST endpoint + the register_service MCP tool.
All offline ($0) with a fake executor / fake runner; no real socket.
"""

import json

import pytest

from hexgraph import policy, settings as st
from hexgraph.db.models import Edge, EdgeType, EgressEvent, Node, NodeType, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.ingest import create_project
from hexgraph.engine.surfaces import register_service_target


# ── register_service_target: the `service` target + channel + node link ────────────

def test_register_service_creates_service_target_and_channel(hg_home):
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "192.168.1.1", 1337, name="bindshell")
        assert t.kind == TargetKind.service
        assert t.path == ""                       # reached via a Channel, not a file
        ch = (t.metadata_json or {}).get("channel")
        assert ch == {"kind": "tcp", "host": "192.168.1.1", "port": 1337}
        # NO credential/username/transport(shell) baggage in the channel.
        assert "username" not in ch and "transport" not in ch
        assert t.name == "bindshell"


def test_register_service_links_shared_socket_node(hg_home):
    """The reachable surface (target) links to the SHARED socket NODE (the network-map
    endpoint, target_id=None) via a `listens_on` edge — target vs node stays distinct."""
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "127.0.0.1", 9000, transport="tcp")
        sock = (s.query(Edge)
                .filter(Edge.project_id == p.id, Edge.src_kind == "target",
                        Edge.src_id == t.id, Edge.type == EdgeType.listens_on.value)
                .first())
        assert sock is not None
        node = s.get(Node, sock.dst_id)
        assert node.node_type == NodeType.socket.value
        assert node.target_id is None              # the socket node is shared, not bound
        assert node.attrs_json.get("port") == 9000


def test_register_service_udp_and_proto_hint(hg_home):
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "10.0.0.5", 5683, transport="udp", proto="coap")
        ch = (t.metadata_json or {}).get("channel")
        assert ch["kind"] == "udp"
        assert (t.metadata_json or {}).get("proto") == "coap"


def test_register_service_validation(hg_home):
    with session_scope() as s:
        p = create_project(s, name="svc")
        with pytest.raises(ValueError):
            register_service_target(s, p, "", 80)               # no host
        with pytest.raises(ValueError):
            register_service_target(s, p, "h", 70000)           # bad port
        with pytest.raises(ValueError):
            register_service_target(s, p, "h", 80, transport="ssh")  # not tcp/udp


# ── infer_surface → network (so it's fuzzable directly) ───────────────────────────

def test_infer_surface_service_is_network(hg_home):
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "127.0.0.1", 1337)
        assert C.infer_surface(t) == "network"


# ── a (mock) network campaign on a socket target: launch, gate, audit, refuse ─────

class _NetExecutor:
    """A fake executor capturing the detached-launch args of a boofuzz campaign."""
    def __init__(self):
        self.calls = []

    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None,
                       allow_network=False, net_container=None):
        from hexgraph.sandbox.runner import DetachedHandle
        self.calls.append({"probe": probe, "name": name, "extra_args": extra_args,
                           "requires_execution": requires_execution,
                           "allow_network": allow_network, "net_container": net_container})
        return DetachedHandle(name=name, outdir=str(outdir))


def _net_spec(t):
    # boofuzz (the default network engine) — host/port are resolved from the socket
    # target's channel by resolve_surface_inputs (NOT passed explicitly here, proving the
    # wiring works end-to-end from a registered socket target).
    return FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")


def test_socket_target_network_campaign_launches_egress_gated_and_audited(hg_home):
    """start_campaign on a socket target rides the EXISTING local-network tier: with
    features.network on, _launch_network builds local_tcp_scope from the target's channel
    host:port, asserts egress, AUDITS an allowed EgressEvent, and launches the detached
    boofuzz container on the bounded-egress path (allow_network, requires_execution=False)."""
    st.update_settings({"features": {"network": {"enabled": True}}})
    ex = _NetExecutor()
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "192.168.0.50", 4444, name="daemon")
        row = C.start_campaign(s, p, t, spec=_net_spec(t), executor=ex)
        assert row.status == "running"
        assert row.surface == "network" and row.engine == "boofuzz"
        # The detached container launched on the bounded-egress path (NOT the exec gate).
        call = ex.calls[0]
        assert call["probe"] == "boofuzz_probe.py"
        assert call["allow_network"] is True and call["requires_execution"] is False
        # The boofuzz channel carries the socket target's host:port from its Channel.
        chan = json.loads(call["extra_args"][call["extra_args"].index("--channel") + 1])
        assert chan["host"] == "192.168.0.50" and chan["port"] == 4444
        assert chan["allow"] == ["192.168.0.50:4444"]
        # An ALLOWED egress event was audited before launch.
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "boofuzz").all()
        assert len(ev) == 1 and ev[0].allowed is True and ev[0].dest == "192.168.0.50:4444"


def test_socket_target_campaign_denied_and_audited_when_network_off(hg_home):
    """With features.network OFF, the same launch fails closed (PolicyViolation surfaced as
    CampaignError) and a DENIED EgressEvent is recorded — nothing reaches the network."""
    ex = _NetExecutor()
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "192.168.0.50", 4444)
        with pytest.raises(C.CampaignError):
            C.start_campaign(s, p, t, spec=_net_spec(t), executor=ex)
        assert not ex.calls                       # never launched
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "boofuzz").all()
        assert len(ev) == 1 and ev[0].allowed is False


def test_socket_target_campaign_refuses_public_host(hg_home):
    """A socket target on a PUBLIC host is refused by local_tcp_scope before any launch —
    the bounded local-network tier never reaches a non-loopback/private host."""
    st.update_settings({"features": {"network": {"enabled": True}}})
    ex = _NetExecutor()
    with session_scope() as s:
        p = create_project(s, name="svc")
        t = register_service_target(s, p, "8.8.8.8", 53, transport="udp")
        with pytest.raises((policy.PolicyViolation, C.CampaignError)):
            C.start_campaign(s, p, t, spec=_net_spec(t), executor=ex)
        assert not ex.calls


# ── REST + MCP registration paths ─────────────────────────────────────────────────

def test_rest_register_service(hg_home):
    from fastapi.testclient import TestClient
    from hexgraph.api.app import create_app

    app = create_app()
    with session_scope() as s:
        pid = create_project(s, name="svc").id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/targets/service",
                   json={"host": "127.0.0.1", "port": 1337, "name": "shell"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["kind"] == "service"
        assert body["channel"] == {"kind": "tcp", "host": "127.0.0.1", "port": 1337}
        # a bad port is a 400, not a 500
        bad = c.post(f"/api/projects/{pid}/targets/service",
                     json={"host": "127.0.0.1", "port": 0})
        assert bad.status_code == 400


def test_mcp_register_service(hg_home):
    from hexgraph.engine.mcp_tools import register_service

    with session_scope() as s:
        pid = create_project(s, name="svc").id
    out = register_service(pid, "192.168.1.9", 22222, transport="tcp", proto="custom")
    assert out["kind"] == "service"
    assert out["channel"]["host"] == "192.168.1.9" and out["channel"]["port"] == 22222
    # bad project / bad parent are clean errors, not exceptions
    assert "error" in register_service("nope", "h", 80)
    assert "error" in register_service(pid, "h", 80, parent_ref="nope")


def test_mcp_register_service_in_catalog():
    """register_service is advertised in the MCP catalog (so an agent can discover it)."""
    from hexgraph.engine.mcp_catalog import _CATALOG

    names = {name for _grp, name, *_ in _CATALOG}
    assert "target_register_service" in names
