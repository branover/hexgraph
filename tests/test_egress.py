"""Phase 2 of dynamic surfaces (docs/design/design-dynamic-surfaces.md): the bounded-egress
machinery — the network policy tier, the loopback/private-only NetworkScope, the
egress audit, the runner's gated network mode, and web_recon's denial-by-default +
audit behaviour (the live probe itself is Docker/feature-gated and not run here)."""

import importlib.util
import socket
import threading
from pathlib import Path

import pytest

from hexgraph import policy, settings

# The egress probes live in the sandbox image where `hexgraph` is NOT installed; they import
# `_egress` as a sibling on sys.path[0]. Load it the same way here, by file path.
_PROBES_DIR = Path(__file__).resolve().parents[1] / "src" / "hexgraph" / "sandbox" / "probes"


def _load_egress():
    import sys

    # Share the one module object across the suite (the probes import `_egress` by this name
    # via their sys.path insert), so the autouse conftest cleanup restores the state we mutate.
    if "_egress" in sys.modules:
        return sys.modules["_egress"]
    spec = importlib.util.spec_from_file_location("_egress", _PROBES_DIR / "_egress.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_egress"] = mod
    spec.loader.exec_module(mod)
    return mod


# The five egress probes that MUST adopt the shared guard. A new egress probe that forgets
# `install_socket_guard` fails `test_every_egress_probe_installs_socket_guard` below.
_EGRESS_PROBES = [
    "http_probe.py", "tcp_probe.py", "surface_probe.py",
    "web_discover_probe.py", "remote_probe.py",
]
from hexgraph.db.models import EgressEvent
from hexgraph.db.session import session_scope
from hexgraph.agent import mcp_tools as M
from hexgraph.engine.audit import list_egress, record_egress
from hexgraph.engine.targets.ingest import create_project
from hexgraph.engine.targets.surfaces import register_web_surface
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
    for public in ("http://example.com", "http://8.8.8.8", "https://1.1.1.1", "http://93.184.216.34",
                   "http://169.254.169.254"):  # incl. the cloud-metadata link-local SSRF vector
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
    from hexgraph.engine.targets.surfaces import run_web_recon
    with session_scope() as s:
        p = create_project(s, name="pub")
        surface = register_web_surface(s, p, "http://example.com", endpoints=[{"path": "/"}])
        with pytest.raises(policy.PolicyViolation):
            run_web_recon(s, p, surface, task=None)


# --- the centralized app-layer egress guard (review #7 middle ground) ----------------
#
# `_egress` is the shared chokepoint every egress probe imports. These tests exercise the
# helper directly (offline, no Docker) and statically assert every egress probe adopts the
# can't-forget socket-guard backstop.

def test_egress_dest_canonicalization():
    eg = _load_egress()
    assert eg.dest("127.0.0.1", 80) == "127.0.0.1:80"
    assert eg.dest("192.168.1.1", 8080) == "192.168.1.1:8080"
    # a bracketed IPv6 literal normalizes to the bare form the policy scope uses
    assert eg.dest("[::1]", 80) == "::1:80"
    assert eg.dest("::1", 80) == "::1:80"


def test_ensure_allowed_allow_and_deny():
    eg = _load_egress()
    allow = {"127.0.0.1:80"}
    eg.ensure_allowed("127.0.0.1", 80, allow)  # on-list → no raise
    with pytest.raises(eg.EgressBlocked):
        eg.ensure_allowed("127.0.0.1", 81, allow)      # wrong port
    with pytest.raises(eg.EgressBlocked):
        eg.ensure_allowed("10.0.0.9", 80, allow)       # wrong host
    with pytest.raises(eg.EgressBlocked):
        eg.ensure_allowed("127.0.0.1", 80, set())      # empty allowlist → fail closed


def test_socket_guard_blocks_offlist_and_allows_onlist():
    eg = _load_egress()
    # real localhost listener on an ephemeral port; that exact host:port is allowlisted
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept():
        try:
            conn, _ = srv.accept()
            conn.close()
        except OSError:
            pass

    threading.Thread(target=_accept, daemon=True).start()
    try:
        eg.install_socket_guard({f"127.0.0.1:{port}"})
        # ON-allowlist connect succeeds (the legitimate target connect, incl. rehost case)
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        # a DIFFERENT port not in allow → blocked, via both entry points
        with pytest.raises(eg.EgressBlocked):
            socket.create_connection(("127.0.0.1", port + 1), timeout=2)
        with pytest.raises(eg.EgressBlocked):
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.connect(("127.0.0.1", port + 1))
    finally:
        srv.close()


def test_socket_guard_allows_hostname_allowlist_entry():
    """Regression: a HOSTNAME allowlist entry (localhost / host.docker.internal — all in
    policy._LOCAL_HOSTNAMES, so a surface can be registered as http://localhost:PORT) must
    NOT be over-blocked. create_connection('localhost', p) resolves to 127.0.0.1 then calls
    the guarded inner connect with the IP; the guard must accept it because the install
    expanded the hostname entry to its resolved-IP form. Pre-fix this raised EgressBlocked."""
    eg = _load_egress()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _accept():
        try:
            conn, _ = srv.accept(); conn.close()
        except OSError:
            pass

    threading.Thread(target=_accept, daemon=True).start()
    try:
        eg.install_socket_guard({f"localhost:{port}"})  # HOSTNAME entry, not an IP
        s = socket.create_connection(("localhost", port), timeout=2)  # must NOT raise
        s.close()
        # a hostname+wrong-port (and its resolved IP) is still blocked
        with pytest.raises(eg.EgressBlocked):
            socket.create_connection(("localhost", port + 1), timeout=2)
    finally:
        srv.close()


def test_socket_guard_leaves_dns_and_udp_alone():
    """CRITICAL: the guard must not interfere with name resolution or UDP — only TCP stream
    connects. getaddrinfo (and the UDP sockets a resolver opens) must flow through."""
    eg = _load_egress()
    eg.install_socket_guard({"127.0.0.1:1"})  # deliberately tiny allowlist
    # DNS resolution path is untouched even though nothing is on the allowlist
    socket.getaddrinfo("localhost", 80)
    # a UDP socket "connect" (sets default peer; no TCP handshake) is not policed
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.connect(("8.8.8.8", 53))  # off-allowlist, but UDP → must NOT raise
    finally:
        u.close()


def test_every_egress_probe_installs_socket_guard():
    """Contract: every egress probe MUST adopt the shared backstop. A new egress probe that
    forgets `install_socket_guard` (so a future redirect/DNS-mismatch could escape the
    app-layer allowlist) fails here."""
    for name in _EGRESS_PROBES:
        src = (_PROBES_DIR / name).read_text()
        assert "import _egress" in src, f"{name} does not import the shared _egress chokepoint"
        assert "_egress.install_socket_guard(" in src, (
            f"{name} is an egress probe but never calls _egress.install_socket_guard()")
