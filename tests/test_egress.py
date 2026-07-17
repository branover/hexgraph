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
from hexgraph.engine.targets.surfaces import (register_web_surface, run_http_request,
                                              run_tcp_probe, run_web_poc)
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


class _ChannelRunner:
    """Stand-in sandbox executor returning a CANNED run_channel_probe result — the REAL contract:
    a socket-level failure comes back as a JSON dict ({"ok": false, "error": ...}), NOT as a raised
    exception (the sandbox probes catch and serialize it). `result` is that dict."""

    def __init__(self, result):
        self.result = result

    def run_channel_probe(self, *a, **kw):
        return self.result


class _HardFailRunner:
    """A HARD failure — the container/probe dies before emitting valid JSON, so run_channel_probe
    itself RAISES (SandboxError). The audit's try/except backstop must still record connect_failed
    (durably) and re-raise."""

    def run_channel_probe(self, *a, **kw):
        from hexgraph.sandbox.runner import SandboxError

        raise SandboxError("probe http_probe did not emit valid JSON")


# The real http_probe shapes: a socket failure is a nested {"response": {"ok": false, "error": ...}}
# (NOT a raise); a real reply — including an HTTP error status — carries a `status`.
_HTTP_CONNFAIL = {"tool": "http_probe", "base_url": "http://127.0.0.1:8080",
                  "response": {"ok": False, "error": "URLError", "dest": "127.0.0.1:8080"}}
_HTTP_OK = {"tool": "http_probe", "base_url": "http://127.0.0.1:8080",
            "response": {"status": 200, "body": "ok"}}
_HTTP_500 = {"tool": "http_probe", "base_url": "http://127.0.0.1:8080",
             "response": {"status": 500, "body": "boom"}}
# tcp/udp results are FLAT (`ok` at top level, no nested "response").
_TCP_CONNFAIL = {"tool": "tcp_probe", "host": "127.0.0.1", "port": 8080, "ok": False,
                 "error": "OSError: [Errno 113] No route to host"}
# tcp SUCCESS: the real probe emits ok:True + the _decode fields (response/encoding), not "raw".
_TCP_OK = {"tool": "tcp_probe", "host": "127.0.0.1", "port": 8080, "ok": True,
           "response": "banner", "encoding": "utf-8"}


def _web_surface(s, name):
    p = create_project(s, name=name)
    surface = register_web_surface(s, p, "http://127.0.0.1:8080",
                                   endpoints=[{"method": "GET", "path": "/"}])
    return p, surface


def _egress_tools(pid):
    with session_scope() as s:
        return [e.tool for e in (s.query(EgressEvent)
                                 .filter(EgressEvent.project_id == pid)
                                 .order_by(EgressEvent.created_at).all())]


def test_http_request_audits_connect_failed_from_returned_error(hg_home):
    """The REAL 'No route to host despite allowed:true' case: the probe RETURNS
    {"ok": false, "error": ...} (it does NOT raise), so run_http_request returns normally — and
    the outcome audit must STILL record :connect_failed. This is exactly what the old
    exception-only check missed (it would have logged :connected)."""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "connfail")
        pid = p.id
        resp = run_http_request(s, p, surface, request={"method": "GET", "path": "/"},
                                runner=_ChannelRunner(_HTTP_CONNFAIL))
        assert resp.get("ok") is False          # returned, not raised — as in production

    tools = _egress_tools(pid)
    assert "http_request" in tools                       # pre-flight policy-allow event
    assert "http_request:connect_failed" in tools         # the real-outcome event
    assert "http_request:connected" not in tools          # must NOT mislabel a failure as connected
    with session_scope() as s:
        failed = next(e for e in s.query(EgressEvent)
                      .filter(EgressEvent.tool == "http_request:connect_failed").all())
        assert failed.allowed is True                     # policy DID allow it
        assert "URLError" in (failed.detail or "")        # the real socket error is captured


def test_http_request_audits_connected_on_real_response(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "connok")
        pid = p.id
        resp = run_http_request(s, p, surface, request={"method": "GET", "path": "/"},
                                runner=_ChannelRunner(_HTTP_OK))
        assert resp["status"] == 200
    tools = _egress_tools(pid)
    assert "http_request:connected" in tools
    assert "http_request:connect_failed" not in tools


def test_http_error_status_counts_as_connected(hg_home):
    """An HTTP 4xx/5xx is a REAL reply — the connection succeeded, the server just answered with an
    error. It must audit :connected, never :connect_failed (guards the 'reached the service' rule)."""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "http500")
        pid = p.id
        run_http_request(s, p, surface, request={"method": "GET", "path": "/"},
                         runner=_ChannelRunner(_HTTP_500))
    tools = _egress_tools(pid)
    assert "http_request:connected" in tools
    assert "http_request:connect_failed" not in tools


def test_tcp_probe_audits_connect_failed_from_flat_result(hg_home):
    """tcp/udp results are a FLAT {"ok": false, ...} (no nested 'response') — the classifier must
    read that shape too, else a network-fuzz/service connect failure would mislabel as connected."""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "tcpfail")
        pid = p.id
        run_tcp_probe(s, p, surface, port=8080, runner=_ChannelRunner(_TCP_CONNFAIL))
    tools = _egress_tools(pid)
    assert "tcp_probe:connect_failed" in tools
    assert "tcp_probe:connected" not in tools


def test_tcp_probe_audits_connected_on_flat_ok(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "tcpok")
        pid = p.id
        run_tcp_probe(s, p, surface, port=8080, runner=_ChannelRunner(_TCP_OK))
    tools = _egress_tools(pid)
    assert "tcp_probe:connected" in tools


def test_web_poc_multistep_connect_failed_when_no_step_reaches(hg_home):
    """A multi-step web_poc result is `{"steps": [...]}`; if EVERY step is a socket-level failure
    the outcome is :connect_failed. (If any step got a real response, the connection was made — see
    the connected variant of this rule in _probe_outcome.)"""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    steps_result = {"tool": "http_probe", "base_url": "http://127.0.0.1:8080",
                    "steps": [{"ok": False, "error": "URLError"}, {"ok": False, "error": "URLError"}]}
    with session_scope() as s:
        p, surface = _web_surface(s, "pocfail")
        pid = p.id
        run_web_poc(s, p, surface, steps=[{"method": "GET", "path": "/"}], oracle={},
                    runner=_ChannelRunner(steps_result))
    tools = _egress_tools(pid)
    assert "web_poc:connect_failed" in tools
    assert "web_poc:connected" not in tools


def test_web_poc_empty_steps_is_not_a_connection_failure(hg_home):
    """An empty `steps` result must NOT be labelled a connection failure — there was nothing to
    classify, and `any([])` is False, so the classifier must default to connected (regression guard)."""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _web_surface(s, "pocempty")
        pid = p.id
        run_web_poc(s, p, surface, steps=[{"method": "GET", "path": "/"}], oracle={},
                    runner=_ChannelRunner({"tool": "http_probe", "steps": []}))
    tools = _egress_tools(pid)
    assert "web_poc:connect_failed" not in tools
    assert "web_poc:connected" in tools


def test_outcome_audit_is_durable_across_a_hard_failure_rollback(hg_home):
    """A HARD failure (probe/container dies before emitting JSON) makes run_channel_probe RAISE. The
    connect_failed audit is durable=True, so it must SURVIVE even though the caller's session_scope
    ROLLS BACK on the propagating error — the whole point is a durable trace. Without durable=True
    the rollback would discard it."""
    settings.update_settings({"features": {"network": {"enabled": True}}})
    from hexgraph.db.models import Project, Target
    from hexgraph.sandbox.runner import SandboxError

    with session_scope() as s:
        p, surface = _web_surface(s, "hardfail")
        s.commit()                              # commit stable ids that outlive the rollback below
        pid, sid = p.id, surface.id

    with pytest.raises(SandboxError):
        with session_scope() as s:              # THIS scope rolls back on the raised error
            run_http_request(s, s.get(Project, pid), s.get(Target, sid),
                             request={"method": "GET", "path": "/"}, runner=_HardFailRunner())

    tools = _egress_tools(pid)
    assert "http_request:connect_failed" in tools           # survived the rollback (durable=True)


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
