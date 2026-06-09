"""Raw-TCP live testing (non-HTTP analogue of the web tools): the bounded-egress gate,
the unforgeable reflection-stripping oracle, the verify_poc `tcp` flavour, and the bounded
remote `launch` op. All offline with fake runners (a real device/socket is exercised in the
rehosting engagement, not here)."""

import pytest

from hexgraph import policy, settings
from hexgraph.db.models import EgressEvent
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project
from hexgraph.engine.findings.poc import verify_poc
from hexgraph.engine.targets.surfaces import register_web_surface, run_tcp_probe, run_udp_probe


# ── the probe's oracle/decoding logic (pure, importable) ───────────────────────────────
def test_probe_oracle_strips_reflection():
    from hexgraph.sandbox.probes import tcp_probe

    nonce = "HEXGRAPH_PWNED_abc123"
    sent = f"id; echo {nonce}".encode()
    # The service merely ECHOED our payload back → the nonce is present only as reflection.
    reflected = f"you sent: id; echo {nonce}\n"
    ok, _ = tcp_probe._check_oracle({"type": "response_contains", "value": nonce}, reflected, sent)
    assert ok is False
    # The service actually RAN the command → the nonce appears as standalone output too.
    produced = f"echo of your input: id; echo {nonce}\nuid=0(root)\n{nonce}\n"
    ok, _ = tcp_probe._check_oracle({"type": "response_contains", "value": nonce}, produced, sent)
    assert ok is True


def test_probe_oracle_strips_transformed_reflection():
    """Parity with http_probe (review #16): a service that echoes our payload back in a
    TRANSFORMED form — URL-encoded or HTML-entity-encoded, possibly wrapped in markup /
    whitespace — still must NOT satisfy the oracle. Only output the service genuinely
    PRODUCED counts. Documents the guarantee: raw + %-encoded + &lt;/&gt;/&amp; forms are
    stripped before matching."""
    from hexgraph.sandbox.probes import tcp_probe

    nonce = "HEXGRAPH_PWNED_xyz789"
    sent = f"<x>{nonce}</x>".encode()  # payload contains chars that get encoded on reflection

    # 1) HTML-entity-encoded reflection wrapped in surrounding markup/whitespace → not proof.
    html_reflected = f"  <pre>echo: &lt;x&gt;{nonce}&lt;/x&gt;</pre>\n"
    ok, detail = tcp_probe._check_oracle({"type": "response_contains", "value": nonce},
                                         html_reflected, sent)
    assert ok is False and "reflected" in detail

    # 2) URL-encoded reflection → also stripped, not proof.
    url_reflected = f"got=%3Cx%3E{nonce}%3C%2Fx%3E\n"
    ok2, _ = tcp_probe._check_oracle({"type": "response_contains", "value": nonce},
                                     url_reflected, sent)
    assert ok2 is False

    # 3) The nonce appears as standalone PRODUCED output (not just a reflected copy) → verified.
    produced = f"<pre>&lt;x&gt;{nonce}&lt;/x&gt;</pre>\nuid=0(root) {nonce}\n"
    ok3, _ = tcp_probe._check_oracle({"type": "response_contains", "value": nonce},
                                     produced, sent)
    assert ok3 is True


def test_probe_payload_and_decode():
    from hexgraph.sandbox.probes import tcp_probe

    assert tcp_probe._payload_bytes({"payload": "abc"}) == b"abc"
    assert tcp_probe._payload_bytes({"payload_hex": "6162"}) == b"ab"
    assert tcp_probe._payload_bytes({}) == b""
    assert tcp_probe._decode(b"hello", 64)["encoding"] == "text"
    assert tcp_probe._decode(b"\x00\x01", 64)["encoding"] == "binary"


# ── the policy scope ───────────────────────────────────────────────────────────────────
def test_local_tcp_scope_refuses_public_host():
    s = policy.local_tcp_scope("192.168.1.1", 1337)
    assert s.allow == frozenset({"192.168.1.1:1337"})
    with pytest.raises(policy.PolicyViolation):
        policy.local_tcp_scope("8.8.8.8", 1337)  # public → refused


# ── run_tcp_probe gate + wiring ─────────────────────────────────────────────────────────
class _FakeRunner:
    def __init__(self, response):
        self.response = response
        self.calls = []
    def run_channel_probe(self, probe, *, channel, net_container=None, **k):
        self.calls.append({"probe": probe, "channel": channel, "net_container": net_container})
        return self.response


def _rehosted_surface(s):
    p = create_project(s, name="dev")
    surface = register_web_surface(s, p, "http://192.168.0.1", name="rehosted")
    ch = dict(surface.metadata_json["channel"])
    ch["rehost"] = {"container": "firmae-xyz", "ip": "192.168.0.1"}
    surface.metadata_json = {**surface.metadata_json, "channel": ch}
    s.flush()
    return p, surface


def test_run_tcp_probe_denied_and_audited_when_network_off(hg_home):
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True})
        with pytest.raises(policy.PolicyViolation):
            run_tcp_probe(s, p, surface, port=1337, payload="x", runner=runner)
        assert not runner.calls  # never reached the probe
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "tcp_probe").all()
        assert len(ev) == 1 and ev[0].allowed is False and ev[0].dest == "192.168.0.1:1337"


def test_run_tcp_probe_reaches_device_via_netns_when_enabled(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True, "response": "BusyBox v1.0", "verified": False})
        run_tcp_probe(s, p, surface, port=1337, payload="ping", runner=runner)
        call = runner.calls[0]
        assert call["probe"] == "tcp_probe.py"
        assert call["net_container"] == "firmae-xyz"           # routed through the emulator
        assert call["channel"]["host"] == "192.168.0.1" and call["channel"]["port"] == 1337
        assert call["channel"]["allow"] == ["192.168.0.1:1337"]
        assert call["channel"]["payload"] == "ping"
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "tcp_probe").all()
        assert len(ev) == 1 and ev[0].allowed is True


def test_verify_poc_routes_tcp_spec_and_substitutes_nonce(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True, "verified": True, "detail": "produced nonce",
                              "response": "uid=0(root)"})
        spec = {"transport": "tcp", "port": 1337, "payload": "id; echo {{NONCE}}",
                "oracle": {"type": "response_contains", "value": "{{NONCE}}"}}
        out = verify_poc(s, p, surface, spec, runner=runner)
        assert out["verified"] is True
        # the {{NONCE}} placeholder was substituted to a real token before hitting the probe
        chan = runner.calls[0]["channel"]
        assert "{{NONCE}}" not in chan["payload"] and "HEXGRAPH_PWNED_" in chan["payload"]
        assert "{{NONCE}}" not in chan["oracle"]["value"]


# ── UDP (the datagram analogue of the raw-TCP path) ─────────────────────────────────────
def test_udp_probe_exchange_real_loopback_datagram():
    """The probe's `_exchange_udp` is exercised against a REAL loopback UDP echo (in-process,
    no sandbox) — proves the sendto/recvfrom datagram path round-trips. The host-side egress
    gate is tested separately; here we confirm the actual datagram I/O works."""
    import socket as _socket
    import threading

    from hexgraph.sandbox.probes import tcp_probe

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def _echo():
        try:
            data, peer = srv.recvfrom(4096)
            srv.sendto(b"REPLY:" + data, peer)
        except Exception:  # noqa: BLE001 — test teardown / timeout
            pass

    t = threading.Thread(target=_echo, daemon=True)
    t.start()
    try:
        ex = tcp_probe._exchange_udp("127.0.0.1", port, b"ping", timeout=2, cap=1024)
    finally:
        srv.close()
    assert ex["ok"] is True
    assert ex["raw"] == b"REPLY:ping"


def test_udp_probe_returns_promptly_after_single_datagram():
    """#230 nit: the UDP path reads the SINGLE reply datagram and returns — it must NOT idle the
    full timeout waiting for a follow-up that (for a request/response service) never comes. A
    server that answers once then stays silent should return in well under the timeout window."""
    import socket as _socket
    import threading
    import time

    from hexgraph.sandbox.probes import tcp_probe

    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    port = srv.getsockname()[1]

    def _answer_once():
        try:
            data, peer = srv.recvfrom(4096)
            srv.sendto(b"ONE:" + data, peer)  # one reply, then go quiet
        except Exception:  # noqa: BLE001
            pass

    th = threading.Thread(target=_answer_once, daemon=True)
    th.start()
    try:
        # Pass a generous timeout; the old read-loop would block ~min(timeout,5)s after the
        # single reply. The single-recvfrom path returns as soon as the one datagram lands.
        start = time.monotonic()
        ex = tcp_probe._exchange_udp("127.0.0.1", port, b"ping", timeout=5, cap=1024)
        elapsed = time.monotonic() - start
    finally:
        srv.close()
    assert ex["ok"] is True and ex["raw"] == b"ONE:ping"
    # Returned promptly after the single reply (not after idling the ~5s read window).
    assert elapsed < 2.0, f"UDP probe idled {elapsed:.2f}s after a single-datagram reply"


def test_udp_probe_silent_service_is_not_an_error():
    """UDP is connectionless: a service that never answers yields an EMPTY response under the
    timeout, which is normal (ok=True, no bytes) — NOT a failure like a refused TCP connect."""
    from hexgraph.sandbox.probes import tcp_probe

    # Nothing is bound here; the datagram is sent into the void and recvfrom times out.
    ex = tcp_probe._exchange_udp("127.0.0.1", 9, b"", timeout=1, cap=64)
    assert ex["ok"] is True and ex["raw"] == b""


def test_udp_probe_main_emits_udp_tool_and_honors_allowlist(monkeypatch):
    """The probe's main() selects the datagram path on transport:'udp', tags its output
    `udp_probe`, and refuses an off-allowlist destination via the explicit ensure_allowed
    chokepoint (the socket-guard backstop only covers TCP connects)."""
    import json as _json

    from hexgraph.sandbox.probes import tcp_probe

    # off-allowlist → refused with the udp tool tag, no datagram sent
    captured = {}
    monkeypatch.setattr(tcp_probe.sys, "argv",
                        ["tcp_probe.py", "--channel",
                         _json.dumps({"host": "127.0.0.1", "port": 5353, "transport": "udp",
                                      "allow": ["127.0.0.1:1900"]})])
    monkeypatch.setattr("builtins.print", lambda s: captured.setdefault("out", s))
    tcp_probe.main()
    out = _json.loads(captured["out"])
    assert out["tool"] == "udp_probe" and out["ok"] is False
    assert "not in allowlist" in out["error"]


def test_run_udp_probe_denied_and_audited_when_network_off(hg_home):
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True})
        with pytest.raises(policy.PolicyViolation):
            run_udp_probe(s, p, surface, port=9999, payload="x", runner=runner)
        assert not runner.calls  # never reached the probe
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "udp_probe").all()
        assert len(ev) == 1 and ev[0].allowed is False and ev[0].dest == "192.168.0.1:9999"


def test_run_udp_probe_reaches_device_via_netns_and_marks_transport(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True, "tool": "udp_probe", "response": "infosvr", "verified": False})
        run_udp_probe(s, p, surface, port=9999, payload="probe", runner=runner)
        call = runner.calls[0]
        assert call["probe"] == "tcp_probe.py"
        assert call["net_container"] == "firmae-xyz"           # routed through the emulator
        assert call["channel"]["transport"] == "udp"           # datagram path
        assert call["channel"]["host"] == "192.168.0.1" and call["channel"]["port"] == 9999
        assert call["channel"]["allow"] == ["192.168.0.1:9999"]
        assert call["channel"]["payload"] == "probe"
        ev = s.query(EgressEvent).filter(EgressEvent.tool == "udp_probe").all()
        assert len(ev) == 1 and ev[0].allowed is True


def test_verify_poc_routes_udp_spec_substitutes_nonce_and_marks_assurance(hg_home):
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p, surface = _rehosted_surface(s)
        runner = _FakeRunner({"ok": True, "verified": True, "detail": "produced nonce",
                              "response": "device-name=ROUTER"})
        spec = {"transport": "udp", "port": 9999, "payload": "WHOAREYOU {{NONCE}}",
                "oracle": {"type": "response_contains", "value": "{{NONCE}}"}}
        out = verify_poc(s, p, surface, spec, runner=runner)
        assert out["verified"] is True
        # the udp transport reached the datagram probe with the nonce substituted
        chan = runner.calls[0]["channel"]
        assert chan["transport"] == "udp"
        assert "{{NONCE}}" not in chan["payload"] and "HEXGRAPH_PWNED_" in chan["payload"]
        assert "{{NONCE}}" not in chan["oracle"]["value"]
        # a verified live-socket surface PoC records the strongest assurance (input_reachable),
        # the SAME entrypoint rung a verified TCP service does.
        assert out["assurance"]["standard"] == "input_reachable"


# ── the bounded remote `launch` op ──────────────────────────────────────────────────────
def test_remote_launch_command_is_quoted_and_backgrounded():
    from hexgraph.sandbox.probes import remote_probe

    cmd = remote_probe._build_command(
        {"op": "launch", "path": "/tmp/socket_cmd", "args": ["1337", "; rm -rf /"]})
    assert cmd.startswith("setsid /tmp/socket_cmd ")
    assert cmd.endswith('& echo "launched pid $!"')
    # the injection-looking arg is shell-quoted, not interpreted
    assert "'; rm -rf /'" in cmd
    assert remote_probe._build_command({"op": "launch"}) == ""  # no path → refused
