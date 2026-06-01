"""Raw-TCP live testing (non-HTTP analogue of the web tools): the bounded-egress gate,
the unforgeable reflection-stripping oracle, the verify_poc `tcp` flavour, and the bounded
remote `launch` op. All offline with fake runners (a real device/socket is exercised in the
rehosting engagement, not here)."""

import pytest

from hexgraph import policy, settings
from hexgraph.db.models import EgressEvent
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project
from hexgraph.engine.poc import verify_poc
from hexgraph.engine.surfaces import register_web_surface, run_tcp_probe


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
