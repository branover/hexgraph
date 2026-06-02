"""Phase-2 verification oracle (docs/design/design-verification-oracles.md §4): the DoS LIVENESS oracle.

A DoS is proven by an unforgeable LIVENESS TRANSITION HexGraph observes ITSELF on the service's
own channel: baseline UP → send the DoS input → re-probe DOWN, and STAYS down across N probes
(hysteresis). The verdict comes from HexGraph's own out-of-band re-probe, NEVER the exploit's
response — so a model can't fake it, and a single transient blip does NOT count.

The sandbox run / live probes are faked here (a scripted runner that returns UP/DOWN responses)
so the transition logic, hysteresis, baseline check, assurance, egress audit, and binary
degradation are tested offline. Mirrors tests/test_oracles.py."""

import pytest

from hexgraph import settings as st
from hexgraph.db.session import session_scope
from hexgraph.engine.audit import list_egress
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.poc import verify_poc
from hexgraph.engine.surfaces import register_web_surface
from hexgraph.policy import PolicyViolation

from conftest import fixture_path


def _enable_net():
    st.update_settings({"features": {"network": {"enabled": True}}})


def _enable_poc():
    st.update_settings({"features.poc.enabled": True})


def _web(s, p, base="http://127.0.0.1:8080"):
    return register_web_surface(s, p, base, name="vr")


# A web target with a live device IP so run_tcp_probe can derive a host:port scope.
def _web_with_tcp(s, p, base="http://127.0.0.1:8080"):
    t = register_web_surface(s, p, base, name="vr-tcp")
    md = dict(t.metadata_json or {})
    md["channel"] = {**md.get("channel", {}), "host": "127.0.0.1"}
    t.metadata_json = md
    s.flush()
    return t


# ── A scripted runner ─────────────────────────────────────────────────────────────────────
#
# run_http_request → channel carries `request`; result read as result["response"].
# run_web_poc      → channel carries `steps`+`oracle`; the exploit run.
# run_tcp_probe    → channel carries `host`+`port` (a liveness connect or the tcp exploit).
#
# `up_sequence` is the list of UP/DOWN booleans the SUCCESSIVE liveness probes return (baseline
# is index 0, then each re-probe). The exploit step is a no-op (DoS produces no useful output).

class ScriptedWebRunner:
    def __init__(self, up_sequence):
        self.up_sequence = list(up_sequence)
        self.probe_i = 0
        self.exploit_calls = 0

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
        if "request" in channel:  # a liveness probe (single request via run_http_request)
            up = self.up_sequence[self.probe_i] if self.probe_i < len(self.up_sequence) else False
            self.probe_i += 1
            if up:
                return {"response": {"ok": True, "status": 200, "body": "alive"}}
            # DOWN: model a connection error (ok False) — what a crashed httpd looks like.
            return {"response": {"ok": False, "error": "ConnectionRefusedError"}}
        # the exploit (multi-step web PoC) — the DoS request itself; its response is ignored
        self.exploit_calls += 1
        return {"steps": [{"ok": True, "status": 200, "body": "(dos sent)"}], "verified": False}


class ScriptedTcpRunner:
    """Same idea for a raw-TCP service: a liveness connect (no payload) vs the tcp exploit
    (carries a payload). The connect succeeds (UP) or is refused (DOWN) per `up_sequence`."""
    def __init__(self, up_sequence):
        self.up_sequence = list(up_sequence)
        self.probe_i = 0

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
        if channel.get("payload") is None and not channel.get("oracle"):  # bare connect = liveness probe
            up = self.up_sequence[self.probe_i] if self.probe_i < len(self.up_sequence) else False
            self.probe_i += 1
            if up:
                return {"ok": True, "response": ""}
            return {"ok": False, "error": "ConnectionRefusedError"}
        return {"ok": True, "response": "(payload sent)"}  # the tcp exploit


_DOS_SPEC = {"steps": [{"method": "POST", "path": "/crash", "body": {"n": "999999999"}}],
             "oracle": {"type": "liveness", "reprobes": 3, "delay": 0}}


# ── web liveness ────────────────────────────────────────────────────────────────────────────

def test_liveness_verified_on_sustained_outage(hg_home):
    """Baseline UP, then DOWN on every re-probe ⇒ a VERIFIED DoS. The verdict is HexGraph's own
    re-probe of the service, not the exploit's response — unforgeable."""
    _enable_net()
    with session_scope() as s:
        p = create_project(s, name="dos")
        t = _web(s, p)
        # baseline UP, then 3 DOWN re-probes
        out = verify_poc(s, p, t, _DOS_SPEC, runner=ScriptedWebRunner([True, False, False, False]))
        assert out["verified"] is True
        # a live web surface ⇒ input_reachable / dynamic
        assert out["assurance"]["standard"] == "input_reachable"
        assert out["assurance"]["method"] == "dynamic"


def test_liveness_transient_blip_does_not_verify(hg_home):
    """THE unforgeability test: a single transient hiccup is NOT a verified DoS. Baseline UP,
    one DOWN re-probe, then the service RECOVERS (UP) — hysteresis rejects it. A real attacker
    (or a flaky network) producing a momentary blip must not be reported as a sustained outage."""
    _enable_net()
    with session_scope() as s:
        p = create_project(s, name="dos_blip")
        t = _web(s, p)
        # baseline UP, re-probe 1 DOWN (the blip), re-probe 2 UP (recovered) → NOT verified
        r = ScriptedWebRunner([True, False, True, False])
        out = verify_poc(s, p, t, _DOS_SPEC, runner=r)
        assert out["verified"] is False
        assert "transient blip" in out["detail"] or "still" in out["detail"]
        assert out["assurance"]["standard"] == "unconfirmed"


def test_liveness_inconclusive_when_already_down(hg_home):
    """If the service is ALREADY down at baseline, we CANNOT attribute a DoS to our input — the
    honest verdict is INCONCLUSIVE (not verified), reported as such."""
    _enable_net()
    with session_scope() as s:
        p = create_project(s, name="dos_predead")
        t = _web(s, p)
        out = verify_poc(s, p, t, _DOS_SPEC, runner=ScriptedWebRunner([False]))
        assert out["verified"] is False
        assert "INCONCLUSIVE" in out["detail"] and "already DOWN" in out["detail"]
        assert out["assurance"]["standard"] == "unconfirmed"


def test_liveness_5xx_counts_as_down(hg_home):
    """A 5xx server-error response counts as DOWN (the spec: connection-refused/timeout/5xx),
    while a 2xx counts as UP — so a service throwing 500 after the DoS input verifies."""
    _enable_net()

    class FiveXXRunner:
        def __init__(self):
            self.probe_i = 0
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            if "request" in channel:
                self.probe_i += 1
                if self.probe_i == 1:
                    return {"response": {"ok": True, "status": 200, "body": "alive"}}  # baseline UP
                return {"response": {"ok": True, "status": 503, "body": "Service Unavailable"}}  # 5xx = DOWN
            return {"steps": [{"ok": True, "status": 200}], "verified": False}

    with session_scope() as s:
        p = create_project(s, name="dos_5xx")
        t = _web(s, p)
        out = verify_poc(s, p, t, _DOS_SPEC, runner=FiveXXRunner())
        assert out["verified"] is True


def test_liveness_every_probe_is_audited(hg_home):
    """Every liveness probe is network egress and MUST be audited to EgressEvent — exactly like
    the Phase-1 oracles. The probes go through run_http_request, which audits each one."""
    _enable_net()
    with session_scope() as s:
        p = create_project(s, name="dos_audit")
        t = _web(s, p)
        out = verify_poc(s, p, t, _DOS_SPEC, runner=ScriptedWebRunner([True, False, False, False]))
        assert out["verified"] is True
        events = list_egress(s, p.id)
        # baseline + 3 re-probes = 4 http_request probes + the exploit web_poc, all audited allowed
        http_probes = [e for e in events if e["tool"] == "http_request" and e["allowed"]]
        assert len(http_probes) >= 4, http_probes
        assert any(e["tool"] == "web_poc" for e in events)  # the DoS input itself audited too


# ── tcp liveness ────────────────────────────────────────────────────────────────────────────

def test_liveness_tcp_verified_on_sustained_outage(hg_home):
    """Raw-TCP service: baseline connect succeeds (UP), then refused on every re-probe (DOWN) ⇒
    verified DoS. UP = connect succeeds, DOWN = connect refused/timeout."""
    _enable_net()
    with session_scope() as s:
        p = create_project(s, name="dos_tcp")
        t = _web_with_tcp(s, p)
        spec = {"transport": "tcp", "port": 9999, "payload": "BOOM",
                "oracle": {"type": "liveness", "reprobes": 2, "delay": 0}}
        out = verify_poc(s, p, t, spec, runner=ScriptedTcpRunner([True, False, False]))
        assert out["verified"] is True
        assert out["assurance"]["standard"] == "input_reachable"


def test_liveness_tcp_needs_a_port(hg_home):
    """A tcp liveness oracle with no port can't probe — reported, not crashed. (Here the spec is
    routed as web since there's no tcp marker+port, so the web path needs an explicit oracle.port
    or it can't find a tcp service; we assert the explicit-tcp-but-no-port guard.)"""
    _enable_net()
    from hexgraph.engine import oracles

    with session_scope() as s:
        p = create_project(s, name="dos_tcp_noport")
        t = _web_with_tcp(s, p)
        # force the tcp branch with a port but strip it at the oracle level to hit the guard
        out = oracles.verify_liveness(s, p, t, {"oracle": {"type": "liveness"}}, ScriptedTcpRunner([]),
                                      "n", is_web=False, is_tcp=True)
        assert out["verified"] is False and "needs a `port`" in out["detail"]


# ── binary degradation ───────────────────────────────────────────────────────────────────────

def test_liveness_binary_degrades_to_crash_oracle(hg_home, monkeypatch):
    """For a BINARY target (not web/tcp), a liveness oracle must degrade to the sandbox `crash`
    oracle (process death = the liveness transition) — it must NOT try to network-probe. We
    assert verify_poc routes to the binary path with the oracle rewritten to `crash`."""
    _enable_poc()
    from hexgraph.engine import poc as poc_mod

    seen = {}

    def fake_binary(session, project, target, live, runner, nonce):
        seen["oracle"] = live.get("oracle")
        return {"verified": True, "exit_code": -11, "output": "Segmentation fault",
                "detail": "exit -11 (crash)", "nonce": nonce, "spec": live}

    monkeypatch.setattr(poc_mod, "_verify_binary_poc", fake_binary)

    with session_scope() as s:
        p = create_project(s, name="dos_bin")
        # a plain binary target (no web channel) → is_web/is_tcp both False
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin")
        spec = {"argv": ["{{NONCE}}"], "oracle": {"type": "liveness"}}
        out = verify_poc(s, p, t, spec, runner=None)
        assert out["verified"] is True
        assert seen["oracle"] == {"type": "crash"}  # degraded, not network-probed
        # an isolated binary exec ⇒ code_present / dynamic (lab-confirmed), NOT input_reachable
        assert out["assurance"]["standard"] == "code_present"
        assert out["assurance"]["method"] == "dynamic"


# ── policy gate ────────────────────────────────────────────────────────────────────────────

def test_liveness_gated_by_network_tier(hg_home):
    """With the network tier OFF, a web-surface liveness oracle must be refused at the egress gate
    (the baseline probe) — the liveness oracle relaxes NO gate outside the policy seam, fail-closed."""
    with session_scope() as s:
        p = create_project(s, name="dos_gate")
        t = _web(s, p)
        with pytest.raises(PolicyViolation):
            verify_poc(s, p, t, _DOS_SPEC, runner=ScriptedWebRunner([True, False, False, False]))


def test_liveness_reprobes_clamped_to_sane_range(hg_home):
    """A stray-huge `reprobes` is capped so it can't block the (synchronous) verify handler for an
    unbounded time. With reprobes=100000 the loop must stop at the cap (≤20 re-probes), and a
    DOWN-throughout sequence still verifies."""
    _enable_net()
    from hexgraph.engine import oracles
    with session_scope() as s:
        p = create_project(s, name="dos_clamp")
        t = _web(s, p)
        spec = {"steps": [{"method": "POST", "path": "/crash"}],
                "oracle": {"type": "liveness", "reprobes": 100000, "delay": 0}}
        # baseline UP, then plenty of DOWN; the runner records how many liveness probes ran
        r = ScriptedWebRunner([True] + [False] * 100)
        out = verify_poc(s, p, t, spec, runner=r)
        assert out["verified"] is True
        # baseline (1) + at most the cap (20) re-probes = 21; never 100001
        assert r.probe_i <= 1 + oracles._LIVENESS_MAX_REPROBES


def test_is_liveness_recognizes_phase2_types(hg_home):
    from hexgraph.engine import oracles
    assert oracles.is_new_oracle({"oracle": {"type": "liveness"}})
    assert oracles.is_new_oracle({"oracle": {"type": "unavailable"}})
    assert oracles.is_liveness({"oracle": {"type": "liveness"}})
    assert oracles.is_liveness({"oracle": {"type": "unavailable"}})
    assert not oracles.is_liveness({"oracle": {"type": "callback"}})
    assert not oracles.is_liveness({"oracle": {"type": "body_contains"}})
