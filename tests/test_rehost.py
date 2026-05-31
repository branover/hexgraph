"""Firmware rehosting seam (docs/design-rehosting.md): the policy gate, surface wiring,
and the netns plumbing that lets a probe reach the emulated device — all offline, with a
fake rehoster (FirmAE itself is Docker/privileged-gated and exercised separately)."""

import pytest

from hexgraph import policy, settings
from hexgraph.db.models import EgressEvent, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.rehost import RehostResult, get_rehoster, rehost_firmware
from hexgraph.engine.surfaces import _rehost_container

from conftest import fixture_path


class _FakeRehoster:
    name = "fake"
    def __init__(self, ip="192.168.0.1"):
        self.ip = ip
        self.stopped = []
    def rehost(self, firmware_path, *, brand=None, timeout=None):
        return RehostResult(ip=self.ip, base_url=f"http://{self.ip}", handle="firmae-test",
                            detail="fake boot")
    def stop(self, handle):
        self.stopped.append(handle)


def _firmware(s):
    p = create_project(s, name="fw")
    t = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="acme-fw")
    return p, t


def test_rehost_gated_off_by_default(hg_home):
    pol = policy.current_policy()
    assert pol.allow_rehost is False
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_rehost()
    with session_scope() as s:
        p, t = _firmware(s)
        with pytest.raises(policy.PolicyViolation):
            rehost_firmware(s, p, t, rehoster=_FakeRehoster())


def test_rehost_opt_in_registers_surface_and_audits(hg_home):
    settings.update_settings({"features": {"rehost": {"enabled": True}}})
    assert policy.current_policy().allow_rehost is True
    with session_scope() as s:
        p, t = _firmware(s)
        surface = rehost_firmware(s, p, t, rehoster=_FakeRehoster("10.0.0.5"))
        # a web_app child of the firmware, channel carries base_url + the rehost container
        assert surface.kind == TargetKind.web_app and surface.parent_id == t.id
        ch = surface.metadata_json["channel"]
        assert ch["base_url"] == "http://10.0.0.5"
        assert ch["rehost"]["container"] == "firmae-test" and ch["rehost"]["ip"] == "10.0.0.5"
        assert _rehost_container(surface) == "firmae-test"
        # the boot is recorded as an allowed egress event (durable proof it was emulated)
        ev = s.query(EgressEvent).filter(EgressEvent.target_id == surface.id,
                                         EgressEvent.tool == "rehost").all()
        assert len(ev) == 1 and ev[0].allowed is True


def test_assess_rehosted_surface_joins_emulator_netns(hg_home):
    """Probing a rehosted surface must route through the FirmAE container's network
    namespace (net_container) so it can reach the emulated device's private IP."""
    settings.update_settings({"features": {"rehost": {"enabled": True}, "network": {"enabled": True}}})

    class _FakeRunner:
        def __init__(self): self.kw = None
        def run_channel_probe(self, probe, *, channel, net_container=None, **k):
            self.kw = {"net_container": net_container, "channel": channel}
            return {"response": {"ok": True, "status": 200, "headers": {}, "body": "ok"}}

    from hexgraph.engine.surfaces import run_http_request
    runner = _FakeRunner()
    with session_scope() as s:
        p, t = _firmware(s)
        surface = rehost_firmware(s, p, t, rehoster=_FakeRehoster("192.168.0.1"))
        run_http_request(s, p, surface, request={"method": "GET", "path": "/"}, runner=runner)
        assert runner.kw["net_container"] == "firmae-test"
        # the egress allowlist still pins the device's private IP
        assert runner.kw["channel"]["allow"] == ["192.168.0.1:80"]


def test_get_rehoster_default(hg_home):
    assert get_rehoster().name == "firmae"
