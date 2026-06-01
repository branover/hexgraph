"""Firmware rehosting seam (docs/design-rehosting.md): the policy gate, surface wiring,
and the netns plumbing that lets a probe reach the emulated device — all offline, with a
fake rehoster (FirmAE itself is Docker/privileged-gated and exercised separately)."""

import pytest

from hexgraph import policy, settings
from hexgraph.db.models import EgressEvent, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.rehost import (FirmAERehoster, QemuDiskRehoster, RehostResult,
                                    _looks_like_disk_image, get_rehoster, rehost_firmware,
                                    select_rehoster)
from hexgraph.engine.surfaces import _rehost_container

from conftest import fixture_path


def _write(tmp_path, name, data: bytes) -> str:
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_looks_like_disk_image(tmp_path):
    # MBR with a non-empty partition entry (type 0x83) + boot signature → disk image
    mbr = bytearray(512)
    mbr[450] = 0x83  # partition 1 type byte (offset 446 + 4)
    mbr[510], mbr[511] = 0x55, 0xAA
    assert _looks_like_disk_image(_write(tmp_path, "disk.img", bytes(mbr) + b"\x00" * 1024))
    # qcow2 + vmdk magics, GPT
    assert _looks_like_disk_image(_write(tmp_path, "a.qcow2", b"QFI\xfb" + b"\x00" * 100))
    assert _looks_like_disk_image(_write(tmp_path, "a.bin", b"KDMV" + b"\x00" * 100))
    assert _looks_like_disk_image(_write(tmp_path, "g.bin", b"\x00" * 512 + b"EFI PART" + b"\x00" * 100))
    # extension-based for VM containers
    assert _looks_like_disk_image(_write(tmp_path, "x.vmdk", b"random"))
    # a vendor squashfs blob is NOT a disk image → FirmAE
    assert not _looks_like_disk_image(_write(tmp_path, "fw.bin", b"hsqs" + b"\x00" * 2048))
    assert not _looks_like_disk_image(_write(tmp_path, "u.bin", b"\x27\x05\x19\x56" + b"\x00" * 64))  # uImage


def test_select_rehoster_routes_by_image_type(tmp_path, monkeypatch):
    monkeypatch.delenv("HEXGRAPH_REHOSTER", raising=False)
    disk = _write(tmp_path, "d.vmdk", b"KDMV")
    blob = _write(tmp_path, "f.bin", b"hsqs" + b"\x00" * 64)
    assert select_rehoster(disk).name == "qemu"
    assert select_rehoster(blob).name == "firmae"
    # explicit override wins
    monkeypatch.setenv("HEXGRAPH_REHOSTER", "firmae")
    assert select_rehoster(disk).name == "firmae"


def test_get_rehoster_by_name_and_auto(tmp_path, monkeypatch):
    monkeypatch.delenv("HEXGRAPH_REHOSTER", raising=False)
    assert isinstance(get_rehoster(name="qemu"), QemuDiskRehoster)
    assert isinstance(get_rehoster(name="firmae"), FirmAERehoster)
    assert get_rehoster(firmware_path=_write(tmp_path, "d.qcow2", b"QFI\xfb")).name == "qemu"
    with pytest.raises(ValueError):
        get_rehoster(name="bogus")


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
        # the audited dest is the same host:port form the egress allowlist uses
        assert ev[0].dest == "10.0.0.5:80"


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


def test_infer_brand_from_firmware_strings(tmp_path):
    from hexgraph.engine.rehost import _infer_brand
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"\x00" * 100 + b"Netgear R6700 httpd build" + b"\x00" * 100)
    assert _infer_brand(str(fw)) == "netgear"
    fw.write_bytes(b"no vendor strings here at all")
    assert _infer_brand(str(fw)) is None
    fw.write_bytes(b"... TP-Link Archon ...")
    assert _infer_brand(str(fw)) == "tplink"
