"""F07/F09 extraction honesty — flag packed containers the unpack left un-recursed so an
agent doesn't trust a partial "N children unpacked" and hunt the wrong (boot-only) surface,
and report the inner children a container-promote registers (hidden) so it doesn't look like
a no-op. Offline: tests the pure helpers (the probe magic-classifier + the manifest filter)."""

import importlib.util
import pathlib

from hexgraph.engine.targets.filesystem import packed_containers, record_manifest


def _load_unpack_probe():
    p = pathlib.Path(__file__).resolve().parents[1] / "src/hexgraph/sandbox/probes/unpack_probe.py"
    spec = importlib.util.spec_from_file_location("unpack_probe", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_container_format_detects_nested_containers():
    up = _load_unpack_probe()
    assert up._container_format(b"hsqs\x01\x00\x00\x00", "x.bin") == "squashfs"
    assert up._container_format(b"sqsh\x00\x00\x00\x00", "x") == "squashfs"
    assert up._container_format(b"070701aa", "x") == "cpio"
    assert up._container_format(b"UBI#\x00\x00\x00\x00", "x") == "ubi"
    # Cisco IOS-XE packages: squashfs/cpio under a signed wrapper the magic misses → flag by ext.
    assert up._container_format(b"\x00" * 8, "asr920-rpios.16.09.08.SPA.pkg") == "cisco-pkg"
    # Plain ELF / ordinary file → not flagged.
    assert up._container_format(b"\x7fELF\x02\x01\x01\x00", "iosd") is None
    assert up._container_format(b"hello wo", "readme.txt") is None


def test_packed_containers_helper_sorts_and_filters():
    files = [
        {"rel": "boot/initramfs", "container": "cpio", "size": 1000},
        {"rel": "usr/sbin/iosd", "is_elf": True, "size": 5000},                 # not a container
        {"rel": "1CDB94A.squashfs", "container": "squashfs", "size": 999999},
        {"rel": "rpios.SPA.pkg", "container": "cisco-pkg", "size": 50000},
        # a container already recursed into a child target is NOT a "go deeper" hint:
        {"rel": "done.squashfs", "container": "squashfs", "size": 10, "child_target_id": "abc"},
    ]
    out = packed_containers(files)
    assert [c["rel"] for c in out] == ["1CDB94A.squashfs", "rpios.SPA.pkg", "boot/initramfs"]
    assert all(c.get("format") for c in out)
    assert "done.squashfs" not in [c["rel"] for c in out]
    assert packed_containers([]) == []


class _FakeTarget:
    """Minimal stand-in for a Target row — record_manifest only touches metadata_json."""
    metadata_json: dict | None = None


def test_record_manifest_persists_container_tag():
    """Regression for the F07 manifest round-trip: record_manifest must KEEP the `container`
    tag the probe emits, else packed_containers (which reads the PERSISTED manifest in
    pipeline.analyze_target / promote_file) always returns [] and the whole feature is dead.
    The earlier helper tests pass the tag in directly and never exercise this persistence path."""
    fw = _FakeTarget()
    record_manifest(fw, method="binwalk", root_rel="", files=[
        {"rel": "1CDB94A.squashfs", "container": "squashfs", "size": 999999},
        {"rel": "usr/sbin/iosd", "is_elf": True, "size": 5000},  # ordinary file → no container key
    ])
    persisted = fw.metadata_json["filesystem"]["files"]
    # the container entry keeps its tag; the ordinary file does not gain a spurious one
    assert persisted[0].get("container") == "squashfs"
    assert "container" not in persisted[1]
    # and the persisted manifest actually feeds packed_containers (the real call path)
    assert [c["rel"] for c in packed_containers(persisted)] == ["1CDB94A.squashfs"]
