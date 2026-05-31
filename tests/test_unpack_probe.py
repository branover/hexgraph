"""Offline unit test for the firmware-unpack manifest walk — the contract the host
relies on to register child targets. The full extraction (sasquatch/binwalk) is
Docker-gated and skips without the image; this exercises the pure walk/ELF-flag
logic so a regression there is caught in plain CI."""

import os

from hexgraph.sandbox.probes import unpack_probe


def test_walk_files_flags_elfs_and_records_rel_paths(tmp_path):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "etc").mkdir()
    # an ELF, a non-ELF regular file, and a symlink (must be skipped)
    (root / "bin" / "busybox").write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 32)
    (root / "etc" / "banner").write_bytes(b"hello world, not an elf")
    os.symlink(root / "bin" / "busybox", root / "bin" / "sh")

    files = unpack_probe._walk_files(str(root))
    by_rel = {f["rel"]: f for f in files}

    assert "bin/busybox" in by_rel and by_rel["bin/busybox"]["is_elf"] is True
    assert "etc/banner" in by_rel and by_rel["etc/banner"]["is_elf"] is False
    assert "bin/sh" not in by_rel                      # symlink skipped
    assert all(not os.path.isabs(r) for r in by_rel)   # paths are relative to root
    assert by_rel["etc/banner"]["size"] == len(b"hello world, not an elf")
