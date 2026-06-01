"""Disk-image detection for the recon/unpack path (gap #1): a partitioned full-OS disk
image (MBR/GPT) is recognized as firmware so its rootfs is extracted at ingest. The
detection is pure-function tested offline; full extraction (The Sleuth Kit / binwalk) is
Docker-gated and exercised by the live IoTGoat path."""

import importlib.util
import os

_HERE = os.path.dirname(__file__)


def _load(rel_name, rel_path):
    spec = importlib.util.spec_from_file_location(
        rel_name, os.path.join(_HERE, "..", "src", "hexgraph", "sandbox", "probes", rel_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


recon = _load("recon_probe", "recon_probe.py")
unpack = _load("unpack_probe", "unpack_probe.py")


def _mbr(part_type=0x83, lba_start=2048):
    b = bytearray(512)
    off = 446  # first partition entry
    b[off + 4] = part_type
    b[off + 8:off + 12] = lba_start.to_bytes(4, "little")
    b[off + 12:off + 16] = (1 << 20).to_bytes(4, "little")  # length
    b[510], b[511] = 0x55, 0xAA
    return bytes(b)


def _gpt():
    return b"\x00" * 512 + b"EFI PART" + b"\x00" * 200


def test_recon_detects_disk_images():
    assert recon._is_disk_image(_mbr(part_type=0x83))      # Linux partition
    assert recon._is_disk_image(_mbr(part_type=0x0c))      # FAT32 (bootable disk)
    assert recon._is_disk_image(_gpt())                    # GPT
    # NOT disk images:
    assert not recon._is_disk_image(b"hsqs" + b"\x00" * 600)          # bare squashfs
    assert not recon._is_disk_image(b"\x7fELF" + b"\x00" * 600)       # an ELF
    assert not recon._is_disk_image(b"\x00" * 510 + b"\x55\xaa")      # 0x55AA alone, no partition entry
    assert not recon._is_disk_image(_mbr(part_type=0xEE))             # protective MBR alone → GPT path only
    assert not recon._is_disk_image(b"\x00" * 100)                    # too short


def test_unpack_and_recon_detectors_agree():
    # the unpack probe's gate must mirror recon's classification
    for blob in (_mbr(0x83), _gpt(), _mbr(0x0c)):
        assert recon._is_disk_image(blob) and unpack._is_disk_image(blob[:520])
    for blob in (b"hsqs" + b"\x00" * 600, b"\x00" * 510 + b"\x55\xaa"):
        assert not recon._is_disk_image(blob) and not unpack._is_disk_image(blob[:520])


def test_pipeline_routes_disk_image_to_unpack():
    from hexgraph.engine.pipeline import _FIRMWARE_FORMATS
    assert "disk_image" in _FIRMWARE_FORMATS
