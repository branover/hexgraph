"""recon must recognize a real vendor firmware image whose rootfs container sits DEEP behind a
proprietary/signed outer wrapper — not just one whose magic is in the first bytes. A modern router
image carries its rootfs squashfs tens of MB past a header the unpacker doesn't know; a header-only
(or first-8-MB) check missed it, so the image ingested to 0 children with format=unknown. recon now
scans the whole blob for a VALIDATED embedded container (squashfs superblock / FIT header) so the
existing binwalk path carves it — while the short wrapper magics stay window-bounded so they can't
false-match over a large image. All synthetic: no real-firmware bytes."""

from __future__ import annotations

from hexgraph.sandbox.probes.recon_probe import (
    _deep_container,
    _firmware_signature,
    _valid_squashfs_superblock,
)

WINDOW = 8 << 20  # the wrapper-header scan window


def _squashfs_superblock(comp: int = 4, vmaj: int = 4, bytes_used: int = 4096) -> bytes:
    """A minimal but field-valid little-endian squashfs v4 superblock (enough for detection;
    recon validates the superblock, it does not extract)."""
    sb = bytearray(0x60)
    sb[0x00:0x04] = b"hsqs"
    sb[0x04:0x08] = (5).to_bytes(4, "little")             # inode count
    sb[0x14:0x16] = comp.to_bytes(2, "little")            # compressor id (4 = xz)
    sb[0x1c:0x1e] = vmaj.to_bytes(2, "little")            # version major
    sb[0x28:0x30] = bytes_used.to_bytes(8, "little")
    return bytes(sb)


def _fit_header(total: int = 0x1000) -> bytes:
    return b"\xd0\x0d\xfe\xed" + total.to_bytes(4, "big") + b"\x00" * 56


def _wrapped(container: bytes, *, at: int = WINDOW + 1_000_000) -> bytes:
    """`container` embedded `at` bytes into an opaque (non-magic) outer wrapper — i.e. DEEP past
    the wrapper-header window, exactly where a header-only scan misses it. Trailing pad so a
    superblock's bytes_used fits within the image."""
    return b"OUTERHDR\x00" + b"\x00" * at + container + b"\x00" * 65536


# ---- the real fix: a deep, validated container IS detected --------------------------------

def test_deep_squashfs_past_the_window_is_detected_as_firmware():
    blob = _wrapped(_squashfs_superblock())
    assert _firmware_signature(blob) == "squashfs"          # the case that used to return None


def test_deep_fit_past_the_window_is_detected():
    blob = _wrapped(_fit_header())
    assert _firmware_signature(blob) == "fit"


def test_fit_scan_retries_past_a_coincidental_first_match():
    # A d00dfeed whose totalsize doesn't validate must not hide a genuine FIT header deeper in
    # the image (the FIT scan rescans like the squashfs scan, not a single find).
    bad_fit = b"\xd0\x0d\xfe\xed" + b"\x00\x00\x00\x00"       # totalsize 0 -> invalid
    blob = b"\x00" * (WINDOW + 500_000) + bad_fit + b"\x00" * 1000 + _fit_header(0x800) + b"\x00" * 4096
    assert _deep_container(blob) == "fit"
    assert _firmware_signature(blob) == "fit"


def test_squashfs_superblock_validation():
    pad = b"\x00" * 8192  # enough trailing bytes for the superblock's bytes_used to fit the image
    assert _valid_squashfs_superblock(_squashfs_superblock() + pad, 0)
    assert _valid_squashfs_superblock(b"\x00" * 1000 + _squashfs_superblock() + pad, 1000)
    # bytes_used larger than what remains in the image -> not a real superblock here
    assert not _valid_squashfs_superblock(_squashfs_superblock(bytes_used=10**9) + pad, 0)
    assert not _valid_squashfs_superblock(_squashfs_superblock(vmaj=3) + pad, 0)    # wrong version
    assert not _valid_squashfs_superblock(_squashfs_superblock(comp=99) + pad, 0)   # unknown compressor


# ---- the false-positive guards: a whole-file scan must not mis-flag ordinary data ---------

def test_bare_hsqs_without_a_valid_superblock_is_not_firmware():
    # 'hsqs' bytes with no real superblock behind them (a coincidental collision) -> NOT firmware.
    blob = b"OUTERHDR\x00" + b"\x00" * (WINDOW + 1_000_000) + b"hsqs" + b"\xff" * 64
    assert _deep_container(blob) is None
    assert _firmware_signature(blob) is None


def test_short_wrapper_magic_deep_in_a_large_blob_is_not_whole_file_scanned():
    # The 3-byte '-lh' (lzh) magic collides constantly over 100s of MB; it must stay window-bounded,
    # so a copy DEEP in the image (past the window) must NOT trigger a firmware classification.
    blob = b"\x00" * (WINDOW + 2_000_000) + b"-lh5-junk"
    assert _firmware_signature(blob) is None


def test_wrapper_magic_within_the_window_still_detected():
    # Existing behavior preserved: a TRX/uImage-style header near the start is still found.
    assert _firmware_signature(b"HDR0" + b"\x00" * 4096) == "trx"
    assert _firmware_signature(b"\x27\x05\x19\x56" + b"\x00" * 4096) == "uimage"
