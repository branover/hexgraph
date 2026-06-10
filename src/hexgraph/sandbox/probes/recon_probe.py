#!/usr/bin/env python3
"""Deterministic recon over a single target file, run INSIDE the sandbox.

Reads the read-only artifact at argv[1], emits a JSON facts blob on stdout.
No network, no execution of the target — static inspection only (hashes,
ELF headers via pyelftools, dynamic symbols/needed libs, mitigation flags,
notable strings). This is the only code that touches target bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
NOTABLE = ("cgi", "admin", "token", "passwd", "/bin/", "http", "Content-", "POST", "GET", "key", "secret")

# machine -> arch label fallback if get_machine_arch is unavailable
_KEYWORDS = NOTABLE


def _hashes(data: bytes) -> dict:
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


def _strings(data: bytes, limit: int = 40) -> list[str]:
    seen: list[str] = []
    notable: list[str] = []
    for m in PRINTABLE.finditer(data):
        # Both lists are capped so a hostile/large blob saturated with notable
        # keywords can't grow `notable` unbounded; stop scanning once both are full.
        if len(notable) >= limit and len(seen) >= limit:
            break
        s = m.group().decode("ascii", "replace")
        if any(k.lower() in s.lower() for k in _KEYWORDS):
            if len(notable) < limit and s not in notable:
                notable.append(s)
        elif len(seen) < limit:
            seen.append(s)
    # notable first, then a sample of the rest
    out: list[str] = []
    for s in notable + seen:
        if s not in out:
            out.append(s)
    return out[:limit]


def _elf_facts(path: str) -> dict:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection

    facts: dict = {"format": "ELF"}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        facts["arch"] = elf.get_machine_arch()
        etype = elf.header["e_type"]
        facts["elf_type"] = etype

        has_interp = any(seg["p_type"] == "PT_INTERP" for seg in elf.iter_segments())
        if etype == "ET_DYN":
            facts["kind"] = "executable" if has_interp else "shared_library"
        elif etype == "ET_EXEC":
            facts["kind"] = "executable"
        else:
            facts["kind"] = "unknown"

        imports: list[str] = []
        exports: list[str] = []
        needed: list[str] = []
        symbol_names: set[str] = set()
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    name = sym.name
                    if not name:
                        continue
                    name = name.split("@", 1)[0]  # drop @GLIBC_x.y version suffix
                    symbol_names.add(name)
                    info_type = sym["st_info"]["type"]
                    if sym["st_shndx"] == "SHN_UNDEF":
                        if info_type in ("STT_FUNC", "STT_NOTYPE"):
                            imports.append(name)
                    elif info_type == "STT_FUNC":
                        exports.append(name)
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.needed)

        facts["imports"] = sorted(set(imports))
        facts["exports"] = sorted(set(exports))
        facts["libraries"] = needed

        # --- mitigations ---
        nx = True  # no GNU_STACK usually means non-exec stack on modern toolchains
        relro = "none"
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                nx = not bool(seg["p_flags"] & 0x1)  # PF_X
            if seg["p_type"] == "PT_GNU_RELRO":
                relro = "partial"

        bind_now = False
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for tag in sec.iter_tags():
                    if tag.entry.d_tag == "DT_BIND_NOW":
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS" and (tag.entry.d_val & 0x8):  # DF_BIND_NOW
                        bind_now = True
                    if tag.entry.d_tag == "DT_FLAGS_1" and (tag.entry.d_val & 0x1):  # DF_1_NOW
                        bind_now = True
        if relro == "partial" and bind_now:
            relro = "full"

        canary = "__stack_chk_fail" in symbol_names
        pie = etype == "ET_DYN" and has_interp

        facts["mitigations"] = {"nx": nx, "canary": canary, "pie": pie, "relro": relro}
    return facts


# Embedded filesystem / firmware-container signatures. If any appears in a non-ELF
# blob, it's a firmware image binwalk can carve (real vendor firmware is always
# wrapped — TRX/uImage/vendor header around a squashfs/jffs2/etc.).
_FW_SIGS = (
    (b"hsqs", "squashfs"), (b"sqsh", "squashfs"), (b"shsq", "squashfs"), (b"qshs", "squashfs"),
    (b"HDR0", "trx"),                       # TRX (Broadcom/Linksys)
    (b"\x27\x05\x19\x56", "uimage"),        # U-Boot uImage
    (b"UBI#", "ubi"), (b"UBI!", "ubi"),
    # NB: jffs2's magic is only 2 bytes (0x1985) and collides constantly in large
    # blobs — omitted here to avoid mis-flagging ordinary files as firmware. Real
    # jffs2 firmware is wrapped (TRX/uImage) and carved by binwalk anyway.
    (b"\x45\x3d\xcd\x28", "cramfs"), (b"\x28\xcd\x3d\x45", "cramfs"),
    (b"\xd0\x0d\xfe\xed", "fit"),            # FIT/DTB
    (b"-lh", "lzh"),
)


# A squashfs hit must be validated (a bare 4-byte 'hsqs' collides in a 100s-of-MB image); cap the
# rescans so a pathological blob full of 'hsqs' bytes can't spin.
_MAX_SQUASHFS_PROBES = 256


def _valid_squashfs_superblock(data: bytes, off: int) -> bool:
    """A genuine little-endian squashfs v4 superblock at `off`, not a coincidental 'hsqs' in
    random bytes: version-major 4, a known compressor id (1=gzip … 6=zstd), and a self-consistent
    bytes_used that fits within the image."""
    if off < 0 or off + 0x30 > len(data) or data[off:off + 4] != b"hsqs":
        return False
    comp = int.from_bytes(data[off + 0x14:off + 0x16], "little")
    vmaj = int.from_bytes(data[off + 0x1c:off + 0x1e], "little")
    bytes_used = int.from_bytes(data[off + 0x28:off + 0x30], "little")
    return vmaj == 4 and 1 <= comp <= 6 and 0 < bytes_used <= len(data) - off


def _valid_fit_header(data: bytes, off: int) -> bool:
    """A plausible FIT/FDT header at `off`: the d00dfeed magic plus a totalsize (big-endian u32
    at +4) that fits within the image — enough to reject a coincidental 4-byte magic match."""
    if off < 0 or off + 8 > len(data) or data[off:off + 4] != b"\xd0\x0d\xfe\xed":
        return False
    total = int.from_bytes(data[off + 4:off + 8], "big")
    return 0 < total <= len(data) - off


def _deep_container(data: bytes) -> str | None:
    """Scan the WHOLE blob for an embedded rootfs container that sits DEEP behind a proprietary/
    signed outer wrapper — a modern router image carries its rootfs squashfs 50 MB+ past the
    header, well beyond the wrapper-header window below. Only the strong, self-validating magics
    are scanned whole-file (each hit is validated), so a short magic colliding in a large image
    can never mis-flag an ordinary file as firmware. Returns the format, or None."""
    off = data.find(b"hsqs")
    tries = 0
    while off != -1 and tries < _MAX_SQUASHFS_PROBES:
        if _valid_squashfs_superblock(data, off):
            return "squashfs"
        off = data.find(b"hsqs", off + 1)
        tries += 1
    off = data.find(b"\xd0\x0d\xfe\xed")
    if off != -1 and _valid_fit_header(data, off):
        return "fit"
    return None


def _firmware_signature(data: bytes) -> str | None:
    """Detect an embedded filesystem/container in a non-ELF blob so the unpacker carves it.

    Two scans: (1) the original WRAPPER-header window — TRX/uImage/UBI/cramfs/… magics that, by
    construction, sit at/near the image header, kept to the first 8 MB because some are short and
    would false-match constantly over a large image; (2) a whole-blob scan for a deep, VALIDATED
    rootfs container (squashfs superblock / FIT header), which is what a signed vendor wrapper hides
    tens of MB in — the case a header-only check used to miss (0 children, format=unknown). A blob
    with neither stays 'unknown' (binwalk no-op)."""
    window = data[: 8 << 20]
    for sig, fmt in _FW_SIGS:
        if sig in window:
            return fmt
    return _deep_container(data)


def _is_disk_image(data: bytes) -> bool:
    """A partitioned full-OS disk image: GPT (\"EFI PART\" at LBA1) or an MBR with a
    non-empty partition entry + the 0x55AA boot signature. (The bare 0x55AA signature
    alone is too weak — many blobs end in it — so require a real partition entry.)"""
    if len(data) < 512:
        return False
    if len(data) >= 520 and data[512:520] == b"EFI PART":
        return True
    if data[510:512] == b"\x55\xaa":
        for i in range(4):  # 4 MBR partition entries × 16 bytes at offset 446
            entry = data[446 + i * 16: 446 + i * 16 + 16]
            ptype = entry[4]
            lba_start = int.from_bytes(entry[8:12], "little")
            if ptype not in (0x00, 0xEE) and lba_start > 0:  # 0xEE = protective MBR (GPT handled above)
                return True
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: recon_probe.py <artifact>"}))
        return 2
    path = sys.argv[1]
    with open(path, "rb") as fh:
        data = fh.read()

    facts: dict = {"tool": "recon_probe", "format": "unknown", "kind": "unknown"}
    facts.update(_hashes(data))
    facts["strings"] = _strings(data)

    if data[:4] == b"\x7fELF":
        try:
            facts.update(_elf_facts(path))
        except Exception as exc:  # keep recon resilient on odd inputs
            facts["elf_error"] = f"{type(exc).__name__}: {exc}"
    else:
        # Non-ELF: best-effort format guess from magic.
        if data[:4] in (b"hsqs", b"sqsh"):
            facts["format"] = "squashfs"
            facts["kind"] = "firmware_image"
        elif data[:6] in (b"070701", b"070702"):
            facts["format"] = "cpio"
            facts["kind"] = "firmware_image"
        else:
            # Wrapped/real firmware: detect an embedded filesystem/container anywhere
            # in the blob (TRX/uImage/vendor header → squashfs/jffs2/…) so binwalk
            # carves it. A blob with none of these stays "unknown" (binwalk no-op).
            fmt = _firmware_signature(data)
            if fmt:
                facts["format"] = fmt
                facts["kind"] = "firmware_image"
            elif _is_disk_image(data):
                # A full-OS disk image (partitioned MBR/GPT, e.g. an x86/ARM SD card or
                # VM disk) — the rootfs is in a partition; unpack extracts it with The
                # Sleuth Kit. Treated as firmware so the same unpack→recon flow runs.
                facts["format"] = "disk_image"
                facts["kind"] = "firmware_image"

    # G01: still unrecognized. Capture the header bytes so the operator can identify the
    # container — a vendor-wrapped/signed firmware image the unpacker doesn't know would
    # otherwise ingest to 0 children with NO signal. A LARGE non-ELF blob with no known
    # signature is very likely an unsupported firmware/container (not an ordinary data file):
    # flag it so the pipeline ATTEMPTS a carve and, failing that, says so with these bytes.
    if facts.get("format") == "unknown":
        facts["magic_hex"] = data[:16].hex()
        facts["magic_ascii"] = "".join((chr(b) if 32 <= b < 127 else ".") for b in data[:16])
        if len(data) >= (1 << 20):  # >= 1 MiB
            facts["likely_unrecognized_container"] = True

    print(json.dumps(facts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
