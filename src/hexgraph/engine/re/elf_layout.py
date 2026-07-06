"""On-disk ELF layout reads for the LIGHTWEIGHT triage tools (`re_resolve`, `re_hexdump`).

These two tools answer WITHOUT a decompile or a Docker round-trip — a crash-address /
pointer / DAT_ orientation and a raw-bytes view — so they read the target's on-disk ELF
directly with pyelftools instead of paying a probe. That maps a virtual address to a file
offset (program headers), reports the section a vaddr falls in and each section's vaddr range
(section table), and reads the symbol table WITH `st_value`+`st_size` so the containing
FUNC / nearest symbol can be computed precisely (`facts.symbols` from the binutils probe carry
nm rows without a size, so containment needs the ELF's own symtab).

**pyelftools is treated as PROBE-ONLY / best-effort here.** pyproject scopes the analysis libs
(`r2pipe`/`lief`/`pyelftools`) to the sandbox probes, so the host/engine venv may not carry it.
Every entry point GUARDS the import and returns a clean `{"error": ..., "degraded": True}` when
it's missing — the callers fall back to a symbols-only answer (`re_resolve`) or point at
`re_disassemble_range` (`re_hexdump`) rather than crashing or faking bytes. Read-only + offline:
never executes the target, opens the file read-binary, and mutates nothing.
"""

from __future__ import annotations

import bisect
import logging

logger = logging.getLogger(__name__)

# Hard ceiling on a single re_hexdump read — a bounded window so a fat-fingered length can't
# pull megabytes into the context (the no-silent-caps discipline: the tool reports when it clamps).
HEXDUMP_MAX = 4096


def _elffile():
    """The pyelftools `ELFFile` class, or None when the (probe-only) lib isn't installed in
    this venv — the caller degrades instead of raising."""
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:  # pyelftools is probe-only per pyproject; host venv may lack it
        return None
    return ELFFile


def available() -> bool:
    """True when pyelftools can be imported in this process (host/engine venv)."""
    return _elffile() is not None


def _load_alloc_sections(elf) -> list[dict]:
    """The SHF_ALLOC sections with vaddr ranges, as `{name, vaddr, size, nobits}` sorted by
    vaddr — the section table `re_resolve` maps an address into and `re_hexdump` notes .bss on.
    `nobits` flags SHT_NOBITS (.bss): mapped in memory but with NO file bytes (zero-fill)."""
    SHF_ALLOC = 0x2
    out: list[dict] = []
    for sec in elf.iter_sections():
        h = sec.header
        if not (h["sh_flags"] & SHF_ALLOC) or h["sh_addr"] == 0:
            continue
        out.append({"name": sec.name, "vaddr": int(h["sh_addr"]), "size": int(h["sh_size"]),
                    "nobits": h["sh_type"] == "SHT_NOBITS"})
    out.sort(key=lambda s: s["vaddr"])
    return out


def _section_of(sections: list[dict], vaddr: int) -> str | None:
    """The name of the section whose [vaddr, vaddr+size) window contains `vaddr`, or None."""
    for sec in sections:
        if sec["vaddr"] <= vaddr < sec["vaddr"] + sec["size"]:
            return sec["name"]
    return None


def _load_func_symbols(elf) -> list[dict]:
    """Defined symbols WITH an address, as `{name, value, size, is_func}` sorted by value — for
    the nearest-symbol + containing-FUNC computation. Reads `.symtab` when present (a non-stripped
    binary), else `.dynsym` (a stripped binary keeps only exported dynamic symbols; a private
    FUN_* has no entry either way — that's why re_resolve is PARTIAL on a stripped target)."""
    from elftools.elf.sections import SymbolTableSection

    tab = elf.get_section_by_name(".symtab")
    if not isinstance(tab, SymbolTableSection):
        tab = elf.get_section_by_name(".dynsym")
    if not isinstance(tab, SymbolTableSection):
        return []
    out: list[dict] = []
    for sym in tab.iter_symbols():
        val = int(sym["st_value"])
        if not sym.name or val == 0:
            continue
        info = sym["st_info"]
        out.append({"name": sym.name, "value": val, "size": int(sym["st_size"]),
                    "is_func": info["type"] == "STT_FUNC"})
    out.sort(key=lambda s: s["value"])
    return out


def _nearest_and_containing(symbols: list[dict], vaddr: int) -> tuple[dict | None, dict | None]:
    """From address-sorted `symbols`, the nearest symbol AT-OR-BELOW `vaddr` (`{name, offset}`)
    and the containing FUNC when one covers it (`{name, address, size, end}`). Uses a binary
    search over the sorted values so a large symbol table stays cheap."""
    if not symbols:
        return None, None
    values = [s["value"] for s in symbols]
    idx = bisect.bisect_right(values, vaddr) - 1  # rightmost symbol whose value <= vaddr
    if idx < 0:
        return None, None
    nearest_sym = symbols[idx]
    nearest = {"name": nearest_sym["name"], "address": nearest_sym["value"],
               "offset": vaddr - nearest_sym["value"]}
    # Containing FUNC: scan the few symbols at/below the address whose [value, value+size) covers
    # it, preferring a FUNC. A size-0 symbol (common for asm stubs) can't "contain" anything.
    containing = None
    for s in symbols[: idx + 1][::-1]:
        if s["size"] > 0 and s["value"] <= vaddr < s["value"] + s["size"]:
            if s["is_func"]:
                containing = {"name": s["name"], "address": s["value"], "size": s["size"],
                              "end": s["value"] + s["size"]}
                break
            if containing is None:  # a non-FUNC cover is a fallback if no FUNC covers it
                containing = {"name": s["name"], "address": s["value"], "size": s["size"],
                              "end": s["value"] + s["size"]}
    return nearest, containing


def resolve_layout(path: str, vaddr: int) -> dict:
    """Assemble the lightweight triage answer for `vaddr` from the on-disk ELF at `path`:
    `{section, nearest_symbol, containing_function}` — WITHOUT a decompile. `nearest_symbol` is
    `{name, address, offset}` (the closest defined symbol at-or-below the address), `section` is
    the containing SHF_ALLOC section name (always, when the address is mapped), and
    `containing_function` is the covering FUNC symbol `{name, address, size, end}` when the symbol
    table knows it (None on a stripped target — that's the PARTIAL case). Returns
    `{"error": ..., "degraded": True}` when pyelftools is unavailable; never raises."""
    ELFFile = _elffile()
    if ELFFile is None:
        return {"error": "pyelftools not available in this environment", "degraded": True}
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            sections = _load_alloc_sections(elf)
            symbols = _load_func_symbols(elf)
    except Exception as exc:  # noqa: BLE001 — a non-ELF / unreadable artifact degrades cleanly
        logger.debug("resolve_layout failed for %s", path, exc_info=True)
        return {"error": f"could not read ELF: {exc}", "degraded": True}
    nearest, containing = _nearest_and_containing(symbols, vaddr)
    return {"section": _section_of(sections, vaddr), "nearest_symbol": nearest,
            "containing_function": containing, "n_symbols": len(symbols)}


def vaddr_to_offset(elf, vaddr: int) -> tuple[int | None, bool]:
    """Map a virtual address to a file offset via the PT_LOAD program headers: for the segment
    with `p_vaddr <= vaddr < p_vaddr + p_memsz`, the offset is `p_offset + (vaddr - p_vaddr)`.
    Returns `(file_offset, zero_fill)` — `zero_fill` is True when the address is in a segment's
    memsz-beyond-filesz tail (.bss), i.e. mapped but backed by NO file bytes (reads as 0). Returns
    `(None, False)` when the address is in no loadable segment (unmapped)."""
    for seg in elf.iter_segments():
        h = seg.header
        if h["p_type"] != "PT_LOAD":
            continue
        start = int(h["p_vaddr"])
        memsz = int(h["p_memsz"])
        if not (start <= vaddr < start + memsz):
            continue
        delta = vaddr - start
        if delta < int(h["p_filesz"]):
            return int(h["p_offset"]) + delta, False
        return None, True  # in the memsz tail (.bss): mapped, zero-filled, no file bytes
    return None, False


def read_bytes(path: str, vaddr: int, length: int) -> dict:
    """Read `length` bytes at virtual address `vaddr` from the on-disk ELF at `path`, mapping
    vaddr->file offset via the program headers. Returns
    `{data: bytes, address, length, zero_fill: bool}` on success — `zero_fill` True when the
    range lands in a .bss/zero-fill region (the bytes are synthesized as 00, never read past the
    file). Returns `{"error": ..., "degraded": True?}` when pyelftools is missing, the artifact
    isn't a readable ELF, or the address isn't mapped (reported, never faked). Never raises."""
    ELFFile = _elffile()
    if ELFFile is None:
        return {"error": "pyelftools not available in this environment", "degraded": True}
    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            off, zero_fill = vaddr_to_offset(elf, vaddr)
            if off is None and not zero_fill:
                return {"error": f"address {vaddr:#x} is not mapped in any PT_LOAD segment"}
            if zero_fill:
                # A .bss / zero-fill region: mapped in memory but backed by no file bytes. Return
                # the length as zeros with the flag so the caller annotates it, never reads garbage.
                return {"data": b"\x00" * length, "address": vaddr, "length": length,
                        "zero_fill": True}
            fh.seek(off)
            data = fh.read(length)
    except Exception as exc:  # noqa: BLE001 — a non-ELF / unreadable artifact degrades cleanly
        logger.debug("read_bytes failed for %s", path, exc_info=True)
        return {"error": f"could not read ELF: {exc}", "degraded": True}
    return {"data": data, "address": vaddr, "length": len(data), "zero_fill": False}


def render_hexdump(data: bytes, base: int) -> str:
    """Render `data` as classic `hexdump -C` lines — 16 bytes/line: `offset  hex bytes  |ascii|`
    with the virtual `base` address as the running offset. A non-printable byte shows as `.` in
    the ascii pane. Returns "(no bytes)" for empty input."""
    if not data:
        return "(no bytes)"
    lines: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_parts = [f"{b:02x}" for b in chunk]
        # Split into two 8-byte groups (the hexdump -C gutter), padding a short final line so the
        # ascii pane stays column-aligned.
        left = " ".join(hex_parts[:8])
        right = " ".join(hex_parts[8:])
        hex_col = f"{left:<23}  {right:<23}" if right or len(chunk) > 8 else f"{left:<23}"
        ascii_col = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:08x}  {hex_col}  |{ascii_col}|")
    return "\n".join(lines)
