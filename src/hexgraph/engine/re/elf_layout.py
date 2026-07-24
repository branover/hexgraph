"""Pure ELF-layout COMPUTE for re_resolve, plus the hexdump FORMATTER shared with re_hexdump.

NO I/O and NO pyelftools here: the hostile ELF is parsed in the SANDBOX (radare2), and these
functions turn the sandbox-sourced plain dicts into an answer. For re_resolve the section + sized
symbol tables come from `decompile_probe.py --layout` (`iSj`/`isj`) via
`R2Decompiler.resolve_layout`, and `section_of` / `nearest_and_containing` compute the
{section, nearest_symbol, containing_function} triage from them. For re_hexdump the raw bytes come
from radare2 `p8` and `render_hexdump` lays them out. Host-side, side-effect-free, never touches
the target bytes — the pyelftools symbol/section reads that used to run in the host process (but
were never shipped host-side, so they always degraded) now live entirely in the sandbox.
"""

from __future__ import annotations

import bisect

# Hard ceiling on a single re_hexdump read — a bounded window so a fat-fingered length can't
# pull megabytes into the context (the no-silent-caps discipline: the tool reports when it clamps).
# The host clamps to this before the sandbox read; decompile_probe._HEXDUMP_MAX_BYTES mirrors it.
HEXDUMP_MAX = 4096


def section_of(sections: list[dict], vaddr: int) -> str | None:
    """The name of the section whose [vaddr, vaddr+size) window contains `vaddr`, or None.
    `sections` are the sandbox-sourced `{name, vaddr, size}` dicts (the mapped, vaddr>0 entries)."""
    for sec in sections:
        if sec["vaddr"] <= vaddr < sec["vaddr"] + sec["size"]:
            return sec["name"]
    return None


def nearest_and_containing(symbols: list[dict], vaddr: int) -> tuple[dict | None, dict | None]:
    """From value-sorted `symbols` (`{name, value, size, is_func}` from the sandbox), the nearest
    symbol AT-OR-BELOW `vaddr` (`{name, address, offset}`) and the containing FUNC when one covers
    it (`{name, address, size, end}`). Binary-searches the sorted values so a large symbol table
    stays cheap. `containing_function` is None on a stripped target (only dynsym exports are known)
    — the PARTIAL case."""
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
