#!/usr/bin/env python3
"""binutils quick-facts over a single ELF target, run INSIDE the sandbox.

Reads the read-only artifact at argv[1] and emits a JSON facts blob on stdout —
the authoritative low-level facts a researcher asks for in the first minute:
the symbol table (nm), dynamic imports/exports + relocations + sections + the
ELF/program headers (readelf), and the program's security mitigations (NX, RELRO,
PIE, stack canary, FORTIFY). It shells out to the real GNU binutils (nm / objdump /
readelf / strings) so the facts are exactly what those canonical tools report,
parsing their text output rather than re-deriving anything.

This rides the same static analysis surface as recon: NO network, the target is
NEVER executed, only inspected. A non-ELF or unreadable artifact is reported as an
error JSON on stdout with a non-zero exit (the runner surfaces the reason).

Caps mirror recon's discipline (Phase O curation): bounded lists so a hostile blob
saturated with symbols/strings can't make the payload grow without bound — this
probe records a curated Observation, it does not re-flood the graph.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

# Bounds (mirror recon's caps so a huge/hostile binary yields a bounded payload).
# These are the FULL recovered lists in the Observation payload; promotion into the
# graph defers to recon's much tighter MAX_SYMBOLS/MAX_STRINGS (the probe feeds the
# substrate, it does not mint nodes).
_MAX_SYMBOLS = 4000      # nm symbol-table rows kept
_MAX_IMPORTS = 2000      # undefined (imported) symbols
_MAX_EXPORTS = 2000      # defined, exported (global) symbols
_MAX_RELOCS = 4000       # dynamic relocations
# The FULL `strings` table kept in the Observation payload — deliberately generous so a
# pattern grep (re_list_strings/list_strings filters THIS table, not the ~40-entry recon
# sample) can find a real string anywhere in the binary, not just in a tiny head sample.
# Still bounded so a hostile blob saturated with strings can't grow the payload without
# limit (recon promotes far fewer into the graph via its own tight MAX_STRINGS).
_MAX_STRINGS = 5000      # `strings` rows kept (recon promotes far fewer)
_MIN_STR_LEN = 6         # `strings -n` minimum (a touch longer than the default 4)

_TIMEOUT = 90            # per-tool wall-clock guard (the sandbox also hard-caps the run)

# A dynamic relocation type naming an imported function (jump-slot) — the PLT entries
# an attacker-relevant call resolves through. Kept distinct from data relocations.
_JUMP_SLOT = re.compile(r"JUMP_SLOT|JMP_SLOT", re.IGNORECASE)


def _run(argv: list[str]) -> tuple[int, str, str]:
    """Run a binutils tool over the artifact, returning (rc, stdout, stderr).

    The argv is a FIXED command this probe assembles (never agent-supplied), always
    ending in the read-only /artifact path — there is no shell and no user input on
    the line, so there is no injection surface."""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return 124, "", f"{argv[0]} timed out after {_TIMEOUT}s"
    except OSError as exc:
        return 127, "", f"failed to run {argv[0]}: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def parse_readelf_header(out: str) -> dict:
    """Pure parser for `readelf -W -h -l` text → the ELF/program-header facts.

    Split out from `_readelf_header` so the NX / RELRO / PIE signal extraction is
    unit-testable on synthetic text WITHOUT a sandbox or subprocess. Returns the same
    dict shape `_readelf_header` does: `elf_type`/`machine`/`entry` plus a
    `mitigations_partial` sub-dict the mitigation fold consumes.
    """
    facts: dict = {}
    if not out:
        return facts
    etype = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Type:"):
            # e.g. "Type:  DYN (Shared object file)" / "EXEC (Executable file)"
            etype = line.split(":", 1)[1].strip()
            facts["elf_type"] = etype
        elif line.startswith("Machine:"):
            facts["machine"] = line.split(":", 1)[1].strip()
        elif line.startswith("Entry point address:"):
            facts["entry"] = line.split(":", 1)[1].strip()
    # NX: a GNU_STACK program header WITHOUT the execute flag means a non-exec stack.
    # When there's no GNU_STACK header at all, modern toolchains default to NX on.
    nx = True
    has_gnu_stack = False
    relro = "none"
    interp = False
    for line in out.splitlines():
        s = line.strip()
        if "GNU_STACK" in s:
            has_gnu_stack = True
            # GNU_STACK Flg column (readelf -lW): "RW " => non-exec, "RWE" => exec stack.
            # The line ends with the Align column, so the flags are the second-to-last
            # token (always contiguous — RW/RWE — on a GNU_STACK row).
            cols = s.split()
            flags = cols[-2] if len(cols) >= 2 else ""
            nx = "E" not in flags
        if "GNU_RELRO" in s:
            relro = "partial"
        if "INTERP" in s:
            interp = True
    facts["mitigations_partial"] = {"nx": nx, "relro": relro,
                                    "_has_gnu_stack": has_gnu_stack, "_interp": interp,
                                    "_etype": etype}
    return facts


def _readelf_header(path: str) -> dict:
    """The ELF/program header facts via `readelf -hl`: type, machine, entry, and the
    program-header-derived NX (GNU_STACK exec bit) + PIE/RELRO signals."""
    rc, out, _err = _run(["readelf", "-W", "-h", "-l", path])
    if rc != 0 or not out:
        return {}
    return parse_readelf_header(out)


def _readelf_dynamic(path: str) -> dict:
    """Dynamic section facts via `readelf -dW`: needed libraries, soname, and the
    BIND_NOW flag that upgrades partial RELRO to full."""
    rc, out, _err = _run(["readelf", "-W", "-d", path])
    libs: list[str] = []
    soname = None
    bind_now = False
    if rc == 0 and out:
        for line in out.splitlines():
            if "(NEEDED)" in line:
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    libs.append(m.group(1))
            elif "(SONAME)" in line:
                m = re.search(r"\[([^\]]+)\]", line)
                if m:
                    soname = m.group(1)
            elif "(BIND_NOW)" in line or (("(FLAGS)" in line or "(FLAGS_1)" in line) and "NOW" in line):
                # Full RELRO upgrade signal: the dedicated BIND_NOW tag, or a FLAGS/FLAGS_1
                # dynamic entry carrying the NOW flag (DF_BIND_NOW / DF_1_NOW).
                bind_now = True
    return {"libraries": libs, "soname": soname, "_bind_now": bind_now}


def _readelf_sections(path: str) -> list[str]:
    """Section names via `readelf -SW` (e.g. .text/.data/.got/.plt) — the section map."""
    rc, out, _err = _run(["readelf", "-W", "-S", path])
    sections: list[str] = []
    if rc == 0 and out:
        for m in re.finditer(r"\]\s+(\.\S+)", out):
            name = m.group(1)
            if name not in sections:
                sections.append(name)
    return sections


def _nm_symbols(path: str) -> dict:
    """The symbol table via `nm -D --defined-only` (exports) and `nm -Du` (undefined =
    imports), with a full `nm -D` row sample. Falls back silently to {} when nm finds
    no symbols (stripped binary) — readelf still provides the dynamic symbol facts."""
    imports: list[str] = []
    exports: list[str] = []
    symbols: list[dict] = []
    # Dynamic symbol table: portable across stripped binaries (static symtab may be gone).
    rc, out, _err = _run(["nm", "-D", path])
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:           # "U printf"  (no address)
                addr, typ, name = "", parts[0], parts[1]
            elif len(parts) >= 3:          # "0000000000001139 T main"
                addr, typ, name = parts[0], parts[1], parts[2]
            else:
                continue
            name = name.split("@", 1)[0]   # drop @GLIBC_2.x version suffix
            if len(symbols) < _MAX_SYMBOLS:
                symbols.append({"name": name, "type": typ,
                                "address": f"0x{addr}" if addr else None})
            if typ in ("U", "w") and name and name not in imports:
                if len(imports) < _MAX_IMPORTS:
                    imports.append(name)
            elif typ in ("T", "W", "D", "B", "R", "G", "S") and name and name not in exports:
                # Upper-case nm type => global (exported) symbol.
                if len(exports) < _MAX_EXPORTS:
                    exports.append(name)
    return {"symbols": symbols, "imports": sorted(set(imports)),
            "exports": sorted(set(exports))}


def _relocations(path: str) -> dict:
    """Dynamic relocations via `readelf -rW`: the count + the imported-function (jump-slot)
    targets, which are the PLT-resolved calls an attacker reaches.

    Each data row is `Offset Info Type [Value] Name@Version + Addend`. The symbol name is
    the column AFTER the relocation type (col index 3 on 32-bit, 4 on 64-bit which carries
    a Symbol's-Value column) — so we take the first token after the `R_*`/type column that
    looks like a symbol name, robust across 32/64-bit and arch reloc spellings."""
    rc, out, _err = _run(["readelf", "-W", "-r", path])
    total = 0
    jump_slots: list[str] = []
    if rc == 0 and out:
        for line in out.splitlines():
            # A relocation data row starts with an offset hex column.
            if not re.match(r"^[0-9a-fA-F]{4,}\s", line):
                continue
            total += 1
            if not _JUMP_SLOT.search(line):
                continue
            parts = line.split()
            # Find the relocation type token (R_<arch>_<kind>), then the next token that
            # is a plausible symbol name (not a hex value, not the `+`/addend tail).
            name = None
            ti = next((i for i, p in enumerate(parts) if p.startswith("R_") or "JUMP_SLOT" in p
                       or "JMP_SLOT" in p), None)
            if ti is not None:
                for tok in parts[ti + 1:]:
                    if tok in ("+",) or re.fullmatch(r"[0-9a-fA-F]{6,}", tok):
                        continue  # the Symbol's-Value column / addend separator
                    name = tok.split("@", 1)[0]
                    break
            if name and not re.fullmatch(r"[0-9a-fA-Fx]+", name) and name not in jump_slots \
                    and len(jump_slots) < _MAX_RELOCS:
                jump_slots.append(name)
    return {"relocation_count": total, "jump_slot_imports": sorted(set(jump_slots))}


def _strings(path: str) -> list[str]:
    """A clean `strings` pass (bounded). The canonical binutils `strings`, capped so the
    payload stays bounded; recon promotes far fewer into the graph."""
    rc, out, _err = _run(["strings", "-a", "-n", str(_MIN_STR_LEN), path])
    if rc != 0 or not out:
        return []
    seen: list[str] = []
    for line in out.splitlines():
        line = line.strip()
        if line and line not in seen:
            seen.append(line)
            if len(seen) >= _MAX_STRINGS:
                break
    return seen


def _canary(symbols: list[dict], imports: list[str]) -> bool:
    """Stack canary present iff the binary references the stack-guard fail handler."""
    names = {s.get("name") for s in symbols} | set(imports)
    return "__stack_chk_fail" in names or "__stack_chk_guard" in names


def _fortify(imports: list[str]) -> bool:
    """FORTIFY_SOURCE in use iff a `*_chk` fortified libc wrapper is imported."""
    return any(name.endswith("_chk") and name != "__stack_chk_fail" for name in imports)


def _mitigations(header: dict, dynamic: dict, syms: dict) -> dict:
    """Fold the header/dynamic/symbol signals into the four classic mitigation flags
    plus canary/fortify — NX, RELRO (none/partial/full), PIE, canary, FORTIFY."""
    partial = header.get("mitigations_partial", {})
    nx = bool(partial.get("nx", True))
    relro = partial.get("relro", "none")
    if relro == "partial" and dynamic.get("_bind_now"):
        relro = "full"
    etype = (partial.get("_etype") or "").upper()
    # PIE: a DYN ELF that is an executable (has an INTERP) — a DYN without INTERP is a .so.
    # Caveat: a static-PIE (ET_DYN, no INTERP) reads as pie=False here; it's rare and
    # indistinguishable from a shared object by this signal alone.
    pie = etype.startswith("DYN") and bool(partial.get("_interp"))
    canary = _canary(syms.get("symbols", []), syms.get("imports", []))
    fortify = _fortify(syms.get("imports", []))
    return {"nx": nx, "relro": relro, "pie": pie, "canary": canary, "fortify": fortify}


def collect(path: str) -> dict:
    """Run the binutils suite over an ELF and assemble the facts payload."""
    header = _readelf_header(path)
    dynamic = _readelf_dynamic(path)
    syms = _nm_symbols(path)
    relocs = _relocations(path)
    sections = _readelf_sections(path)
    strings = _strings(path)
    mitigations = _mitigations(header, dynamic, syms)

    facts: dict = {
        "tool": "binutils_probe",
        "format": "ELF",
        "elf_type": header.get("elf_type"),
        "machine": header.get("machine"),
        "entry": header.get("entry"),
        "soname": dynamic.get("soname"),
        "symbols": syms.get("symbols", []),
        "imports": syms.get("imports", []),
        "exports": syms.get("exports", []),
        "libraries": dynamic.get("libraries", []),
        "sections": sections,
        "relocation_count": relocs.get("relocation_count", 0),
        "jump_slot_imports": relocs.get("jump_slot_imports", []),
        "mitigations": mitigations,
        "strings": strings,
    }
    return facts


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: binutils_probe.py <artifact>"}))
        return 2
    path = sys.argv[1]
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError as exc:
        print(json.dumps({"error": f"cannot read artifact: {exc}"}))
        return 1
    if magic != b"\x7fELF":
        # binutils quick-facts is an ELF tool; a non-ELF artifact is reported as an
        # error with a non-zero exit (the runner surfaces the reason). recon already
        # classifies firmware/disk images on the non-ELF path.
        print(json.dumps({"error": "not an ELF binary (binutils facts apply to ELF only)"}))
        return 1
    try:
        facts = collect(path)
    except Exception as exc:  # noqa: BLE001 — keep the probe resilient; report the reason
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
        return 1
    print(json.dumps(facts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
