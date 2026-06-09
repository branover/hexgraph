#!/usr/bin/env python3
"""Decompile a target INSIDE the sandbox using radare2 (r2pipe).

argv[1] = /artifact (read-only); the remaining args are an optional focus
(a function NAME or a hex ADDRESS like 0x401200) plus an optional --reanalyze
flag. A focus given as an address resolves to the function CONTAINING it
(analyze-at-address), so a bare address from xrefs/strings is decompilable
without first knowing the function name.

Emits JSON: { functions: [...], focus: {name, address, pseudocode, disasm,
callees} | null }.

A separate RANGE mode (`--range <addr> [--length N] [--count N]`) disassembles
a RAW byte range starting at `addr` with NO function required — the fallback for
a CFG blind spot where neither r2 nor Ghidra defined a function, so the focus
paths above return "not found". It runs `pD <length> @ <addr>` (disassemble N
bytes) or `pd <count> @ <addr>` (N instructions) and emits
{ range: {address, length|count, disasm} | {error} }.

radare2 is the v1 decompiler (the Decompiler seam lets Ghidra drop in later).
We use built-in `pdc` (pseudo-C) with a `pdf` (disassembly) fallback — no
r2ghidra plugin required. No network; the target is analyzed, never executed.
"""

from __future__ import annotations

import json
import re
import sys

# `call <target>` in r2 disassembly. Capture the callee symbol/function name,
# skipping register-indirect calls (call rax / call qword [..]).
_CALL_RE = re.compile(r"\bcall\b\s+(?:dword |qword |word |byte )?(?:sym\.imp\.|sym\.|fcn\.|loc\.)?([A-Za-z_][\w]*)")
_REGISTERS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
}


def _callees(disasm: str) -> list[str]:
    out: list[str] = []
    for m in _CALL_RE.finditer(disasm or ""):
        name = m.group(1)
        if name in _REGISTERS or name in out:
            continue
        out.append(name)
    return out


# A function/symbol name is interpolated into an r2 command (`pdc @ <name>`), where
# `;` chains commands and `!`/backticks reach the shell. Only allow characters that
# occur in real symbol names, so an unresolved name can never inject a command.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@$:]+$")

# A focus given as a hex address (e.g. from xrefs/strings). Validated separately and
# strictly so it, too, can never inject a command when interpolated into an r2 seek.
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")

# Range-mode defaults + ceilings. The probe disassembles at most this many bytes /
# instructions in one call so a pathological request can't run unbounded; the host clips
# the returned text separately (the no-silent-caps marker). Generous enough to read a whole
# blind-spot region in one pass.
_RANGE_DEFAULT_LENGTH = 256
_RANGE_MAX_LENGTH = 8192
_RANGE_MAX_COUNT = 1024


def _name_candidates(fn: str) -> list[str]:
    fn = fn.lstrip(".")
    return [f"sym.{fn}", f"sym.imp.{fn}", f"fcn.{fn}", fn]


def _containing_function(addr: int, funcs: list[dict]) -> dict | None:
    """The aflj function record whose [offset, offset+size) contains `addr`, or None.
    Pure-Python over r2's own function table — no command interpolation, so resolving
    an attacker-influenced address is injection-safe."""
    for f in funcs:
        off = f.get("offset")
        size = f.get("size") or f.get("realsz") or 0
        if isinstance(off, int) and off <= addr < off + (size or 1):
            return f
    return None


def _function_facts(r2, seek: str) -> dict:
    """Rich, always-welcome function facts for the focus — recovered prototype/signature,
    calling convention, and arg/local variables — from r2's function info (`afij`: the
    signature, calling convention, arg/local counts) and variables (`afvj`). `seek` is the
    same already-validated flag/address used for the `pdc`/`pdf` seek, so this adds no new
    injection surface. Best-effort: every field is guarded, so a missing/odd shape just
    omits that fact rather than failing the decompile."""
    facts: dict = {}
    try:
        info = json.loads(r2.cmd(f"afij @ {seek}") or "[]")
    except (json.JSONDecodeError, TypeError):
        info = []
    if isinstance(info, list) and info and isinstance(info[0], dict):
        fi = info[0]
        sig = fi.get("signature")
        if sig:
            # r2's signature IS the recovered C prototype; expose it under both keys the
            # enrichment whitelist accepts (prototype is the primary, signature the synonym).
            facts["prototype"] = sig
            facts["signature"] = sig
        if fi.get("calltype"):
            facts["calling_convention"] = fi["calltype"]
        if isinstance(fi.get("nargs"), int):
            facts["param_count"] = fi["nargs"]
        if isinstance(fi.get("nlocals"), int):
            facts["local_count"] = fi["nlocals"]
    # afvj's shape varies across r2 versions: either a {storage_class: [vars]} map
    # ("reg"/"sp"/"bp"/"stack") OR a flat [vars] list — handle both. A variable's `kind`
    # is its STORAGE class, NOT an arg/local marker, so don't key on kind=="arg"; r2 marks
    # a parameter with an `isarg`/`arg` boolean (newer) or kind=="arg" (older), so take the
    # union of those signals and default to local. Misclassifying is worse than omitting,
    # so unmarked variables are locals (the prototype + param_count still convey the args).
    try:
        vars_ = json.loads(r2.cmd(f"afvj @ {seek}") or "[]")
    except (json.JSONDecodeError, TypeError):
        vars_ = []
    if isinstance(vars_, dict):
        entries = [v for group in vars_.values() for v in (group or []) if isinstance(v, dict)]
    elif isinstance(vars_, list):
        entries = [v for v in vars_ if isinstance(v, dict)]
    else:
        entries = []

    def _is_arg(v: dict) -> bool:
        return bool(v.get("isarg") or v.get("arg") or v.get("kind") == "arg")

    params: list = []
    locals_: list = []
    for v in entries:
        if not v.get("name"):
            continue
        entry = {"name": v.get("name"), "type": v.get("type")}
        (params if _is_arg(v) else locals_).append(entry)
    if params:
        facts["params"] = params
        facts.setdefault("param_count", len(params))
    if locals_:
        facts["locals"] = locals_
        facts.setdefault("local_count", len(locals_))
    return facts


def _disassemble_range(r2, address: str, *, length: int | None, count: int | None) -> dict:
    """Disassemble a RAW byte range at `address` — NO function required.

    `address` is the already-validated hex string (`_ADDR`), interpolated into an r2 seek
    only after that check, so it can never inject. `count` (instruction count) takes
    precedence over `length` (byte count) when both are given; otherwise `length` bytes
    are disassembled, defaulting to _RANGE_DEFAULT_LENGTH. Bounds are clamped to the
    ceilings so a pathological N can't run unbounded. Returns the range payload with the
    resolved mode echoed back, or an {error} if r2 produced nothing."""
    if count is not None:
        n = max(1, min(count, _RANGE_MAX_COUNT))
        # `pd N @ addr` — disassemble N instructions from addr (no function needed).
        disasm = (r2.cmd(f"pd {n} @ {address}") or "").strip()
        meta = {"count": n}
    else:
        n = length if length is not None else _RANGE_DEFAULT_LENGTH
        n = max(1, min(n, _RANGE_MAX_LENGTH))
        # `pD N @ addr` — disassemble N BYTES from addr (capital D = byte length, not insn
        # count), the raw-range read for a CFG blind spot with no defined function.
        disasm = (r2.cmd(f"pD {n} @ {address}") or "").strip()
        meta = {"length": n}
    if not disasm:
        return {"address": address, **meta,
                "error": "no disassembly at this address (out of range, or not mapped)"}
    return {"address": address, **meta, "disasm": disasm}


def _flag_value(rest: list[str], flag: str) -> str | None:
    """The value following `flag` in argv (`--length 256`), or None if absent/dangling."""
    if flag in rest:
        i = rest.index(flag)
        if i + 1 < len(rest):
            return rest[i + 1]
    return None


def _parse_int(val: str | None) -> int | None:
    """A non-negative int from a flag value, or None if absent/unparseable (clamped in
    _disassemble_range). Accepts decimal or 0x-hex so the host can pass either form."""
    if val is None:
        return None
    try:
        return int(val, 0)
    except (TypeError, ValueError):
        return None


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: decompile_probe.py <artifact> [function|0xADDR] "
                                   "[--reanalyze] | --range <0xADDR> [--length N | --count N]"}))
        return 2
    path = sys.argv[1]
    # Remaining args: an optional positional focus (name or 0xADDR) + a --reanalyze flag.
    rest = sys.argv[2:]
    reanalyze = "--reanalyze" in rest
    # RANGE mode: `--range <0xADDR>` disassembles a raw byte range with NO function needed.
    # The address comes as the value AFTER --range (kept off the positionals so it isn't
    # mistaken for a focus). --length / --count bound it (count wins if both given).
    range_addr = _flag_value(rest, "--range")
    _value_flags = {"--range", "--length", "--count"}  # consume their following value too
    positionals = []
    skip = False
    for tok in rest:
        if skip:
            skip = False
            continue
        if tok in _value_flags:
            skip = True
            continue
        if tok.startswith("--"):
            continue
        positionals.append(tok)
    focus_arg = positionals[0] if positionals else None

    try:
        import r2pipe
    except ImportError as exc:
        print(json.dumps({"error": f"radare2/r2pipe not available in the sandbox image: {exc}"}))
        return 3

    try:
        r2 = r2pipe.open(path, flags=["-2"])  # -2 silences stderr
    except Exception as exc:  # noqa: BLE001 — surface a structured reason, not a bare traceback
        print(json.dumps({"error": f"radare2 failed to open the target: {exc}"}))
        return 4
    try:
        if range_addr is not None:
            # RANGE mode: no analysis pass needed — `pD`/`pd` read+disassemble raw bytes,
            # which is the whole point (the function-based paths already failed). Validate
            # the address with the SAME strict regex as a focus so it can never inject.
            if not _ADDR.match(range_addr):
                print(json.dumps({"tool": "decompile_probe",
                                  "range": {"error": f"invalid address {range_addr!r} "
                                                     "(expected hex like 0x401200)"}}))
                return 0
            length = _parse_int(_flag_value(rest, "--length"))
            count = _parse_int(_flag_value(rest, "--count"))
            rng = _disassemble_range(r2, range_addr, length=length, count=count)
            print(json.dumps({"tool": "decompile_probe", "range": rng}))
            return 0
        # --reanalyze raises the analysis depth (aaaa: the deeper, more aggressive pass)
        # so a missed function/edge gets a second chance; the default aaa is the fast path.
        r2.cmd("aaaa" if reanalyze else "aaa")
        records = []
        offsets = {}
        try:
            for f in (json.loads(r2.cmd("aflj") or "[]")):
                if f.get("name"):
                    records.append(f)
                    offsets[f["name"]] = f.get("offset")
        except json.JSONDecodeError:
            pass
        functions = list(offsets.keys())

        focus = None
        if focus_arg and _ADDR.match(focus_arg):
            # ADDRESS focus (analyze-at-address): resolve the function CONTAINING it.
            addr = int(focus_arg, 16)
            hit = _containing_function(addr, records)
            # Seek to the containing function by its r2-known name, else to the raw
            # (validated) address — `pdc @ 0xADDR` decompiles from there regardless.
            seek = hit["name"] if hit else focus_arg
            pseudo = r2.cmd(f"pdc @ {seek}").strip()
            disasm = r2.cmd(f"pdf @ {seek}").strip()
            off = hit.get("offset") if hit else addr
            focus = {
                "name": hit["name"] if hit else focus_arg,
                "resolved": hit["name"] if hit else None,
                "address": hex(off) if isinstance(off, int) else focus_arg,
                "pseudocode": pseudo,
                "disasm": disasm,
                "callees": _callees(disasm),
                **_function_facts(r2, seek),
            }
        elif focus_arg:
            # NAME focus. Resolve the function symbol r2 actually knows.
            resolved = next(
                (c for c in _name_candidates(focus_arg) if c in functions),
                focus_arg if focus_arg in functions else None,
            )
            # Never interpolate an unvalidated name into an r2 command. Use the
            # resolved flag, or the sym.<name> fallback ONLY if the name is safe;
            # otherwise refuse to seek (treated as "function not found").
            if resolved:
                seek = resolved
            elif _SAFE_NAME.match(focus_arg):
                seek = f"sym.{focus_arg.lstrip('.')}"
            else:
                seek = None
            pseudo = r2.cmd(f"pdc @ {seek}").strip() if seek else ""
            disasm = r2.cmd(f"pdf @ {seek}").strip() if seek else ""
            off = offsets.get(resolved) if resolved else None
            focus = {
                "name": focus_arg,
                "resolved": resolved,
                "address": hex(off) if isinstance(off, int) else None,
                "pseudocode": pseudo,
                "disasm": disasm,
                "callees": _callees(disasm),
                **(_function_facts(r2, seek) if seek else {}),
            }

        print(json.dumps({"tool": "decompile_probe", "functions": functions[:200], "focus": focus}))
        return 0
    finally:
        r2.quit()


if __name__ == "__main__":
    raise SystemExit(main())
