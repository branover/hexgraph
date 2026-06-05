#!/usr/bin/env python3
"""Decompile a target INSIDE the sandbox using radare2 (r2pipe).

argv[1] = /artifact (read-only); the remaining args are an optional focus
(a function NAME or a hex ADDRESS like 0x401200) plus an optional --reanalyze
flag. A focus given as an address resolves to the function CONTAINING it
(analyze-at-address), so a bare address from xrefs/strings is decompilable
without first knowing the function name.

Emits JSON: { functions: [...], focus: {name, address, pseudocode, disasm,
callees} | null }.

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


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: decompile_probe.py <artifact> [function|0xADDR] [--reanalyze]"}))
        return 2
    path = sys.argv[1]
    # Remaining args: an optional positional focus (name or 0xADDR) + a --reanalyze flag.
    rest = sys.argv[2:]
    reanalyze = "--reanalyze" in rest
    positionals = [a for a in rest if not a.startswith("--")]
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
