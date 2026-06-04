#!/usr/bin/env python3
"""Decompile a target INSIDE the sandbox using radare2 (r2pipe).

argv[1] = /artifact (read-only), argv[2] = optional function name to focus.
Emits JSON: { functions: [...], focus: {name, pseudocode, disasm} | null }.

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


def _name_candidates(fn: str) -> list[str]:
    fn = fn.lstrip(".")
    return [f"sym.{fn}", f"sym.imp.{fn}", f"fcn.{fn}", fn]


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: decompile_probe.py <artifact> [function]"}))
        return 2
    path = sys.argv[1]
    focus_name = sys.argv[2] if len(sys.argv) > 2 else None

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
        r2.cmd("aaa")  # analyze all
        offsets = {}
        try:
            for f in (json.loads(r2.cmd("aflj") or "[]")):
                if f.get("name"):
                    offsets[f["name"]] = f.get("offset")
        except json.JSONDecodeError:
            pass
        functions = list(offsets.keys())

        focus = None
        if focus_name:
            # Resolve the function symbol r2 actually knows.
            resolved = next(
                (c for c in _name_candidates(focus_name) if c in functions),
                focus_name if focus_name in functions else None,
            )
            # Never interpolate an unvalidated name into an r2 command. Use the
            # resolved flag, or the sym.<name> fallback ONLY if the name is safe;
            # otherwise refuse to seek (treated as "function not found").
            if resolved:
                seek = resolved
            elif _SAFE_NAME.match(focus_name):
                seek = f"sym.{focus_name.lstrip('.')}"
            else:
                seek = None
            pseudo = r2.cmd(f"pdc @ {seek}").strip() if seek else ""
            disasm = r2.cmd(f"pdf @ {seek}").strip() if seek else ""
            off = offsets.get(resolved) if resolved else None
            focus = {
                "name": focus_name,
                "resolved": resolved,
                "address": hex(off) if isinstance(off, int) else None,
                "pseudocode": pseudo,
                "disasm": disasm,
                "callees": _callees(disasm),
            }

        print(json.dumps({"tool": "decompile_probe", "functions": functions[:200], "focus": focus}))
        return 0
    finally:
        r2.quit()


if __name__ == "__main__":
    raise SystemExit(main())
