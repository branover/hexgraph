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


def _name_candidates(fn: str) -> list[str]:
    fn = fn.lstrip(".")
    return [f"sym.{fn}", f"sym.imp.{fn}", f"fcn.{fn}", fn]


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: decompile_probe.py <artifact> [function]"}))
        return 2
    path = sys.argv[1]
    focus_name = sys.argv[2] if len(sys.argv) > 2 else None

    import r2pipe

    r2 = r2pipe.open(path, flags=["-2"])  # -2 silences stderr
    try:
        r2.cmd("aaa")  # analyze all
        try:
            functions = [f.get("name") for f in (json.loads(r2.cmd("aflj") or "[]"))]
        except json.JSONDecodeError:
            functions = []

        focus = None
        if focus_name:
            # Resolve the function symbol r2 actually knows.
            resolved = next(
                (c for c in _name_candidates(focus_name) if c in functions),
                focus_name if focus_name in functions else None,
            )
            seek = resolved or f"sym.{focus_name.lstrip('.')}"
            pseudo = r2.cmd(f"pdc @ {seek}").strip()
            disasm = r2.cmd(f"pdf @ {seek}").strip()
            focus = {
                "name": focus_name,
                "resolved": resolved,
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
