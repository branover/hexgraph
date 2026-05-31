#!/usr/bin/env python3
"""Cross-reference ("who calls this") analysis INSIDE the sandbox via radare2.

argv[1] = /artifact (read-only), argv[2] = optional symbol to cross-reference.

With a symbol, returns every call site that references it and the function each
call lives in — i.e. the callers. With no symbol, sweeps a default set of
dangerous sinks (system/popen/exec*/strcpy/sprintf/…) and reports which are
imported and where each is reached from. This is the "find the path from input
to a dangerous sink" accelerator: locate the sink, see who calls it, then
decompile those callers.

No network; the target is analyzed, never executed.
"""

from __future__ import annotations

import json
import sys

# Sinks worth mapping by default — memory-unsafe copies, format strings, and
# command/exec sinks. Untrusted data reaching any of these is the usual bug.
_DEFAULT_SINKS = [
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
    "memcpy", "alloca", "stpcpy",
]


def _candidates(sym: str) -> list[str]:
    sym = sym.lstrip(".")
    # Imports are usually flagged sym.imp.<name>; local defs sym.<name>.
    return [f"sym.imp.{sym}", f"sym.{sym}", f"fcn.{sym}", sym]


def _xrefs_to(r2, sym: str, flagset: set[str]) -> list[dict]:
    """Call sites referencing `sym`, with the function each lives in."""
    flag = next((c for c in _candidates(sym) if c in flagset), None)
    if flag is None:
        return []
    try:
        refs = json.loads(r2.cmd(f"axtj @ {flag}") or "[]")
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()
    for ref in refs:
        caller = ref.get("fcn_name") or ref.get("refname") or "?"
        at = ref.get("from")
        key = (caller, at)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "caller": caller,
            "caller_addr": hex(ref["fcn_addr"]) if isinstance(ref.get("fcn_addr"), int) else None,
            "at": hex(at) if isinstance(at, int) else None,
            "kind": ref.get("type"),
            "opcode": ref.get("opcode"),
        })
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: xrefs_probe.py <artifact> [symbol]"}))
        return 2
    path = sys.argv[1]
    symbol = sys.argv[2] if len(sys.argv) > 2 else None

    import r2pipe

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        r2.cmd("aaa")
        # The set of flag names r2 knows, so we can resolve sym.imp.X vs sym.X
        # (`fj` is the JSON flag list; `flsj`/`fsj` list flag *spaces*, not flags).
        flagset: set[str] = set()
        try:
            for f in json.loads(r2.cmd("fj") or "[]"):
                if f.get("name"):
                    flagset.add(f["name"])
        except json.JSONDecodeError:
            pass

        if symbol:
            refs = _xrefs_to(r2, symbol, flagset)
            print(json.dumps({"tool": "xrefs_probe", "symbol": symbol, "callers": refs}))
        else:
            sinks: dict[str, list[dict]] = {}
            for s in _DEFAULT_SINKS:
                refs = _xrefs_to(r2, s, flagset)
                if refs:
                    sinks[s] = refs
            print(json.dumps({"tool": "xrefs_probe", "sinks": sinks}))
        return 0
    finally:
        r2.quit()


if __name__ == "__main__":
    raise SystemExit(main())
