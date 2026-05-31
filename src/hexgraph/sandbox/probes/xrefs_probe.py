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

# Memory-unsafe + command/exec sinks: untrusted data reaching any of these is
# almost always a bug regardless of context.
_DEFAULT_SINKS = [
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "strcpy", "strcat", "gets", "scanf", "sscanf", "memcpy", "alloca", "stpcpy",
]

# The printf family: dangerous ONLY when the FORMAT argument is attacker-controlled
# (CWE-134) — but then it's a disclosure/write primitive. Reported separately
# because these are called pervasively, so the callers list is context, not a
# verdict: check each call's format argument.
_FORMAT_SINKS = [
    "printf", "fprintf", "sprintf", "snprintf", "dprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "syslog", "vsyslog", "asprintf",
]

# Network / IPC surface: who opens sockets, listens, connects, or reads off the
# wire. Not "dangerous" per se — it's the attack surface + the socket map (model
# these as `socket` nodes with listens_on/connects_to edges).
_NETWORK_SINKS = [
    "socket", "bind", "listen", "accept", "accept4", "connect", "recv", "recvfrom",
    "recvmsg", "read", "send", "sendto", "sendmsg", "setsockopt", "getaddrinfo",
    "gethostbyname", "socketpair",
]

_MAX_CALLERS = 30  # bound per-sink caller lists so a noisy printf doesn't flood


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
            print(json.dumps({"tool": "xrefs_probe", "symbol": symbol,
                              "callers": refs[:_MAX_CALLERS], "total": len(refs)}))
        else:
            def sweep(names):
                out = {}
                for s in names:
                    refs = _xrefs_to(r2, s, flagset)
                    if refs:
                        out[s] = {"callers": refs[:_MAX_CALLERS], "total": len(refs)}
                return out
            print(json.dumps({"tool": "xrefs_probe",
                              "sinks": sweep(_DEFAULT_SINKS),
                              "format_sinks": sweep(_FORMAT_SINKS),
                              "network": sweep(_NETWORK_SINKS)}))
        return 0
    finally:
        r2.quit()


if __name__ == "__main__":
    raise SystemExit(main())
