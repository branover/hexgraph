#!/usr/bin/env python3
"""Cross-reference analysis INSIDE the sandbox via radare2.

argv[1] = /artifact (read-only); then an optional subject (a symbol/function name
or a hex address) and an optional `--mode`:

  (default / --mode callers)  who CALLS a symbol — every call site + the function
        it lives in. With no subject, sweeps the dangerous/format/network sinks.
  --mode function   callers AND callees of one function (the bidirectional view).
  --mode data       data/string/code xrefs TO an address (who references it).
  --mode callgraph  the whole-program call graph as [caller, callee] pairs.
  --mode search     scan the mapped image for a BYTE pattern (`--bytes <hexpairs>`,
        r2 `/xj`) or an IMMEDIATE value (`--imm <value>`, r2 `/vj`), each hit mapped
        to the function that contains it. The "reach code NOT yet decompiled" verb
        (callers-of-a-symbol is `--mode callers` / re_xrefs; this is the constant/opcode
        scan re_search_decompiled and the call-graph can't answer).

This is the "find the path from input to a dangerous sink" accelerator, plus the
breadth verbs (a function's neighbours, references to an address, the call graph).

No network; the target is analyzed, never executed.
"""

from __future__ import annotations

import json
import re
import sys

# A subject given as a hex address (data xrefs / an address subject). Validated
# strictly so it can never inject a command when interpolated into an r2 seek.
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")
# A symbol/function name interpolated into `axffj @ <name>`; only real symbol-name
# characters, so an unresolved name can't reach the shell (mirrors decompile_probe).
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@$:]+$")
# A byte pattern for `/xj` — hex pairs (whitespace tolerated), and an immediate value
# for `/vj`. Both are validated STRICTLY before interpolation into the r2 command so a
# search argument can never inject (mirrors the address/name discipline above).
_HEXPAIRS = re.compile(r"^[0-9A-Fa-f]{2,}$")
_IMM = re.compile(r"^(?:0x[0-9A-Fa-f]+|[0-9]+)$")

_MAX_GRAPH_FUNCS = 600   # bound the call-graph sweep (mirrors the Ghidra POST_SCRIPT caps)
_MAX_GRAPH_EDGES = 2000
_MAX_SEARCH_HITS = 200   # bound a byte/immediate scan so a common pattern can't flood

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
    # Imports are usually flagged sym.imp.<name>; local defs sym.<name>; data objects obj.<name>.
    return [f"sym.imp.{sym}", f"sym.{sym}", f"obj.{sym}", f"fcn.{sym}", sym]


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


def _resolve_seek(subject: str, flagset: set[str]) -> str | None:
    """The r2 seek for a function/address subject, or None if it can't be safely
    interpolated: an r2-known flag (sym.X/fcn.X) wins; a validated hex address or
    bare safe name is accepted as-is; anything else is refused (treated as unfound)."""
    if _ADDR.match(subject):
        return subject
    flag = next((c for c in _candidates(subject) if c in flagset), None)
    if flag:
        return flag
    return subject if _SAFE_NAME.match(subject) else None


def _symbol_addr(r2, name: str) -> str | None:
    """Resolve a symbol/label NAME to its hex address via r2's symbol table (`isj`), so a data
    xref BY NAME works for a local/static data symbol whose bare name isn't a seekable flag
    (e.g. a non-stripped binary's `KEY_ENC`). Returns a validated hex address (the caller seeks
    THAT, never the raw name, so it stays injection-safe), or None. Matches the symbol's full
    name or its trailing component (after any radare `sym.`/`obj.` prefixing)."""
    if not _SAFE_NAME.match(name):
        return None
    try:
        syms = json.loads(r2.cmd("isj") or "[]")
    except json.JSONDecodeError:
        return None
    want = name.lstrip(".")
    for s in syms:
        nm = s.get("name") or s.get("realname") or s.get("flagname") or ""
        if nm == name or nm == want or nm.split(".")[-1] == want:
            va = s.get("vaddr")
            if isinstance(va, int) and va:
                return hex(va)
    return None


def _calls_from(r2, seek: str) -> list[dict]:
    """Callees of a function: the CALL refs FROM it (axffj), with the target name/addr."""
    try:
        refs = json.loads(r2.cmd(f"axffj @ {seek}") or "[]")
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    seen: set[str] = set()
    for ref in refs:
        if str(ref.get("type", "")).lower() not in ("call", "c"):
            continue
        name = ref.get("name") or ref.get("refname")
        ref_addr = ref.get("ref") if isinstance(ref.get("ref"), int) else ref.get("addr")
        key = name or (hex(ref_addr) if isinstance(ref_addr, int) else None)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "addr": hex(ref_addr) if isinstance(ref_addr, int) else None,
                    "at": hex(ref["at"]) if isinstance(ref.get("at"), int) else None})
    return out


def _refs_to(r2, seek: str) -> list[dict]:
    """All xrefs TO an address (data/string/code refs), classified by kind."""
    try:
        refs = json.loads(r2.cmd(f"axtj @ {seek}") or "[]")
    except json.JSONDecodeError:
        return []
    out: list[dict] = []
    seen: set[tuple] = set()
    for ref in refs:
        frm = ref.get("from")
        fn = ref.get("fcn_name") or ref.get("refname") or "?"
        key = (fn, frm)
        if key in seen:
            continue
        seen.add(key)
        out.append({"from_function": fn,
                    "at": hex(frm) if isinstance(frm, int) else None,
                    "kind": ref.get("type"), "opcode": ref.get("opcode")})
    return out


def _call_graph(r2) -> list[list[str]]:
    """The whole-program call graph as [caller, callee] name pairs, bounded."""
    try:
        funcs = json.loads(r2.cmd("aflj") or "[]")
    except json.JSONDecodeError:
        return []
    edges: list[list[str]] = []
    for f in funcs[:_MAX_GRAPH_FUNCS]:
        caller, off = f.get("name"), f.get("offset")
        if not caller or not isinstance(off, int):
            continue
        for callee in _calls_from(r2, hex(off)):
            cname = callee.get("name")
            if cname:
                edges.append([caller, cname])
                if len(edges) >= _MAX_GRAPH_EDGES:
                    return edges
    return edges


def _fn_at(r2, off: int) -> str | None:
    """The name of the function CONTAINING address `off`, via `afij @ <off>` (bounded to a
    single function). None when no function is defined there — a hit in raw data/padding."""
    try:
        info = json.loads(r2.cmd(f"afij @ {off}") or "[]")
    except json.JSONDecodeError:
        return None
    if isinstance(info, list) and info:
        return info[0].get("name")
    return None


def _search(r2, *, bytes_pat: str | None, imm: str | None) -> dict:
    """Scan the mapped image for a byte pattern (`/xj <hexpairs>`) or an immediate value
    (`/vj <value>`), returning hits [{addr, in_function}] (each mapped to its containing
    function). The pattern/value is validated by the caller, so it can't inject here."""
    if bytes_pat is not None:
        cmd, term = f"/xj {bytes_pat}", {"kind": "bytes", "pattern": bytes_pat}
    else:
        cmd, term = f"/vj {imm}", {"kind": "immediate", "value": imm}
    try:
        raw = json.loads(r2.cmd(cmd) or "[]")
    except json.JSONDecodeError:
        raw = []
    hits: list[dict] = []
    seen: set[int] = set()
    for h in raw:
        # r2 `/xj` and `/vj` report the match address under `addr`; accept `offset` too so a
        # future r2 output shape (or a `/j`-family alias) still resolves.
        off = h.get("addr")
        if not isinstance(off, int):
            off = h.get("offset")
        if not isinstance(off, int) or off in seen:
            continue
        seen.add(off)
        hits.append({"addr": hex(off), "in_function": _fn_at(r2, off)})
        if len(hits) >= _MAX_SEARCH_HITS:
            break
    return {"tool": "xrefs_probe", "mode": "search", **term,
            "hits": hits, "total": len(seen)}


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: xrefs_probe.py <artifact> [subject] [--mode MODE]"}))
        return 2
    path = sys.argv[1]
    rest = sys.argv[2:]

    def _take_flag(name: str) -> str | None:
        # Pull a `--flag value` pair out of `rest` (like --mode), returning its value or None.
        nonlocal rest
        if name in rest:
            i = rest.index(name)
            val = rest[i + 1] if i + 1 < len(rest) else None
            rest = rest[:i] + rest[i + 2:]
            return val
        return None

    mode = _take_flag("--mode") or "callers"
    bytes_pat = _take_flag("--bytes")
    imm = _take_flag("--imm")
    positionals = [a for a in rest if not a.startswith("--")]
    subject = positionals[0] if positionals else None

    import r2pipe

    r2 = r2pipe.open(path, flags=["-2"])
    try:
        # A byte/immediate SEARCH is a raw memory scan — it does NOT need whole-binary analysis, and
        # running `aaa` on a large target is exactly the ~2547s timeout re_search_code hit. So skip
        # both `aaa` and the flag-set build for `--mode search` (the search + `_fn_at` work off the
        # loaded image / symbols alone; a hit then carries a containing-function name only where a
        # symbol already covers it — the WARM Ghidra search_bytes path gives precise mapping, this
        # fast fallback trades some mapping for not hanging). Every OTHER mode still needs `aaa`.
        flagset: set[str] = set()
        if mode != "search":
            r2.cmd("aaa")
            # The set of flag names r2 knows, so we can resolve sym.imp.X vs sym.X
            # (`fj` is the JSON flag list; `flsj`/`fsj` list flag *spaces*, not flags).
            try:
                for f in json.loads(r2.cmd("fj") or "[]"):
                    if f.get("name"):
                        flagset.add(f["name"])
            except json.JSONDecodeError:
                pass

        if mode == "search":
            # Validate the pattern/value STRICTLY before it reaches the r2 command (injection
            # safety, same discipline as _ADDR/_SAFE_NAME). Exactly one of --bytes/--imm.
            clean = bytes_pat.replace(" ", "") if bytes_pat else None
            if clean is not None:
                if not _HEXPAIRS.match(clean) or len(clean) % 2:
                    print(json.dumps({"tool": "xrefs_probe", "mode": "search",
                                      "error": "bytes must be an even-length hex string, e.g. 'deadbeef'"}))
                    return 0
                print(json.dumps(_search(r2, bytes_pat=clean, imm=None)))
            elif imm is not None:
                if not _IMM.match(imm):
                    print(json.dumps({"tool": "xrefs_probe", "mode": "search",
                                      "error": "immediate must be a hex (0x..) or decimal value"}))
                    return 0
                print(json.dumps(_search(r2, bytes_pat=None, imm=imm)))
            else:
                print(json.dumps({"tool": "xrefs_probe", "mode": "search",
                                  "error": "search needs --bytes <hexpairs> or --imm <value>"}))
        elif mode == "callgraph":
            edges = _call_graph(r2)
            print(json.dumps({"tool": "xrefs_probe", "mode": "callgraph",
                              "calls": edges, "total": len(edges)}))
        elif mode == "function":
            seek = _resolve_seek(subject, flagset) if subject else None
            if not seek:
                print(json.dumps({"tool": "xrefs_probe", "mode": "function",
                                  "subject": subject, "callers": [], "callees": [],
                                  "error": "function not found"}))
                return 0
            callers = _xrefs_to(r2, subject, flagset)
            callees = _calls_from(r2, seek)
            print(json.dumps({"tool": "xrefs_probe", "mode": "function", "subject": subject,
                              "callers": callers[:_MAX_CALLERS], "callees": callees[:_MAX_CALLERS],
                              "total_callers": len(callers), "total_callees": len(callees)}))
        elif mode == "data":
            seek = _resolve_seek(subject, flagset) if subject else None
            # A local/static data symbol given by NAME may not be a seekable flag — fall back to
            # the symbol table to resolve it to its address (the seek becomes a validated hex
            # address, so this stays injection-safe). Only when _resolve_seek didn't already
            # land a hex address or a known flag.
            if subject and (seek is None or (not _ADDR.match(seek) and seek not in flagset)):
                sym_addr = _symbol_addr(r2, subject)
                if sym_addr:
                    seek = sym_addr
            if not seek:
                print(json.dumps({"tool": "xrefs_probe", "mode": "data", "subject": subject,
                                  "data_refs": [], "error": "address not resolvable"}))
                return 0
            refs = _refs_to(r2, seek)
            print(json.dumps({"tool": "xrefs_probe", "mode": "data", "subject": subject,
                              "data_refs": refs[:_MAX_CALLERS], "total": len(refs)}))
        elif subject:  # mode == "callers" with a subject (legacy symbol xref)
            refs = _xrefs_to(r2, subject, flagset)
            print(json.dumps({"tool": "xrefs_probe", "symbol": subject,
                              "callers": refs[:_MAX_CALLERS], "total": len(refs)}))
        else:  # the legacy dangerous-sink sweep
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
