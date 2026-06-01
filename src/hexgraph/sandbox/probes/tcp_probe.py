#!/usr/bin/env python3
"""Talk to ONE live TCP service from INSIDE the sandbox (bounded egress) — the non-HTTP
analogue of http_probe, for raw socket services a rehosted/remote device exposes (a bind
shell, a vendor binary protocol, a custom daemon on some high port).

  argv: tcp_probe.py --channel <json>

channel = {host, port, allow: ["host:port", ...], timeout,
           payload?: str | payload_hex?: hex-str,   # bytes to send (omit → banner grab)
           read_bytes?: int,                          # cap on response (default 64 KiB)
           oracle?: {"type": "response_contains", "value": "..."}}

→ emits {"tool":"tcp_probe","host","port","ok",
         "response": <text>, "response_hex"?: <hex if binary>, "response_truncated": bool,
         "verified"?: bool, "detail"?: str}     # verified/detail only when an oracle is given

Defense-in-depth, on top of the host-side policy/allowlist:
  - the host:port MUST be in `allow` (deny-all-but-this), else refused;
  - the response is bounded (read_bytes, default 64 KiB);
  - short timeout; recv stops at our timeout even if the service holds the connection open;
  - the oracle STRIPS the bytes we sent from the response before matching, so a service that
    merely echoes our payload (reflection) can't forge a 'verified' result — only output the
    service actually PRODUCED counts (the same unforgeable-{{NONCE}} principle as http_probe).

No target bytes are executed; this is a network client interaction, gated by the
bounded-egress policy tier and audited by the caller. stdlib only.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import urllib.parse

# Shared bounded-egress chokepoint, a sibling module. As a sandbox script the probes dir is
# already sys.path[0]; when loaded by file path (tests) it isn't, so add it explicitly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _egress  # noqa: E402

MAX_BYTES = 64 * 1024


def _echoed_forms(sent: bytes) -> list[str]:
    """Every form the bytes we SENT could be reflected back as — raw, URL-encoded
    (quote / quote_plus), and HTML-entity-encoded — so a service that merely echoes our
    payload (verbatim OR transformed by its templating/encoding) can't satisfy the oracle.
    Mirrors http_probe._echoed_strings so the raw-TCP oracle is as unforgeable as the web one."""
    s = sent.decode("utf-8", "replace")
    if not s:
        return []
    return [s, urllib.parse.quote(s), urllib.parse.quote_plus(s),
            s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")]


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def _payload_bytes(ch: dict) -> bytes:
    if ch.get("payload_hex"):
        try:
            return bytes.fromhex(ch["payload_hex"])
        except ValueError:
            return b""
    p = ch.get("payload")
    if p is None:
        return b""
    return p.encode("utf-8", "replace") if isinstance(p, str) else bytes(p)


def _exchange(host: str, port: int, payload: bytes, timeout: int, cap: int) -> dict:
    """Connect, optionally send, read up to `cap` bytes (stopping at our timeout even if the
    peer keeps the connection open), and return the raw response."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — refused/timeout/unreachable
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    chunks: list[bytes] = []
    got = 0
    try:
        if payload:
            sock.sendall(payload)
        # Read with a short per-recv timeout; many services don't close, so we stop on the
        # first idle gap rather than block until the overall deadline.
        sock.settimeout(min(timeout, 5))
        while got < cap + 1:
            try:
                buf = sock.recv(min(8192, cap + 1 - got))
            except socket.timeout:
                break
            except Exception:  # noqa: BLE001
                break
            if not buf:
                break
            chunks.append(buf)
            got += len(buf)
    finally:
        try:
            sock.close()
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "raw": b"".join(chunks)[: cap + 1]}


def _decode(raw: bytes, cap: int) -> dict:
    truncated = len(raw) > cap
    raw = raw[:cap]
    if b"\x00" in raw:
        return {"response_hex": raw.hex(), "response": raw.decode("utf-8", "replace"),
                "response_truncated": truncated, "encoding": "binary"}
    return {"response": raw.decode("utf-8", "replace"), "response_truncated": truncated,
            "encoding": "text"}


def _check_oracle(oracle: dict, response: str, sent: bytes) -> tuple[bool, str]:
    """Strip the bytes we sent (reflection) from the response, then match. So a daemon that
    echoes our payload back can't satisfy the oracle — only output it COMPUTED can."""
    typ = oracle.get("type") or "response_contains"
    val = oracle.get("value")
    if typ not in ("response_contains", "banner_contains"):
        return False, f"unknown oracle type {typ!r}"
    if not isinstance(val, str):
        return False, "oracle needs a string `value`"
    stripped = response
    for echo in _echoed_forms(sent):
        stripped = stripped.replace(echo, "")
    ok = val in stripped
    if not ok and val in response:
        return False, f"{val!r} present only as reflected input — not proof of execution"
    return ok, f"response {'contains' if ok else 'does not contain'} {val!r}"


def main() -> int:
    rest = sys.argv[1:]
    try:
        ch = json.loads(_flag(rest, "--channel", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --channel json: {exc}"}))
        return 2
    host, port = ch.get("host"), int(ch.get("port", 0))
    allow = set(ch.get("allow") or [])
    _egress.install_socket_guard(allow)  # can't-forget backstop on every TCP connect
    try:
        _egress.ensure_allowed(host, port, allow)  # explicit pre-connect check
    except _egress.EgressBlocked:
        print(json.dumps({"tool": "tcp_probe", "ok": False, "error": "destination not in allowlist"}))
        return 0
    timeout = int(ch.get("timeout", 15))
    cap = max(1, min(int(ch.get("read_bytes", MAX_BYTES)), MAX_BYTES))
    payload = _payload_bytes(ch)

    ex = _exchange(host, port, payload, timeout, cap)
    out: dict = {"tool": "tcp_probe", "host": host, "port": port, "ok": ex["ok"]}
    if not ex["ok"]:
        out["error"] = ex.get("error")
        print(json.dumps(out))
        return 0
    out.update(_decode(ex["raw"], cap))
    if payload:
        out["sent"] = payload.decode("utf-8", "replace")
    oracle = ch.get("oracle") or {}
    if oracle:
        verified, detail = _check_oracle(oracle, out.get("response") or "", payload)
        out["verified"] = verified
        out["detail"] = detail
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
