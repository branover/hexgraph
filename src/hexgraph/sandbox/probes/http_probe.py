#!/usr/bin/env python3
"""Send crafted HTTP request(s) to a web surface from INSIDE the sandbox (bounded egress).

  argv: http_probe.py --channel <json>

The channel is one of:
  - a SINGLE request (the `http_request` tool):
      {"base_url", "allow": ["host:port", ...], "timeout": N,
       "request": {"method","path","params"?,"headers"?,"body"?,"json"?}}
    → emits {"response": {...}}
  - a multi-step PoC with an oracle (web `verify_poc`):
      {"base_url", "allow":[...], "timeout":N,
       "steps": [ {request}, ... ],
       "oracle": {"type":"body_contains|status_is|status_differs", "value": ...}}
    → emits {"steps":[{response}...], "verified": bool, "detail": str}

Cookies set by one step carry to the next (a CookieJar), so an auth flow works:
login → receive Set-Cookie → access a protected route in the same run.

Defense-in-depth, on top of the host-side policy/allowlist:
  - every request's host:port MUST be in `allow` (deny-all-but-this), else it's refused;
  - redirects are NEVER followed (a hostile target can't bounce us to another host);
  - the response body is bounded (64 KiB) so a huge body can't blow up the model context;
  - short timeout; stdlib only (no extra deps in the sandbox image).

No target bytes are executed; this is a network client interaction, gated by the
bounded-egress policy tier and audited by the caller.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# Shared bounded-egress chokepoint, a sibling module. As a sandbox script the probes dir is
# already sys.path[0]; when loaded by file path (tests) it isn't, so add it explicitly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _egress  # noqa: E402

MAX_BODY = 64 * 1024  # bytes of response body returned to the model


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow a redirect (would dodge the host allowlist)


def _dest(url: str) -> str:
    """The `host:port` an allowlist check is run against. A crafted path can produce a
    malformed netloc (e.g. base+'http://evil/' → port not an int); return an unmatchable
    sentinel rather than raise, so such a URL is *refused* by the allowlist, not crashed."""
    try:
        u = urllib.parse.urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        host = u.hostname
    except ValueError:
        return "<malformed>"
    if not host:
        return "<malformed>"
    return f"{host}:{port}"


def _build(base: str, spec: dict):
    """Turn a request spec into a urllib Request. Body is form-encoded by default;
    set `json: true` to send it as application/json."""
    method = (spec.get("method") or "GET").upper()
    path = spec.get("path") or "/"
    url = base + path
    params = spec.get("params") or {}
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
    headers = dict(spec.get("headers") or {})
    data = None
    body = spec.get("body")
    if body is not None:
        if spec.get("json"):
            data = json.dumps(body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif isinstance(body, (dict, list)):
            data = urllib.parse.urlencode(body, doseq=True).encode("utf-8")
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = str(body).encode("utf-8")
    return method, url, urllib.request.Request(url, method=method, data=data, headers=headers)


def _do(opener, base: str, spec: dict, allow: set, timeout: int) -> dict:
    method, url, req = _build(base, spec)
    dest = _dest(url)  # canonical "host:port" (or "<malformed>" sentinel → always refused)
    try:
        # Explicit pre-connect check via the shared chokepoint; the socket guard installed
        # at startup is the backstop. `dest` is already canonical, so split-free matching.
        if dest not in allow:
            raise _egress.EgressBlocked(dest)
    except _egress.EgressBlocked:
        return {"method": method, "url": url, "dest": dest,
                "error": "destination not in allowlist", "ok": False}
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BODY + 1)
            return _resp(method, url, dest, resp.status, resp.headers, raw)
    except urllib.error.HTTPError as e:  # 4xx/5xx is still a real response
        raw = e.read(MAX_BODY + 1) if hasattr(e, "read") else b""
        return _resp(method, url, dest, e.code, e.headers, raw)
    except Exception as exc:  # noqa: BLE001 — refused/timeout/etc.
        return {"method": method, "url": url, "dest": dest, "ok": False,
                "error": type(exc).__name__}


def _resp(method, url, dest, status, headers, raw: bytes) -> dict:
    truncated = len(raw) > MAX_BODY
    body = raw[:MAX_BODY].decode("utf-8", errors="replace")
    hdrs = {k: v for k, v in (headers.items() if headers else [])}
    # Surface ALL Set-Cookie values (the dict above collapses duplicates) so the host can
    # keep a per-session cookie jar across separate single-request calls.
    set_cookie = headers.get_all("Set-Cookie") if headers and hasattr(headers, "get_all") else []
    return {"method": method, "url": url, "dest": dest, "ok": True, "status": status,
            "headers": hdrs, "set_cookie": set_cookie or [], "body": body, "body_truncated": truncated}


def _echoed_strings(step: dict) -> list[str]:
    """Everything the request SUBMITTED (path, query/body param values, raw body), in raw +
    URL-encoded forms — so we can strip a server's reflection of our own payload from the
    response before a body_contains check. A reflective page (a 403 re-auth form echoing the
    request URI, a search box, an error page) would otherwise match the {{NONCE}} we sent and
    forge a 'verified' PoC even though no command ran."""
    vals: list[str] = []
    if step.get("path"):
        vals.append(str(step["path"]))
    body = step.get("body")
    if isinstance(body, dict):
        vals += [str(v) for v in body.values()]
    elif isinstance(body, (str, bytes)):
        vals.append(body.decode() if isinstance(body, bytes) else body)
    for v in (step.get("params") or {}).values():
        vals.append(str(v))
    out: list[str] = []
    for v in vals:
        if not v:
            continue
        out += [v, urllib.parse.quote(v), urllib.parse.quote_plus(v),
                v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")]
    return out


def _check_oracle(oracle: dict, responses: list, last_step: dict | None = None) -> tuple[bool, str]:
    if not oracle or not responses:
        return False, "no oracle or no response"
    last = responses[-1]
    if not last.get("ok"):
        return False, f"last request failed: {last.get('error')}"
    typ = oracle.get("type") or "body_contains"
    val = oracle.get("value")
    status = last.get("status")
    if typ == "body_contains":
        # Strip the request's own reflected payload first, so a match means the value was
        # PRODUCED by the target (e.g. command output), not just echoed back.
        body = last.get("body") or ""
        for echo in _echoed_strings(last_step or {}):
            body = body.replace(echo, "")
        ok = isinstance(val, str) and val in body
        note = ""
        if not ok and isinstance(val, str) and val in (last.get("body") or ""):
            note = " [present only as reflected request input — not proof of execution]"
        if ok and status in (401, 403):
            # Genuine post-auth output behind a 401/403 is contradictory; flag it.
            note = f" [warning: matched on a {status} response — verify this isn't an auth wall]"
        return ok, f"status {status}: body {'contains' if ok else 'does not contain'} {val!r}{note}"
    if typ == "status_is":
        ok = int(last.get("status", 0)) == int(val)
        return ok, f"status {last.get('status')} {'==' if ok else '!='} {val}"
    if typ == "status_differs":
        # value is the baseline status that an UNbypassed request returns; success =
        # this (bypass) request returned something else (e.g. 401 baseline → 200 here).
        ok = int(last.get("status", 0)) != int(val)
        return ok, f"status {last.get('status')} {'differs from' if ok else 'matches'} baseline {val}"
    return False, f"unknown oracle type {typ!r}"


def main() -> int:
    rest = sys.argv[1:]
    try:
        channel = json.loads(_flag(rest, "--channel", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --channel json: {exc}"}))
        return 2
    base = (channel.get("base_url") or "").rstrip("/")
    allow = set(channel.get("allow") or [])
    _egress.install_socket_guard(allow)  # can't-forget backstop on every TCP connect
    timeout = int(channel.get("timeout", 15))
    jar = http.cookiejar.CookieJar()
    # Embedded devices serve HTTPS with self-signed/expired certs (LuCI, vendor admin UIs);
    # we're ASSESSING a hostile target, not trusting it, so don't verify TLS (like curl -k).
    # Containment is the allowlist + no-redirects + the bounded-egress scope, not cert chains.
    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=tls),
        urllib.request.HTTPCookieProcessor(jar))

    if channel.get("request") is not None:  # single-request mode (http_request tool)
        r = _do(opener, base, channel["request"], allow, timeout)
        print(json.dumps({"tool": "http_probe", "base_url": base, "response": r}))
        return 0

    steps = channel.get("steps") or []
    responses = [_do(opener, base, step, allow, timeout) for step in steps]
    verified, detail = _check_oracle(channel.get("oracle") or {}, responses,
                                     last_step=steps[-1] if steps else None)
    print(json.dumps({"tool": "http_probe", "base_url": base, "steps": responses,
                      "verified": verified, "detail": detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
