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
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 64 * 1024  # bytes of response body returned to the model


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow a redirect (would dodge the host allowlist)


def _dest(url: str) -> str:
    u = urllib.parse.urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return f"{u.hostname}:{port}"


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
    dest = _dest(url)
    if dest not in allow:
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
    return {"method": method, "url": url, "dest": dest, "ok": True, "status": status,
            "headers": hdrs, "body": body, "body_truncated": truncated}


def _check_oracle(oracle: dict, responses: list) -> tuple[bool, str]:
    if not oracle or not responses:
        return False, "no oracle or no response"
    last = responses[-1]
    if not last.get("ok"):
        return False, f"last request failed: {last.get('error')}"
    typ = oracle.get("type") or "body_contains"
    val = oracle.get("value")
    if typ == "body_contains":
        ok = isinstance(val, str) and val in (last.get("body") or "")
        return ok, f"body {'contains' if ok else 'does not contain'} {val!r}"
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
    timeout = int(channel.get("timeout", 15))
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(jar))

    if channel.get("request") is not None:  # single-request mode (http_request tool)
        r = _do(opener, base, channel["request"], allow, timeout)
        print(json.dumps({"tool": "http_probe", "base_url": base, "response": r}))
        return 0

    responses = [_do(opener, base, step, allow, timeout) for step in (channel.get("steps") or [])]
    verified, detail = _check_oracle(channel.get("oracle") or {}, responses)
    print(json.dumps({"tool": "http_probe", "base_url": base, "steps": responses,
                      "verified": verified, "detail": detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
