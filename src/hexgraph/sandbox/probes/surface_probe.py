#!/usr/bin/env python3
"""Liveness-probe a web surface from INSIDE the sandbox (bounded egress).

  argv: surface_probe.py --channel <json>

The channel is {"base_url", "allow": ["host:port", ...], "endpoints": [{"method","path"}]}.
For each endpoint we make ONE request (HEAD, falling back to GET) and record the status —
no body is returned to the model, only metadata. Enforced here as defense-in-depth on top
of the host-side policy/allowlist:
  - the request's host:port MUST be in `allow` (deny-all-but-this), else it's skipped;
  - redirects are NEVER followed (a hostile target can't bounce us to another host);
  - short timeout; stdlib only (no extra deps in the sandbox image).

No target bytes are executed; this is a network client interaction, gated by the
bounded-egress policy tier.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # never follow a redirect


def _dest(url: str) -> str:
    u = urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return f"{u.hostname}:{port}"


def _probe_one(url: str, method: str, allow: set, timeout: int) -> dict:
    dest = _dest(url)
    if dest not in allow:
        return {"url": url, "skipped": "destination not in allowlist", "dest": dest}
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, method=method)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return {"url": url, "dest": dest, "status": resp.status,
                    "server": resp.headers.get("Server"), "alive": True}
    except urllib.error.HTTPError as e:  # a real HTTP response (4xx/5xx/3xx) = alive
        return {"url": url, "dest": dest, "status": e.code,
                "server": e.headers.get("Server") if e.headers else None, "alive": True}
    except Exception as exc:  # noqa: BLE001 — connection refused/timeout/etc.
        return {"url": url, "dest": dest, "alive": False, "error": type(exc).__name__}


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
    probes = []
    for ep in channel.get("endpoints") or []:
        method = (ep.get("method") or "HEAD").upper()
        if method not in ("HEAD", "GET"):  # liveness recon is read-only
            method = "HEAD"
        url = base + (ep.get("path") or "/")
        r = _probe_one(url, method, allow, timeout)
        r["endpoint"] = f"{(ep.get('method') or 'GET').upper()} {ep.get('path') or '/'}"
        probes.append(r)
    print(json.dumps({"tool": "surface_probe", "base_url": base, "probes": probes}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
