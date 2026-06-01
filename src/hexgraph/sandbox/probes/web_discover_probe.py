#!/usr/bin/env python3
"""Discover a web surface's routes from INSIDE the sandbox (bounded egress).

  argv: web_discover_probe.py --channel <json>

channel = {"base_url", "allow": ["host:port", ...], "timeout": N, "max_pages": M}

A BOUNDED, read-only crawl that maps what's actually there (surface_recon otherwise only
materializes a route spec the caller supplied). It:
  - seeds with "/" + a small builtin wordlist of common embedded/admin paths;
  - GETs each (HEAD-ish, but GET to read links), parses <a href>/<form> for more same-host
    paths and form params, and records 30x `Location` targets (same-host only);
  - stays on the surface's host:port (the `allow` allowlist — deny-all-but-this), never
    follows a cross-host redirect, caps total pages, and uses a short timeout.

No target bytes are executed; this is a bounded network client interaction, gated by the
bounded-egress policy tier and audited by the caller. Emits {"endpoints": [...]}.
"""

from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import os
from collections import deque
from html.parser import HTMLParser

# Shared bounded-egress chokepoint, a sibling module. As a sandbox script the probes dir is
# already sys.path[0]; when loaded by file path (tests) it isn't, so add it explicitly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _egress  # noqa: E402

# Common paths worth probing on an embedded/admin web surface even if nothing links to them.
SEEDS = [
    "/", "/index.html", "/login", "/login.cgi", "/admin", "/admin/", "/cgi-bin/",
    "/cgi-bin/luci", "/api", "/api/", "/status", "/system.html", "/info", "/robots.txt",
    "/.htaccess", "/config", "/setup.cgi", "/diagnostic", "/ping.cgi", "/upload",
]


def _flag(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Links(HTMLParser):
    """Collect same-doc hrefs/form actions + form input names."""
    def __init__(self):
        super().__init__()
        self.hrefs: list[str] = []
        self.forms: list[dict] = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "GET").upper(),
                          "params": []}
        elif tag in ("input", "select", "textarea") and self._form is not None and a.get("name"):
            self._form["params"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _dest(url: str) -> str:
    u = urllib.parse.urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    return f"{u.hostname}:{port}"


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
    max_pages = int(channel.get("max_pages", 40))
    base_host = _dest(base)

    tls = ssl.create_default_context()
    tls.check_hostname = False
    tls.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=tls))

    seen: set[str] = set()
    queue: deque[str] = deque(SEEDS)
    endpoints: dict[str, dict] = {}  # "METHOD path" -> {method, path, params, status}
    fetched = 0

    def record(method: str, path: str, params=None, status=None):
        key = f"{method} {path}"
        e = endpoints.setdefault(key, {"method": method, "path": path, "params": [], "status": status})
        if status is not None:
            e["status"] = status
        for p in params or []:
            if p and p not in e["params"]:
                e["params"].append(p)

    while queue and fetched < max_pages:
        path = queue.popleft()
        if not path.startswith("/"):
            continue
        path = path.split("#", 1)[0]
        if path in seen:
            continue
        seen.add(path)
        url = base + path
        try:
            if _dest(url) not in allow:    # same-host only (deny-all-but-this)
                raise _egress.EgressBlocked(_dest(url))
        except _egress.EgressBlocked:      # explicit check; socket guard is the backstop
            continue
        fetched += 1
        try:
            with opener.open(urllib.request.Request(url), timeout=timeout) as resp:
                status, body, ctype = resp.status, resp.read(256 * 1024), resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            record("GET", path, status=e.code)        # 401/403/404 are still real routes
            continue
        except Exception:  # noqa: BLE001
            continue
        record("GET", path, status=status)
        if "html" not in ctype.lower():
            continue
        parser = _Links()
        try:
            parser.feed(body.decode("utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            pass
        for href in parser.hrefs:
            nxt = urllib.parse.urljoin(url, href)
            if _dest(nxt) == base_host:
                p = urllib.parse.urlparse(nxt).path or "/"
                if p not in seen:
                    queue.append(p)
        for form in parser.forms:
            act = urllib.parse.urljoin(url, form["action"]) if form["action"] else url
            if _dest(act) == base_host:
                record(form["method"], urllib.parse.urlparse(act).path or "/", params=form["params"])

    print(json.dumps({"tool": "web_discover", "base_url": base,
                      "endpoints": list(endpoints.values()), "pages_fetched": fetched}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
