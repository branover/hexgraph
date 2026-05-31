#!/usr/bin/env python3
"""Vulnrouter — an intentionally-vulnerable "router admin" web service, for testing
HexGraph's dynamic web-surface analysis (recon / PoC) against a REAL, runnable target.

⚠ DELIBERATELY INSECURE. Runs only in the test container, bound to a local address.
Two planted bugs mirroring the cases HexGraph targets:

  • Auth bypass (CWE-287/697): /api/login compares only the FIRST len(token) bytes of
    the admin secret, so an EMPTY token authenticates. A bypassed session can then read
    /admin/flag, which an unauthenticated request cannot — the differential oracle.
  • Post-auth command injection (CWE-78): /api/diag pings `host` via the shell with no
    sanitisation, and returns ONLY the command's output (no input reflection), so an
    injected command's output proves execution rather than echo.

Stdlib only. Secrets come from the environment (ADMIN_TOKEN, ROUTER_FLAG).
"""

from __future__ import annotations

import os
import subprocess
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "s3cret-admin-token-not-guessable")
ROUTER_FLAG = os.environ.get("ROUTER_FLAG", "ROUTER-FLAG-7Q2X")
_SESSIONS: set[str] = set()


def _check_token(supplied: str) -> bool:
    # BUG: compares only len(supplied) bytes — an empty/short prefix authenticates.
    return ADMIN_TOKEN[: len(supplied)] == supplied


class Handler(BaseHTTPRequestHandler):
    server_version = "Orbweaver-httpd/1.0"

    def log_message(self, *a):  # quiet
        pass

    def _send(self, code: int, body: str, ctype: str = "text/plain", cookie: str | None = None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", f"session={cookie}; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def _session(self) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            if part.strip().startswith("session="):
                return part.strip()[len("session="):]
        return None

    def _form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return {k: v[0] for k, v in parse_qs(body).items()}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, "Orbweaver Router — admin console\n", "text/html")
        elif path == "/admin/flag":
            if self._session() in _SESSIONS:
                self._send(200, f"FLAG={ROUTER_FLAG}\n")        # only an authed session sees this
            else:
                self._send(401, "authentication required\n")
        else:
            self._send(404, "not found\n")

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._form()
        if path == "/api/login":
            if _check_token(form.get("token", "x-not-empty")):
                sid = uuid.uuid4().hex
                _SESSIONS.add(sid)
                self._send(200, "login ok\n", cookie=sid)
            else:
                self._send(401, "bad token\n")
        elif path == "/api/diag":
            if self._session() not in _SESSIONS:
                self._send(401, "authentication required\n")
                return
            host = form.get("host", "127.0.0.1")
            # BUG: shell command injection; returns only the command output.
            try:
                out = subprocess.run(f"ping -c1 -W1 {host}", shell=True, capture_output=True,
                                     text=True, timeout=10).stdout
            except subprocess.TimeoutExpired:
                out = "timeout\n"
            self._send(200, out)
        else:
            self._send(404, "not found\n")


def main() -> int:
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
