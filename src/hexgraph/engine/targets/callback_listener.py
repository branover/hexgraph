"""Bounded local callback listener — the INGRESS mirror of the bounded-egress tier.

The `callback` oracle (docs/design/design-verification-oracles.md §1) proves a *blind* vuln —
blind command-injection, SSRF, blind RCE, OOB exfil — by having HexGraph stand up a small
listener the target can reach, minting a per-run token (`{{CALLBACK}}` = host:port + a nonce
path), substituting it into the PoC like `{{NONCE}}`, running the exploit, and confirming the
listener received a hit carrying the nonce. Receiving the token is unforgeable proof the
injected code/SSRF ran, even with ZERO reflected output: the model never controls the listener
and cannot fabricate a connection to it from outside.

**Policy-seam placement (the doc's open question — decided here).** The listener is the
*ingress* mirror of bounded egress, so it lives under the SAME policy discipline:

  - it binds ONLY to a loopback/private address (`policy._host_is_local`), never `0.0.0.0`/
    a public IP — the same structural containment as `local_network_scope`;
  - it is gated: a `callback` oracle requires the bounded-network tier (`features.network`),
    asserted by the caller via `assert_allows_egress` exactly like every other live-target
    tool, so it is never reachable in the static-only default;
  - every hit is audited to `EgressEvent` (allowed/denied) — a complete ingress log.

**Listener PLACEMENT for the two reachable cases:**

  - **Local target (implemented + integration-tested).** A host-side listener bound to a
    loopback/private host the target can already reach (the same host the web/tcp/remote
    channel egresses to). For a local web/tcp/remote surface — or the integration test's fake
    target process — this is directly reachable.
  - **Rehosted firmware (mechanism shipped, live netns validation deferred).** The emulated
    device runs inside the FirmAE/qemu container's network namespace, so a host-loopback bind
    is NOT on the device's network. The decided placement is a SIDECAR: bind the listener
    inside the emulator container's netns on the device-facing gateway IP (the address the
    device already routes to its host), reached by running the listener thread joined to that
    netns — the ingress analogue of `run_channel_probe(net_container=...)`. We expose
    `bind_host` so the caller can pass that gateway IP; a fully-validated rehost-netns callback
    needs a cooperative firmware whose exploit can dial back, so end-to-end live validation is
    a documented follow-up. The local mechanism (this module) is the must-have and is proven by
    a real loopback integration test.

Stdlib only, bounded: one short-lived TCP listener per verification, a hard wall-clock wait,
torn down in a `finally`. No target bytes ever run here — this is HexGraph's own socket.
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
from dataclasses import dataclass, field

from hexgraph.policy import PolicyViolation, _host_is_local

# How a callback token is spelled in a PoC spec (mirrors NONCE_PLACEHOLDER).
CALLBACK_PLACEHOLDER = "{{CALLBACK}}"

# Bounded read per connection: enough to capture an HTTP request line + a few headers (so an
# SSRF GET /<nonce> or a `wget http://host:port/<nonce>` callback is recorded) without letting
# a chatty/hostile client stream unbounded data into our process.
_MAX_HIT_BYTES = 8192


@dataclass
class CallbackHit:
    """One inbound connection the listener accepted, with the bytes it sent (bounded)."""
    data: str
    peer: str
    at: float = field(default_factory=time.time)


class CallbackListener:
    """A bounded, loopback/private-only TCP listener for one verification run.

    Usage:
        with CallbackListener(host="127.0.0.1") as cb:
            token = cb.token()                 # host:port + /<nonce> path
            ...substitute {{CALLBACK}} = token, run the exploit...
            hit = cb.wait(timeout=10)          # the hit carrying the nonce, or None
    """

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0) -> None:
        # Fail-closed: refuse to ever bind to a non-local address. This is the ingress
        # mirror of local_network_scope's "loopback/private only" rule, enforced HERE so a
        # caller can never stand up a publicly-reachable collaborator.
        if not _host_is_local(host):
            raise PolicyViolation(
                f"callback listener host {host!r} is not loopback/private — the canary "
                "listener is local-only, the ingress mirror of the bounded-egress tier")
        self._host = host
        self._want_port = int(port)
        self._nonce = "cb_" + secrets.token_hex(8)
        self._sock: socket.socket | None = None
        self._hits: list[CallbackHit] = []
        self._hit_event = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.bound_host: str | None = None
        self.bound_port: int | None = None

    # -- lifecycle ---------------------------------------------------------------------
    def start(self) -> "CallbackListener":
        sock = socket.socket(socket.AF_INET6 if ":" in self._host else socket.AF_INET,
                             socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self._host, self._want_port))
        sock.listen(8)
        sock.settimeout(0.25)
        self._sock = sock
        self.bound_host, self.bound_port = self._host, sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, name="hexgraph-callback", daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()  # type: ignore[union-attr]
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.0)
                chunks: list[bytes] = []
                got = 0
                while got < _MAX_HIT_BYTES:
                    try:
                        buf = conn.recv(min(2048, _MAX_HIT_BYTES - got))
                    except (TimeoutError, socket.timeout, OSError):
                        break
                    if not buf:
                        break
                    chunks.append(buf)
                    got += len(buf)
                data = b"".join(chunks).decode("utf-8", "replace")
                peer = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
                self._hits.append(CallbackHit(data=data, peer=peer))
                self._hit_event.set()
                # Best-effort 200 so an HTTP-flavoured callback (SSRF / wget) doesn't error.
                try:
                    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
                except OSError:
                    pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def __enter__(self) -> "CallbackListener":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    # -- token + verification ----------------------------------------------------------
    @property
    def nonce(self) -> str:
        return self._nonce

    def token(self) -> str:
        """The `{{CALLBACK}}` value: `host:port/<nonce>`. A blind-cmdi PoC embeds it in a
        `wget`/`curl`/`nc`; an SSRF PoC points the server at `http://<token>`. The nonce path
        is what makes a received hit attributable to THIS run (and unforgeable)."""
        return f"{self.bound_host}:{self.bound_port}/{self._nonce}"

    def url(self) -> str:
        return f"http://{self.bound_host}:{self.bound_port}/{self._nonce}"

    def wait(self, timeout: float) -> CallbackHit | None:
        """Block up to `timeout`s for a hit carrying our nonce; return it (or None). Bounded —
        the verifier never waits indefinitely. A hit WITHOUT the nonce (stray connection) does
        not count: only the per-run nonce proves it was our injected callback."""
        deadline = time.time() + max(0.0, float(timeout))
        while time.time() < deadline:
            if self._hit_event.wait(timeout=min(0.25, max(0.0, deadline - time.time()))):
                hit = next((h for h in self._hits if self._nonce in h.data), None)
                if hit is not None:
                    return hit
                self._hit_event.clear()  # only stray hits so far; keep waiting
        # final check (a hit may have landed in the last slice)
        return next((h for h in self._hits if self._nonce in h.data), None)

    @property
    def hits(self) -> list[CallbackHit]:
        return list(self._hits)
