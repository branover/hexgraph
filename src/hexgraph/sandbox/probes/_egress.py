#!/usr/bin/env python3
"""Centralized bounded-egress allowlist enforcement for the egress probes — the single
chokepoint every network-touching probe (http/tcp/surface/web_discover/remote) shares.

This is **defense-in-depth for HexGraph's OWN probe code**, not target-byte containment:
the egress container runs OUR network-client probes (with `--network bridge`), never the
hostile target's bytes. Without this, each probe re-implemented its own ad-hoc
`dest in allow` string check, so a NEW probe (or an unsuppressed redirect / DNS mismatch)
that forgot the check would get unconfined L3 egress. This module makes the app-layer
allowlist robust-by-construction in two layers:

  1. `ensure_allowed(host, port, allow)` — the explicit pre-connect check each probe still
     calls (preserving its existing `{"error": "destination not in allowlist"}` response).
  2. `install_socket_guard(allow)` — the can't-forget BACKSTOP: monkeypatches the stdlib
     TCP connect path so EVERY outbound stream connect is checked against `allow`, even
     one a probe forgot to gate. Raises `EgressBlocked` off-list.

Kernel-level confinement (per-container nftables DROP-default, "Option B") is the real
containment story and is **deferred** — see the "Future hardening" subsection of
`docs/design-dynamic-surfaces.md`. This module is the interim app-layer middle ground.

STDLIB ONLY: this runs inside the sandbox image where the `hexgraph` package is NOT
installed; probes import it as a sibling via `sys.path[0]` (the probes dir).
"""

from __future__ import annotations

import socket


class EgressBlocked(Exception):
    """Raised when an outbound connection's destination is not in the run's allowlist."""


def dest(host, port) -> str:
    """Canonical `"host:port"` string used for allowlist matching.

    Mirrors how the policy scopes build their entries (`f"{host}:{port}"` over the URL's
    *hostname* — already unbracketed for IPv6). We normalize a bracketed IPv6 literal
    (e.g. `"[::1]"`) down to its bare form so a probe-supplied bracketed host matches a
    scope entry built from `urlparse(...).hostname` (which is unbracketed).
    """
    h = "" if host is None else str(host)
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return f"{h}:{port}"


def ensure_allowed(host, port, allow) -> None:
    """Raise `EgressBlocked` unless `dest(host, port)` is in `allow` (a set/iterable of
    canonical `"host:port"` strings). The explicit pre-connect check; probes translate the
    raised exception into their existing error-response shape."""
    if dest(host, port) not in set(allow or ()):
        raise EgressBlocked(f"destination not in allowlist: {dest(host, port)}")


# --- the backstop --------------------------------------------------------------------

_GUARD_ALLOW: set | None = None  # the active allowlist; None until installed
_INSTALLED = False               # idempotency latch — patch the stdlib exactly once
_orig_create_connection = None
_orig_connect = None
_orig_connect_ex = None


def _is_tcp_inet(sock) -> bool:
    """True only for an AF_INET/AF_INET6 SOCK_STREAM socket. We guard ONLY TCP stream
    connects — never UDP, never AF_UNIX, and never the DNS-resolution path — so name
    resolution (getaddrinfo, which itself opens UDP sockets to the resolver) is untouched."""
    try:
        fam = sock.family
        typ = sock.type
    except Exception:  # noqa: BLE001 — anything odd → don't claim it's a guarded TCP socket
        return False
    # `type` can carry SOCK_NONBLOCK/SOCK_CLOEXEC bits on Linux; mask to the base kind.
    base = typ & 0xFF if isinstance(typ, int) else typ
    return fam in (socket.AF_INET, socket.AF_INET6) and base == socket.SOCK_STREAM


def _check_addr(address) -> None:
    """Check a (host, port[, ...]) connect address against the active allowlist. A
    non-tuple/odd address (e.g. an AF_UNIX path str) is left alone — only INET tuples
    carry a host:port we can match."""
    if _GUARD_ALLOW is None:
        return
    if not isinstance(address, (tuple, list)) or len(address) < 2:
        return  # not an inet (host, port) address → not ours to police
    host, port = address[0], address[1]
    if dest(host, port) not in _GUARD_ALLOW:
        raise EgressBlocked(f"socket guard: destination not in allowlist: {dest(host, port)}")


def install_socket_guard(allow) -> None:
    """Monkeypatch the stdlib TCP connect path so every outbound AF_INET/AF_INET6
    SOCK_STREAM connect is checked against `allow`. Idempotent and safe to call once at
    probe startup (a second call just refreshes the allowlist).

    Guards: `socket.create_connection`, `socket.socket.connect`, `socket.socket.connect_ex`.
    Does NOT touch UDP, AF_UNIX, or `getaddrinfo` — DNS resolution flows through unimpeded,
    and the legitimate on-allowlist target connect (incl. the rehost device's private IP)
    is allowed through to the original implementation.
    """
    global _GUARD_ALLOW, _INSTALLED
    global _orig_create_connection, _orig_connect, _orig_connect_ex

    _GUARD_ALLOW = set(allow or ())
    if _INSTALLED:
        return  # already patched; the refreshed _GUARD_ALLOW above is enough

    _orig_create_connection = socket.create_connection
    _orig_connect = socket.socket.connect
    _orig_connect_ex = socket.socket.connect_ex

    def guarded_create_connection(address, *args, **kwargs):
        # create_connection always targets an inet (host, port) → check before connecting.
        _check_addr(address)
        return _orig_create_connection(address, *args, **kwargs)

    def guarded_connect(self, address):
        if _is_tcp_inet(self):
            _check_addr(address)
        return _orig_connect(self, address)

    def guarded_connect_ex(self, address):
        if _is_tcp_inet(self):
            _check_addr(address)
        return _orig_connect_ex(self, address)

    socket.create_connection = guarded_create_connection
    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    _INSTALLED = True


def uninstall_socket_guard() -> None:
    """Restore the original stdlib connect path. A no-op if never installed.

    Irrelevant in the sandbox (each probe is a fresh, disposable process), but essential for
    in-process test isolation: the monkeypatch is global interpreter state, so a test that
    installs the guard must restore it so it can't leak into an unrelated test's connect."""
    global _GUARD_ALLOW, _INSTALLED
    global _orig_create_connection, _orig_connect, _orig_connect_ex
    if not _INSTALLED:
        _GUARD_ALLOW = None
        return
    socket.create_connection = _orig_create_connection
    socket.socket.connect = _orig_connect
    socket.socket.connect_ex = _orig_connect_ex
    _orig_create_connection = _orig_connect = _orig_connect_ex = None
    _GUARD_ALLOW = None
    _INSTALLED = False
