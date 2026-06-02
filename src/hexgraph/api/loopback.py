"""Loopback bind guard (SPEC §1, §7).

The API/UI must bind to 127.0.0.1 only. A startup assertion refuses a
non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1` — and warns loudly
even then. Kept dependency-free (no FastAPI import) so it is unit-testable in
isolation.
"""

from __future__ import annotations

import ipaddress
import os
import sys

OVERRIDE_ENV = "HEXGRAPH_I_KNOW_WHAT_IM_DOING"
# Set inside the official app container (docker/app.Dockerfile + docker-compose.yml). The
# container binds 0.0.0.0 so it can receive traffic Docker forwards from the published port,
# but the host-side loopback guarantee is preserved at the PUBLISH boundary: compose maps
# `127.0.0.1:8765:8765`, so the only thing that can reach the container is the host's own
# loopback. Binding 0.0.0.0 inside that namespace is therefore safe, and this flag lets the
# assertion accept it WITHOUT widening the Host-header allowlist to a wildcard (unlike the
# operator override) — the anti-DNS-rebinding defense stays intact.
CONTAINER_ENV = "HEXGRAPH_IN_CONTAINER"
# The only non-loopback bind the container mode accepts: the "all interfaces" wildcard that
# lets Docker's published-port forwarder reach the service. Any other non-loopback host still
# raises even in container mode (it would imply a deliberate, unguarded external bind).
_CONTAINER_BIND = "0.0.0.0"
_LOOPBACK_NAMES = {"localhost"}


def _in_container_bind(host: str) -> bool:
    """True when we're the official app container binding the published-port wildcard."""
    return host == _CONTAINER_BIND and os.environ.get(CONTAINER_ENV) == "1"


def is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def allowed_hosts(bind_host: str | None = None) -> list[str]:
    """The Host-header allowlist for TrustedHostMiddleware — the primary defense against
    DNS-rebinding (which relies on the victim's browser sending the attacker's foreign Host
    header to 127.0.0.1). We only ever accept loopback names/IPs.

    When the operator has DELIBERATELY bound a non-loopback address (override env set, see
    `assert_loopback`), the served host is no longer loopback, so we widen to a wildcard
    (the operator has explicitly opted out of the local-only posture; TrustedHost can no
    longer be the rebinding defense once exposed to the network). Loopback stays allowed
    regardless so the local UI keeps working."""
    # `testserver` is Starlette's TestClient default Host; harmless to accept (a real
    # rebinding attack carries the attacker's OWN domain, not this fixed literal) and it
    # keeps the in-process API tests working without rewriting their Host header.
    hosts = ["localhost", "127.0.0.1", "[::1]", "::1", "testserver"]
    if bind_host and not is_loopback(bind_host) and os.environ.get(OVERRIDE_ENV) == "1":
        return ["*"]
    return hosts


def _hostname_only(host_header: str) -> str:
    """Extract just the hostname from a Host header, stripping any :port — and handling a
    bracketed IPv6 literal (`[::1]` / `[::1]:8765`), which a naive `split(':')[0]` mangles to
    `[`. A bare (unbracketed) IPv6 literal has multiple colons and no port, so it's returned
    as-is."""
    h = (host_header or "").strip()
    if h.startswith("["):                      # [v6] or [v6]:port
        return h[1:h.index("]")] if "]" in h else h.strip("[]")
    if h.count(":") == 1:                       # name:port or v4:port
        return h.rsplit(":", 1)[0]
    return h                                     # bare hostname/IPv4, or bare IPv6 literal


def host_allowed(host_header: str, bind_host: str | None = None) -> bool:
    """Is this request's Host header permitted? The primary anti-DNS-rebinding defense
    (a rebinding page carries the attacker's OWN domain, not loopback). Parses the host
    correctly (incl. bracketed IPv6) before matching, so `[::1]:8765` is accepted on systems
    where localhost resolves to ::1. Widens to allow-all only on a deliberate non-loopback
    bind (see allowed_hosts)."""
    if "*" in allowed_hosts(bind_host):
        return True
    name = _hostname_only(host_header)
    return name == "testserver" or is_loopback(name)


def assert_loopback(host: str) -> None:
    """Raise unless `host` is loopback, we're the official container binding the published-port
    wildcard (see CONTAINER_ENV), or the operator override is set (warn even then)."""
    if is_loopback(host):
        return
    if _in_container_bind(host):
        # Recognized container mode: 0.0.0.0 inside a namespace whose only ingress is the
        # host-loopback-published port. No warning — this is the supported compose path.
        return
    if os.environ.get(OVERRIDE_ENV) == "1":
        print(
            f"\n*** WARNING: binding HexGraph to NON-LOOPBACK address {host!r} ***\n"
            f"*** This exposes a workbench that handles hostile targets to your network. ***\n"
            f"*** {OVERRIDE_ENV}=1 is set, so proceeding anyway. You have been warned. ***\n",
            file=sys.stderr,
        )
        return
    raise RuntimeError(
        f"refusing to bind to non-loopback address {host!r}. HexGraph is local-only. "
        f"Set {OVERRIDE_ENV}=1 to override (not recommended)."
    )
