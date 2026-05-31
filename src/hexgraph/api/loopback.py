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
_LOOPBACK_NAMES = {"localhost"}


def is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_loopback(host: str) -> None:
    """Raise unless `host` is loopback or the override env is set (warn even then)."""
    if is_loopback(host):
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
