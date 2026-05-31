"""The Principal seam (v2 P0-5).

Identity of "who is acting." Today HexGraph is single-user local, so there is one
local principal. This seam is where multi-user / enterprise / ACLs attach later
(per-principal entitlements, project ownership) without touching feature code.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str
    name: str
    is_local: bool = True


_LOCAL = Principal(id="local", name="local-user", is_local=True)


def current_principal() -> Principal:
    """The acting principal. Always the local user in v1."""
    return _LOCAL
