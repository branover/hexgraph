"""The Entitlements seam (v2 P0-3).

Answers "is this feature available to this principal?" The open-source, BYOK build
grants everything. This is where a future paid-credits / license backend (keyed on
a HexGraph account + `HEXGRAPH_API_KEY`) returns a restricted set — so paid
features land by *asking the seam*, never by branching on a license flag inline.
"""

from __future__ import annotations

from hexgraph.principal import Principal, current_principal


class EntitlementError(PermissionError):
    """The active plan does not include the requested feature."""


class Entitlements:
    """Local/BYOK entitlements: everything is allowed."""

    name = "local"

    def allows(self, feature: str, principal: Principal | None = None) -> bool:
        return True


def current_entitlements() -> Entitlements:
    return Entitlements()


def require(feature: str, principal: Principal | None = None) -> None:
    """Raise EntitlementError if `feature` is not entitled. No-op in the local build."""
    p = principal or current_principal()
    if not current_entitlements().allows(feature, p):
        raise EntitlementError(f"feature not available on this plan: {feature}")
