"""The analysis-policy seam (v2 P0-4).

v1 is static-only: targets are never executed, sandboxes have no network. This
policy makes that an explicit, enforced setting rather than a scattered
assumption — so future dynamic/emulated execution and fuzzing land by flipping a
policy + selecting a capable executor, not by unwinding hard-coded behavior.
"""

from __future__ import annotations

from dataclasses import dataclass


class PolicyViolation(RuntimeError):
    """An operation was attempted that the active analysis policy forbids."""


@dataclass(frozen=True)
class NetworkScope:
    """The ONLY destinations egress is permitted to. Empty == deny-all (the only
    value any tier produces today; bounded scopes arrive with the network phase —
    see docs/design-dynamic-surfaces.md)."""
    allow: frozenset[str] = frozenset()
    rationale: str = ""


# Graduated, opt-in tiers (docs/design-dynamic-surfaces.md). Each is derived ONLY
# from features.* — there is no settable "tier" knob — so enabling a capability is
# the sole way to raise it, and any settings error fails closed at tier 0.
TIER_STATIC_ONLY = 0       # no exec, no network (default)
TIER_SANDBOXED_EXEC = 1    # exec (PoC/fuzzing), still --network none


@dataclass(frozen=True)
class AnalysisPolicy:
    static_only: bool = True
    allow_execution: bool = False  # never run the target (v1)
    allow_network: bool = False    # sandboxes run --network none (v1)
    tier: int = TIER_STATIC_ONLY
    # The bounded egress scope for this policy. None == --network none (tiers 0,1).
    network: NetworkScope | None = None


def current_policy() -> AnalysisPolicy:
    # Static-only by default. Enabling fuzzing/PoC in Settings flips this to the
    # sandboxed-exec tier that permits execution (still --network none, capped,
    # timed). This is the single, explicit place the static-only invariant is
    # relaxed. No tier grants network egress yet (network stays None).
    try:
        from hexgraph import settings

        if settings.get("features.fuzzing.enabled") or settings.get("features.poc.enabled"):
            return AnalysisPolicy(static_only=False, allow_execution=True, allow_network=False,
                                  tier=TIER_SANDBOXED_EXEC)
    except Exception:  # noqa: BLE001 — a settings problem must never widen the policy
        pass
    return AnalysisPolicy()


def assert_allows_execution(policy: AnalysisPolicy | None = None) -> None:
    policy = policy or current_policy()
    if not policy.allow_execution:
        raise PolicyViolation("analysis policy is static-only; executing the target is not permitted")


def egress_scope(policy: AnalysisPolicy | None = None) -> NetworkScope | None:
    return (policy or current_policy()).network


def assert_allows_egress(dest: str | None = None, policy: AnalysisPolicy | None = None) -> None:
    """Gate any outbound connection to a live target. Fails closed: with no network
    scope (every tier today) it always raises. Bounded scopes arrive with the
    network phase; feature code calls this, never branches on tier."""
    policy = policy or current_policy()
    scope = policy.network
    if scope is None or (dest is not None and dest not in scope.allow):
        raise PolicyViolation(
            "analysis policy does not permit network egress to "
            f"{dest!r}" if dest else "analysis policy does not permit network egress")
