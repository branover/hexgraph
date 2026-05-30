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
class AnalysisPolicy:
    static_only: bool = True
    allow_execution: bool = False  # never run the target (v1)
    allow_network: bool = False    # sandboxes run --network none (v1)


def current_policy() -> AnalysisPolicy:
    # Defaults are static-only. Future dynamic/fuzz profiles return a policy with
    # allow_execution=True and pair it with a DynamicExecutor.
    return AnalysisPolicy()


def assert_allows_execution(policy: AnalysisPolicy | None = None) -> None:
    policy = policy or current_policy()
    if not policy.allow_execution:
        raise PolicyViolation("analysis policy is static-only; executing the target is not permitted")
