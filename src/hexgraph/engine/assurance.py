"""The two standards of "verified" (docs/design-verification-oracles.md).

A finding's verification is described by an **assurance triple**, so HexGraph differentiates —
and never blurs — *what* is being claimed:

  - `standard`     — `code_present` (the flaw exists in code) vs `input_reachable` (it is
                     reachable/triggerable via user-provided input in normal operation).
  - `method`       — `static` (argued from the graph/decompilation) vs `dynamic` (demonstrated
                     by a live trigger + an unforgeable oracle).
  - `precondition` — the principal/config the reachability claim requires
                     (`unauthenticated` / `requires_credentials` / `unspecified`). "Reachable in
                     normal operation" is meaningless without stating *for whom*.

This module is the single source of truth for that vocabulary and for deriving the triple. It is
recorded in the finding's `evidence.extra` (the DB envelope) — NOT the frozen finding schema.
"""

from __future__ import annotations

# Standards (what is claimed)
CODE_PRESENT = "code_present"        # Standard A — the flaw exists in code
INPUT_REACHABLE = "input_reachable"  # Standard B — reachable/triggerable via user input
UNCONFIRMED = "unconfirmed"          # neither standard established (e.g. a PoC that didn't fire)

# Methods (how it was established)
STATIC = "static"      # argued from the graph / decompilation
DYNAMIC = "dynamic"    # demonstrated by a live trigger + an unforgeable oracle

# Preconditions (the principal/config Standard B requires)
UNAUTHENTICATED = "unauthenticated"
REQUIRES_CREDENTIALS = "requires_credentials"
UNSPECIFIED = "unspecified"

_VALID_STANDARDS = {CODE_PRESENT, INPUT_REACHABLE, UNCONFIRMED}
_VALID_METHODS = {STATIC, DYNAMIC}


def assurance(standard: str, method: str, precondition: str = UNSPECIFIED,
              *, precondition_inferred: bool = False, detail: str | None = None) -> dict:
    """Build a normalized assurance triple. Unknown values pass through (the vocabulary is
    guidance, like the edge schemas) but the canonical strings above should be preferred."""
    out = {"standard": standard, "method": method, "precondition": precondition or UNSPECIFIED}
    if precondition_inferred:
        out["precondition_inferred"] = True
    if detail:
        out["detail"] = detail
    return out


def _infer_web_precondition(spec: dict) -> tuple[str, bool]:
    """Best-effort precondition for a web PoC, returned as (value, inferred?).

    A caller-declared `spec["precondition"]` always wins. Otherwise we make the WEAKEST honest
    inference: only claim `unauthenticated` when the PoC carries no auth artifact at all (a
    single step, no Cookie/Authorization header and no login-looking step); a multi-step flow or
    any auth artifact ⇒ `requires_credentials`; anything ambiguous ⇒ `unspecified`. We never
    *upgrade* to unauthenticated on a guess — overstating "reachable for anyone" is the failure
    mode this whole concept exists to prevent."""
    steps = spec.get("steps") or ([spec["request"]] if spec.get("request") else [])

    def _has_auth_artifact(step: dict) -> bool:
        headers = {str(k).lower() for k in (step.get("headers") or {})}
        if "cookie" in headers or "authorization" in headers:
            return True
        path = str(step.get("path") or "").lower()
        return any(w in path for w in ("login", "auth", "session", "signin"))

    if len(steps) <= 1 and steps and not _has_auth_artifact(steps[0]):
        return UNAUTHENTICATED, True
    if any(_has_auth_artifact(s) for s in steps) or len(steps) > 1:
        return REQUIRES_CREDENTIALS, True
    return UNSPECIFIED, True


def derive_poc_assurance(verification: dict, spec: dict, *, is_web: bool, is_tcp: bool) -> dict:
    """Derive the assurance triple for a `verify_poc` result. A PoC is always a DYNAMIC method
    (it drove a real input boundary); a *verified* one establishes `input_reachable` (the trigger
    fired through real input). An unverified PoC establishes neither standard here (a separate
    static finding may still assert `code_present`)."""
    verified = bool(verification.get("verified"))
    standard = INPUT_REACHABLE if verified else UNCONFIRMED

    declared = (spec or {}).get("precondition")
    if declared:
        precondition, inferred = str(declared), False
    elif is_web:
        precondition, inferred = _infer_web_precondition(spec or {})
    elif is_tcp:
        # a raw-socket PoC to a listening service is reached without web auth
        precondition, inferred = UNAUTHENTICATED, True
    else:
        # a binary PoC drives argv/stdin/env directly — "reachability" is the local exec boundary,
        # not a network principal; leave the network precondition unspecified.
        precondition, inferred = UNSPECIFIED, False

    return assurance(standard, DYNAMIC, precondition, precondition_inferred=inferred)
