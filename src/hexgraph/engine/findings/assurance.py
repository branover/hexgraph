"""The two standards of "verified" (docs/design/design-verification-oracles.md).

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
# The closed precondition vocabulary — the single source the reachability tool's schema enum
# and meta_get_schemas both read, so they can't drift from these constants.
PRECONDITIONS = (UNAUTHENTICATED, REQUIRES_CREDENTIALS, UNSPECIFIED)

# Scope of a DYNAMIC test — the crux of "lab-confirmed" vs "reachable in the deployed system":
HARNESS = "harness"        # the code was executed in ISOLATION (a binary/fuzz harness) → code_present
ENTRYPOINT = "entrypoint"  # the trigger went through the LIVE DEPLOYED input boundary → input_reachable

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


# Findings carrying a vuln claim must document AT LEAST the floor; recon/annotation don't.
_VULN_FINDING_TYPES = {"vulnerability", "poc", "fuzz_crash", "harness", "verified", "other"}


def assurance_of(evidence: dict | None) -> dict | None:
    """The finding's assurance triple, if any. Canonical location is `evidence.extra.assurance`;
    a PoC also nests it under `evidence.extra.verification.assurance` (verify_poc) — read both so
    callers have one accessor regardless of which path produced the finding."""
    extra = (evidence or {}).get("extra") or {}
    return extra.get("assurance") or ((extra.get("verification") or {}).get("assurance"))


def default_for(finding_type: str | None) -> dict | None:
    """The FLOOR assurance to stamp on a finding that carries a vuln claim but recorded none —
    so every flaw documents at least the minimum level reached. A finding with no dynamic trigger
    and no argued reachability is, by default, only `code_present` / `static` / `unspecified`.
    Returns None for non-vuln findings (recon/annotation), which make no exploitability claim."""
    if (finding_type or "vulnerability") in _VULN_FINDING_TYPES:
        return assurance(CODE_PRESENT, STATIC, UNSPECIFIED)
    return None


def compact_assurance(a: dict | None) -> dict | None:
    """The compact triple {standard, method, precondition} (+ precondition_inferred when set) for
    list/return surfaces — so an agent sees the rung without reading the full finding evidence.
    Drops the verbose `detail` prose. Returns None when there is no assurance."""
    if not a:
        return None
    out = {"standard": a.get("standard"), "method": a.get("method"),
           "precondition": a.get("precondition")}
    if a.get("precondition_inferred"):
        out["precondition_inferred"] = True
    return out


def summary_line(a: dict | None) -> str:
    """One-line `standard / method / precondition` for reasoning text / display."""
    if not a:
        return "—"
    s = f"{a.get('standard')} / {a.get('method')} / {a.get('precondition')}"
    return s + " (inferred precondition)" if a.get("precondition_inferred") else s


# The assurance ladder, weakest → strongest — advertised to agents (SKILL / get_schemas) so they
# document the floor and STRIVE for the ceiling. (The middle two are not strictly comparable: one
# proves the bug fires but not that it's reached; the other argues reach but not that it fires.)
LADDER = [
    f"{CODE_PRESENT} / {STATIC}     — 'looks vulnerable': observed in decompilation/pattern, NOT executed. May be a false positive. The FLOOR.",
    f"{CODE_PRESENT} / {DYNAMIC}    — LAB-CONFIRMED: the bug was fired by executing the code in isolation (a harness/fuzzer). Proven real; the production input path is NOT established (which ≠ unreachable — it may exist directly or via composition). Strictly beats the static guess.",
    f"{INPUT_REACHABLE} / {STATIC}  — a source→sink path from a real input boundary is ARGUED over the graph; not triggered.",
    f"{INPUT_REACHABLE} / {DYNAMIC} — triggered END-TO-END through the live deployed input boundary (the running service's real input). STRONGEST: reached AND fires.",
]


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
    """Derive the assurance triple for a `verify_poc` result — distinguishing the SCOPE of the
    dynamic test, which is the crux of "lab-confirmed code bug" vs "reachable in the real system":

      - **entrypoint** scope — the trigger fired through the LIVE DEPLOYED input boundary (the
        running service's real network/socket input: a web/tcp surface). That establishes
        `input_reachable` (reached AND fired).
      - **harness** scope — the bug was PROVEN by executing the code in ISOLATION (a binary run in
        the sandbox, fed crafted argv/stdin directly). That establishes `code_present` *dynamically*
        — the flaw is real (not a static guess), but the production input path is NOT established
        (which does not mean none exists — it may be reachable directly or via composition with
        other bugs / unexpected state). Strictly better than `code_present/static` ("looks
        vulnerable"), strictly weaker than triggering it through the real input boundary.

    A live web/tcp surface ⇒ entrypoint; an isolated binary exec ⇒ harness; override with
    `spec["scope"]` ("entrypoint"/"harness") when the agent justifies it (e.g. a CGI invoked
    exactly as the httpd would). An unverified PoC establishes neither standard (`unconfirmed`)."""
    if not bool(verification.get("verified")):
        return assurance(UNCONFIRMED, DYNAMIC, UNSPECIFIED)

    declared_scope = (spec or {}).get("scope")
    if declared_scope in (HARNESS, ENTRYPOINT):
        scope = declared_scope
    else:
        scope = ENTRYPOINT if (is_web or is_tcp) else HARNESS  # live surface vs isolated exec

    if scope == HARNESS:
        # Proven-real by lab execution; production input path not established.
        return assurance(CODE_PRESENT, DYNAMIC, UNSPECIFIED,
                         detail="lab-confirmed: the code was executed in isolation and the bug "
                                "fired; the production input path is not established")

    # entrypoint scope → triggered through the live deployed input boundary
    declared = (spec or {}).get("precondition")
    if declared:
        precondition, inferred = str(declared), False
    elif is_web:
        precondition, inferred = _infer_web_precondition(spec or {})
    elif is_tcp:
        precondition, inferred = UNAUTHENTICATED, True  # a raw-socket service reached without web auth
    else:
        precondition, inferred = UNSPECIFIED, False
    return assurance(INPUT_REACHABLE, DYNAMIC, precondition, precondition_inferred=inferred,
                     detail="triggered through the live deployed input boundary")


def derive_fuzz_assurance() -> dict:
    """A fuzzing crash executes the vulnerable code via a generated HARNESS that feeds the
    function directly — it PROVES the code is vulnerable (code_present, dynamic, lab-confirmed),
    but bypasses the production input path, so it is NOT input_reachable on its own."""
    return assurance(CODE_PRESENT, DYNAMIC, UNSPECIFIED,
                     detail="lab-confirmed by a fuzzing harness; production input path not established")


def derive_network_fuzz_assurance() -> dict:
    """A NETWORK fuzz crash drops a LIVE service through its real socket input boundary
    (the liveness oracle confirmed the process died and stayed down on the mutated
    message). Unlike a harness crash, the production input path IS the one exercised —
    so this is `input_reachable/dynamic`, the strongest assurance (reached AND fires),
    exactly like a verified live-surface PoC (design §5.6)."""
    return assurance(INPUT_REACHABLE, DYNAMIC, UNSPECIFIED,
                     detail="the live service died on a mutated message sent over its real "
                            "socket — reached and triggered end-to-end through the input boundary")


# ── Precedence on the ladder, so a weaker rung NEVER overwrites a stronger one ──────────────
#
# The ladder (weakest → strongest), per LADDER above. The middle two are NOT strictly
# comparable (one proves the bug FIRES but not that it's REACHED; the other argues REACH but not
# that it fires) — so neither may displace the other. We model that with a partial order:
#
#       code_present/static  <  code_present/dynamic   <  input_reachable/dynamic
#       code_present/static  <  input_reachable/static  <  input_reachable/dynamic
#       code_present/dynamic  ‖  input_reachable/static   (incomparable — keep what's there)
#
# Phase 4 (input_reachable/static) must therefore upgrade ONLY a code_present/static floor; it
# must NEVER downgrade a dynamic claim (code_present/dynamic OR input_reachable/dynamic) — the
# whole point is to ARGUE reach when we couldn't trigger it, not to weaken a real trigger.
_RANK = {
    (CODE_PRESENT, STATIC): 0,
    (CODE_PRESENT, DYNAMIC): 1,
    (INPUT_REACHABLE, STATIC): 1,   # same TIER as code_present/dynamic, but incomparable to it
    (INPUT_REACHABLE, DYNAMIC): 2,
}


def rank(a: dict | None) -> int:
    """Numeric tier of an assurance triple on the ladder (higher = stronger). UNCONFIRMED and
    any unknown standard/method combination rank below the floor (-1). Used for the coarse
    'is this clearly weaker' test; the incomparable middle rungs are disambiguated by
    `_strictly_stronger`."""
    if not a:
        return -1
    return _RANK.get((a.get("standard"), a.get("method")), -1)


def _strictly_stronger(candidate: dict, current: dict) -> bool:
    """True iff `candidate` is strictly above `current` in the PARTIAL order — a real upgrade,
    not a sideways move between the two incomparable middle rungs. A candidate at the same
    numeric tier as the current claim is NOT an upgrade (so input_reachable/static does not
    displace an equal-tier code_present/dynamic, and vice-versa). Because a tier-1 candidate can
    only out-rank a tier-0 current, and a tier-2 candidate out-ranks everything below it, a strict
    numeric increase is both necessary and sufficient — the incomparable pair shares a tier."""
    return rank(candidate) > rank(current)


def merge_assurance(current: dict | None, candidate: dict | None) -> dict | None:
    """The partial-order MERGE of an already-stored assurance with an incoming one: return
    `candidate` ONLY if it is strictly stronger than `current` (a real upgrade, or the first
    record), otherwise keep `current`. NEVER downgrades — a failed/weaker re-verify
    (e.g. `unconfirmed/dynamic`, or an `input_reachable/static` argument) must NOT lower an
    already-stronger stored rung (code_present/dynamic, input_reachable/dynamic). A genuine
    re-confirmation at the SAME or a HIGHER rung is fine: same-tier keeps `current` (the identical
    claim, no change), higher-tier adopts `candidate`. This is the pure-function core the re-verify
    write paths (MCP verify_poc + REST re-verify) and `upgrade_if_stronger` share."""
    if current is None:
        return candidate
    if candidate is not None and _strictly_stronger(candidate, current):
        return candidate
    return current


def upgrade_if_stronger(evidence: dict | None, candidate: dict) -> dict:
    """Record `candidate` as the finding's assurance ONLY if it is strictly stronger than what's
    already there (per the partial order). Mutates and returns `evidence` (creating
    `evidence.extra.assurance`). NEVER downgrades — a dynamic claim (code_present/dynamic or
    input_reachable/dynamic) is preserved against an incoming input_reachable/static. Returns the
    evidence dict so callers can chain. This is the single guard Phase 4 (and any future
    static-rung writer) goes through to stamp a finding."""
    evidence = evidence if isinstance(evidence, dict) else {}
    current = assurance_of(evidence)
    if current is None or _strictly_stronger(candidate, current):
        evidence.setdefault("extra", {})["assurance"] = candidate
    return evidence
