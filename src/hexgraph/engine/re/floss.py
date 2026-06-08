"""The FLOSS string-deobfuscation helper (design §3.2, Phase 5A PR 5A-2).

Runs the sandboxed `floss_probe` over a target — the FLARE FLOSS deobfuscator — to
recover the strings a plain `strings` pass misses: STACK strings, TIGHT strings, and
strings produced by a DECODE routine FLOSS lightly emulates. It records the recovered
set as a single `floss_strings` Observation, scoped to the analyzed bytes.

There is NO new seam (FLOSS is singular — nothing else deobfuscates strings) and NO
policy gate: FLOSS emulates the decode routines IN-PROCESS inside the sandbox (vivisect,
never native target execution, no network), the same posture as `assert_allows_emulation`.
It raises NO policy tier, so `policy.py` is untouched. FLOSS rides the static surface
UNGATED, like recon and binutils — it relaxes no sandbox/exec/egress boundary, so there
is no `features.floss` toggle; it is always available wherever the sandbox is up.

Unlike binutils, FLOSS recovers *results*, not always-welcome facts about objects that
already exist, so it registers NO enrichment extractor and mints ZERO nodes. The
Observation is the durable substrate; the agent PROMOTES the interesting recovered
strings to `string` nodes deliberately. We do not auto-flood the graph (the Phase O
curation rule).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.engine import observations as O

RESULT_KIND = "floss_strings"

# FLOSS's minimum-string-length knob (the one agent-influenced parameter, design §2.8).
# Mirror the probe's clamp HERE too, so the Observation dedup key is the EFFECTIVE value:
# raw inputs that clamp to the same floor (or None vs the explicit default) are the SAME
# slow pass and must not record duplicate Observations / re-run FLOSS.
_MIN_LEN_FLOOR = 4
_MIN_LEN_CEIL = 64
_DEFAULT_MIN_LEN = 4


def effective_min_length(min_length: int | None) -> int:
    """The min_length actually used: None -> default, else clamped to [floor, ceil]
    (matching floss_probe). Used for both the probe arg and the dedup/cache key, so
    equivalent requests resolve to one slow pass."""
    if min_length is None:
        return _DEFAULT_MIN_LEN
    try:
        return max(_MIN_LEN_FLOOR, min(_MIN_LEN_CEIL, int(min_length)))
    except (TypeError, ValueError):
        return _DEFAULT_MIN_LEN


_REUSE_HINT = (
    "FLOSS results persist as a floss_strings Observation on this target; they do NOT add "
    "graph nodes. Check list_observations(target_id) before re-running (FLOSS is slow), and "
    "get_observation(id) for the full payload (stack/tight/decoded/static strings). Promote "
    "the interesting recovered strings to string nodes deliberately."
)


def _summary(facts: dict) -> str:
    c = facts.get("counts", {}) or {}
    degraded = " (degraded: static-only, non-PE)" if facts.get("degraded") else ""
    return (f"FLOSS: {c.get('stack_strings', 0)} stack, {c.get('tight_strings', 0)} tight, "
            f"{c.get('decoded_strings', 0)} decoded, {c.get('static_strings', 0)} static "
            f"strings{degraded}").strip()


def collect_floss_strings(
    session: Session,
    project: Project,
    target: Target,
    *,
    min_length: int | None = None,
    source: str = "agent",
    runner=None,
) -> dict:
    """Run `floss_probe` in the sandbox and record a `floss_strings` Observation.

    Returns a dict with the raw `facts`, the recorded `observation_id`, a `cached` flag
    (the call dedups by content_hash + min_length, so a repeat returns the prior row), and
    the standing reuse hint — or `{"error": ...}` when the sandbox is down or the artifact
    isn't analyzable. Creates ZERO graph nodes and registers NO enrichment extractor (FLOSS
    recovers results, not always-welcome facts).

    `min_length` is the single optional, validated agent knob (design §2.8) — FLOSS's
    minimum string length, clamped in the probe; everything else about the invocation is
    fixed by HexGraph.
    """
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import SandboxError, docker_available

    if runner is None:
        if not docker_available():
            return {"error": "FLOSS unavailable (Docker/sandbox not running)"}
        runner = get_executor()
    if not str(target.path or "").strip():
        return {"error": "this target has no byte artifact (a Channel-reached surface has no file to inspect)"}

    eff_min_length = effective_min_length(min_length)
    extra_args = ["--min-length", str(eff_min_length)]
    try:
        facts = runner.run_json_probe("floss_probe.py", target.path, extra_args=extra_args)
    except SandboxError as exc:
        # A non-analyzable / unreadable artifact exits non-zero with an error JSON; the
        # runner surfaces that reason. Return it rather than raising so the tool survives.
        return {"error": f"FLOSS failed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"FLOSS failed: {exc}"}

    if isinstance(facts, dict) and facts.get("error"):
        return {"error": f"FLOSS failed: {facts['error']}"}

    # Dedup key: the analyzed bytes AND the EFFECTIVE min_length (clamped above) — so a
    # different floor is a distinct pass, but raw values that clamp to the same floor (and
    # None vs the explicit default) dedup to ONE slow pass instead of re-running FLOSS.
    args = {"min_length": eff_min_length}
    obs, cached = O.record_observation(
        session,
        project_id=project.id,
        target_id=target.id,
        source=source,
        tool="floss_strings",
        args=args,
        result_kind=RESULT_KIND,
        payload=facts,
        summary=_summary(facts),
        content_hash=O.content_hash_for(target),
    )
    return {
        "facts": facts,
        "observation_id": obs.id if obs is not None else None,
        "cached": cached,
        "reuse_hint": _REUSE_HINT,
    }
