"""The `binutils` quick-facts helper (design §3.1, Phase 5A PR 5A-1).

Runs the sandboxed `binutils_probe` over a target — the canonical GNU binutils
(nm / objdump / readelf / strings) — and records its authoritative low-level facts
as a single `binutils_facts` Observation, scoped to the analyzed bytes. There is NO
new seam (these are deterministic facts, not a swappable backend) and NO policy gate
(static, no execution, no network — it rides the existing recon/analysis surface,
exactly like recon).

It does NOT mint nodes. The Observation is the durable substrate; the always-welcome
SUBSET of these facts auto-enriches objects that already exist via the enrichment
extractor registered below (imports → `symbol`/`is_sink`, mitigation flags →
target metadata). Promote what matters into the graph deliberately — the probe feeds
the substrate, it does not re-flood the graph (the Phase O curation rule; it defers
to recon's tight import/string caps).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target
from hexgraph.engine import observations as O

RESULT_KIND = "binutils_facts"

_REUSE_HINT = (
    "binutils facts persist as a binutils_facts Observation on this target; they do NOT "
    "add graph nodes. Check list_observations(target_id) before re-running, and "
    "get_observation(id) for the full payload (symbols/imports/exports/relocations/"
    "sections/mitigations)."
)


def _summary(facts: dict) -> str:
    mit = facts.get("mitigations", {}) or {}
    weak = [k for k in ("nx", "canary", "pie") if mit.get(k) is False]
    relro = mit.get("relro")
    if relro in ("none", "partial"):
        weak.append(f"relro={relro}")
    weak_str = f"weak: {', '.join(weak)}" if weak else "standard mitigations"
    return (f"{facts.get('elf_type') or 'ELF'} {facts.get('machine') or ''}: "
            f"{len(facts.get('imports', []))} imports, {len(facts.get('exports', []))} exports, "
            f"{len(facts.get('sections', []))} sections; {weak_str}").strip()


def collect_binutils_facts(
    session: Session,
    project: Project,
    target: Target,
    *,
    source: str = "agent",
    runner=None,
) -> dict:
    """Run `binutils_probe` in the sandbox and record a `binutils_facts` Observation.

    Returns a dict with the raw `facts`, the recorded `observation_id`, a `cached`
    flag (the call dedups by content_hash, so a repeat returns the prior row), and the
    standing reuse hint — or `{"error": ...}` when the sandbox is down or the artifact
    isn't an analyzable ELF. Creates ZERO graph nodes; enrichment of ALREADY-existing
    nodes fires automatically inside record_observation.
    """
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import SandboxError, docker_available

    if runner is None:
        if not docker_available():
            return {"error": "binutils facts unavailable (Docker/sandbox not running)"}
        runner = get_executor()
    if not str(target.path or "").strip():
        return {"error": "this target has no byte artifact (a Channel-reached surface has no ELF to inspect)"}
    try:
        facts = runner.run_json_probe("binutils_probe.py", target.path)
    except SandboxError as exc:
        # A non-ELF / unreadable artifact exits non-zero with an error JSON; the runner
        # surfaces that reason. Return it rather than raising so the tool call survives.
        return {"error": f"binutils facts failed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"binutils facts failed: {exc}"}

    obs, cached = O.record_observation(
        session,
        project_id=project.id,
        target_id=target.id,
        source=source,
        tool="binutils_facts",
        args={},
        result_kind=RESULT_KIND,
        payload=facts,
        summary=_summary(facts),
        content_hash=O.content_hash_for(target),
    )
    # The dangerous-import `is_sink` enrichment fired inside record_observation (the
    # shared extractor). Mitigation flags are the TARGET analogue — fold them onto the
    # target's metadata (idempotent; a re-apply is a no-op).
    apply_mitigations_to_target(target, facts)
    return {
        "facts": facts,
        "observation_id": obs.id if obs is not None else None,
        "cached": cached,
        "reuse_hint": _REUSE_HINT,
    }


# --- the always-welcome target-metadata enrichment (design §3.1, §5.4) --------
# The `is_sink` enrichment for dangerous imports rides the SHARED extractor registered
# in engine.enrichment ("binutils_facts" → DANGEROUS_IMPORTS path), so it fires
# automatically inside record_observation. Mitigation flags describe the TARGET, not a
# node, so they don't pass through the node-fact index — they're recorded here instead.

def apply_mitigations_to_target(target: Target, facts: dict) -> bool:
    """Record the always-welcome mitigation flags on the TARGET's metadata_json (the
    target analogue of the symbol enrichment — a mitigation describes the whole binary,
    not a node). Idempotent: returns True only if anything actually changed, so a
    re-apply is a no-op. Never overwrites a value with None."""
    mit = facts.get("mitigations") if isinstance(facts, dict) else None
    if not isinstance(mit, dict):
        return False
    meta = dict(target.metadata_json or {})
    existing = dict(meta.get("mitigations") or {})
    merged = dict(existing)
    for k, v in mit.items():
        if v is not None and merged.get(k) != v:
            merged[k] = v
    if merged == existing:
        return False
    meta["mitigations"] = merged
    target.metadata_json = meta
    return True
