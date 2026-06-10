"""Reveal hidden targets into the curated graph.

`unpack_firmware` registers each firmware ELF child HIDDEN (`visible=False`): it's
recorded, searchable, and addressable, but contributes nothing to the curated
graph — recon ENRICHED it (metadata + a recon Observation) without materializing
nodes. Revealing a target flips `visible=True` and materializes its recon nodes
from the ALREADY-STORED facts (no re-run). Hiding a revealed target restores the
hidden state.

Two granularities (both mirrored to REST + MCP + the UI):
  * `set_visible(target, visible)` — one target.
  * `reveal_dir(firmware, prefix)`  — every hidden firmware child whose rootfs path
    is under `prefix` ("reveal all ELFs under /usr/sbin").
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target


def _recon_facts(session: Session, project: Project, target: Target) -> dict:
    """The recon facts to materialize nodes from on reveal. Prefer the full payload
    of the recon Observation (the authoritative, uncapped facts); fall back to the
    facts already folded onto the target's metadata (imports/strings/…)."""
    from hexgraph.db.models import Observation
    from hexgraph.engine.observations import get_observation

    obs = (
        session.query(Observation)
        .filter(
            Observation.target_id == target.id,
            Observation.result_kind == "recon",
            Observation.status == "ok",
        )
        .order_by(Observation.created_at.desc())
        .first()
    )
    if obs is not None:
        full = get_observation(session, obs.id)
        payload = (full or {}).get("payload")
        if isinstance(payload, dict):
            return payload
    return target.metadata_json or {}


def _materialize_on_reveal(session: Session, project: Project, target: Target) -> None:
    """Bring a just-revealed target's enrichment into the curated graph: its recon
    symbol/string nodes (from stored facts) plus the optional Ghidra enrichment that
    was deferred while it was hidden. Idempotent (materialize_* dedups)."""
    from hexgraph.engine.re.recon import materialize_recon_nodes

    facts = _recon_facts(session, project, target)
    materialize_recon_nodes(session, project.id, target, facts)
    # Mirror analyze_target's optional Ghidra enrich pass (skipped while hidden).
    try:
        from hexgraph.engine.re.ghidra import enrich_enabled, enrich_target

        if enrich_enabled() and (facts.get("kind") in ("executable", "shared_library")):
            enrich_target(session, project, target)
    except Exception:  # noqa: BLE001 — enrichment is an optional bonus pass
        pass


def set_visible(session: Session, project_id: str, target_id: str, visible: bool) -> dict:
    """Reveal (visible=True) or re-hide (visible=False) one target. Revealing
    materializes its recon nodes from the already-stored facts (no re-run). Returns
    {target_id, visible, materialized} (materialized = nodes were (re)materialized)."""
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        raise ValueError("target not found in project")
    was_visible = t.visible
    t.visible = visible
    materialized = False
    if visible and not was_visible:
        project = session.get(Project, project_id)
        _materialize_on_reveal(session, project, t)
        materialized = True
    session.flush()
    return {"target_id": t.id, "name": t.name, "visible": t.visible, "materialized": materialized}


def reveal_dir(session: Session, project_id: str, firmware_target_id: str, prefix: str) -> dict:
    """Reveal every HIDDEN child of a firmware whose rootfs-relative name (path) is
    under `prefix` (a directory prefix like "usr/sbin" or "/usr/sbin"). Materializes
    each revealed child's recon nodes. Returns {firmware_target_id, prefix, revealed,
    target_ids}. Already-visible children are left untouched."""
    fw = session.get(Target, firmware_target_id)
    if fw is None or fw.project_id != project_id:
        raise ValueError("firmware target not found in project")

    norm = (prefix or "").strip().strip("/")
    project = session.get(Project, project_id)

    def _under(rel: str) -> bool:
        # Match the dir prefix: the whole tree ("" matches all), an exact dir
        # ("usr/sbin" matches "usr/sbin/telnetd"), or an exact file path. Avoid a
        # bare substring match ("usr/sb" must NOT match "usr/sbnet/x").
        rel = (rel or "").strip("/")
        return norm == "" or rel == norm or rel.startswith(norm + "/")

    # F08: a binary deduped to a shared target has no row of its own at its alternate path(s) —
    # only a `dedup_of` ref in the manifest. Build the path→target map from the manifest so
    # revealing a directory still reveals every target that lives under it, including via a deduped
    # path whose keeper's own name sits in a different directory.
    fs = (fw.metadata_json or {}).get("filesystem") or {}
    ids_under_prefix = {
        f.get("child_target_id") for f in fs.get("files", [])
        if f.get("child_target_id") and _under(f.get("rel"))
    }
    children = (
        session.query(Target)
        .filter(Target.project_id == project_id, Target.parent_id == firmware_target_id)
        .all()
    )
    revealed_ids: list[str] = []
    for c in children:
        if c.visible:
            continue
        if c.id in ids_under_prefix or _under(c.name):   # any manifest path under prefix, or its own name
            c.visible = True
            _materialize_on_reveal(session, project, c)
            revealed_ids.append(c.id)
    session.flush()
    return {
        "firmware_target_id": firmware_target_id,
        "prefix": prefix,
        "revealed": len(revealed_ids),
        "target_ids": revealed_ids,
    }
