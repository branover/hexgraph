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


def _materialize_on_reveal(session: Session, project: Project, target: Target) -> bool:
    """Bring a just-revealed target's enrichment into the curated graph: its recon
    symbol/string nodes (from stored facts — fast, synchronous) plus the optional Ghidra
    enrichment that was deferred while it was hidden — kicked off DETACHED (see
    `_ensure_ghidra_enrichment`), not run inline. A cold headless Ghidra full-analysis can
    take many minutes per binary; `reveal_dir` can reveal a dozen+ targets in one call, and
    running that many sequentially inline turned a single MCP call into a multi-hour block —
    the same class of bug `promote_file` had (see engine.targets.filesystem._ensure_analysis).
    Idempotent (materialize_* dedups). Returns True if Ghidra enrichment was (newly) queued."""
    from hexgraph.engine.re.recon import materialize_recon_nodes

    facts = _recon_facts(session, project, target)
    materialize_recon_nodes(session, project.id, target, facts)
    if facts.get("kind") not in ("executable", "shared_library"):
        return False
    try:
        return _ensure_ghidra_enrichment(session, project, target)
    except Exception:  # noqa: BLE001 — enrichment is an optional bonus pass
        return False


def _ensure_ghidra_enrichment(session: Session, project: Project, target: Target) -> bool:
    """Kick off `target`'s optional Ghidra enrichment (`engine.re.ghidra.enrich_target`) in a
    DETACHED background OS process if it isn't already done or in flight — same pattern as
    `engine.targets.filesystem._ensure_analysis`. Safe to call repeatedly: no-ops once
    enriched (marked by the `ghidra_enrich` task on success) or while a `ghidra_enrich` Task
    for this target is still queued/running, and self-heals a task that died before finishing
    instead of leaving the target silently unenriched forever. Returns True if a task was
    (newly) queued."""
    from hexgraph.engine.re.ghidra import enrich_enabled

    if not enrich_enabled():
        return False
    if (target.metadata_json or {}).get("ghidra_enriched"):
        return False
    from hexgraph.db.models import Task, TaskStatus

    already_running = (
        session.query(Task)
        .filter(Task.target_id == target.id, Task.type == "ghidra_enrich",
                Task.status.in_((TaskStatus.queued, TaskStatus.running)))
        .first()
    )
    if already_running is not None:
        return False

    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import spawn_detached_task
    from sqlalchemy.orm.attributes import flag_modified

    task = create_task(session, project=project, target_id=target.id, type="ghidra_enrich")
    meta = dict(target.metadata_json or {})
    meta["ghidra_enrich_task_id"] = task.id
    target.metadata_json = meta
    flag_modified(target, "metadata_json")
    session.commit()
    spawn_detached_task(task.id)
    return True


def set_visible(session: Session, project_id: str, target_id: str, visible: bool) -> dict:
    """Reveal (visible=True) or re-hide (visible=False) one target. Revealing
    materializes its recon nodes from the already-stored facts (no re-run); optional Ghidra
    enrichment runs detached (see `_materialize_on_reveal`). Returns {target_id, visible,
    materialized} (materialized = nodes were (re)materialized)."""
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        raise ValueError("target not found in project")
    was_visible = t.visible
    t.visible = visible
    materialized = False
    enrichment_queued = False
    if visible and not was_visible:
        project = session.get(Project, project_id)
        enrichment_queued = _materialize_on_reveal(session, project, t)
        materialized = True
    session.flush()
    return {"target_id": t.id, "name": t.name, "visible": t.visible, "materialized": materialized,
            "enrichment_queued": enrichment_queued}


def reveal_dir(session: Session, project_id: str, firmware_target_id: str, prefix: str) -> dict:
    """Reveal every HIDDEN child of a firmware whose rootfs-relative name (path) is
    under `prefix` (a directory prefix like "usr/sbin" or "/usr/sbin"). Materializes
    each revealed child's recon nodes (fast); optional Ghidra enrichment for each runs
    DETACHED in the background rather than blocking this call — see `_materialize_on_reveal`.
    Returns {firmware_target_id, prefix, revealed, target_ids, enrichment_queued}
    (enrichment_queued = how many revealed targets got a background Ghidra enrichment task).
    Already-visible children are left untouched."""
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
    enrichment_queued = 0
    for c in children:
        if c.visible:
            continue
        if c.id in ids_under_prefix or _under(c.name):   # any manifest path under prefix, or its own name
            c.visible = True
            if _materialize_on_reveal(session, project, c):
                enrichment_queued += 1
            revealed_ids.append(c.id)
    session.flush()
    return {
        "firmware_target_id": firmware_target_id,
        "prefix": prefix,
        "revealed": len(revealed_ids),
        "target_ids": revealed_ids,
        "enrichment_queued": enrichment_queued,
    }
