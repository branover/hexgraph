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


def _materialize_recon_only(session: Session, project: Project, target: Target) -> dict:
    """The fast, synchronous half of revealing: materialize `target`'s recon symbol/string
    nodes from already-stored facts (no re-run). Returns the facts dict so the caller can
    decide whether Ghidra enrichment applies (see `_needs_ghidra_enrichment`)."""
    from hexgraph.engine.re.recon import materialize_recon_nodes

    facts = _recon_facts(session, project, target)
    materialize_recon_nodes(session, project.id, target, facts)
    return facts


def _needs_ghidra_enrichment(target: Target) -> bool:
    """Whether `target` still wants Ghidra enrichment: the feature is on and it hasn't
    already been recorded (see the `ghidra_enrich`/`ghidra_enrich_batch` task dispatch,
    which marks `ghidra_enriched` on success only — a soft failure or a killed task leaves
    it unmarked so a later reveal retries instead of silently giving up forever)."""
    from hexgraph.engine.re.ghidra import enrich_enabled

    return enrich_enabled() and not (target.metadata_json or {}).get("ghidra_enriched")


def _materialize_on_reveal(session: Session, project: Project, target: Target) -> bool:
    """Bring a just-revealed target's enrichment into the curated graph: recon nodes (fast,
    synchronous) plus optional Ghidra enrichment, kicked off DETACHED (see
    `_ensure_ghidra_enrichment`) rather than run inline — a cold headless Ghidra full-analysis
    can take many minutes. Used by `set_visible` (ONE target — see `reveal_dir` for the bulk
    path, which batches enrichment instead of spawning one detached process per target).
    Idempotent (materialize_* dedups). Returns True if Ghidra enrichment was (newly) queued."""
    facts = _materialize_recon_only(session, project, target)
    if facts.get("kind") not in ("executable", "shared_library"):
        return False
    try:
        return _ensure_ghidra_enrichment(session, project, target) if _needs_ghidra_enrichment(target) else False
    except Exception:  # noqa: BLE001 — enrichment is an optional bonus pass
        return False


def _ensure_ghidra_enrichment(session: Session, project: Project, target: Target) -> bool:
    """Kick off `target`'s optional Ghidra enrichment (`engine.re.ghidra.enrich_target`) in a
    DETACHED background OS process if it isn't already in flight — same pattern as
    `engine.targets.filesystem._ensure_analysis`. Caller must have already checked
    `_needs_ghidra_enrichment`. Safe to call repeatedly: no-ops while a `ghidra_enrich` Task
    for this target is still queued/running. Returns True if a task was (newly) queued."""
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
    try:
        spawn_detached_task(task.id)
    except Exception:  # noqa: BLE001 — if the spawn itself fails (fork/exec resource
        # exhaustion), mark the task failed rather than leaving it stuck "queued" forever —
        # a permanently-queued task would wrongly satisfy the already_running check above
        # and block every future reveal from ever retrying.
        from hexgraph.engine.tasks import mark_failed

        mark_failed(task, "failed to spawn detached enrichment process")
        session.commit()
        return False
    return True


def _ensure_batch_ghidra_enrichment(session: Session, project: Project, firmware: Target,
                                    target_ids: list[str]) -> int:
    """Kick off Ghidra enrichment for MANY targets in ONE detached process that runs them
    SEQUENTIALLY, not one detached process per target. `reveal_dir` can reveal a dozen+
    binaries in one call — each is its own cold headless Ghidra analysis (`--memory 2g
    --cpus 2.0` per the sandbox spec), so spawning one INDEPENDENT process per target would
    launch that many CONCURRENT containers and genuinely contend for host resources, unlike
    `promote_file`'s single detached analysis. The Task is anchored on `firmware` (there's no
    single natural target for a batch); `target_ids` travel in `params_json`. Returns how
    many targets were queued (0 if none needed it or the feature is off)."""
    if not target_ids:
        return 0

    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import spawn_detached_task

    task = create_task(session, project=project, target_id=firmware.id, type="ghidra_enrich_batch",
                       params={"target_ids": target_ids})
    session.commit()
    try:
        spawn_detached_task(task.id)
    except Exception:  # noqa: BLE001 — enrichment is optional, must never break reveal_dir;
        # same self-heal reasoning as _ensure_ghidra_enrichment above.
        from hexgraph.engine.tasks import mark_failed

        mark_failed(task, "failed to spawn detached enrichment process")
        session.commit()
        return 0
    return len(target_ids)


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
    each revealed child's recon nodes (fast); optional Ghidra enrichment for the whole batch
    runs as ONE detached background process working through them sequentially — not one
    process per target (see `_ensure_batch_ghidra_enrichment`: a directory can have a dozen+
    binaries, and spawning that many CONCURRENT cold headless Ghidra containers would
    contend hard for host resources, unlike a single target's `set_visible`).
    Returns {firmware_target_id, prefix, revealed, target_ids, enrichment_queued}
    (enrichment_queued = how many revealed targets got queued into that background batch).
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
    to_enrich: list[str] = []
    for c in children:
        if c.visible:
            continue
        if c.id in ids_under_prefix or _under(c.name):   # any manifest path under prefix, or its own name
            c.visible = True
            facts = _materialize_recon_only(session, project, c)
            if facts.get("kind") in ("executable", "shared_library") and _needs_ghidra_enrichment(c):
                to_enrich.append(c.id)
            revealed_ids.append(c.id)
    session.flush()
    enrichment_queued = _ensure_batch_ghidra_enrichment(session, project, fw, to_enrich)
    return {
        "firmware_target_id": firmware_target_id,
        "prefix": prefix,
        "revealed": len(revealed_ids),
        "target_ids": revealed_ids,
        "enrichment_queued": enrichment_queued,
    }
