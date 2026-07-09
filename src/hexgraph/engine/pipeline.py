"""Ingest-and-analyze orchestration (the M2 core loop, zero model calls).

  ingest file → recon → (if firmware) unpack into children → recon each child
              → links_against edges

Used by the CLI `ingest` command and by the demo. Recon auto-runs on ingest for
every target (SPEC §5).
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from hexgraph.db.models import Project, Target
from hexgraph.engine.targets.ingest import ingest_file
from hexgraph.engine.re.recon import run_recon
from hexgraph.engine.targets.unpack import build_links_against, unpack_firmware
from hexgraph.sandbox.executor import Executor, get_executor

log = logging.getLogger(__name__)

_FIRMWARE_FORMATS = {"squashfs", "cpio", "disk_image"}
_ENRICHABLE_KINDS = {"executable", "shared_library"}

# How many unpacked children to recon INLINE before switching to a detached background task
# instead. Existing test fixtures unpack into single digits (unaffected); a real large
# firmware can unpack into thousands — reconning each is its own sandboxed container
# spin-up, so a small firmware still analyzes fully synchronously (unchanged behavior, exact
# same summary shape as before) while a large one returns fast with the child TARGET ROWS
# already created (unpack_firmware's own registration is a cheap host-side copy+hash, not
# the bottleneck — see _ensure_children_recon_detached) and a task id to poll instead of
# blocking the ingest call for what can be hours. Same bug class already fixed tonight for
# promote_file/reveal_dir, just at the INITIAL-ingest call site (`ingest_and_analyze` /
# `hexgraph ingest` / `target_ingest` never routed through the detached-task system at all).
CHILD_RECON_DETACH_THRESHOLD = 25


def _record_progress(session: Session, target: Target, stage: str, **extra) -> None:
    """Emit a coarse ingest-progress signal so the multi-minute unpack+recon isn't a silent
    black box (dogfood F05): log the stage AND stamp it on the root target's
    `metadata_json["ingest_progress"]`, committing so a concurrent poller (the UI / target_facts)
    sees it mid-run — under WAL another connection only sees COMMITTED rows, so we commit each
    stage. Best-effort: a progress hiccup must never break the actual ingest.

    NOTE (scope): this is the pragmatic signal, not a job-id + async-poll redesign. The ingest
    request is still synchronous; the operator/UI polls the root target's metadata to watch it
    advance, and the final stage is "done"."""
    payload = {"stage": stage, **extra}
    log.info("ingest progress [%s]: %s%s", target.id, stage,
             (" " + ", ".join(f"{k}={v}" for k, v in extra.items()) if extra else ""))
    try:
        meta = dict(target.metadata_json or {})
        meta["ingest_progress"] = payload
        target.metadata_json = meta
        flag_modified(target, "metadata_json")
        session.commit()
    except Exception:  # noqa: BLE001 — progress is advisory; never let it abort the ingest
        session.rollback()


def _maybe_enrich_ghidra(session: Session, project: Project, target: Target, facts: dict) -> None:
    """Optionally fold Ghidra's function/call-graph/struct inventory into the graph
    (Settings → features.ghidra.enrich_recon). Best-effort: never breaks recon.
    Skipped for HIDDEN targets — a hidden target adds nothing to the curated graph until
    revealed, and revealing no longer auto-enriches either (engine.targets.reveal requires
    an explicit per-call `enrich=True`, not just the global setting)."""
    if not target.visible:
        return
    if facts.get("kind") not in _ENRICHABLE_KINDS:
        return
    try:
        from hexgraph.engine.re.ghidra import enrich_enabled, enrich_target

        if enrich_enabled():
            enrich_target(session, project, target)
    except Exception:  # noqa: BLE001 — enrichment is an optional bonus pass
        pass


def _ensure_children_recon_detached(session: Session, project: Project, target: Target,
                                    children: list[Target]) -> str:
    """Kick off recon for `children` as ONE detached process working through them
    SEQUENTIALLY — same "one process for the whole batch, not one per item" reasoning as
    `engine.targets.reveal._ensure_batch_ghidra_enrichment` (a directory/firmware can have
    thousands of children; spawning one INDEPENDENT process per child would launch that many
    CONCURRENT sandbox containers and contend hard for host resources). The Task is anchored
    on `target` (the firmware/parent being analyzed); child ids travel in `params_json`.
    Returns "queued", or "failed" if the spawn itself raised (the Task ends up marked
    failed rather than stuck queued forever — see engine.targets.reveal for the same
    self-heal reasoning)."""
    from hexgraph.engine.tasks import create_task, mark_failed
    from hexgraph.engine.worker import spawn_detached_task

    task = create_task(session, project=project, target_id=target.id, type="recon_children_batch",
                       params={"target_ids": [c.id for c in children]})
    session.commit()
    try:
        spawn_detached_task(task.id)
    except Exception:  # noqa: BLE001 — never let a spawn failure break the ingest call
        mark_failed(task, "failed to spawn detached recon-children process")
        session.commit()
        return "failed"
    meta = dict(target.metadata_json or {})
    meta["recon_children_task_id"] = task.id
    target.metadata_json = meta
    flag_modified(target, "metadata_json")
    session.commit()
    return "queued"


def recon_children(session: Session, project: Project, anchor: Target, children: list[Target],
                    runner: Executor) -> str:
    """Recon `children` — inline sequentially if there are few, ONE detached batch task
    (see `_ensure_children_recon_detached`) if there are more than
    `CHILD_RECON_DETACH_THRESHOLD`. Progress/detach state is recorded against `anchor`
    (the firmware/directory root the children belong to). Shared by `analyze_target`'s
    firmware-unpack path and `ingest_directory_and_analyze`'s directory-import path — both
    eagerly register the same kind of child (a hidden ELF target) and need the same
    "don't block on thousands of sequential sandbox runs" handling.

    Returns "done", "queued", or "failed" (the detach itself couldn't start)."""
    total = len(children)
    if total > CHILD_RECON_DETACH_THRESHOLD:
        return _ensure_children_recon_detached(session, project, anchor, children)
    for i, child in enumerate(children, start=1):
        _record_progress(session, anchor, "recon_children", done=i - 1, total=total)
        child_facts = run_recon(session, project, child, runner)
        _maybe_enrich_ghidra(session, project, child, child_facts)
    return "done"


def analyze_target(
    session: Session,
    project: Project,
    target: Target,
    runner: Executor,
) -> dict:
    """Recon a target; if it's firmware, unpack and recon each child.

    Emits coarse per-stage progress on the root target's metadata (recon → unpacking →
    recon i/N children → done) so the multi-minute firmware path isn't a silent black box
    (F05). The signal is advisory — a poller watches `metadata_json["ingest_progress"]`.

    Above `CHILD_RECON_DETACH_THRESHOLD` children, per-child recon runs DETACHED (see
    `recon_children`) instead of inline. `summary["recon_status"]` is "done" (small —
    recon already ran, exactly like before), "queued" (large — child TARGET ROWS exist
    and are already in `summary["children"]`, but their recon facts land later — poll via
    `target_facts`/re-ingesting), or "failed" (the detach itself couldn't start)."""
    _record_progress(session, target, "recon")
    facts = run_recon(session, project, target, runner)
    summary = {"target_id": target.id, "name": target.name, "children": [], "recon_status": "done"}

    # G01: a recognized firmware format OR a large blob whose format we couldn't recognize —
    # in the latter case ATTEMPT a binwalk carve anyway (it often recognizes vendor wrappers our
    # signature scan misses), and if it yields nothing, say so loudly below instead of silently
    # returning 0 children.
    is_firmware = (facts.get("kind") == "firmware_image" or facts.get("format") in _FIRMWARE_FORMATS
                   or facts.get("likely_unrecognized_container"))
    if is_firmware:
        summary["format"] = facts.get("format")
        _record_progress(session, target, "unpacking", format=facts.get("format"))
        # unpack_firmware flips the parent's kind to firmware_image; capture the pre-unpack kind so
        # we can UNDO that for a `likely_unrecognized_container` blob the carve proves is NOT a
        # container (below), rather than leaving an opaque blob mislabeled as firmware.
        pre_unpack_kind = target.kind
        # Materialize the child list first so we can report "recon i/N children" with a known N.
        children = list(unpack_firmware(session, project, target, runner))
        total = len(children)
        summary["children"] = [{"target_id": c.id, "name": c.name} for c in children]
        # Children are registered HIDDEN by unpack_firmware: recon ENRICHES each (metadata +
        # a recon Observation) but materializes no graph nodes — a hidden child contributes
        # nothing to the graph until revealed.
        summary["recon_status"] = recon_children(session, project, target, children, runner)
        # F07: flag packed containers the unpack left in the tree (a large vendor firmware image leaves
        # the real web UI/SSH/SNMP runtime in nested .pkg/squashfs that aren't auto-recursed).
        # Without this, "N children unpacked" reads as "fully unpacked" and a researcher hunts the
        # boot-only surface. A container entry with no child_target_id wasn't promoted/registered;
        # surface the biggest few so the agent can promote them (target_promote_file) to go deeper.
        from hexgraph.engine.targets.filesystem import packed_containers
        fs_files = ((target.metadata_json or {}).get("filesystem") or {}).get("files", [])
        packed = packed_containers(fs_files)
        if packed:
            summary["packed_containers"] = packed[:20]
            summary["packed_containers_count"] = len(packed)
        # G01: the carve of an unrecognized blob yielded NOTHING analyzable — no ELF child AND no
        # promotable nested container — so don't return a silent 0-child result that leaves the
        # operator dead in the water. Surface the header bytes + an "unsupported container" signal so
        # they can identify it and act. Gate on `not packed`: when the carve DID surface nested
        # containers, `packed_containers` already says "promote one to go deeper" — emitting the
        # "unsupported, extract out-of-band" note alongside it would contradict that guidance.
        if total == 0 and not packed and facts.get("likely_unrecognized_container"):
            # The carve proved this speculative "container" holds nothing analyzable, so it isn't
            # firmware — undo the firmware_image label unpack_firmware optimistically set, leaving
            # the blob with its real (recon-derived) kind instead of a misleading firmware row.
            target.kind = pre_unpack_kind
            summary["unrecognized_container"] = {
                "format": facts.get("format"),
                "magic_hex": facts.get("magic_hex"),
                "magic_ascii": facts.get("magic_ascii"),
                "note": ("the unpacker did not recognize this container and extracted no analyzable "
                         "binaries — it's likely a vendor-wrapped/signed firmware image whose format "
                         "isn't supported. Identify it from the magic bytes (host `file`/binwalk), "
                         "then extract a known inner artifact out-of-band and re-ingest it, or file "
                         "an issue with the magic so support can be added."),
            }
    else:
        _maybe_enrich_ghidra(session, project, target, facts)
    summary["children_count"] = len(summary["children"])
    final_stage = "recon_children_queued" if summary["recon_status"] == "queued" else "done"
    _record_progress(session, target, final_stage, children=summary["children_count"])
    return summary


def ingest_and_analyze(
    session: Session,
    project: Project,
    src_path: str | Path,
    *,
    name: str | None = None,
    runner: Executor | None = None,
) -> dict:
    runner = runner or get_executor()
    root = ingest_file(session, project, src_path, name=name)
    summary = analyze_target(session, project, root, runner)
    links = build_links_against(session, project)
    summary["links_against_edges"] = links
    summary["root_target_id"] = root.id
    return summary


def ingest_directory_and_analyze(
    session: Session,
    project: Project,
    src_dir: str | Path,
    *,
    name: str | None = None,
    runner: Executor | None = None,
) -> dict:
    """The directory-import counterpart to `ingest_and_analyze`: no packed blob to recon
    at the root (`ingest_directory` walks + copies the tree directly, eagerly registering
    ELF children), so this skips straight to reconning those children — same
    threshold/detach handling as a large firmware's unpacked children (`recon_children`).
    Returns the SAME summary shape as `ingest_and_analyze` (target_id/name/children/
    children_count/recon_status/root_target_id/links_against_edges), so every existing
    consumer (CLI/MCP/API) handles either with no branching of its own."""
    from hexgraph.engine.targets.dirimport import ingest_directory

    runner = runner or get_executor()
    root, children = ingest_directory(session, project, src_dir, name=name)
    summary = {
        "target_id": root.id, "name": root.name, "format": "directory",
        "children": [{"target_id": c.id, "name": c.name} for c in children],
    }
    summary["recon_status"] = recon_children(session, project, root, children, runner)
    summary["children_count"] = len(summary["children"])
    links = build_links_against(session, project)
    summary["links_against_edges"] = links
    summary["root_target_id"] = root.id
    final_stage = "recon_children_queued" if summary["recon_status"] == "queued" else "done"
    _record_progress(session, root, final_stage, children=summary["children_count"])
    return summary
