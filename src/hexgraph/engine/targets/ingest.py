"""Ingest a path into the graph (SPEC §4, §9 M1).

M1 scope: a lone file → project + one root target, with the artifact copied into
the project's data dir. Firmware unpacking into child targets + `contains` edges
is added in M2 (`unpack_firmware`). Byte-level classification (format/arch/
mitigations) is deferred to the sandboxed `recon` task — ingest never parses
target bytes, it only copies them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.config import projects_dir
from hexgraph.db.models import LLMBackendName, Project, Target, TargetKind


def create_project(
    session: Session,
    name: str,
    *,
    llm_backend: str = "mock",
    model_pref: str | None = None,
) -> Project:
    project = Project(
        name=name,
        llm_backend=LLMBackendName(llm_backend),
        model_pref=model_pref,
        data_dir="",  # filled once the id is assigned
    )
    session.add(project)
    session.flush()  # assign id
    data_dir = projects_dir() / project.id
    (data_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    project.data_dir = str(data_dir)
    return project


def ingest_file(
    session: Session,
    project: Project,
    src_path: str | Path,
    *,
    name: str | None = None,
    parent: Target | None = None,
    visible: bool = True,
) -> Target:
    """Copy a file into the project and register it as a target.

    The artifact is copied to ``artifacts/<target_id>/<basename>`` — namespaced by
    the target's UUID so two different files (or two unpacked firmware children)
    that share a basename never overwrite each other on disk. (A flat
    ``artifacts/<basename>`` silently clobbered colliding names, so recon/decompile
    later read the WRONG bytes for one target — undetected graph corruption.)

    ``visible`` controls whether the new target contributes to the curated graph
    (the default for a lone ingest / a promoted file). ``unpack_firmware`` passes
    ``visible=False`` so a 765-ELF firmware doesn't flood the graph/Targets pane;
    those children are still recorded + searchable + addressable, and revealing one
    flips it visible and materializes its recon nodes from the already-stored facts.
    """
    src = Path(src_path).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"not a file: {src}")

    # Content hash at ingest time (not just from recon) so target identity —
    # archive/restore matching and cross-target dedup — works even when recon
    # hasn't run (no Docker, or --no-recon). Recon later rewrites the same value.
    from hexgraph.engine.targets.targets import file_sha256

    # Create the row first so its UUID is assigned, then copy into a per-target
    # subdir keyed on that id and record the final path. The dir is unique per
    # target, so the basename within it can never collide with another target's.
    target = Target(
        project_id=project.id,
        parent_id=parent.id if parent else None,
        name=name or src.name,
        path="",  # filled once the id is assigned (see below)
        kind=TargetKind.unknown,  # refined by the sandboxed recon task (M2)
        visible=visible,
    )
    session.add(target)
    session.flush()  # assign id

    dst_dir = Path(project.data_dir) / "artifacts" / target.id
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    shutil.copy2(src, dst)

    target.path = str(dst)
    target.metadata_json = {"size": dst.stat().st_size, "original_path": str(src),
                            "sha256": file_sha256(str(dst))}
    session.flush()
    return target
