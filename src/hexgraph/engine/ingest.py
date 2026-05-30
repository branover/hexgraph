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
) -> Target:
    """Copy a file into the project and register it as a target."""
    src = Path(src_path).expanduser().resolve()
    if not src.is_file():
        raise FileNotFoundError(f"not a file: {src}")

    artifacts = Path(project.data_dir) / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    dst = artifacts / src.name
    shutil.copy2(src, dst)

    target = Target(
        project_id=project.id,
        parent_id=parent.id if parent else None,
        name=name or src.name,
        path=str(dst),
        kind=TargetKind.unknown,  # refined by the sandboxed recon task (M2)
        metadata_json={"size": dst.stat().st_size, "original_path": str(src)},
    )
    session.add(target)
    session.flush()
    return target
