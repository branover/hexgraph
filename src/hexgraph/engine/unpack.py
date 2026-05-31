"""Firmware unpack (SPEC §9 M2): binwalk/unsquashfs a firmware image into child
targets joined by `contains` edges. Extraction happens in the sandbox; the host
only copies the resulting ELF files (read from the mounted output dir) into the
project and registers them."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Project, Target, TargetKind
from hexgraph.engine.edges import add_edge
from hexgraph.engine.filesystem import persistent_base, record_manifest
from hexgraph.engine.ingest import ingest_file
from hexgraph.sandbox.executor import Executor, get_executor


def unpack_firmware(
    session: Session,
    project: Project,
    parent: Target,
    runner: Executor | None = None,
) -> list[Target]:
    """Unpack `parent` into a child target + `contains` edge per ELF, and persist
    the full extracted tree (+ a manifest on the firmware) so any file can be
    browsed and added as a target later."""
    runner = runner or get_executor()
    children: list[Target] = []

    # Persist the extraction under the project data dir (not a temp dir) so the
    # filesystem stays browsable and addable after unpack.
    base = persistent_base(project, parent.id)
    base.mkdir(parents=True, exist_ok=True)
    manifest = runner.run_json_probe("unpack_probe.py", parent.path, outdir=str(base))
    root_container = manifest.get("root") or "/out"
    root_rel = root_container.replace("/out", "", 1).lstrip("/")  # "root" | "" (binwalk)
    root = base / root_rel
    files = manifest.get("files", [])

    for entry in files:
        if not entry.get("is_elf"):
            continue
        host_path = base / (entry["container_path"].replace("/out", "", 1).lstrip("/"))
        if not host_path.is_file():
            host_path = root / entry["rel"]
        if not host_path.is_file():
            continue

        child = ingest_file(session, project, host_path, name=entry["rel"], parent=parent)
        add_edge(
            session, project_id=project.id,
            src=("target", parent.id), dst=("target", child.id),
            type=EdgeType.contains, origin="tool", confidence=1.0,
            created_by_tool="unpack", attrs={"path": entry["rel"]},
        )
        entry["child_target_id"] = child.id
        children.append(child)

    if parent.kind != TargetKind.firmware_image:
        parent.kind = TargetKind.firmware_image
    record_manifest(parent, method=manifest.get("method", "?"), root_rel=root_rel, files=files)
    return children


def build_links_against(session: Session, project: Project) -> int:
    """Create `links_against` edges from each target to sibling targets whose
    filename matches a needed library. Best-effort; returns edges created."""
    targets = session.query(Target).filter(Target.project_id == project.id).all()
    by_basename: dict[str, Target] = {}
    for t in targets:
        by_basename.setdefault(Path(t.name).name, t)

    created = 0
    for t in targets:
        for lib in (t.metadata_json or {}).get("libraries", []):
            dep = by_basename.get(Path(lib).name)
            if dep is not None and dep.id != t.id:
                add_edge(
                    session, project_id=project.id,
                    src=("target", t.id), dst=("target", dep.id),
                    type=EdgeType.links_against, origin="tool", confidence=1.0,
                    created_by_tool="recon", attrs={"lib": lib},
                )
                created += 1
    return created
