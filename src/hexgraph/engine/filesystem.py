"""Traversable unpacked filesystem for firmware targets.

Firmware unpack persists the extracted tree under the project data dir and records
a manifest on the firmware target (`metadata_json["filesystem"]`). The detail panel
browses that tree; any file can be added as a child target on demand (real bytes →
recon), not just the ELFs auto-detected at unpack time.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Project, Target


def persistent_base(project: Project, firmware_id: str) -> Path:
    """Stable on-disk root for a firmware's extracted files (survives so files can
    be added later). Derived from the project data dir — never trust a stored
    absolute path."""
    return Path(project.data_dir) / "unpacked" / firmware_id


def record_manifest(firmware: Target, *, method: str, root_rel: str, files: list[dict]) -> None:
    """Store the unpacked file listing on the firmware target."""
    meta = dict(firmware.metadata_json or {})
    meta["filesystem"] = {
        "method": method,
        "root_rel": root_rel,
        "files": [
            {"rel": f["rel"], "size": f.get("size"), "is_elf": bool(f.get("is_elf")),
             "child_target_id": f.get("child_target_id")}
            for f in files
        ],
    }
    firmware.metadata_json = meta


def _host_root(project: Project, firmware: Target) -> Path:
    fs = (firmware.metadata_json or {}).get("filesystem") or {}
    return persistent_base(project, firmware.id) / (fs.get("root_rel") or "")


def host_root(project: Project, firmware: Target) -> Path:
    """Public: the on-disk root of a firmware's extracted filesystem (its rootfs).
    Used e.g. as the qemu-user sysroot when running a foreign-arch child binary."""
    return _host_root(project, firmware)


def list_filesystem(project: Project, firmware: Target) -> dict:
    """The firmware's file tree for the detail panel (paths/sizes/types + which are
    already targets)."""
    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        return {"unpacked": False, "files": []}
    return {
        "unpacked": True,
        "method": fs.get("method"),
        "files": [
            {"rel": f["rel"], "size": f.get("size"), "is_elf": f.get("is_elf"),
             "child_target_id": f.get("child_target_id"), "added": bool(f.get("child_target_id"))}
            for f in fs.get("files", [])
        ],
    }


class FilesystemError(ValueError):
    pass


def add_file_as_target(session: Session, project: Project, firmware: Target, rel: str, runner=None):
    """Ingest a file from the firmware's unpacked tree as a child target (real
    bytes → recon if Docker is up). Idempotent per `rel` (returns the existing
    child if already added)."""
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.pipeline import analyze_target
    from hexgraph.engine.unpack import build_links_against
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        raise FilesystemError("this target has no unpacked filesystem")
    entry = next((f for f in fs["files"] if f["rel"] == rel), None)
    if entry is None:
        raise FilesystemError(f"{rel!r} is not in the unpacked filesystem")
    if entry.get("child_target_id"):
        existing = session.get(Target, entry["child_target_id"])
        if existing is not None:
            return existing

    host_path = _host_root(project, firmware) / rel
    if not host_path.is_file():
        raise FilesystemError(f"{rel!r} is no longer on disk; re-unpack the firmware")

    child = ingest_file(session, project, host_path, name=rel, parent=firmware)
    add_edge(session, project_id=project.id, src=("target", firmware.id), dst=("target", child.id),
             type=EdgeType.contains, origin="human", confidence=1.0,
             created_by_tool="add-from-fs", attrs={"path": rel})
    if (runner or (get_executor() if docker_available() else None)):
        analyze_target(session, project, child, runner or get_executor())
        build_links_against(session, project)

    # mark the manifest entry so the UI shows it as added
    meta = dict(firmware.metadata_json or {})
    for f in meta["filesystem"]["files"]:
        if f["rel"] == rel:
            f["child_target_id"] = child.id
    firmware.metadata_json = meta
    return child
