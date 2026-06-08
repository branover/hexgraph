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


# Bytes of a file we'll surface to the UI viewer (config files etc.). The human is
# VIEWING content, not executing or parsing the target — and the bytes already sit on
# the host disk from unpack — so reading them is bounded and read-only, not a sandbox
# escape. A hard cap keeps a huge/again-firmware file from blowing up the response.
MAX_VIEW_BYTES = 256 * 1024


def read_file(project: Project, firmware: Target, rel: str, *, max_bytes: int = MAX_VIEW_BYTES) -> dict:
    """Read a file from the firmware's unpacked tree for the in-UI viewer. Returns
    {rel, size, encoding: 'text'|'binary', content, truncated}. Path-traversal safe:
    the resolved path must stay within the firmware's extracted root."""
    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        raise FilesystemError("this target has no unpacked filesystem")
    entry = next((f for f in fs.get("files", []) if f.get("rel") == rel), None)
    if entry is None:
        raise FilesystemError(f"{rel!r} is not in the unpacked filesystem")

    root = _host_root(project, firmware).resolve()
    path = (root / rel).resolve()
    if root not in path.parents and path != root:
        raise FilesystemError("path escapes the unpacked filesystem")
    if not path.is_file():
        raise FilesystemError(f"{rel!r} is no longer on disk; re-unpack the firmware")

    size = path.stat().st_size
    raw = path.read_bytes()[: max_bytes + 1]
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    # Treat as text if it decodes cleanly and has no NULs; otherwise hand back a hex dump.
    if b"\x00" not in raw:
        try:
            return {"rel": rel, "size": size, "encoding": "text",
                    "content": raw.decode("utf-8"), "truncated": truncated}
        except UnicodeDecodeError:
            pass
    return {"rel": rel, "size": size, "encoding": "binary",
            "content": raw.hex(), "truncated": truncated}


def promote_file(session: Session, project: Project, firmware: Target, rel: str, runner=None):
    """Ingest a file from the firmware's unpacked tree as a child target (real
    bytes → recon if Docker is up). Idempotent per `rel` (returns the existing
    child if already added)."""
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.pipeline import analyze_target
    from hexgraph.engine.unpack import build_links_against
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        raise FilesystemError("this target has no unpacked filesystem")
    entry = next((f for f in fs.get("files", []) if f.get("rel") == rel), None)
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
             created_by_tool="promote-file", attrs={"path": rel})
    if (runner or (get_executor() if docker_available() else None)):
        analyze_target(session, project, child, runner or get_executor())
        build_links_against(session, project)

    # Mark the manifest entry as added so the UI shows it AND promote-file is idempotent
    # across sessions (an agent's repeat call must return this child, not make a dupe).
    # Rebuild with fresh dicts + flag_modified: a shallow copy that mutates the shared
    # nested entries leaves the JSON column unchanged-by-identity, so it never persists.
    from sqlalchemy.orm.attributes import flag_modified

    meta = dict(firmware.metadata_json or {})
    fsmeta = dict(meta.get("filesystem") or {})
    fsmeta["files"] = [
        {**f, "child_target_id": child.id} if f.get("rel") == rel else f
        for f in fsmeta.get("files", [])
    ]
    meta["filesystem"] = fsmeta
    firmware.metadata_json = meta
    flag_modified(firmware, "metadata_json")
    return child
