"""Import an already-extracted/mounted filesystem directory as a target — the
alternative to `hexgraph ingest <firmware.bin>` for when the operator already has a
rootfs on disk (self-extracted, mounted, or a live device's exported filesystem) and
there's no packed blob to unpack.

Unlike `unpack_firmware` (which drives the sandboxed `unpack_probe.py` over untrusted
firmware BYTES — genuinely risky format parsing: unsquashfs/binwalk/cpio), a directory
import walks a tree the operator already expanded on disk. That's the same trust level
`ingest_file` already extends to a host path (copy bytes, sniff a 4-byte ELF magic) —
not the sandboxed-extraction threat model — so the walk runs on the host, not in Docker.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Project, Target, TargetKind
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.targets.filesystem import persistent_base, record_manifest
from hexgraph.engine.targets.ingest import ingest_file
from hexgraph.engine.targets.targets import file_sha256


def _walk_and_copy(src: Path, dst: Path) -> list[dict]:
    """Copy every regular file under `src` into `dst`, building a manifest entry per
    file. Skips symlinks and any non-regular entry (device/socket/FIFO nodes a real
    rootfs mount can contain) — `Path.is_file()` already resolves to False for those;
    `is_symlink()` additionally excludes a symlink to a regular file, which `is_file()`
    alone would follow and admit. Mirrors `unpack_probe.py`'s `_walk_files` guard."""
    files: list[dict] = []
    for dirpath, _dirnames, filenames in os.walk(src, followlinks=False):
        rel_dir = Path(dirpath).relative_to(src)
        for fname in filenames:
            abspath = Path(dirpath) / fname
            try:
                if abspath.is_symlink() or not abspath.is_file():
                    continue
                size = abspath.stat().st_size
                with open(abspath, "rb") as fh:
                    head = fh.read(4)
            except OSError:
                continue
            rel = (rel_dir / fname).as_posix() if str(rel_dir) != "." else fname
            dst_path = dst / rel
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(abspath, dst_path)
            except OSError:
                continue
            files.append({"rel": rel, "size": size, "is_elf": head == b"\x7fELF"})
    return files


def ingest_directory(
    session: Session,
    project: Project,
    src_dir: str | Path,
    *,
    name: str | None = None,
    visible: bool = True,
) -> tuple[Target, list[Target]]:
    """Copy `src_dir`'s tree into the project and register it as a firmware-kind root
    target with a `filesystem` manifest (the same shape `unpack_firmware` produces, so
    fs_list/fs_read_file/promote_file all work unchanged), eagerly registering every ELF
    as a HIDDEN child target — byte-identical ELFs dedup to one target (F08, same
    reasoning as `unpack_firmware`).

    The root target's `path` is left empty: there's no single packed byte artifact to
    recon here (unlike a firmware blob), only a directory of files, so any code that
    guards on `target.path` being non-empty (byte recon, decompile, YARA, …) naturally
    treats this root the same way it already treats a path-less surface target — see
    `worker._dispatch`'s SURFACE_KINDS / empty-path check.

    Returns (root_target, new_children); reconning those children is the CALLER's job
    (`pipeline.ingest_directory_and_analyze`) — same split as `unpack_firmware`."""
    src = Path(src_dir).expanduser().resolve()
    if not src.is_dir():
        raise NotADirectoryError(f"not a directory: {src}")

    target = Target(
        project_id=project.id,
        parent_id=None,
        name=name or src.name,
        path="",
        kind=TargetKind.firmware_image,
        visible=visible,
    )
    session.add(target)
    session.flush()  # assign id

    base = persistent_base(project, target.id)
    base.mkdir(parents=True, exist_ok=True)
    files = _walk_and_copy(src, base)
    target.metadata_json = {"original_path": str(src)}

    # F08: register each unique-bytes ELF once; every later byte-identical path points
    # at the same target instead of cloning a row/edge — same reasoning as unpack_firmware.
    seen_sha: dict[str, str] = {}
    children: list[Target] = []
    for entry in files:
        if not entry.get("is_elf"):
            continue
        host_path = base / entry["rel"]
        digest = file_sha256(str(host_path))
        keeper = seen_sha.get(digest)
        if keeper is not None:
            entry["child_target_id"] = keeper
            entry["dedup_of"] = keeper
            continue
        child = ingest_file(session, project, host_path, name=entry["rel"], parent=target, visible=False)
        add_edge(
            session, project_id=project.id,
            src=("target", target.id), dst=("target", child.id),
            type=EdgeType.contains, origin="tool", confidence=1.0,
            created_by_tool="ingest-dir", attrs={"path": entry["rel"]},
        )
        entry["child_target_id"] = child.id
        seen_sha[digest] = child.id
        children.append(child)

    record_manifest(target, method="directory_import", root_rel="", files=files)
    session.flush()
    return target, children
