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
             "child_target_id": f.get("child_target_id"),
             # F07: keep the container-format tag so packed_containers() can flag un-recursed
             # nested filesystems (omitted entirely for ordinary files, so the manifest stays lean).
             **({"container": f["container"]} if f.get("container") else {}),
             # F08: this path is byte-identical to (and reuses the target of) an earlier ELF — the
             # row was deduped, not cloned. Present only on the duplicate paths.
             **({"dedup_of": f["dedup_of"]} if f.get("dedup_of") else {})}
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


def list_filesystem(project: Project, firmware: Target, session=None, *,
                    path_prefix: str | None = None, offset: int = 0,
                    limit: int | None = None, elf_only: bool = False) -> dict:
    """The firmware's file tree (paths/sizes/types + which are already targets, and whether
    those are revealed into the curated graph).

    Every unpacked ELF gets a `child_target_id` at unpack time, but unpack registers
    those children HIDDEN — so `added` (a child exists) is distinct from `revealed`
    (it's visible in the graph/Targets pane). The browser shows "Reveal" for an added
    but hidden child, and the plain "added" badge once revealed.

    Filter/paginate for big firmware (a large vendor firmware image unpacks to hundreds-to-thousands of
    files — listing them all overflows an agent's context): `path_prefix` keeps only entries
    under a directory (e.g. "usr/sbin"), `elf_only` keeps only ELF binaries, and `offset`/`limit`
    page the (filtered) list. `total`/`next_offset`/`has_more` report the full size + where to
    page on. **`limit=None` returns everything** — the UI detail panel relies on that, so its
    call site is unchanged."""
    fs = (firmware.metadata_json or {}).get("filesystem")
    if not fs:
        return {"unpacked": False, "files": [], "total": 0}

    # Map child_target_id → visible, so the listing can distinguish hidden vs revealed.
    # Read it from the live target rows (the manifest doesn't carry mutable visibility).
    visible_by_id: dict[str, bool] = {}
    if session is not None:
        rows = (session.query(Target)
                .filter(Target.project_id == project.id, Target.parent_id == firmware.id).all())
        visible_by_id = {t.id: bool(t.visible) for t in rows}

    matched = []
    for f in fs.get("files", []):
        rel = f["rel"]
        if path_prefix and not rel.startswith(path_prefix):
            continue
        if elf_only and not f.get("is_elf"):
            continue
        cid = f.get("child_target_id")
        added = bool(cid)
        revealed = bool(cid and visible_by_id.get(cid, True))  # default True when not resolvable
        matched.append({
            "rel": rel, "size": f.get("size"), "is_elf": f.get("is_elf"),
            "child_target_id": cid, "added": added, "revealed": revealed,
        })

    total = len(matched)
    offset = max(0, offset)
    page = matched[offset:] if limit is None else matched[offset:offset + max(0, limit)]
    next_off = offset + len(page)
    # `and page` guards the degenerate limit<=0 case (empty page, offset<total) from reporting
    # has_more with a non-advancing next_offset — an infinite-paging trap. (The MCP wrapper also
    # clamps limit to >=1, so this only bites a direct caller.)
    has_more = next_off < total and bool(page)
    out = {"unpacked": True, "method": fs.get("method"), "files": page,
           "total": total, "offset": offset,
           "next_offset": next_off if has_more else None, "has_more": has_more}
    if path_prefix:
        out["path_prefix"] = path_prefix
    if elf_only:
        out["elf_only"] = True
    return out


def packed_containers(files: list[dict]) -> list[dict]:
    """The container-format files in a manifest that were NOT recursed into a child target —
    the "promote this to go deeper" set (F07). A large vendor firmware image leaves its web UI/SSH
    runtime in nested .pkg/squashfs that the unpack doesn't auto-recurse; surfacing them stops
    "N children unpacked" from reading as "fully unpacked". Biggest first (the meaningful
    surfaces) — the caller caps + counts."""
    return sorted(
        ({"rel": f["rel"], "format": f.get("container"), "size": f.get("size")}
         for f in files if f.get("container") and not f.get("child_target_id")),
        key=lambda c: c.get("size") or 0, reverse=True)


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
    from hexgraph.engine.targets.ingest import ingest_file
    from hexgraph.engine.pipeline import analyze_target
    from hexgraph.engine.targets.unpack import build_links_against
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
