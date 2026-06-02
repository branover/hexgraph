"""Managed source trees + lazy `source_file` nodes (design §4.1–§4.4, Phase 1).

A `SourceTree` is trusted material we possess and (in later phases) build — the
opposite of a hostile `target`. A project holds MULTIPLE independent source trees;
each may be linked to a target via a `built_from` edge. This module mirrors
`engine/filesystem.py` (a firmware's extracted rootfs): files live on disk under
the project data dir, indexed by a manifest on the `source_tree` row; individual
`source_file` *graph nodes* are materialized LAZILY on reference (a finding links
to a line, a harness is promoted), never one row per file — exactly the
`engine/nodes.py` lazy discipline. The kernel-tree case (70k files) stays a single
table row + a flat manifest, not 70k nodes.

Phase 1 is read-only browse: NO execution, NO build, NO new policy gate. Source
*text* is read host-side only for the IDE viewer — bounded and path-traversal-safe
(the same guard as `filesystem.read_file`). Firmware-*extracted* files added as a
source tree are marked `origin="extracted"` (untrusted-for-reading, build-only in
later phases); all compiling/parsing/fuzzing of any bytes still happens only in the
sandbox in later phases. Here we merely display text.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Node, NodeType, Project, SourceTree

# A file's bytes we'll surface to the UI viewer. The human is VIEWING source text
# (no execution / no parse of hostile bytes), bounded so a huge generated file can't
# blow up the response. Mirrors filesystem.MAX_VIEW_BYTES.
MAX_VIEW_BYTES = 512 * 1024

# Roles a source_file may carry (design §4.3 D3 — harnesses/PoCs/scripts unify as
# role-tagged source_file). `code` is plain imported/extracted source.
SOURCE_ROLES = ("code", "harness", "poc", "script", "build_recipe", "dictionary", "corpus_seed")

# Source-tree origins (design §4.5). `extracted` == firmware bytes (untrusted-for-
# reading, build-only); `scratch`/HexGraph-authored roles are editable later.
SOURCE_ORIGINS = ("upload", "git", "archive", "extracted", "scratch")


class SourceError(ValueError):
    """A source-tree request violated an invariant (missing tree/file, traversal)."""


def persistent_base(project: Project, tree_id: str) -> Path:
    """Stable on-disk root for a source tree's working files. Derived from the
    project data dir — never trust a stored absolute path (mirrors
    filesystem.persistent_base)."""
    return Path(project.data_dir) / "source" / tree_id


def _host_root(project: Project, tree: SourceTree) -> Path:
    return persistent_base(project, tree.id)


def host_root(project: Project, tree: SourceTree) -> Path:
    """Public: the on-disk root of a source tree (e.g. as a build context later)."""
    return _host_root(project, tree)


def tree_content_sha(project: Project, tree: SourceTree) -> str:
    """A TRUE byte-content hash over every file in the tree (rel + sha256(bytes)), for
    BUILD reproducibility + the cache key (design §3 Phase 7). Distinct from the row's
    `content_hash`, which is a cheap manifest (size-based) identity (D2) — that is fine for
    'is this the same tree?' but NOT for cache reuse, where a same-SIZE byte edit must
    produce a different key (else a stale artifact would be wrongly reused). Reads the
    on-disk working tree (trusted source text). Deterministic; sorted by rel."""
    h = hashlib.sha256()
    root = _host_root(project, tree).resolve()
    for f in sorted(_manifest_files(tree), key=lambda x: x["rel"]):
        rel = f["rel"]
        try:
            data = (root / rel).read_bytes()
        except OSError:
            data = b""
        h.update(rel.encode("utf-8"))
        h.update(b"\x00")
        h.update(hashlib.sha256(data).digest())
        h.update(b"\n")
    return h.hexdigest()


def _tree_hash(files: list[dict]) -> str:
    """A cheap content identity over the manifest (rel+size+role), NOT a byte sha256
    of every file — enough to detect "this is the same tree" and to anchor builds."""
    h = hashlib.sha256()
    for f in sorted(files, key=lambda x: x["rel"]):
        h.update(f"{f['rel']}\x00{f.get('size', 0)}\x00{f.get('role', 'code')}\n".encode())
    return h.hexdigest()


def _scan_dir(root: Path) -> list[dict]:
    """Flat manifest of regular files under `root` (rel/size), skipping VCS/symlink
    cruft. Mirrors how unpack records a firmware filesystem manifest."""
    files: list[dict] = []
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        parts = set(p.relative_to(root).parts)
        if ".git" in parts or "__pycache__" in parts:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        files.append({"rel": p.relative_to(root).as_posix(), "size": size, "role": "code"})
    return files


def record_manifest(tree: SourceTree, files: list[dict]) -> None:
    """Store the file listing on the source-tree row (rel/size/role) and refresh the
    tree content hash. `role` defaults to `code`; harness/poc/script entries are
    promoted explicitly (e.g. by the harness backfill)."""
    norm = [
        {"rel": f["rel"], "size": f.get("size"), "role": f.get("role", "code")}
        for f in files
    ]
    tree.manifest_json = {"files": norm}
    tree.content_hash = _tree_hash(norm)


def _manifest_files(tree: SourceTree) -> list[dict]:
    return list((tree.manifest_json or {}).get("files") or [])


def create_source_tree(
    session: Session, project: Project, *, name: str, origin: str = "scratch",
    editable: bool | None = None, vcs_rev: str | None = None,
) -> SourceTree:
    """Create an empty managed source tree row + its on-disk root. Files are written
    in later (write_source_file / import). `editable` defaults from origin: imported/
    extracted source is read-only (reproducibility / untrusted bytes), scratch trees
    are editable. Phase 1 never *runs* anything from a tree."""
    if origin not in SOURCE_ORIGINS:
        raise SourceError(f"origin must be one of {SOURCE_ORIGINS}")
    if not (name or "").strip():
        raise SourceError("a source tree needs a name")
    if editable is None:
        editable = origin == "scratch"
    tree = SourceTree(project_id=project.id, name=name.strip(), origin=origin,
                      editable=bool(editable), vcs_rev=vcs_rev, manifest_json={"files": []})
    session.add(tree)
    session.flush()
    persistent_base(project, tree.id).mkdir(parents=True, exist_ok=True)
    record_manifest(tree, [])
    return tree


def _safe_path(project: Project, tree: SourceTree, rel: str) -> Path:
    """Resolve `rel` inside the tree's on-disk root, refusing traversal. Reuses the
    `filesystem.read_file` containment check (root must be a parent of the resolved
    path, or the path itself)."""
    root = _host_root(project, tree).resolve()
    path = (root / rel).resolve()
    if root not in path.parents and path != root:
        raise SourceError("path escapes the source tree")
    return path


def write_source_file(
    session: Session, project: Project, tree: SourceTree, rel: str, content: str,
    *, role: str = "code",
) -> dict:
    """Write a file into a source tree (path-traversal safe) and refresh the
    manifest. Used to import scratch/HexGraph-authored source (harness/poc/script)
    and by the harness backfill. NOT a target-byte path — this is trusted text we
    author. Returns the manifest entry."""
    if role not in SOURCE_ROLES:
        raise SourceError(f"role must be one of {SOURCE_ROLES}")
    if not tree.editable:
        # `editable` is the single source of truth for writability: imported/extracted
        # source is read-only (reproducibility / untrusted bytes), only HexGraph-authored
        # scratch trees accept writes in Phase 1. (Origin sets the default editable in
        # create_source_tree; this just enforces whatever it resolved to.)
        raise SourceError(f"source tree {tree.id} is read-only (origin={tree.origin})")
    path = _safe_path(project, tree, rel)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    files = [f for f in _manifest_files(tree) if f["rel"] != rel]
    entry = {"rel": rel, "size": len(content.encode("utf-8")), "role": role}
    files.append(entry)
    record_manifest(tree, files)
    return entry


def list_source_trees(session: Session, project: Project, *, include_archived: bool = False) -> list[dict]:
    """All managed source trees in a project (id/name/origin/editable/file count +
    which target each is built_from). Mirrors list_filesystem's shape for the UI."""
    from hexgraph.db.models import Edge

    q = session.query(SourceTree).filter(SourceTree.project_id == project.id)
    if not include_archived:
        q = q.filter(SourceTree.archived.is_(False))
    trees = q.order_by(SourceTree.created_at.asc()).all()
    # built_from edges: target → source_tree
    links: dict[str, list[str]] = {}
    for e in (session.query(Edge)
              .filter(Edge.project_id == project.id, Edge.type == EdgeType.built_from.value,
                      Edge.dst_kind == "source_tree").all()):
        links.setdefault(e.dst_id, []).append(e.src_id)
    return [
        {"id": t.id, "name": t.name, "origin": t.origin, "editable": t.editable,
         "vcs_rev": t.vcs_rev, "content_hash": t.content_hash,
         "file_count": len(_manifest_files(t)), "archived": t.archived,
         "target_ids": links.get(t.id, [])}
        for t in trees
    ]


def list_source_files(session: Session, project: Project, tree: SourceTree) -> dict:
    """The tree's file listing for the IDE explorer (rel/size/role). Plus per-file
    finding/harness flags so the file-tree can decorate (dots/badges). Mirrors
    filesystem.list_filesystem."""
    # which rels have a materialized source_file node (and any located_in finding)
    nodes = (session.query(Node)
             .filter(Node.project_id == project.id, Node.node_type == NodeType.source_file.value,
                     Node.archived.is_(False)).all())
    by_rel = {}
    for n in nodes:
        a = n.attrs_json or {}
        if a.get("tree_id") == tree.id and a.get("rel"):
            by_rel[a["rel"]] = n
    files = []
    for f in _manifest_files(tree):
        node = by_rel.get(f["rel"])
        files.append({
            "rel": f["rel"], "size": f.get("size"), "role": f.get("role", "code"),
            "node_id": node.id if node else None,
            "is_harness": bool(node and (node.attrs_json or {}).get("role") == "harness"),
        })
    return {"id": tree.id, "name": tree.name, "origin": tree.origin, "editable": tree.editable,
            "content_hash": tree.content_hash, "files": files}


def read_source_file(project: Project, tree: SourceTree, rel: str, *, max_bytes: int = MAX_VIEW_BYTES) -> dict:
    """Read one file from a source tree for the in-UI viewer / agent. Returns
    {rel, size, role, encoding: 'text'|'binary', content, truncated, origin}.
    Path-traversal safe (must stay within the tree root). For `origin="extracted"`
    the file is firmware bytes — we still only DISPLAY text here (no execute/parse);
    the flag lets the UI mark it untrusted. Mirrors filesystem.read_file."""
    entry = next((f for f in _manifest_files(tree) if f["rel"] == rel), None)
    if entry is None:
        raise SourceError(f"{rel!r} is not in this source tree")
    path = _safe_path(project, tree, rel)
    if not path.is_file():
        raise SourceError(f"{rel!r} is no longer on disk")
    size = path.stat().st_size
    raw = path.read_bytes()[: max_bytes + 1]
    truncated = len(raw) > max_bytes
    raw = raw[:max_bytes]
    out = {"rel": rel, "size": size, "role": entry.get("role", "code"),
           "origin": tree.origin, "truncated": truncated}
    if b"\x00" not in raw:
        try:
            return {**out, "encoding": "text", "content": raw.decode("utf-8")}
        except UnicodeDecodeError:
            pass
    return {**out, "encoding": "binary", "content": raw.hex()}


def _sha(*parts: str | None) -> str:
    return hashlib.sha256("\x00".join(p or "" for p in parts).encode("utf-8")).hexdigest()


def materialize_source_file(
    session: Session, project: Project, tree: SourceTree, rel: str, *,
    role: str | None = None, created_by: str = "human", attrs: dict[str, Any] | None = None,
) -> Node:
    """Lazily materialize a `source_file` node for `tree:rel` (on reference — a
    finding links to it, a harness is promoted). Identity is (project, source_file,
    fq_name=`<tree_id>:<rel>`) so re-referencing the same file returns the SAME node
    (and nodemerge's default key folds any dupes by that fq_name). The node carries
    target_id=None (it belongs to a source tree, not a hostile target) and is anchored
    in the graph by its semantic edges (located_in / harnesses), not target→contains."""
    from hexgraph.engine.nodes import get_or_create_node

    entry = next((f for f in _manifest_files(tree) if f["rel"] == rel), None)
    if entry is None:
        raise SourceError(f"{rel!r} is not in this source tree")
    eff_role = role or entry.get("role", "code")
    fq = f"{tree.id}:{rel}"
    node = get_or_create_node(
        session, project_id=project.id, node_type=NodeType.source_file,
        name=rel.rsplit("/", 1)[-1], target_id=None, fq_name=fq,
        content_hash=_sha("source_file", tree.id, rel),
        attrs={"tree_id": tree.id, "rel": rel, "role": eff_role,
               "origin": tree.origin, **(attrs or {})},
        created_by=created_by,
    )
    return node


def link_finding_to_source(
    session: Session, project: Project, *, finding_id: str, tree: SourceTree, rel: str,
    line: int | None = None, col: int | None = None,
) -> Node:
    """Wire a finding → its source location: materialize the source_file node and add
    a `located_in` edge (attrs={line,col}) — the jump-from-finding-to-source link
    (design §4.4). Also stamps evidence.extra.source_ref so the Inspector can offer
    "Open in source" without traversing the graph (frozen schema untouched — rides
    evidence.extra)."""
    from hexgraph.db.models import Finding
    from hexgraph.engine.edges import add_edge

    f = session.get(Finding, finding_id)
    if f is None or f.project_id != project.id:
        raise SourceError("finding not found in this project")
    node = materialize_source_file(session, project, tree, rel)
    attrs: dict[str, Any] = {}
    if line is not None:
        attrs["line"] = int(line)
    if col is not None:
        attrs["col"] = int(col)
    add_edge(session, project_id=project.id, src=("finding", finding_id), dst=("node", node.id),
             type=EdgeType.located_in, origin="human", confidence=1.0,
             created_by_tool="link-source", attrs=attrs, merge=True)
    # mirror onto evidence.extra.source_ref (frozen-schema-respecting)
    ev = dict(f.evidence_json or {})
    extra = dict(ev.get("extra") or {})
    extra["source_ref"] = {"tree_id": tree.id, "rel": rel,
                           **({"line": int(line)} if line is not None else {})}
    ev["extra"] = extra
    f.evidence_json = ev
    return node
