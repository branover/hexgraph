"""Editable-IDE source revisions (design §6.2 D-edit, Phase 7).

The editable IDE never mutates a file in place. A save writes a NEW `SourceRevision`
(the full new content in CAS + a unified diff against the prior revision) and the
working-tree file is updated to match — so every edit is durable, reversible, and a
build can be launched **rebuild-from-a-revision**. Confinement is the safety property:

  - Only HexGraph-AUTHORED / role-tagged files (harness/poc/script/build_recipe) in an
    EDITABLE tree get revisions. `write_source_file` already refuses a write to a
    read-only tree (origin=git|archive|extracted|upload). Editing imported/vendor/extracted
    source is forbidden — it would break the content_hash reproducibility contract — so
    the editable surface is confined to scratch + HexGraph's own roles.
  - SCOPED gate (a UI/capability flag, never policy): a SCRATCH tree (HexGraph-authored,
    ephemeral, origin="scratch" + editable) is editable UNCONDITIONALLY — it exists to be
    iterated on and saves are append-only — so no `features.source.edit` is required. Any
    OTHER authored tree still needs the opt-in `features.source.edit` flag. The per-tree
    structural editability check (`write_source_file` refuses a non-editable tree) is the
    hard enforcement either way, so this is safe even if the flag is bypassed.

Revisions are content-addressed in CAS (free dedup; reverting to a past revision is just
re-pointing the working file at that content). The frozen Finding schema is untouched.
"""

from __future__ import annotations

import difflib

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, SourceRevision, SourceTree
from hexgraph.engine import cas
from hexgraph.engine.source import SOURCE_ROLES, SourceError, _safe_path, read_source_file


# The roles whose files are EDITABLE in the IDE (HexGraph-authored). `code` is editable
# too BUT only when its tree is editable (scratch) — an extracted/vendor `code` tree is
# read-only by tree.editable, which write_source_file enforces. So this set is advisory
# UI metadata; tree.editable is the hard gate.
EDITABLE_ROLES = ("harness", "poc", "script", "build_recipe", "code")


class RevisionError(SourceError):
    """A revision request violated an invariant (read-only tree, missing revision)."""


def is_scratch_tree(tree: SourceTree) -> bool:
    """A SCRATCH tree is HexGraph-authored, ephemeral, and exists precisely to be
    iterated on (the harness-promote tree, an MCP `import_source_tree` scratch tree).
    Saves to it are append-only revisions that never touch target bytes, so editing it
    is unconditionally allowed (no `features.source.edit` needed) — the scoped
    source-edit design. Imported/extracted/vendor trees are NOT scratch even when an
    importer marked them editable, so they still require the opt-in flag below.
    Identity is structural: `origin == "scratch"` AND the tree is editable."""
    return tree.origin == "scratch" and bool(tree.editable)


def can_edit_tree(tree: SourceTree) -> bool:
    """Read-side mirror of `_gate_edit`: would a save to this tree be allowed right now?
    A read-only tree (not editable) is never editable; a scratch tree always is; any other
    editable tree depends on `features.source.edit`. The SPA reads this per-tree so scratch
    trees show edit affordances by default while other authored trees stay gated."""
    if not bool(tree.editable):
        return False
    if is_scratch_tree(tree):
        return True
    from hexgraph import settings

    return bool(settings.get("features.source.edit"))


def _gate_edit(tree: SourceTree) -> None:
    """Per-tree edit gate (NOT policy — a UI/capability flag). A SCRATCH tree is editable
    unconditionally; any OTHER tree requires `features.source.edit`. Either way the
    structural read-only check in `write_source_file` still refuses an imported/extracted/
    vendor tree, so the reproducible-build content_hash contract stays safe."""
    from hexgraph import settings
    from hexgraph.policy import PolicyViolation

    if is_scratch_tree(tree):
        return
    if not bool(settings.get("features.source.edit")):
        raise PolicyViolation(
            "editing this source tree is not permitted (scratch/HexGraph-authored trees "
            "are editable by default; enable features.source.edit to edit other authored "
            "harness/poc/script files in the IDE)")


def _next_seq(session: Session, tree: SourceTree, rel: str) -> int:
    last = (session.query(SourceRevision)
            .filter(SourceRevision.source_tree_id == tree.id, SourceRevision.rel == rel)
            .order_by(SourceRevision.seq.desc()).first())
    return (last.seq + 1) if last else 1


def _prior_content(project: Project, session: Session, tree: SourceTree, rel: str) -> str:
    """The latest revision's content (for the diff), or the on-disk content, or ''."""
    last = (session.query(SourceRevision)
            .filter(SourceRevision.source_tree_id == tree.id, SourceRevision.rel == rel)
            .order_by(SourceRevision.seq.desc()).first())
    if last and last.content_cas:
        raw = cas.get(project, last.content_cas)
        if raw is not None:
            return raw.decode("utf-8", errors="replace")
    try:
        return read_source_file(project, tree, rel).get("content", "") or ""
    except SourceError:
        return ""


def save_revision(session: Session, project: Project, tree: SourceTree, rel: str,
                  content: str, *, role: str | None = None, origin: str = "analyst-edit",
                  note: str | None = None, gate: bool = True) -> dict:
    """Save a new revision of an editable source file (the IDE save). Writes the working
    file (path-traversal safe, refuses a read-only tree) AND records a `SourceRevision`
    (content in CAS + a diff vs the prior revision). Returns the revision dict.

    Gated by features.source.edit (`gate=False` for the internal backfill of an existing
    file's first revision). The write itself goes through `write_source_file`, which
    refuses any non-editable tree — so extracted/vendor source can NEVER be revised."""
    from hexgraph.engine.source import write_source_file

    if gate:
        _gate_edit(tree)
    eff_role = role or _role_of(tree, rel) or "code"
    if eff_role not in SOURCE_ROLES:
        raise RevisionError(f"role must be one of {SOURCE_ROLES}")
    prior = _prior_content(project, session, tree, rel)
    # write_source_file enforces tree.editable (refuses read-only/extracted trees).
    write_source_file(session, project, tree, rel, content, role=eff_role)
    seq = _next_seq(session, tree, rel)
    diff = "".join(difflib.unified_diff(
        prior.splitlines(keepends=True), content.splitlines(keepends=True),
        fromfile=f"{rel}@{seq - 1}", tofile=f"{rel}@{seq}"))
    rev = SourceRevision(
        project_id=project.id, source_tree_id=tree.id, rel=rel, seq=seq, role=eff_role,
        content_cas=cas.put(project, content), size=len(content.encode("utf-8")),
        diff=diff or None, origin=origin, note=note,
    )
    session.add(rev)
    session.flush()
    return revision_to_dict(rev)


def _role_of(tree: SourceTree, rel: str) -> str | None:
    for f in (tree.manifest_json or {}).get("files") or []:
        if f.get("rel") == rel:
            return f.get("role")
    return None


def list_revisions(session: Session, tree: SourceTree, rel: str | None = None) -> list[dict]:
    """Revision history for a tree (optionally one file), newest first."""
    q = session.query(SourceRevision).filter(SourceRevision.source_tree_id == tree.id)
    if rel is not None:
        q = q.filter(SourceRevision.rel == rel)
    return [revision_to_dict(r) for r in q.order_by(SourceRevision.seq.desc()).all()]


def get_revision_content(project: Project, session: Session, revision_id: str) -> str:
    rev = session.get(SourceRevision, revision_id)
    if rev is None or rev.project_id != project.id:
        raise RevisionError("revision not found in this project")
    raw = cas.get(project, rev.content_cas) if rev.content_cas else None
    return raw.decode("utf-8", errors="replace") if raw is not None else ""


def revert_to_revision(session: Session, project: Project, tree: SourceTree,
                       revision_id: str, *, gate: bool = True) -> dict:
    """Revert a file to a past revision by writing its content as a NEW revision (so the
    history is append-only — a revert is itself an edit, fully reversible). Gated."""
    rev = session.get(SourceRevision, revision_id)
    if rev is None or rev.source_tree_id != tree.id:
        raise RevisionError("revision not found in this tree")
    content = get_revision_content(project, session, revision_id)
    return save_revision(session, project, tree, rev.rel, content, role=rev.role,
                         origin="analyst-edit", note=f"revert to rev {rev.seq}", gate=gate)


def revision_to_dict(r: SourceRevision) -> dict:
    return {
        "id": r.id, "tree_id": r.source_tree_id, "rel": r.rel, "seq": r.seq,
        "role": r.role, "content_cas": r.content_cas, "size": r.size,
        "origin": r.origin, "note": r.note, "has_diff": bool(r.diff),
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
