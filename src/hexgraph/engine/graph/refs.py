"""Resolve target references and pick sibling targets.

Shared by the LLM-task runner (related_to edges, sibling context) and the
follow-up spawner (resolving a suggested follow-up's `target_ref`).
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Target, TargetKind

_PEER_KINDS = {TargetKind.executable, TargetKind.shared_library}


def resolve_target_ref(session: Session, project_id: str, ref: str | None) -> Target | None:
    """Resolve a target id or name (basename) within a project to a Target."""
    if not ref:
        return None
    direct = session.get(Target, ref)
    if direct is not None and direct.project_id == project_id:
        return direct
    base = Path(ref).name
    for t in session.query(Target).filter(Target.project_id == project_id).all():
        if Path(t.name).name == base:
            return t
    return None


def pick_sibling(session: Session, project_id: str, target: Target) -> Target | None:
    """A peer target for cross-target context. Prefers same-parent executables/
    libraries (the real 'sibling' in an unpacked firmware), else any other target."""
    others = (
        session.query(Target)
        .filter(Target.project_id == project_id, Target.id != target.id)
        .all()
    )
    if not others:
        return None
    same_parent_peers = [
        t for t in others if t.parent_id == target.parent_id and t.kind in _PEER_KINDS
    ]
    if same_parent_peers:
        return same_parent_peers[0]
    peers = [t for t in others if t.kind in _PEER_KINDS]
    return peers[0] if peers else others[0]
