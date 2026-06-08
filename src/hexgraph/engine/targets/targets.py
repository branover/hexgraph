"""Soft removal of targets (reversible archive).

Removing a target from the project archives it and its whole subtree (child
targets) rather than deleting — nodes and findings are hidden by virtue of their
target being archived (no rows are destroyed; the project DB stays durable).
Re-adding the same bytes (matched by sha256) restores the archived target and its
findings reappear.
"""

from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target


def _subtree_ids(session: Session, project_id: str, root_id: str) -> list[str]:
    """All target ids in the parent_id subtree rooted at root_id (inclusive)."""
    ids = [root_id]
    frontier = [root_id]
    while frontier:
        kids = (
            session.query(Target.id)
            .filter(Target.project_id == project_id, Target.parent_id.in_(frontier))
            .all()
        )
        kid_ids = [k[0] for k in kids if k[0] not in ids]
        ids.extend(kid_ids)
        frontier = kid_ids
    return ids


def _set_archived(session: Session, project_id: str, root_id: str, archived: bool) -> int:
    ids = _subtree_ids(session, project_id, root_id)
    n = (
        session.query(Target)
        .filter(Target.project_id == project_id, Target.id.in_(ids))
        .update({Target.archived: archived}, synchronize_session=False)
    )
    return n


def archive_target(session: Session, project_id: str, target_id: str) -> int:
    """Archive a target and its subtree. Returns the number of targets archived."""
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        raise ValueError("target not found in project")
    return _set_archived(session, project_id, target_id, True)


def restore_target(session: Session, project_id: str, target_id: str) -> int:
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        raise ValueError("target not found in project")
    return _set_archived(session, project_id, target_id, False)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def restore_matching(session: Session, project: Project, file_path: str) -> Target | None:
    """If an archived target in this project has the same bytes (sha256) as
    `file_path`, restore its subtree and return it — so re-adding a removed target
    brings back its findings instead of creating a duplicate."""
    sha = file_sha256(file_path)
    for t in session.query(Target).filter(Target.project_id == project.id, Target.archived.is_(True)).all():
        if (t.metadata_json or {}).get("sha256") == sha:
            _set_archived(session, project.id, t.id, False)
            return t
    return None
