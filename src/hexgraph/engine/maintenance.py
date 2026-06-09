"""Project-store maintenance helpers (the on-disk ↔ DB reconciliation).

Every project's runtime state roots at `<HEXGRAPH_HOME>/projects/<project.id>` (the
project's `data_dir`: artifacts, the CAS, unpacked filesystems). The DB is the source of
truth, but the two can drift — a deleted-from-DB project leaves its dir behind, a relocated
HEXGRAPH_HOME orphans a dir, a half-finished ingest leaves a dir with no committed project.
The dogfood saw 1 project in the DB but 3 dirs on disk with no way to tell which were stale.

`project_dir_report` walks both sides and reports the drift (read-only); `prune_orphan_dirs`
deletes the orphan DIRS (never DB rows — those are durable researcher knowledge removed only
via the explicit delete_project path). A DB project whose dir is MISSING is flagged, never
auto-created (the data is already gone; only the operator can decide what to do).
"""

from __future__ import annotations

import shutil
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.config import projects_dir
from hexgraph.db.models import Project


def project_dir_report(session: Session) -> dict:
    """Reconcile on-disk project dirs against the DB (read-only). Returns
    ``{projects_dir, db_projects, on_disk_dirs, orphan_dirs, missing_dirs}`` where:

    - ``orphan_dirs``  — directory names under projects/ with NO matching DB project
      (a dir id that isn't a live `Project.id`); safe to delete (the bytes the operator
      asked to remove, or a relocated/half-finished ingest).
    - ``missing_dirs`` — DB projects whose `data_dir` does not exist on disk (the durable
      knowledge is in the DB but its artifacts/CAS are gone); flagged, never auto-fixed.
    """
    root = projects_dir()
    db = session.query(Project).all()
    db_ids = {p.id for p in db}

    on_disk: list[str] = []
    if root.is_dir():
        on_disk = sorted(d.name for d in root.iterdir() if d.is_dir())

    orphan_dirs = sorted(name for name in on_disk if name not in db_ids)

    missing_dirs: list[dict] = []
    for p in db:
        dd = Path(p.data_dir) if p.data_dir else (root / p.id)
        if not dd.is_dir():
            missing_dirs.append({"project_id": p.id, "name": p.name, "data_dir": str(dd)})

    return {
        "projects_dir": str(root),
        "db_projects": len(db),
        "on_disk_dirs": len(on_disk),
        "orphan_dirs": orphan_dirs,
        "missing_dirs": missing_dirs,
    }


def prune_orphan_dirs(session: Session) -> dict:
    """Delete project dirs under projects/ that have NO matching DB project. Returns the
    report plus a `deleted` list of the dir names removed. Touches the FILESYSTEM only —
    never a DB row (a project is removed from the DB only via the explicit delete_project
    path; this just reclaims orphaned bytes). Path-traversal safe: only direct children of
    the projects dir whose name isn't a live project id are removed."""
    report = project_dir_report(session)
    root = Path(report["projects_dir"])
    deleted: list[str] = []
    for name in report["orphan_dirs"]:
        target = (root / name).resolve()
        # Defensive: the candidate must be a DIRECT child of the projects root (no traversal).
        if target.parent != root.resolve() or not target.is_dir():
            continue
        shutil.rmtree(target, ignore_errors=True)
        deleted.append(name)
    report["deleted"] = deleted
    return report
