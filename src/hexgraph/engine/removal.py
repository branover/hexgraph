"""Removal of graph entities.

Two flavours, matching how each entity behaves:
- **Soft (archive/restore)** for nodes and targets — reversible: an archived node and
  the edges touching it are hidden from the graph/search, and re-adding the same node
  (`get_or_create_node`) un-archives it so its edges reappear (edges are never deleted).
  Targets archive their whole subtree (see `engine/targets.py`).
- **Hard delete** for a specific edge (cheap to recreate), for a single finding
  (the irreversible counterpart to *dismissing* it — `delete_finding` removes the
  row plus everything that polymorphically references it), and for a whole project
  (durable removal of the project's rows + its on-disk data dir).
"""

from __future__ import annotations

import shutil

from sqlalchemy import or_
from sqlalchemy.orm import Session

from hexgraph.db.models import (
    AnalysisRun, Annotation, ContextBundle, ContextItem, Edge, EgressEvent,
    Finding, Node, Project, Target, Task,
)


def archive_node(session: Session, project_id: str, node_id: str) -> Node:
    """Soft-remove a node: hide it and (via the graph's endpoint filter) its edges.
    Reversible — re-adding the same node, or restore_node, brings it (and its edges) back."""
    n = session.get(Node, node_id)
    if n is None or n.project_id != project_id:
        raise ValueError("node not found in project")
    n.archived = True
    return n


def restore_node(session: Session, project_id: str, node_id: str) -> Node:
    n = session.get(Node, node_id)
    if n is None or n.project_id != project_id:
        raise ValueError("node not found in project")
    n.archived = False
    return n


def delete_edge(session: Session, edge_id: str) -> bool:
    """Hard-delete one edge. Returns True if an edge was removed."""
    e = session.get(Edge, edge_id)
    if e is None:
        return False
    session.delete(e)
    session.flush()
    return True


def delete_finding(session: Session, finding_id: str) -> dict:
    """Permanently delete ONE finding and every polymorphic reference to it.

    This is the HARD counterpart to *dismissing* a finding (`status="dismissed"`,
    which keeps the row, reversibly greyed). Deleting is irreversible: the row is
    gone. Because foreign-key enforcement is OFF and edges/annotations are
    polymorphic string refs, we clean up each referencing thing explicitly so no
    dangling ref survives:
      - edges where the finding is the src OR the dst endpoint (`about`,
        `located_in`, hypothesis `link_evidence`, …);
      - annotations keyed to it (`node_kind="finding"`);
      - any task spawned from it (`parent_finding_id`) is detached, not deleted —
        the task ran and its log/result stand on their own (mirrors how we never
        orphan-cascade a run).

    Idempotent: deleting an already-gone finding is a safe no-op. Returns a small
    summary of what was removed, like the other removal fns."""
    f = session.get(Finding, finding_id)
    if f is None:
        return {"deleted_finding": finding_id, "found": False, "edges": 0,
                "annotations": 0, "tasks_detached": 0}

    edges = (
        session.query(Edge)
        .filter(or_(
            (Edge.src_kind == "finding") & (Edge.src_id == finding_id),
            (Edge.dst_kind == "finding") & (Edge.dst_id == finding_id),
        ))
        .delete(synchronize_session=False)
    )
    annotations = (
        session.query(Annotation)
        .filter(Annotation.node_kind == "finding", Annotation.node_id == finding_id)
        .delete(synchronize_session=False)
    )
    # Tasks spawned from this finding keep their own history; just drop the dangling
    # pointer so the column doesn't reference a deleted row.
    tasks_detached = (
        session.query(Task)
        .filter(Task.parent_finding_id == finding_id)
        .update({Task.parent_finding_id: None}, synchronize_session=False)
    )
    session.delete(f)
    session.flush()
    return {"deleted_finding": finding_id, "found": True, "edges": edges,
            "annotations": annotations, "tasks_detached": tasks_detached}


def delete_project(session: Session, project_id: str) -> dict:
    """Permanently delete a project and ALL its rows + on-disk data dir. Destructive
    and irreversible (unlike archive). FKs are off, so each table is cleared explicitly."""
    proj = session.get(Project, project_id)
    if proj is None:
        raise ValueError("project not found")
    data_dir = proj.data_dir

    # context_item has no project_id — clear it via its bundles first.
    bundle_ids = [b.id for b in session.query(ContextBundle.id).filter(
        ContextBundle.project_id == project_id).all()]
    if bundle_ids:
        session.query(ContextItem).filter(ContextItem.bundle_id.in_(bundle_ids)).delete(
            synchronize_session=False)
    removed = {}
    for model in (EgressEvent, AnalysisRun, ContextBundle, Annotation, Finding, Edge, Node, Task, Target):
        removed[model.__tablename__] = session.query(model).filter(
            model.project_id == project_id).delete(synchronize_session=False)
    session.delete(proj)
    session.flush()
    if data_dir:
        shutil.rmtree(data_dir, ignore_errors=True)
    return {"deleted_project": project_id, "rows": removed}
