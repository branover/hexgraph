"""Polymorphic edge creation + integrity (design §3.3).

One helper creates every edge so attribution (origin/confidence) is consistent.
Because endpoints are polymorphic, SQLite can't enforce them with FKs — so node
deletion must cascade through `delete_node_cascade`.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import or_
from sqlalchemy.orm import Session

from hexgraph.db.models import EDGE_KINDS, Edge, EdgeType, Node

# Confidence floats for the agent/API low|medium|high enum (design ruling #4).
CONFIDENCE = {"low": 0.3, "medium": 0.6, "high": 0.9}


def add_edge(
    session: Session,
    *,
    project_id: str,
    src: tuple[str, str],
    dst: tuple[str, str],
    type: EdgeType | str,
    origin: str = "tool",
    confidence: float | str | None = None,
    weight: float | None = None,
    directed: bool = True,
    created_by_task_id: str | None = None,
    created_by_tool: str | None = None,
    attrs: dict[str, Any] | None = None,
    merge: bool = False,
) -> Edge:
    src_kind, src_id = src
    dst_kind, dst_id = dst
    if src_kind not in EDGE_KINDS or dst_kind not in EDGE_KINDS:
        raise ValueError(f"edge endpoints must be one of {EDGE_KINDS}; got {src_kind!r}/{dst_kind!r}")
    if isinstance(confidence, str):
        confidence = CONFIDENCE.get(confidence)
    type_str = type.value if isinstance(type, EdgeType) else str(type)

    if merge:
        # One edge per (src, dst, type): fold a repeat into the existing edge,
        # accumulating contributing finding ids instead of drawing a parallel edge.
        existing = (
            session.query(Edge)
            .filter(Edge.project_id == project_id, Edge.type == type_str,
                    Edge.src_kind == src_kind, Edge.src_id == src_id,
                    Edge.dst_kind == dst_kind, Edge.dst_id == dst_id)
            .first()
        )
        if existing is not None:
            merged = dict(existing.attrs_json or {})
            ids = list(merged.get("finding_ids") or ([merged["finding_id"]] if merged.get("finding_id") else []))
            new_fid = (attrs or {}).get("finding_id")
            if new_fid and new_fid not in ids:
                ids.append(new_fid)
            if ids:
                merged["finding_ids"] = ids
            if confidence is not None and (existing.confidence is None or confidence > existing.confidence):
                existing.confidence = confidence
            existing.attrs_json = merged
            session.flush()
            return existing

    edge = Edge(
        project_id=project_id,
        src_kind=src_kind, src_id=src_id, dst_kind=dst_kind, dst_id=dst_id,
        type=type_str,
        directed=directed, confidence=confidence, weight=weight, origin=origin,
        created_by_task_id=created_by_task_id, created_by_tool=created_by_tool,
        attrs_json=attrs or {},
    )
    session.add(edge)
    session.flush()
    return edge


def edges_touching(session: Session, kind: str, id_: str) -> list[Edge]:
    return (
        session.query(Edge)
        .filter(
            or_(
                (Edge.src_kind == kind) & (Edge.src_id == id_),
                (Edge.dst_kind == kind) & (Edge.dst_id == id_),
            )
        )
        .all()
    )


def delete_node_cascade(session: Session, node_id: str) -> int:
    """Delete a node and every edge touching it. Returns edges removed."""
    removed = (
        session.query(Edge)
        .filter(
            or_(
                (Edge.src_kind == "node") & (Edge.src_id == node_id),
                (Edge.dst_kind == "node") & (Edge.dst_id == node_id),
            )
        )
        .delete(synchronize_session=False)
    )
    node = session.get(Node, node_id)
    if node is not None:
        session.delete(node)
    return removed
