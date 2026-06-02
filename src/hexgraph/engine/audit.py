"""Egress audit — a durable, queryable log of every outbound action against a live
target (docs/design/design-dynamic-surfaces.md). Mandatory once the bounded-egress tier is
enabled: nothing should reach the network without a corresponding EgressEvent."""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import EgressEvent


def record_egress(session: Session, *, project_id: str, dest: str, allowed: bool,
                  tool: str = "", target_id: str | None = None, task_id: str | None = None,
                  detail: str | None = None) -> EgressEvent:
    """Log one outbound action (allowed or denied). Call this for EVERY egress
    decision — including denials — so the audit is complete."""
    ev = EgressEvent(project_id=project_id, target_id=target_id, task_id=task_id,
                     dest=dest, allowed=bool(allowed), tool=tool, detail=detail)
    session.add(ev)
    session.flush()
    return ev


def list_egress(session: Session, project_id: str, limit: int = 500) -> list[dict]:
    rows = (session.query(EgressEvent)
            .filter(EgressEvent.project_id == project_id)
            .order_by(EgressEvent.created_at.desc()).limit(limit).all())
    return [{"id": e.id, "dest": e.dest, "allowed": e.allowed, "tool": e.tool,
             "target_id": e.target_id, "task_id": e.task_id, "detail": e.detail,
             "created_at": e.created_at.isoformat() if e.created_at else None}
            for e in rows]
