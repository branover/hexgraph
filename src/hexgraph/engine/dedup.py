"""Collapse near-identical findings within a project (SPEC §9 M5).

Findings are considered duplicates when they share a target, category, title, and
the same key evidence (function + sink). The earliest finding (by creation time)
is kept; later duplicates are removed. Useful after re-running the same analysis
or sweeping overlapping patterns.
"""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, Finding


def _signature(f: Finding) -> tuple:
    ev = f.evidence_json or {}
    return (f.target_id, f.category, f.title, ev.get("function", ""), ev.get("sink", ""))


def _delete_finding_edges(session: Session, finding_id: str) -> None:
    """Remove edges touching a finding (about/supports/refutes/derived_from/…) so
    deleting the finding doesn't leave dangling polymorphic refs (FKs are off)."""
    session.query(Edge).filter(
        or_((Edge.src_kind == "finding") & (Edge.src_id == finding_id),
            (Edge.dst_kind == "finding") & (Edge.dst_id == finding_id))
    ).delete(synchronize_session=False)


def dedupe_findings(session: Session, project_id: str) -> int:
    """Delete duplicate findings, keeping the earliest of each signature.
    Returns the number removed."""
    findings = (
        session.query(Finding)
        .filter(Finding.project_id == project_id)
        .order_by(Finding.created_at.asc())
        .all()
    )
    seen: set[tuple] = set()
    removed = 0
    for f in findings:
        sig = _signature(f)
        if sig in seen:
            _delete_finding_edges(session, f.id)
            session.delete(f)
            removed += 1
        else:
            seen.add(sig)
    return removed
