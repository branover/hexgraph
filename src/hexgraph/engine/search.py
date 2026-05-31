"""Project search with coverage honesty (P7-1).

LIKE-based search over findings + materialized nodes. (FTS5 is a later
optimization.) Crucially honest about coverage: function-body search only covers
*decompiled* functions, so an empty result is never "not present" — it's "not
found in what's been analyzed so far."
"""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from hexgraph.db.models import Finding, Node, NodeType, Target


def search_project(session: Session, project_id: str, q: str, limit: int = 50) -> dict:
    like = f"%{q}%"
    archived = {
        t[0] for t in session.query(Target.id).filter(
            Target.project_id == project_id, Target.archived.is_(True)
        ).all()
    }  # hide results belonging to removed targets
    findings = [
        f for f in (
            session.query(Finding)
            .filter(
                Finding.project_id == project_id,
                or_(Finding.title.ilike(like), Finding.category.ilike(like), Finding.summary.ilike(like)),
            )
            .limit(limit * 2).all()
        )
        if f.target_id not in archived
    ][:limit]
    nodes = [
        n for n in (
            session.query(Node)
            .filter(Node.project_id == project_id, or_(Node.name.ilike(like), Node.fq_name.ilike(like)))
            .limit(limit * 2).all()
        )
        if n.target_id is None or n.target_id not in archived
    ][:limit]
    func_count = (
        session.query(Node)
        .filter(Node.project_id == project_id, Node.node_type == NodeType.function.value).count()
    )
    return {
        "query": q,
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
                      "target_id": f.target_id, "status": f.status} for f in findings],
        "nodes": [{"id": n.id, "node_type": n.node_type, "name": n.name, "target_id": n.target_id}
                  for n in nodes],
        "coverage": {
            "functions_materialized": func_count,
            "note": "Function-body search covers only decompiled functions; "
                    "undecompiled code is not yet searchable (run static_analysis/decompile to widen).",
        },
    }
