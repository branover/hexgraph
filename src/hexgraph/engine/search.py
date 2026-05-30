"""Project search with coverage honesty (P7-1).

LIKE-based search over findings + materialized nodes. (FTS5 is a later
optimization.) Crucially honest about coverage: function-body search only covers
*decompiled* functions, so an empty result is never "not present" — it's "not
found in what's been analyzed so far."
"""

from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from hexgraph.db.models import Finding, Node, NodeType


def search_project(session: Session, project_id: str, q: str, limit: int = 50) -> dict:
    like = f"%{q}%"
    findings = (
        session.query(Finding)
        .filter(
            Finding.project_id == project_id,
            or_(Finding.title.ilike(like), Finding.category.ilike(like), Finding.summary.ilike(like)),
        )
        .limit(limit).all()
    )
    nodes = (
        session.query(Node)
        .filter(Node.project_id == project_id, or_(Node.name.ilike(like), Node.fq_name.ilike(like)))
        .limit(limit).all()
    )
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
