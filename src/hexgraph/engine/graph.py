"""Build the project graph as nodes + edges JSON (SPEC §8).

Nodes are targets and findings; edges are the target↔target relations
(contains | links_against | related_to) plus a finding→target "about" edge so
findings render as connected nodes in the UI.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, Finding, Target


def build_graph(session: Session, project_id: str) -> dict:
    targets = session.query(Target).filter(Target.project_id == project_id).all()
    edges = session.query(Edge).filter(Edge.project_id == project_id).all()
    findings = session.query(Finding).filter(Finding.project_id == project_id).all()

    nodes: list[dict] = []
    for t in targets:
        nodes.append(
            {
                "id": t.id,
                "type": "target",
                "label": t.name,
                "kind": t.kind.value,
                "format": t.format,
                "arch": t.arch,
                "parent_id": t.parent_id,
            }
        )
    for f in findings:
        nodes.append(
            {
                "id": f.id,
                "type": "finding",
                "label": f.title,
                "severity": f.severity,
                "category": f.category,
                "confidence": f.confidence,
                "status": f.status.value,
                "target_id": f.target_id,
            }
        )

    out_edges: list[dict] = []
    for e in edges:
        out_edges.append(
            {"id": e.id, "source": e.src_target_id, "target": e.dst_target_id, "type": e.type.value}
        )
    for f in findings:
        out_edges.append(
            {"id": f"about-{f.id}", "source": f.id, "target": f.target_id, "type": "about"}
        )

    return {"project_id": project_id, "nodes": nodes, "edges": out_edges}


def export_graph(session: Session, project_id: str, path: str | Path) -> Path:
    graph = build_graph(session, project_id)
    out = Path(path)
    out.write_text(json.dumps(graph, indent=2))
    return out
