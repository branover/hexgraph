"""Build the project graph as nodes + edges JSON (SPEC §8).

Graph nodes = targets (artifacts) + typed `node` rows (function/symbol/string/...)
+ findings. Edges = the polymorphic, attributed `edge` rows (contains,
links_against, calls, about, instance_of_pattern, related_to, ...). Edge
endpoint ids reference whichever entity the (kind, id) pair points at.
"""

from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, Finding, Node, Target


def build_graph(session: Session, project_id: str) -> dict:
    targets = session.query(Target).filter(Target.project_id == project_id).all()
    code_nodes = session.query(Node).filter(Node.project_id == project_id).all()
    edges = session.query(Edge).filter(Edge.project_id == project_id).all()
    findings = session.query(Finding).filter(Finding.project_id == project_id).all()

    nodes: list[dict] = []
    for t in targets:
        nodes.append(
            {
                "id": t.id, "type": "target", "label": t.name, "kind": t.kind.value,
                "format": t.format, "arch": t.arch, "parent_id": t.parent_id,
            }
        )
    for n in code_nodes:
        nodes.append(
            {
                "id": n.id, "type": "node", "node_type": n.node_type, "label": n.name,
                "target_id": n.target_id, "address": n.address, "attrs": n.attrs_json or {},
            }
        )
    for f in findings:
        nodes.append(
            {
                "id": f.id, "type": "finding", "label": f.title, "severity": f.severity,
                "category": f.category, "confidence": f.confidence, "status": f.status,
                "target_id": f.target_id,
            }
        )

    out_edges = [
        {
            "id": e.id, "source": e.src_id, "target": e.dst_id, "type": e.type,
            "src_kind": e.src_kind, "dst_kind": e.dst_kind,
            "origin": e.origin, "confidence": e.confidence,
        }
        for e in edges
    ]
    return {"project_id": project_id, "nodes": nodes, "edges": out_edges}


def export_graph(session: Session, project_id: str, path: str | Path) -> Path:
    graph = build_graph(session, project_id)
    out = Path(path)
    out.write_text(json.dumps(graph, indent=2))
    return out
