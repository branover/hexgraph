"""Cross-target "same code as" (P7-4).

Links function nodes that share a content hash across *different* targets with a
`similar_to` edge (the n-day-hunting primitive: the same vulnerable routine
reused across binaries/firmware versions). Local-only; uses the content-addressed
identity already on nodes.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, EdgeType, Node, NodeType
from hexgraph.engine.edges import add_edge


def link_same_code(session: Session, project_id: str) -> int:
    """Create `similar_to` edges between same-content function nodes in different
    targets. Idempotent. Returns edges created."""
    nodes = (
        session.query(Node)
        .filter(Node.project_id == project_id, Node.node_type == NodeType.function.value,
                Node.content_hash.isnot(None))
        .all()
    )
    by_hash: dict[str, list[Node]] = defaultdict(list)
    for n in nodes:
        by_hash[n.content_hash].append(n)

    created = 0
    for group in by_hash.values():
        # only link across distinct targets
        if len({n.target_id for n in group}) < 2:
            continue
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                if a.target_id == b.target_id:
                    continue
                exists = (
                    session.query(Edge)
                    .filter(Edge.project_id == project_id, Edge.type == EdgeType.similar_to.value,
                            Edge.src_id == a.id, Edge.dst_id == b.id)
                    .first()
                )
                if exists:
                    continue
                add_edge(session, project_id=project_id, src=("node", a.id), dst=("node", b.id),
                         type=EdgeType.similar_to, origin="derived", confidence=1.0, directed=False,
                         weight=1.0, attrs={"by": "content_hash"})
                created += 1
    return created
