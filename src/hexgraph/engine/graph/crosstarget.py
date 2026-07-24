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
from hexgraph.db.session import release_write_lock
from hexgraph.engine.graph.edges import add_edge

# Commit the accumulated similar_to edges every this many so a large same-content clique doesn't
# hold the single SQLite write lock across thousands of inserts (bounds the hold; busy_timeout
# absorbs the brief re-acquire).
_LINK_COMMIT_EVERY = 500


def link_same_code(session: Session, project_id: str) -> int:
    """Create `similar_to` edges between same-content function nodes in different
    targets. Idempotent. Returns edges created.

    NB: on a large clique this commits the caller's session every `_LINK_COMMIT_EVERY` edges to
    bound the write-lock hold — so it is NOT transaction-neutral. Both current callers (the MCP
    `link_same_code` tool and the recon pipeline) run it as a self-contained unit, which is fine."""
    nodes = (
        session.query(Node)
        .filter(Node.project_id == project_id, Node.node_type == NodeType.function.value,
                Node.content_hash.isnot(None))
        .all()
    )
    by_hash: dict[str, list[Node]] = defaultdict(list)
    for n in nodes:
        by_hash[n.content_hash].append(n)

    # Pre-load the project's existing similar_to pairs ONCE (as undirected {src,dst} keys) instead
    # of a per-pair `session.query(Edge).first()` — that existence check ran O(pairs) round-trips
    # under the write lock (the #291 O(N²) shape) and, being a directed src/dst match, could even
    # miss an edge stored in the opposite order. One query + an O(1) set lookup fixes both.
    existing: set[frozenset[str]] = {
        frozenset((src, dst)) for src, dst in
        session.query(Edge.src_id, Edge.dst_id).filter(
            Edge.project_id == project_id, Edge.type == EdgeType.similar_to.value).all()
    }

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
                key = frozenset((a.id, b.id))
                if key in existing:
                    continue
                add_edge(session, project_id=project_id, src=("node", a.id), dst=("node", b.id),
                         type=EdgeType.similar_to, origin="derived", confidence=1.0, directed=False,
                         weight=1.0, attrs={"by": "content_hash"})
                existing.add(key)
                created += 1
                if created % _LINK_COMMIT_EVERY == 0:
                    release_write_lock(session)
    return created
