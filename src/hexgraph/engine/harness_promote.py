"""Promote transient harnesses to managed `source_file`s (design §4.3 D3).

Historically a fuzz harness lived only as a string in a `harness_generation`
finding's `evidence.decompiled_snippet` — transient, un-navigable, no history.
Phase 1 promotes harnesses to first-class `source_file(role=harness)` files in a
managed source tree, plus a `harness` graph node that `harnesses`→ the target it
exercises. PoCs and run-scripts share the SAME representation in later phases
(role=poc|script) — this sets up the role tagging now.

Two pieces, both safe and offline:
- `promote_harness(...)`: store one harness's C source into the project's managed
  harness tree, materialize a `harness` node, wire `harnesses`→target, and (when a
  finding produced it) `located_in` finding→source_file.
- `backfill_harnesses(...)`: idempotently promote every existing
  `harness_generation` finding's snippet. Run on demand (API/MCP). Old findings
  STILL render — the back-compat read path (`fuzzing.resolve_harness`) reads the
  managed source first, then falls back to `evidence.decompiled_snippet`, so nothing
  breaks before/without a backfill.

No execution here — this is pure data movement (text we authored, not target bytes).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Finding, NodeType, Project, SourceTree, Task
from hexgraph.engine.edges import add_edge
from hexgraph.engine.nodes import get_or_create_node
from hexgraph.engine.source import (
    create_source_tree,
    materialize_source_file,
    write_source_file,
)

# The per-project scratch tree that holds HexGraph-authored harnesses/PoCs/scripts.
HARNESS_TREE_NAME = "HexGraph harnesses"


def get_or_create_harness_tree(session: Session, project: Project) -> SourceTree:
    """The project's editable scratch tree for HexGraph-authored harnesses/PoCs.
    Idempotent (one per project, identified by name + origin=scratch)."""
    existing = (session.query(SourceTree)
                .filter(SourceTree.project_id == project.id, SourceTree.origin == "scratch",
                        SourceTree.name == HARNESS_TREE_NAME)
                .first())
    if existing is not None:
        return existing
    return create_source_tree(session, project, name=HARNESS_TREE_NAME, origin="scratch", editable=True)


def _harness_rel(target_id: str, function: str | None, finding_id: str | None) -> str:
    """Stable path for a harness so re-promoting the same finding is idempotent."""
    stem = (function or "harness").replace("/", "_").strip() or "harness"
    suffix = (finding_id or target_id)[:8]
    return f"{target_id}/{stem}_{suffix}.c"


def promote_harness(
    session: Session, project: Project, target_id: str, source: str, *,
    function: str | None = None, finding_id: str | None = None, role: str = "harness",
):
    """Store harness C `source` as a managed source_file + a `harness` node that
    `harnesses`→ the target, and (if from a finding) `located_in` finding→file.
    Returns the (harness_node, source_file_node). Idempotent per (target, function,
    finding)."""
    tree = get_or_create_harness_tree(session, project)
    rel = _harness_rel(target_id, function, finding_id)
    write_source_file(session, project, tree, rel, source, role=role)
    file_node = materialize_source_file(session, project, tree, rel, role=role, created_by="derived")

    # the `harness` node (a logical harness referencing its source_file)
    label = f"{function or 'harness'} ({rel.rsplit('/', 1)[-1]})"
    harness_node = get_or_create_node(
        session, project_id=project.id, node_type=NodeType.harness, name=label,
        target_id=None, fq_name=f"harness:{tree.id}:{rel}",
        attrs={"tree_id": tree.id, "rel": rel, "function": function,
               "source_finding_id": finding_id},
        created_by="derived",
    )
    # harness -> source_file (it is backed by this file)
    add_edge(session, project_id=project.id, src=("node", harness_node.id), dst=("node", file_node.id),
             type=EdgeType.located_in, origin="derived", confidence=1.0,
             created_by_tool="promote-harness", merge=True)
    # harness -> target (it exercises this target)
    add_edge(session, project_id=project.id, src=("node", harness_node.id), dst=("target", target_id),
             type=EdgeType.harnesses, origin="derived", confidence=1.0,
             created_by_tool="promote-harness",
             attrs={"function": function} if function else None, merge=True)
    if finding_id:
        add_edge(session, project_id=project.id, src=("finding", finding_id), dst=("node", file_node.id),
                 type=EdgeType.located_in, origin="derived", confidence=1.0,
                 created_by_tool="promote-harness", merge=True)
    return harness_node, file_node


def backfill_harnesses(session: Session, project: Project) -> dict:
    """Promote every `harness_generation` finding's transient snippet to a managed
    source_file + harness node. Idempotent — re-running promotes nothing new.
    Returns {promoted, scanned}."""
    rows = (session.query(Finding, Task)
            .join(Task, Finding.task_id == Task.id)
            .filter(Finding.project_id == project.id, Task.type == "harness_generation")
            .all())
    promoted = 0
    for f, t in rows:
        ev = f.evidence_json or {}
        src = ev.get("decompiled_snippet")
        if not src:
            continue
        promote_harness(session, project, f.target_id, src,
                        function=ev.get("function"), finding_id=f.id)
        promoted += 1
    session.flush()
    return {"promoted": promoted, "scanned": len(rows)}


def resolve_managed_harness(session: Session, project: Project, target_id: str) -> tuple[str | None, str | None]:
    """Back-compat-friendly lookup: the latest managed harness source_file for a
    target (read host-side), → (source, source_file_node_id). Returns (None, None)
    when no harness has been promoted (the caller then falls back to the legacy
    `evidence.decompiled_snippet` path)."""
    from hexgraph.db.models import Edge, Node
    from hexgraph.engine.source import read_source_file

    # harness nodes that `harnesses` -> this target, newest first
    edges = (session.query(Edge)
             .filter(Edge.project_id == project.id, Edge.type == EdgeType.harnesses.value,
                     Edge.dst_kind == "target", Edge.dst_id == target_id, Edge.src_kind == "node")
             .all())
    harness_ids = [e.src_id for e in edges]
    if not harness_ids:
        return None, None
    harnesses = (session.query(Node)
                 .filter(Node.id.in_(harness_ids), Node.archived.is_(False))
                 .order_by(Node.created_at.desc()).all())
    for h in harnesses:
        a = h.attrs_json or {}
        tree = session.get(SourceTree, a.get("tree_id"))
        if tree is None or not a.get("rel"):
            continue
        # find the source_file node for this harness (the located_in edge target)
        sf = (session.query(Node)
              .filter(Node.project_id == project.id, Node.node_type == NodeType.source_file.value,
                      Node.fq_name == f"{tree.id}:{a['rel']}").first())
        try:
            text = read_source_file(project, tree, a["rel"])
        except Exception:  # noqa: BLE001
            continue
        if text.get("encoding") == "text":
            return text.get("content"), (sf.id if sf else None)
    return None, None
