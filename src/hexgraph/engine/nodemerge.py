"""Merge duplicate graph entities without losing analysis (design §3.2 identity).

Duplicates arise when the same function/symbol/binary is materialized from
different code paths or names — e.g. radare2's `sym.get_param` vs a bare
`get_param`, or the same bytes ingested at two paths. We collapse them by a
per-type **canonical key**:

  function/symbol/struct → (target, normalized name)   (sym./imp./loc. stripped)
  string                 → (target, content_hash of the value)
  pattern                → content_hash
  hypothesis/other       → (target, fq_name)
  target (binary)        → sha256 of the bytes, within the project

The keeper is the most-complete node (real body hash > has address > clean name >
oldest). Everything attached to a duplicate is moved onto the keeper — edges
(re-pointed, self-edges dropped), findings, annotations, child targets, and a
union of attrs (with the duplicate's names kept in `name_history`) — so no
information is lost. Idempotent.
"""

from __future__ import annotations

from collections import defaultdict

from sqlalchemy.orm import Session

from hexgraph.db.models import Annotation, Edge, Finding, Node, Target, Task
from hexgraph.engine.edges import edges_touching
from hexgraph.engine.nodes import normalize_symbol_name


# --- nodes --------------------------------------------------------------------

def _node_key(n: Node):
    t = n.node_type
    if t == "string":
        return (t, n.target_id, n.content_hash or n.name)
    if t in ("function", "symbol", "struct"):
        return (t, n.target_id, normalize_symbol_name(n.fq_name or n.name))
    if t == "pattern":
        return (t, None, n.content_hash or n.fq_name or n.name)
    return (t, n.target_id, n.fq_name or n.name)


def _node_keeper(group: list[Node]) -> Node:
    # group is created_at-ascending; prefer real body > address > clean name, then oldest.
    def score(n: Node):
        clean = normalize_symbol_name(n.name) == n.name
        return (bool(n.content_hash), bool(n.address), clean)
    best = group[0]
    for n in group[1:]:
        if score(n) > score(best):
            best = n
    return best


def _absorb_node(session: Session, keeper: Node, dup: Node) -> None:
    for e in edges_touching(session, "node", dup.id):
        if e.src_kind == "node" and e.src_id == dup.id:
            e.src_id = keeper.id
        if e.dst_kind == "node" and e.dst_id == dup.id:
            e.dst_id = keeper.id
        if e.src_kind == "node" and e.dst_kind == "node" and e.src_id == e.dst_id:
            session.delete(e)  # self-edge created by the merge
    (session.query(Annotation)
     .filter(Annotation.node_kind == "node", Annotation.node_id == dup.id)
     .update({Annotation.node_id: keeper.id}, synchronize_session=False))

    merged = dict(keeper.attrs_json or {})
    for k, v in (dup.attrs_json or {}).items():
        merged.setdefault(k, v)
    history = set(merged.get("name_history") or [])
    for nm in (dup.name, dup.fq_name, merged.get("name_raw")):
        if nm and nm != keeper.name:
            history.add(nm)
    if history:
        merged["name_history"] = sorted(history)
    keeper.attrs_json = merged
    if not keeper.content_hash and dup.content_hash:
        keeper.content_hash = dup.content_hash
    if not keeper.address and dup.address:
        keeper.address = dup.address
    session.delete(dup)


def merge_duplicate_nodes(session: Session, project_id: str) -> int:
    """Collapse duplicate nodes in a project; returns the number removed."""
    nodes = (session.query(Node).filter(Node.project_id == project_id)
             .order_by(Node.created_at.asc()).all())
    groups: dict[tuple, list[Node]] = defaultdict(list)
    for n in nodes:
        groups[_node_key(n)].append(n)
    removed = 0
    for group in groups.values():
        if len(group) < 2:
            continue
        keeper = _node_keeper(group)
        # canonicalize the keeper's display/identity to the clean name
        if keeper.node_type in ("function", "symbol", "struct"):
            keeper.name = normalize_symbol_name(keeper.name) or keeper.name
            keeper.fq_name = normalize_symbol_name(keeper.fq_name or keeper.name)
        for dup in group:
            if dup.id == keeper.id:
                continue
            _absorb_node(session, keeper, dup)
            removed += 1
    session.flush()
    return removed


# --- targets (binaries) -------------------------------------------------------

def _target_sha(t: Target) -> str | None:
    return (t.metadata_json or {}).get("sha256")


def _absorb_target(session: Session, keeper: Target, dup: Target) -> None:
    # reparent everything that pointed at the duplicate binary
    session.query(Target).filter(Target.parent_id == dup.id).update(
        {Target.parent_id: keeper.id}, synchronize_session=False)
    session.query(Finding).filter(Finding.target_id == dup.id).update(
        {Finding.target_id: keeper.id}, synchronize_session=False)
    session.query(Node).filter(Node.target_id == dup.id).update(
        {Node.target_id: keeper.id}, synchronize_session=False)
    session.query(Task).filter(Task.target_id == dup.id).update(
        {Task.target_id: keeper.id}, synchronize_session=False)
    for e in edges_touching(session, "target", dup.id):
        if e.src_kind == "target" and e.src_id == dup.id:
            e.src_id = keeper.id
        if e.dst_kind == "target" and e.dst_id == dup.id:
            e.dst_id = keeper.id
        if e.src_kind == "target" and e.dst_kind == "target" and e.src_id == e.dst_id:
            session.delete(e)
    (session.query(Annotation)
     .filter(Annotation.node_kind == "target", Annotation.node_id == dup.id)
     .update({Annotation.node_id: keeper.id}, synchronize_session=False))
    if dup.parent_id and not keeper.parent_id:
        keeper.parent_id = dup.parent_id
    session.delete(dup)


def merge_duplicate_targets(session: Session, project_id: str) -> int:
    """Collapse targets with identical bytes (same sha256) in a project. The keeper
    is the one with the most children/findings (then oldest). Returns removed."""
    targets = (session.query(Target).filter(Target.project_id == project_id)
               .order_by(Target.created_at.asc()).all())
    groups: dict[str, list[Target]] = defaultdict(list)
    for t in targets:
        sha = _target_sha(t)
        if sha:
            groups[sha].append(t)
    child_count = defaultdict(int)
    for t in targets:
        if t.parent_id:
            child_count[t.parent_id] += 1
    finding_count: dict[str, int] = defaultdict(int)
    for (tid,) in session.query(Finding.target_id).filter(Finding.project_id == project_id):
        finding_count[tid] += 1

    removed = 0
    for group in groups.values():
        if len(group) < 2:
            continue
        keeper = max(group, key=lambda t: (child_count[t.id], finding_count[t.id]))
        for dup in group:
            if dup.id == keeper.id:
                continue
            _absorb_target(session, keeper, dup)
            removed += 1
    session.flush()
    return removed


def merge_duplicates(session: Session, project_id: str) -> dict:
    """Full pass: merge duplicate binaries first (which re-homes their nodes), then
    duplicate nodes. Idempotent."""
    targets = merge_duplicate_targets(session, project_id)
    nodes = merge_duplicate_nodes(session, project_id)
    return {"targets_merged": targets, "nodes_merged": nodes}
