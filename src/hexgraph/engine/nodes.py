"""Typed-node materialization (design §3.2).

Nodes are materialized lazily — on reference (a finding attaches, a task launches,
a human pins) — not eagerly for every symbol in a firmware. Identity is
content-addressed (`content_hash`) so renames/findings/edges survive
re-decompilation and match across binaries.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import Node, NodeType

# Bounded caps so recon never writes thousands of rows (design §3.2 lazy rule).
MAX_SYMBOLS = 60
MAX_STRINGS = 20


def _sha(*parts: str | None) -> str:
    return hashlib.sha256("\x00".join(p or "" for p in parts).encode("utf-8")).hexdigest()


def get_or_create_node(
    session: Session,
    *,
    project_id: str,
    node_type: NodeType | str,
    name: str,
    target_id: str | None = None,
    fq_name: str | None = None,
    address: str | None = None,
    content_hash: str | None = None,
    attrs: dict[str, Any] | None = None,
    created_by: str = "recon",
    force_hash: bool = False,
) -> Node:
    nt = node_type.value if isinstance(node_type, NodeType) else str(node_type)
    fq = fq_name or name
    q = session.query(Node).filter(Node.project_id == project_id, Node.node_type == nt)
    # Within a target, identity is the locator (target, fq_name) — so the SAME
    # function in two binaries stays two nodes (linkable by `similar_to`).
    # content_hash is a cross-target *matching attribute*, used only when there's
    # no target (e.g. patterns).
    existing = q.filter(Node.target_id == target_id, Node.fq_name == fq).first() if target_id else None
    if existing is None and content_hash and target_id is None:
        existing = q.filter(Node.content_hash == content_hash).first()
    if existing is not None:
        if attrs:
            merged = dict(existing.attrs_json or {})
            merged.update(attrs)
            existing.attrs_json = merged
        # Upgrade to a body hash when one is provided (force_hash); never downgrade.
        if content_hash and (force_hash or not existing.content_hash):
            existing.content_hash = content_hash
        return existing
    node = Node(
        project_id=project_id, node_type=nt, target_id=target_id, name=name,
        fq_name=fq, address=address, content_hash=content_hash,
        attrs_json=attrs or {}, created_by=created_by,
    )
    session.add(node)
    session.flush()
    # Tie code nodes back to the binary/library they live in (target ─contains→ node)
    # so functions/symbols are connected to their target in the graph, not floating.
    if target_id and nt in ("function", "symbol", "string", "struct"):
        from hexgraph.db.models import EdgeType
        from hexgraph.engine.edges import add_edge

        add_edge(
            session, project_id=project_id, src=("target", target_id), dst=("node", node.id),
            type=EdgeType.contains, origin="derived", confidence=1.0, attrs={"declares": nt},
        )
    return node


def materialize_function(
    session: Session, *, project_id: str, target_id: str | None, name: str,
    address: str | None = None, pseudocode: str | None = None,
    attrs: dict[str, Any] | None = None, created_by: str = "decompile",
) -> Node:
    # Prefer a body hash (matches across binaries); fall back to a locator hash.
    content_hash = _sha(pseudocode) if pseudocode else _sha(target_id, "fn", name)
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.function, name=name,
        target_id=target_id, fq_name=name, address=address,
        content_hash=content_hash, attrs=attrs, created_by=created_by,
        force_hash=bool(pseudocode),  # a real decompiled body upgrades the cross-target hash
    )


def materialize_symbol(
    session: Session, *, project_id: str, target_id: str | None, name: str,
    kind: str = "import", library: str | None = None, is_sink: bool = False,
    created_by: str = "recon",
) -> Node:
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.symbol, name=name,
        target_id=target_id, fq_name=name,
        attrs={"kind": kind, "library": library, "is_sink": is_sink},
        created_by=created_by,
    )


def materialize_string(
    session: Session, *, project_id: str, target_id: str | None, value: str,
    created_by: str = "recon",
) -> Node:
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.string,
        name=value[:120], target_id=target_id, fq_name=None,
        content_hash=_sha(value), attrs={"value": value[:512]}, created_by=created_by,
    )
