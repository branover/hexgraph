"""Authoring with enforced invariants (web app = no CLI required).

Everything the CLI can create, the API can — but creation is gated so the graph
stays meaningful:

- **Targets** (binaries/firmware) can ONLY come from real uploaded bytes, and
  their classification (kind/format/arch/hashes) is populated by sandboxed recon,
  never claimed by the caller. (See the API upload handler.)
- **Sub-file nodes** (function/symbol/string/struct) require their binary
  (`target_id`) to already exist in the project — you can't create a function
  node without the binary existing.
- **Edges** must connect entities that actually exist in the project.

Violations raise `InvariantError` (mapped to HTTP 400 by the API).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import (
    EDGE_KINDS, BuildSpec, Edge, EdgeType, Finding, Node, NodeType, Project, SourceTree,
    Target, Task,
)
from hexgraph.engine.edges import add_edge
from hexgraph.engine.nodes import get_or_create_node

# Node types a human may hand-author. `task` is not authorable (tasks come from
# launching analysis); `target` is not a node (it requires uploaded bytes).
MANUAL_NODE_TYPES = {"function", "symbol", "string", "struct", "hypothesis", "pattern",
                     "input", "sink", "socket", "endpoint", "param"}
# These belong to a specific target (a binary, or a web surface), so they require one.
TARGET_BOUND = {"function", "symbol", "string", "struct", "endpoint", "param"}


class InvariantError(ValueError):
    """A create request violated a graph invariant."""


def _entity_exists(session: Session, project_id: str, kind: str, id_: str) -> bool:
    # `source_tree`/`build_spec` are polymorphic edge endpoints (built_from / builds)
    # — SQL entities, not nodes — so they join the existence check alongside target/
    # node/finding/task (design §4.5 D-edge widening).
    model = {"target": Target, "node": Node, "finding": Finding, "task": Task,
             "source_tree": SourceTree, "build_spec": BuildSpec}.get(kind)
    if model is None:
        return False
    row = session.get(model, id_)
    return row is not None and getattr(row, "project_id", None) == project_id


def create_node(
    session: Session, project: Project, *, node_type: str, name: str,
    target_id: str | None = None, address: str | None = None, attrs: dict[str, Any] | None = None,
) -> Node:
    if node_type not in MANUAL_NODE_TYPES:
        raise InvariantError(
            f"node_type {node_type!r} cannot be hand-created (allowed: {sorted(MANUAL_NODE_TYPES)}; "
            "binaries/firmware are added by uploading a file)"
        )
    # Sockets have their own identity (kind+port|name, shared across binaries) — route
    # to the dedicated builder, taking kind/port/name/bind_addr from attrs.
    if node_type == "socket":
        a = dict(attrs or {})
        return create_socket(session, project, kind=a.get("kind", "tcp"), port=a.get("port"),
                             name=a.get("name") or (name if not a.get("port") else None),
                             bind_addr=a.get("bind_addr"),
                             attrs={k: v for k, v in a.items()
                                    if k not in ("kind", "port", "name", "bind_addr")})
    if not (name or "").strip():
        raise InvariantError("node name is required")
    if node_type in TARGET_BOUND:
        if not target_id:
            raise InvariantError(f"a {node_type} node requires target_id (the binary it lives in)")
        if not _entity_exists(session, project.id, "target", target_id):
            raise InvariantError(f"target {target_id} does not exist in this project")
    elif target_id and not _entity_exists(session, project.id, "target", target_id):
        raise InvariantError(f"target {target_id} does not exist in this project")
    return get_or_create_node(
        session, project_id=project.id, node_type=NodeType(node_type), name=name.strip(),
        target_id=target_id, address=address, attrs=attrs, created_by="human",
    )


def create_socket(
    session: Session, project: Project, *, kind: str = "tcp", port: int | str | None = None,
    name: str | None = None, bind_addr: str | None = None, attrs: dict[str, Any] | None = None,
    created_by: str = "human",
) -> Node:
    """Create (or reuse) a socket node — a network/IPC endpoint shared across the
    firmware's binaries. Identity is (kind, port|name); a server `listens_on` it and
    a client `connects_to` it, both resolving to this one node."""
    from hexgraph.engine.edge_schemas import SOCKET_KINDS
    from hexgraph.engine.nodes import materialize_socket

    if kind not in SOCKET_KINDS:
        raise InvariantError(f"socket kind must be one of {list(SOCKET_KINDS)}")
    if port in (None, "") and not name:
        raise InvariantError("a socket needs a port or a name")
    return materialize_socket(session, project_id=project.id, kind=kind, port=port, name=name,
                              bind_addr=bind_addr, attrs=attrs, created_by=created_by)


def create_edge(
    session: Session, project: Project, *, src_kind: str, src_id: str, dst_kind: str, dst_id: str,
    type: str, attrs: dict[str, Any] | None = None, confidence: float | None = 1.0,
    merge: bool = False,
) -> Edge:
    if src_kind not in EDGE_KINDS or dst_kind not in EDGE_KINDS:
        raise InvariantError(f"edge endpoint kinds must be one of {EDGE_KINDS}")
    try:
        edge_type = EdgeType(type)
    except ValueError:
        raise InvariantError(f"invalid edge type {type!r}")
    if src_kind == dst_kind and src_id == dst_id:
        raise InvariantError("an edge cannot connect an entity to itself")
    for kind, id_ in ((src_kind, src_id), (dst_kind, dst_id)):
        if not _entity_exists(session, project.id, kind, id_):
            raise InvariantError(f"{kind} {id_} does not exist in this project")
    return add_edge(
        session, project_id=project.id, src=(src_kind, src_id), dst=(dst_kind, dst_id),
        type=edge_type, origin="human", confidence=confidence, attrs=attrs, merge=merge,
    )
