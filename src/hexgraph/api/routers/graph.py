"""Graph authoring: nodes, edges, sockets, the typed schemas, and graph JSON."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from hexgraph.db.models import Edge, Node, Project
from hexgraph.db.session import session_scope
from hexgraph.engine.authoring import (
    InvariantError,
    create_edge,
    create_node,
    create_socket,
)
from hexgraph.engine.edge_schemas import SOCKET_KINDS, describe_edges, merge_edge_attrs
from hexgraph.engine.graph import build_graph, build_room, build_skeleton, graph_size
from hexgraph.engine.node_schemas import describe_nodes
from hexgraph.engine.nodes import normalize_symbol_name
from hexgraph.engine.removal import archive_node, delete_edge, restore_node

from ._shared import EdgeAttrsUpdate, EdgeCreate, NodeCreate, NodePatch, SocketCreate

router = APIRouter()


# --- Nodes ---
@router.post("/api/projects/{project_id}/nodes")
def api_create_node(project_id: str, body: NodeCreate):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            n = create_node(s, project, node_type=body.node_type, name=body.name,
                            target_id=body.target_id, address=body.address, attrs=body.attrs)
        except InvariantError as exc:
            raise HTTPException(400, str(exc))
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "target_id": n.target_id,
                "address": n.address, "attrs": n.attrs_json or {}}


@router.delete("/api/projects/{project_id}/nodes/{node_id}")
def api_remove_node(project_id: str, node_id: str):
    """Soft-remove a node (REVERSIBLE): hides the node and the edges touching it.
    Re-adding the same node, or POST .../restore, brings it and its edges back."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        try:
            n = archive_node(s, project_id, node_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        return {"archived": n.archived, "id": n.id}


@router.post("/api/projects/{project_id}/nodes/{node_id}/restore")
def api_restore_node(project_id: str, node_id: str):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        try:
            n = restore_node(s, project_id, node_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))
        return {"archived": n.archived, "id": n.id}


@router.patch("/api/projects/{project_id}/nodes/{node_id}")
def api_patch_node(project_id: str, node_id: str, body: NodePatch):
    """Edit a node's fields from the UI (name/address/attrs). Renaming a function/
    symbol/struct also updates its normalized identity so it stays dedupable."""
    with session_scope() as s:
        n = s.get(Node, node_id)
        if n is None or n.project_id != project_id:
            raise HTTPException(404, "node not found")
        if body.name is not None and body.name.strip():
            name = body.name.strip()
            if n.node_type in ("function", "symbol", "struct"):
                name = normalize_symbol_name(name) or name
            n.name = name
            n.fq_name = name
        if body.address is not None:
            n.address = body.address or None
        if body.attrs is not None:
            n.attrs_json = body.attrs
        return {"id": n.id, "node_type": n.node_type, "name": n.name,
                "address": n.address, "attrs": n.attrs_json or {}}


# --- Edges ---
@router.post("/api/projects/{project_id}/edges")
def api_create_edge(project_id: str, body: EdgeCreate):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            e = create_edge(s, project, src_kind=body.src_kind, src_id=body.src_id,
                            dst_kind=body.dst_kind, dst_id=body.dst_id, type=body.type,
                            attrs=body.attrs, merge=body.merge)
        except InvariantError as exc:
            raise HTTPException(400, str(exc))
        return {"id": e.id, "type": e.type, "src_id": e.src_id, "dst_id": e.dst_id,
                "attrs": e.attrs_json or {}}


@router.patch("/api/edges/{edge_id}")
def api_update_edge(edge_id: str, body: EdgeAttrsUpdate):
    with session_scope() as s:
        e = s.get(Edge, edge_id)
        if e is None:
            raise HTTPException(404, "edge not found")
        e.attrs_json = (merge_edge_attrs(e.type, e.attrs_json, body.attrs)
                        if body.merge else dict(body.attrs or {}))
        return {"id": e.id, "type": e.type, "attrs": e.attrs_json}


@router.delete("/api/edges/{edge_id}")
def api_delete_edge(edge_id: str):
    """Permanently delete one edge (hard delete — recreate with POST .../edges to
    restore). To remove a node's edges reversibly, archive the node instead."""
    with session_scope() as s:
        if not delete_edge(s, edge_id):
            raise HTTPException(404, "edge not found")
        return {"deleted": True, "id": edge_id}


# --- Sockets ---
@router.post("/api/projects/{project_id}/sockets")
def api_create_socket(project_id: str, body: SocketCreate):
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            n = create_socket(s, project, kind=body.kind, port=body.port, name=body.name,
                              bind_addr=body.bind_addr, attrs=body.attrs)
        except InvariantError as exc:
            raise HTTPException(400, str(exc))
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "attrs": n.attrs_json or {}}


# --- Typed schemas ---
@router.get("/api/edge-schemas")
def api_edge_schemas():
    """What attributes are meaningful per edge type + the socket kinds — for the
    UI's edge inspector and for any client populating typed edges."""
    return {"edges": describe_edges(), "socket_kinds": list(SOCKET_KINDS)}


@router.get("/api/node-schemas")
def api_node_schemas():
    """Per node-type description, when-to-use, and recommended attributes — for the
    Add-node UI help and any client populating nodes consistently."""
    return {"nodes": describe_nodes()}


# --- Graph JSON ---
@router.get("/graph/{project_id}")
def api_graph(project_id: str):
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return build_graph(s, project_id)


@router.get("/graph/{project_id}/size")
def api_graph_size(project_id: str):
    """Cheap node/edge counts so the client decides skeleton-first vs full load
    WITHOUT first fetching the whole (possibly ~13k-node) graph."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return graph_size(s, project_id)


@router.get("/graph/{project_id}/skeleton")
def api_graph_skeleton(project_id: str):
    """The STRUCTURAL SKELETON: rooms (byte targets) with per-room counts +
    worst-severity rollup, the shared sockets, and aggregated cross-room
    meta-edges. NO interiors — a ~13k-node firmware collapses to a few hundred
    countable rooms the browser can render at once. Expand a room → /room/<id>."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return build_skeleton(s, project_id)


@router.get("/graph/{project_id}/room/{target_id}")
def api_graph_room(project_id: str, target_id: str):
    """One room's INTERIOR on demand: the target's nodes + findings + the edges
    among them (and to the shared sockets). Loaded when the user expands a room
    in the skeleton, so the browser never receives every interior at once."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        return build_room(s, project_id, target_id)
