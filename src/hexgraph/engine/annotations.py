"""Annotations: human/agent rename · note · tag · type_decl on graph entities (P6).

Confirmed **renames** update a node's display `name` (keeping `fq_name` as the
durable identity, with `attrs.name_history`). Confirmed renames + notes flow back
into agent context (the "ANALYST-CONFIRMED FACTS" loop). Tags are a findings
filter facet. Agent-proposed annotations land `proposed` for human confirm/reject.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Annotation, Finding, Node, Target
from hexgraph.engine.nodes import is_placeholder_name

KINDS = {"rename", "note", "tag", "type_decl"}
NODE_KINDS = {"target", "node", "finding"}


class AnnotationError(ValueError):
    pass


def _entity(session: Session, project_id: str, node_kind: str, node_id: str):
    model = {"target": Target, "node": Node, "finding": Finding}.get(node_kind)
    if model is None:
        return None
    row = session.get(model, node_id)
    return row if row is not None and row.project_id == project_id else None


def create_annotation(
    session: Session, project_id: str, *, node_kind: str, node_id: str, kind: str, value: str,
    origin: str = "human",
) -> Annotation:
    if kind not in KINDS:
        raise AnnotationError(f"invalid annotation kind {kind!r} (allowed: {sorted(KINDS)})")
    if node_kind not in NODE_KINDS:
        raise AnnotationError(f"invalid node_kind {node_kind!r}")
    if not (value or "").strip():
        raise AnnotationError("annotation value is required")
    ent = _entity(session, project_id, node_kind, node_id)
    if ent is None:
        raise AnnotationError(f"{node_kind} {node_id} does not exist in this project")
    if kind == "rename" and node_kind != "node":
        raise AnnotationError("rename annotations apply only to nodes")
    status = "confirmed" if origin == "human" else "proposed"
    # Naming a genuinely-unnamed object (a decompiler placeholder like `fcn.00401234`)
    # is pure value-add — nothing meaningful is overwritten — so an agent's rename of a
    # placeholder-named node auto-confirms (still audited: the annotation row stays
    # origin=agent, and _apply_rename appends the old placeholder to name_history).
    # Renaming a node that already has a real name is higher-stakes and still needs a
    # human confirm. (Owner decision.)
    if kind == "rename" and status == "proposed" and is_placeholder_name(ent.name):
        status = "confirmed"
    ann = Annotation(project_id=project_id, node_kind=node_kind, node_id=node_id, kind=kind,
                     value=value.strip(), origin=origin, status=status)
    session.add(ann)
    session.flush()
    if status == "confirmed" and kind == "rename":
        _apply_rename(session, ent, value.strip())
    return ann


def auto_note(
    session: Session, project_id: str, *, node_kind: str, node_id: str, value: str, origin: str = "agent",
) -> Annotation | None:
    """Auto-populate a node's context from an LLM task (HITL: lands `proposed`).
    De-duplicated — an identical note on the same node is not re-added (so re-runs
    don't spam). Returns the existing/created annotation, or None for empty input."""
    value = (value or "").strip()
    if not value:
        return None
    existing = (
        session.query(Annotation)
        .filter(Annotation.project_id == project_id, Annotation.node_kind == node_kind,
                Annotation.node_id == node_id, Annotation.kind == "note", Annotation.value == value)
        .first()
    )
    if existing is not None:
        return existing
    return create_annotation(session, project_id, node_kind=node_kind, node_id=node_id,
                             kind="note", value=value, origin=origin)


def set_status(session: Session, annotation_id: str, status: str) -> Annotation:
    if status not in ("proposed", "confirmed", "rejected"):
        raise AnnotationError(f"invalid status {status!r}")
    ann = session.get(Annotation, annotation_id)
    if ann is None:
        raise AnnotationError("annotation not found")
    ann.status = status
    if status == "confirmed" and ann.kind == "rename" and ann.node_kind == "node":
        node = session.get(Node, ann.node_id)
        if node is not None:
            _apply_rename(session, node, ann.value)
    return ann


def _apply_rename(session: Session, node: Node, new_name: str) -> None:
    attrs = dict(node.attrs_json or {})
    history = list(attrs.get("name_history") or [])
    if node.name and node.name != new_name:
        history.append(node.name)
    attrs["name_history"] = history
    node.attrs_json = attrs
    node.name = new_name  # display name; fq_name stays the durable identity

    # Phase 3 rename round-trip: best-effort, propagate the rename INTO the persistent Ghidra
    # project and re-decompile so it sticks for every future decompile. A no-op unless headless
    # Ghidra is the active, project-backed backend (radare2 users pay only a couple of config
    # checks). Never let a Ghidra hiccup break the confirmed graph rename — propagation is gravy.
    try:
        from hexgraph.engine.re.ghidra import propagate_function_rename

        propagate_function_rename(session, node, new_name)
    except Exception:  # noqa: BLE001
        pass


def list_for(session: Session, project_id: str, node_kind: str, node_id: str) -> list[Annotation]:
    return (
        session.query(Annotation)
        .filter(Annotation.project_id == project_id, Annotation.node_kind == node_kind, Annotation.node_id == node_id)
        .order_by(Annotation.created_at.asc()).all()
    )


def confirmed_facts(session: Session, project_id: str, target_id: str) -> list[str]:
    """Confirmed renames/notes for a target and its nodes — for the context feedback loop."""
    node_ids = [n.id for n in session.query(Node).filter(Node.project_id == project_id, Node.target_id == target_id).all()]
    anns = (
        session.query(Annotation)
        .filter(Annotation.project_id == project_id, Annotation.status == "confirmed",
                Annotation.kind.in_(("rename", "note", "type_decl")))
        .all()
    )
    facts = []
    for a in anns:
        if (a.node_kind == "target" and a.node_id == target_id) or (a.node_kind == "node" and a.node_id in node_ids):
            facts.append(f"{a.kind}: {a.value}")
    return facts
