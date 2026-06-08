"""Hypotheses: the researcher's open questions, evidenced over time (P6).

A hypothesis is a first-class `hypothesis` node ("the CGI handler trusts a
length field from the network"). Findings attach to it as evidence via
`supports`/`refutes` edges (finding → hypothesis). The node's `status` is
*derived* from that evidence (open → supported / refuted / contested) unless a
human pins a verdict (confirmed / rejected), which is sticky.

Open and supported hypotheses about a target flow into that target's task
context (engine/context.py) so the agent reasons against the live question set —
the same human-ground-truth feedback loop annotations use.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Edge, EdgeType, Finding, Node, NodeType, Project, Target
from hexgraph.engine.edges import add_edge
from hexgraph.engine.nodes import get_or_create_node

# Evidence relations (stored as edge types). `contradicts` reads as refuting.
# `confirms`/`contradicts` are accepted aliases for `supports`/`refutes`: agents
# reach for "confirms" on a verified finding (it's an advertised edge type), so we
# map it to a supporting edge rather than rejecting it.
SUPPORTS = "supports"
REFUTES = "refutes"
RELATIONS = {
    SUPPORTS: EdgeType.supports,
    REFUTES: EdgeType.refutes,
    "confirms": EdgeType.supports,
    "contradicts": EdgeType.refutes,
}
_REFUTING = (EdgeType.refutes.value, EdgeType.contradicts.value)

# Derived states + the two sticky human verdicts.
DERIVED = ("open", "supported", "refuted", "contested")
HUMAN_VERDICTS = ("confirmed", "rejected")
STATUSES = DERIVED + HUMAN_VERDICTS

# The WORK-STATE axis (design-working-memory.md §4.2) — orthogonal to the evidence
# `status` above. `status` answers "what does the evidence say?"; `work_state` answers
# "am I on this?". A fresh hypothesis is `investigating`; "checking it off" sets `done`
# and records the evidence verdict separately. The single source of truth, imported into
# both the MCP catalog enum and meta_get_schemas so they can't drift.
WORK_STATES = ("investigating", "parked", "done")
DEFAULT_WORK_STATE = "investigating"


class HypothesisError(ValueError):
    pass


def create_hypothesis(
    session: Session, project: Project, *, statement: str, rationale: str | None = None,
    target_id: str | None = None, origin: str = "human",
) -> Node:
    statement = (statement or "").strip()
    if not statement:
        raise HypothesisError("a hypothesis needs a statement")
    if target_id is not None:
        t = session.get(Target, target_id)
        if t is None or t.project_id != project.id:
            raise HypothesisError(f"target {target_id} does not exist in this project")
    node = get_or_create_node(
        session, project_id=project.id, node_type=NodeType.hypothesis,
        name=statement[:120], fq_name=statement,
        attrs={"statement": statement, "rationale": rationale, "status": "open",
               "status_origin": "derived", "work_state": DEFAULT_WORK_STATE,
               "pinned_to_graph": False},
        created_by=origin,
    )
    if target_id:
        add_edge(session, project_id=project.id, src=("node", node.id), dst=("target", target_id),
                 type=EdgeType.about, origin=origin, confidence=0.9)
    return node


def _require_hypothesis(session: Session, hypothesis_id: str) -> Node:
    node = session.get(Node, hypothesis_id)
    if node is None or node.node_type != NodeType.hypothesis.value:
        raise HypothesisError(f"{hypothesis_id} is not a hypothesis node")
    return node


def link_evidence(
    session: Session, project: Project, *, hypothesis_id: str, finding_id: str,
    relation: str, origin: str = "human",
) -> Edge:
    if relation not in RELATIONS:
        raise HypothesisError(f"relation must be one of {sorted(RELATIONS)}")
    node = _require_hypothesis(session, hypothesis_id)
    f = session.get(Finding, finding_id)
    if f is None or f.project_id != project.id:
        raise HypothesisError(f"finding {finding_id} does not exist in this project")
    edge = add_edge(
        session, project_id=project.id, src=("finding", finding_id), dst=("node", node.id),
        type=RELATIONS[relation], origin=origin, confidence=0.7,
    )
    recompute_status(session, node)
    return edge


def set_status(session: Session, hypothesis_id: str, status: str, *, origin: str = "human",
               rationale: str | None = None) -> Node:
    if status not in STATUSES:
        raise HypothesisError(f"invalid status {status!r} (allowed: {list(STATUSES)})")
    node = _require_hypothesis(session, hypothesis_id)
    attrs = dict(node.attrs_json or {})
    attrs["status"] = status
    attrs["status_origin"] = origin
    if rationale:
        attrs["status_note"] = rationale
    node.attrs_json = attrs
    # A human reopening to a derived state hands control back to the evidence.
    if origin == "human" and status in DERIVED:
        recompute_status(session, node)
    return node


def set_work_state(session: Session, hypothesis_id: str, work_state: str, *,
                   verdict: str | None = None, origin: str = "human",
                   rationale: str | None = None) -> Node:
    """Move a hypothesis along the work-state axis (investigating/parked/done) — orthogonal
    to the evidence `status`. "Checking off" is `work_state="done"`; pass `verdict` to also
    record what the evidence said on close (confirmed/rejected/… via set_status)."""
    if work_state not in WORK_STATES:
        raise HypothesisError(f"invalid work_state {work_state!r} (allowed: {list(WORK_STATES)})")
    node = _require_hypothesis(session, hypothesis_id)
    attrs = dict(node.attrs_json or {})
    attrs["work_state"] = work_state
    node.attrs_json = attrs
    # Closing with a verdict records the evidence outcome on the orthogonal status axis.
    if verdict is not None:
        set_status(session, hypothesis_id, verdict, origin=origin, rationale=rationale)
    return node


def set_pinned(session: Session, hypothesis_id: str, pinned: bool) -> Node:
    """Pin/unpin a hypothesis to the graph canvas (attrs.pinned_to_graph). Unpinned (the
    default) hypotheses live in the worklist panel and stay OFF the canvas to keep it clean."""
    node = _require_hypothesis(session, hypothesis_id)
    attrs = dict(node.attrs_json or {})
    attrs["pinned_to_graph"] = bool(pinned)
    node.attrs_json = attrs
    return node


def _evidence_edges(session: Session, node_id: str) -> list[Edge]:
    return (
        session.query(Edge)
        .filter(Edge.dst_kind == "node", Edge.dst_id == node_id, Edge.src_kind == "finding",
                Edge.type.in_((EdgeType.supports.value, *_REFUTING)))
        .all()
    )


def recompute_status(session: Session, node: Node) -> str:
    """Derive status from supporting/refuting findings — unless a human pinned a
    verdict (confirmed/rejected), which stays put until they reopen it."""
    attrs = dict(node.attrs_json or {})
    if attrs.get("status_origin") == "human" and attrs.get("status") in HUMAN_VERDICTS:
        return attrs["status"]
    edges = _evidence_edges(session, node.id)
    s = sum(1 for e in edges if e.type == EdgeType.supports.value)
    r = sum(1 for e in edges if e.type in _REFUTING)
    if s and r:
        status = "contested"
    elif s:
        status = "supported"
    elif r:
        status = "refuted"
    else:
        status = "open"
    attrs["status"] = status
    attrs["status_origin"] = "derived"
    node.attrs_json = attrs
    return status


def summary(session: Session, hypothesis_id: str) -> dict:
    node = _require_hypothesis(session, hypothesis_id)
    attrs = node.attrs_json or {}
    supports, refutes = [], []
    for e in _evidence_edges(session, node.id):
        f = session.get(Finding, e.src_id)
        if f is None:
            continue
        item = {"finding_id": f.id, "title": f.title, "severity": f.severity,
                "status": f.status, "origin": e.origin}
        (supports if e.type == EdgeType.supports.value else refutes).append(item)
    return {
        "id": node.id,
        "statement": attrs.get("statement", node.name),
        "rationale": attrs.get("rationale"),
        "status": attrs.get("status", "open"),
        "status_origin": attrs.get("status_origin", "derived"),
        "work_state": attrs.get("work_state", DEFAULT_WORK_STATE),
        "pinned_to_graph": bool(attrs.get("pinned_to_graph", False)),
        "supports": supports,
        "refutes": refutes,
    }


def list_hypotheses(session: Session, project: Project, *, work_state: str | None = None,
                    status: str | None = None) -> list[dict]:
    """The hypothesis worklist for a project — a summary row per hypothesis (statement,
    evidence status, work_state, pinned_to_graph, support/refute counts), newest-first.
    Optionally filter by `work_state` (investigating/parked/done) and/or evidence `status`.
    Backs the Hypotheses panel and the agent's "what am I working on" orient."""
    if work_state is not None and work_state not in WORK_STATES:
        raise HypothesisError(f"invalid work_state {work_state!r} (allowed: {list(WORK_STATES)})")
    if status is not None and status not in STATUSES:
        raise HypothesisError(f"invalid status {status!r} (allowed: {list(STATUSES)})")
    nodes = (
        session.query(Node)
        .filter(Node.project_id == project.id, Node.node_type == NodeType.hypothesis.value,
                Node.archived.is_(False))
        .order_by(Node.created_at.desc())
        .all()
    )
    out = []
    for n in nodes:
        attrs = n.attrs_json or {}
        ws = attrs.get("work_state", DEFAULT_WORK_STATE)
        st = attrs.get("status", "open")
        if work_state is not None and ws != work_state:
            continue
        if status is not None and st != status:
            continue
        supports = refutes = 0
        for e in _evidence_edges(session, n.id):
            if e.type == EdgeType.supports.value:
                supports += 1
            else:
                refutes += 1
        out.append({
            "id": n.id,
            "statement": attrs.get("statement", n.name),
            "rationale": attrs.get("rationale"),
            "status": st,
            "status_origin": attrs.get("status_origin", "derived"),
            "work_state": ws,
            "pinned_to_graph": bool(attrs.get("pinned_to_graph", False)),
            "supports_count": supports,
            "refutes_count": refutes,
            "created_at": n.created_at.isoformat() if n.created_at else None,
        })
    return out


def open_for_target(session: Session, project_id: str, target_id: str) -> list[dict]:
    """Open/supported/contested hypotheses anchored (`about`) to a target — the
    live question set fed into that target's task context."""
    edges = (
        session.query(Edge)
        .filter(Edge.project_id == project_id, Edge.type == EdgeType.about.value,
                Edge.src_kind == "node", Edge.dst_kind == "target", Edge.dst_id == target_id)
        .all()
    )
    out = []
    for e in edges:
        n = session.get(Node, e.src_id)
        if n is None or n.node_type != NodeType.hypothesis.value:
            continue
        attrs = n.attrs_json or {}
        if attrs.get("status") in ("open", "supported", "contested"):
            out.append({"statement": attrs.get("statement", n.name), "status": attrs.get("status")})
    return out


def unevidenced_investigating_for_target(session: Session, project_id: str,
                                         target_id: str) -> list[str]:
    """Statements of hypotheses anchored to this target that are still being actively
    chased (`work_state="investigating"`) but have NO linked evidence yet — the stale
    worklist entries the Layer-2 context nudge surfaces so the agent wires evidence or
    closes them as it works (design-working-memory.md §6)."""
    edges = (
        session.query(Edge)
        .filter(Edge.project_id == project_id, Edge.type == EdgeType.about.value,
                Edge.src_kind == "node", Edge.dst_kind == "target", Edge.dst_id == target_id)
        .all()
    )
    out: list[str] = []
    for e in edges:
        n = session.get(Node, e.src_id)
        if n is None or n.node_type != NodeType.hypothesis.value or n.archived:
            continue
        attrs = n.attrs_json or {}
        if attrs.get("work_state", DEFAULT_WORK_STATE) != "investigating":
            continue
        if _evidence_edges(session, n.id):
            continue
        out.append(attrs.get("statement", n.name))
    return out
