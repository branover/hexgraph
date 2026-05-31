"""Persist emitted Findings (pydantic) as DB rows, and convert back."""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType
from hexgraph.db.models import Finding as FindingRow
from hexgraph.db.models import FindingStatus
from hexgraph.engine.edges import add_edge
from hexgraph.engine.nodes import materialize_function
from hexgraph.models.finding import Finding


def persist_finding(
    session: Session,
    *,
    project_id: str,
    target_id: str,
    task_id: str,
    finding: Finding,
    status: FindingStatus = FindingStatus.new,
) -> FindingRow:
    """Store a schema-shaped Finding payload as a DB row with the envelope."""
    row = FindingRow(
        project_id=project_id,
        target_id=target_id,
        task_id=task_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        category=finding.category,
        summary=finding.summary,
        reasoning=finding.reasoning,
        evidence_json=finding.evidence.model_dump(exclude_none=True),
        suggested_followups_json=[
            f.model_dump(exclude_none=True) for f in (finding.suggested_followups or [])
        ],
        related_target_refs_json=list(finding.related_target_refs or []),
        status=status,
    )
    session.add(row)
    session.flush()

    # Attach the finding to the finest node its evidence concerns via an `about`
    # edge (design ruling #7). Falls back to the coarse target. `finding.target_id`
    # remains the coarse pointer.
    func = finding.evidence.function
    if func:
        node = materialize_function(
            session, project_id=project_id, target_id=target_id, name=func, created_by="llm"
        )
        add_edge(
            session, project_id=project_id,
            src=("finding", row.id), dst=("node", node.id),
            type=EdgeType.about, origin="derived", confidence=1.0,
            attrs={"role": "primary"},
        )
        # Auto-populate the node with context from the LLM call (agent-proposed
        # note, deduped). Gives freshly-materialized nodes some description; the
        # analyst confirms it before it feeds back into context as authoritative.
        from hexgraph.engine.annotations import auto_note

        sink = f" [sink: {finding.evidence.sink}]" if finding.evidence.sink else ""
        auto_note(session, project_id, node_kind="node", node_id=node.id,
                  value=f"[{finding.severity}] {finding.category}: {finding.title}{sink}")
    else:
        add_edge(
            session, project_id=project_id,
            src=("finding", row.id), dst=("target", target_id),
            type=EdgeType.about, origin="derived", confidence=1.0,
            attrs={"role": "context"},
        )
    return row


def row_to_payload(row: FindingRow) -> dict:
    """DB row -> schema-shaped payload dict (for export / API)."""
    payload: dict = {
        "title": row.title,
        "severity": row.severity,
        "confidence": row.confidence,
        "category": row.category,
        "summary": row.summary,
        "reasoning": row.reasoning,
        "evidence": row.evidence_json or {},
    }
    if row.suggested_followups_json:
        payload["suggested_followups"] = row.suggested_followups_json
    if row.related_target_refs_json:
        payload["related_target_refs"] = row.related_target_refs_json
    return payload
