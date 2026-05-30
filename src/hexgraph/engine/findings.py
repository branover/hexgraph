"""Persist emitted Findings (pydantic) as DB rows, and convert back."""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Finding as FindingRow
from hexgraph.db.models import FindingStatus
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
