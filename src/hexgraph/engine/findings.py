"""Persist emitted Findings (pydantic) as DB rows, and convert back."""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType
from hexgraph.db.models import Finding as FindingRow
from hexgraph.db.models import FindingStatus, Task
from hexgraph.engine.assurance import assurance_of, default_for
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.models.finding import Finding


# Map a producing task type → the default finding_type (overridable per call).
_TYPE_BY_TASK = {
    "recon": "recon",
    "harness_generation": "harness",
    "fuzzing": "fuzz_crash",
    "poc": "poc",
}
FINDING_TYPES = ("vulnerability", "recon", "harness", "fuzz_crash", "poc", "annotation", "other")


def is_verified(evidence: dict | None) -> bool:
    """True if a PoC verification was attached to this finding's evidence and it
    passed (evidence.extra.verification.verified). The single source for the
    `verified` flag surfaced by the API and MCP read tools."""
    return bool((((evidence or {}).get("extra") or {}).get("verification") or {}).get("verified"))


def classify_finding(task_type: str | None, category: str | None) -> str:
    """Classify a finding for sort/filter from its producing task + category."""
    if category == "recon":
        return "recon"
    if category == "annotation":
        return "annotation"
    return _TYPE_BY_TASK.get(task_type or "", "vulnerability")


def normalize_cwe(value: object) -> str | None:
    """Canonicalize a CWE id to `CWE-<n>` (accepts "CWE-787" / "787" / 787 / "cwe_787").
    Returns None for anything that isn't recognizably a CWE reference — a bare number or a
    `CWE`-prefixed one — so a stray-digit string ("version 3") doesn't mint a bogus CWE-3 and
    the envelope `cwe` stays unset rather than storing junk."""
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():                                   # a bare CWE number
        return f"CWE-{int(s)}"
    m = re.search(r"cwe[-_ ]?(\d+)", s, re.IGNORECASE)  # a CWE-NNN reference (anchored on "cwe")
    return f"CWE-{int(m.group(1))}" if m else None


def persist_finding(
    session: Session,
    *,
    project_id: str,
    target_id: str,
    task_id: str,
    finding: Finding,
    status: FindingStatus = FindingStatus.new,
    finding_type: str | None = None,
) -> FindingRow:
    """Store a schema-shaped Finding payload as a DB row with the envelope.

    `finding_type` classifies it for sort/filter; if omitted it's derived from the
    producing task type + category (vulnerability is the default)."""
    if finding_type is None:
        task = session.get(Task, task_id)
        finding_type = classify_finding(task.type if task else None, finding.category)

    # Floor: every finding that makes a vuln claim documents AT LEAST its assurance level
    # (code_present/static) unless a stronger one was already recorded — verify_poc set it, or an
    # agent declared input_reachable. Never overwrites a stronger claim. (design-verification-oracles.md)
    evidence_json = finding.evidence.model_dump(exclude_none=True)
    if assurance_of(evidence_json) is None:
        floor = default_for(finding_type)
        if floor is not None:
            evidence_json.setdefault("extra", {})["assurance"] = floor

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
        evidence_json=evidence_json,
        suggested_followups_json=[
            f.model_dump(exclude_none=True) for f in (finding.suggested_followups or [])
        ],
        related_target_refs_json=list(finding.related_target_refs or []),
        status=status,
        finding_type=finding_type,
        # Lift CWE out of evidence.extra into a first-class, filterable envelope field.
        cwe=normalize_cwe((evidence_json.get("extra") or {}).get("cwe")),
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
        from hexgraph.engine.graph.annotations import auto_note

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
