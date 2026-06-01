"""The Finding — the heart of the product.

Defined once, here, as a Pydantic model that mirrors
`hexgraph/schemas/finding.schema.json` exactly. Every task type and every LLM
backend (mock and real) emits exactly this shape; that uniformity is what makes
triage and the graph possible.

This models the *finding payload* a task/backend emits. The persisted DB row
(`db.models.Finding`) wraps this with envelope fields (id, project_id,
target_id, task_id, status, created_at) that are not part of the emitted
content and therefore not in the JSON schema.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Category = Literal[
    "recon",
    "memory-safety",
    "command-injection",
    "unsafe-parsing",
    "weak-crypto",
    "hardcoded-secret",
    "auth",
    "info-leak",
    "annotation",
    "other",
]
TaskType = Literal[
    "static_analysis",
    "reverse_engineering",
    "harness_generation",
    "pattern_sweep",
    "recon",
]


class Evidence(BaseModel):
    """Concrete, auditable support for a finding (schema: `evidence`)."""

    model_config = ConfigDict(extra="forbid")

    function: str | None = Field(default=None, description="Symbol/function name the finding concerns.")
    file: str | None = Field(default=None, description="Path within the target (e.g. /sbin/httpd).")
    address: str | None = Field(default=None, description="Address/offset, e.g. 0x4a21c.")
    line: int | None = None
    decompiled_snippet: str | None = Field(default=None, description="Relevant pseudocode/disassembly.")
    reproducer: str | None = Field(default=None, description="Input or command that triggers the issue.")
    backtrace: list[str] | None = None
    sink: str | None = Field(default=None, description="The dangerous call/sink, e.g. strcpy.")
    strings: list[str] | None = None
    extra: dict[str, Any] | None = None


class FollowupSuggestion(BaseModel):
    """A next agent task the user can launch in one click (schema: `suggested_followups[]`)."""

    model_config = ConfigDict(extra="forbid")

    task_type: TaskType
    label: str
    target_ref: str | None = Field(
        default=None,
        description="Optional target id/name the follow-up runs against (e.g. a sibling).",
    )
    params: dict[str, Any] | None = None


class Finding(BaseModel):
    """Canonical structured finding. Matches finding.schema.json (additionalProperties: false)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=200)
    severity: Severity
    confidence: Confidence
    category: Category
    summary: str = Field(min_length=1, description="One or two sentence human summary.")
    reasoning: str = Field(description="The agent's reasoning trace that led to this finding.")
    evidence: Evidence
    suggested_followups: list[FollowupSuggestion] | None = None
    related_target_refs: list[str] | None = None

    def to_payload(self) -> dict[str, Any]:
        """Schema-shaped dict with unset/None fields dropped (for storage / validation / export)."""
        return self.model_dump(exclude_none=True)
