"""Parse raw model text into validated Findings.

Shared by every backend so the JSON-repair path is identical for mock and real.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from hexgraph.llm.base import SchemaValidationError
from hexgraph.models.finding import Finding

_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def _strip_fences(text: str) -> str:
    return _FENCE_RE.sub("", text.strip())


def parse_findings(text: str) -> list[Finding]:
    """Extract and validate the findings list from a model's text output.

    Accepts either a bare JSON array of findings or an object with a top-level
    `findings` key. Raises `SchemaValidationError` on any parse/validation
    failure so the runner can trigger a repair retry.
    """
    cleaned = _strip_fences(text)
    try:
        data: Any = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise SchemaValidationError(f"model output was not valid JSON: {exc}") from exc

    if isinstance(data, dict):
        raw_findings = data.get("findings", [])
    elif isinstance(data, list):
        raw_findings = data
    else:
        raise SchemaValidationError("expected a findings array or an object with a 'findings' key")

    if not isinstance(raw_findings, list):
        raise SchemaValidationError("'findings' must be an array")

    findings: list[Finding] = []
    for i, item in enumerate(raw_findings):
        try:
            findings.append(Finding.model_validate(item))
        except ValidationError as exc:
            raise SchemaValidationError(f"finding[{i}] failed schema validation: {exc}") from exc
    return findings
