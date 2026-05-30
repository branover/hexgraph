"""Locate bundled context assets (schema + mock fixtures).

For v1 HexGraph runs from a repo checkout, so the canonical
`finding.schema.json` and the mock-LLM fixtures are read straight from
`context/` — a single source of truth, no duplication (per the build plan
and CLAUDE.md "the mock backend reads context/fixtures/** directly").
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def repo_root() -> Path:
    """Walk up from this file until the directory containing `context/` is found."""
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "context" / "SPEC.md").exists():
            return parent
    # Fallback: two levels up from src/hexgraph/.
    return here.parents[2]


def finding_schema_path() -> Path:
    return repo_root() / "context" / "schemas" / "finding.schema.json"


def mock_fixtures_dir() -> Path:
    return repo_root() / "context" / "fixtures" / "mock_llm"
