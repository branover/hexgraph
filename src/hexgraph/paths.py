"""Locate bundled assets (the Finding schema + mock-LLM fixtures) and the repo root.

The canonical `finding.schema.json` and the mock-LLM fixtures ship *inside the
package* (`hexgraph/schemas/` and `hexgraph/llm/fixtures/mock_llm/`), so they are
resolved relative to this module — not a repo-root folder — and are packaged into
the wheel (see `pyproject.toml` `package-data`). This means installs and tests
find them whether or not a source checkout is present.

`repo_root()` is still needed for repo-relative, dev-time resources that are *not*
shipped in the wheel (the Alembic `migrations/` tree and `tests/fixtures/`). It is
anchored on a robust sentinel (`pyproject.toml` / `.git`) rather than the retired
`context/` bundle.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=1)
def repo_root() -> Path:
    """Walk up from this file until a repo-root sentinel is found.

    Sentinel = `pyproject.toml` or a `.git` dir. Used only for dev-time,
    repo-relative resources (migrations, tests/fixtures), never for shipped assets.
    """
    here = Path(__file__).resolve()
    for parent in (here, *here.parents):
        if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
            return parent
    # Fallback: two levels up from src/hexgraph/.
    return here.parents[2]


def finding_schema_path() -> Path:
    """The canonical Finding JSON schema, shipped inside the package."""
    return _PACKAGE_DIR / "schemas" / "finding.schema.json"


def mock_fixtures_dir() -> Path:
    """The mock-LLM fixture tree, shipped inside the package."""
    return _PACKAGE_DIR / "llm" / "fixtures" / "mock_llm"
