"""Contract test — prevents mock drift (CLAUDE.md, docs/design/mock-llm-provider §7).

Every finding in every mock fixture (and, later, every recorded cassette) must
validate against hexgraph/schemas/finding.schema.json. Changing the schema forces
fixtures to update or this test fails.
"""

from __future__ import annotations

import json

import pytest
import yaml
from jsonschema import Draft202012Validator

from hexgraph.models.finding import Finding
from hexgraph.paths import finding_schema_path, mock_fixtures_dir


def _load_schema_validator() -> Draft202012Validator:
    schema = json.loads(finding_schema_path().read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _iter_findings_from_fixture(data: dict) -> list[dict]:
    """Collect every finding object a fixture can yield (incl. on_retry payloads)."""
    findings: list[dict] = []
    if isinstance(data.get("findings"), list):
        findings.extend(data["findings"])
    if isinstance(data.get("on_retry"), dict):
        findings.extend(data["on_retry"].get("findings", []))
    return findings


def _discover_fixture_files() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []
    for path in sorted(mock_fixtures_dir().rglob("*.json")):
        cases.append((str(path.relative_to(mock_fixtures_dir())), json.loads(path.read_text())))
    return cases


FIXTURES = _discover_fixture_files()


def test_fixtures_exist() -> None:
    assert FIXTURES, "no mock fixtures discovered — check hexgraph/llm/fixtures/mock_llm"


@pytest.mark.parametrize("relpath,data", FIXTURES, ids=[c[0] for c in FIXTURES])
def test_fixture_findings_validate_against_schema(relpath: str, data: dict) -> None:
    validator = _load_schema_validator()
    findings = _iter_findings_from_fixture(data)
    # Some fixtures (no_findings) legitimately carry zero findings.
    for i, finding in enumerate(findings):
        errors = sorted(validator.iter_errors(finding), key=lambda e: e.path)
        assert not errors, f"{relpath} finding[{i}] schema errors: {[e.message for e in errors]}"


@pytest.mark.parametrize("relpath,data", FIXTURES, ids=[c[0] for c in FIXTURES])
def test_fixture_findings_parse_into_pydantic_model(relpath: str, data: dict) -> None:
    # The Pydantic model (extra='forbid') is the runtime mirror of the schema.
    for i, finding in enumerate(_iter_findings_from_fixture(data)):
        Finding.model_validate(finding)


def test_manifest_scenarios_have_files_or_are_errors() -> None:
    manifest = yaml.safe_load((mock_fixtures_dir() / "_manifest.yaml").read_text())
    for task_type, entry in manifest.items():
        for scenario in entry.get("scenarios", []):
            if scenario.startswith("error_"):
                continue  # behavioral-only, no file
            path = mock_fixtures_dir() / task_type / f"{scenario}.json"
            assert path.exists(), f"manifest lists {task_type}/{scenario} but {path} is missing"
