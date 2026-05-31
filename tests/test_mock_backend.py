"""MockLLMBackend behavior: replay, scenario precedence, templating, faults, retry."""

from __future__ import annotations

import os

import pytest

from hexgraph.llm.base import (
    LLMRequest,
    LLMTimeoutError,
    RateLimitError,
)
from hexgraph.llm.mock import MockLLMBackend
from hexgraph.llm.parsing import parse_findings
from hexgraph.llm.runner import run_findings


def _req(task_type: str, task_id: str = "t-1", scenario: str | None = None, **vars):
    return LLMRequest(
        task_type=task_type,
        task_id=task_id,
        mock_scenario=scenario,
        template_vars=vars,
    )


def test_layer1_replay_critical_overflow():
    mock = MockLLMBackend()
    findings, usage = run_findings(mock, _req("static_analysis", scenario="critical_overflow"))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.category == "memory-safety"
    assert usage.cost_source == "mock" and usage.cost_usd == 0.0


def test_layer2_templating_fills_real_artifacts():
    mock = MockLLMBackend()
    findings, _ = run_findings(
        mock,
        _req(
            "static_analysis",
            scenario="critical_overflow",
            function="do_login",
            sink="memcpy",
            target_name="/bin/foo",
            sibling_target_id="sib-123",
        ),
    )
    f = findings[0]
    assert "do_login" in f.title
    assert f.evidence.function == "do_login"
    assert f.evidence.sink == "memcpy"
    assert f.evidence.file == "/bin/foo"
    assert f.related_target_refs == ["sib-123"]


def test_layer2_falls_back_to_literal_default():
    mock = MockLLMBackend()
    findings, _ = run_findings(mock, _req("static_analysis", scenario="critical_overflow"))
    # No template_vars provided -> the {{function|cgi_handler}} default applies.
    assert findings[0].evidence.function == "cgi_handler"


def test_no_findings_scenario_is_empty_not_error():
    mock = MockLLMBackend()
    findings, _ = run_findings(mock, _req("static_analysis", scenario="no_findings"))
    assert findings == []


def test_scenario_precedence_env(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_MOCK_SCENARIO", "no_findings")
    mock = MockLLMBackend()
    # No explicit arg -> env wins.
    findings, _ = run_findings(mock, _req("static_analysis"))
    assert findings == []


def test_scenario_precedence_arg_beats_env(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_MOCK_SCENARIO", "no_findings")
    mock = MockLLMBackend()
    findings, _ = run_findings(mock, _req("static_analysis", scenario="critical_overflow"))
    assert len(findings) == 1


def test_hash_fallback_is_deterministic(monkeypatch):
    monkeypatch.delenv("HEXGRAPH_MOCK_SCENARIO", raising=False)
    mock = MockLLMBackend()
    a = mock._resolve_scenario(_req("static_analysis", task_id="abc"))
    b = mock._resolve_scenario(_req("static_analysis", task_id="abc"))
    assert a == b  # same task_id -> same scenario


def test_error_rate_limit_raises_real_type():
    mock = MockLLMBackend()
    with pytest.raises(RateLimitError):
        mock.complete(_req("static_analysis", scenario="error_rate_limit"))


def test_error_timeout_raises_real_type():
    mock = MockLLMBackend()
    with pytest.raises(LLMTimeoutError):
        mock.complete(_req("static_analysis", scenario="error_timeout"))


def test_error_exhausts_retries_and_raises():
    mock = MockLLMBackend()
    with pytest.raises(RateLimitError):
        run_findings(mock, _req("static_analysis", scenario="error_rate_limit"), max_attempts=3)


def test_malformed_then_valid_repairs_on_retry():
    mock = MockLLMBackend()
    req = _req("static_analysis", task_id="malformed-task", scenario="malformed_then_valid")
    # First call: invalid JSON text.
    first = mock.complete(req)
    with pytest.raises(Exception):
        parse_findings(first.text)
    # The runner retries and gets the valid object.
    mock2 = MockLLMBackend()
    findings, _ = run_findings(
        mock2,
        _req("static_analysis", task_id="malformed-task-2", scenario="malformed_then_valid"),
        max_attempts=3,
    )
    assert len(findings) == 1
    assert findings[0].evidence.function == "log_event"
