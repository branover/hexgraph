"""M3-T5: real backends behind the seam. Offline — no network, no key.

The Anthropic SDK calls are exercised via an injected fake client so the
exception-mapping and parse logic are tested without spending tokens.
"""

import json
from types import SimpleNamespace

import httpx
import pytest

from hexgraph.llm.anthropic_api import AnthropicAPIBackend, _estimate_cost
from hexgraph.llm.base import LLMError, LLMRequest, RateLimitError, TransientServerError
from hexgraph.llm.runner import run_findings

VALID_FINDING = {
    "title": "Stack overflow in f",
    "severity": "high",
    "confidence": "medium",
    "category": "memory-safety",
    "summary": "unbounded copy",
    "reasoning": "strcpy into fixed buffer",
    "evidence": {"function": "f", "sink": "strcpy"},
}


def _fake_response(text, it=1000, ot=200):
    block = SimpleNamespace(type="text", text=text)
    return SimpleNamespace(content=[block], usage=SimpleNamespace(input_tokens=it, output_tokens=ot))


class _FakeMessages:
    def __init__(self, result=None, exc=None):
        self.result, self.exc = result, exc
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return self.result


class _FakeClient:
    def __init__(self, result=None, exc=None):
        self.messages = _FakeMessages(result, exc)


def _req():
    return LLMRequest(task_type="static_analysis", task_id="t", prompt="analyze this")


def test_anthropic_success_parses_findings():
    client = _FakeClient(result=_fake_response(json.dumps({"findings": [VALID_FINDING]})))
    backend = AnthropicAPIBackend(client=client, api_key="sk-test")
    findings, usage = run_findings(backend, _req())
    assert len(findings) == 1 and findings[0].evidence.sink == "strcpy"
    assert usage.cost_source == "anthropic"
    assert usage.cost_usd > 0  # sonnet default pricing applied
    # The system prompt (with the schema) was sent.
    assert "JSON Schema" in client.messages.calls[0]["system"]


def test_anthropic_rate_limit_maps_to_our_type():
    import anthropic

    resp = httpx.Response(429, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
    exc = anthropic.RateLimitError("rate limited", response=resp, body=None)
    backend = AnthropicAPIBackend(client=_FakeClient(exc=exc), api_key="sk-test")
    with pytest.raises(RateLimitError):
        backend.complete(_req())


def test_anthropic_5xx_maps_to_transient():
    import anthropic

    resp = httpx.Response(503, request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"))
    exc = anthropic.APIStatusError("server error", response=resp, body=None)
    backend = AnthropicAPIBackend(client=_FakeClient(exc=exc), api_key="sk-test")
    with pytest.raises(TransientServerError):
        backend.complete(_req())


def test_anthropic_missing_key_errors(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    backend = AnthropicAPIBackend(client=None, api_key=None)
    with pytest.raises(LLMError):
        backend.complete(_req())


def test_cost_estimate():
    assert _estimate_cost("claude-sonnet-4-6", 1_000_000, 1_000_000) == pytest.approx(18.0)
    assert _estimate_cost("unknown-model", 1_000_000, 1_000_000) == 0.0


def test_claude_code_missing_cli_errors():
    from hexgraph.llm.claude_code import ClaudeCodeBackend

    backend = ClaudeCodeBackend(binary="hexgraph-no-such-claude-binary")
    with pytest.raises(LLMError):
        backend.complete(_req())


def test_registry_selects_real_backends():
    from hexgraph.llm.anthropic_api import AnthropicAPIBackend as A
    from hexgraph.llm.claude_code import ClaudeCodeBackend as C
    from hexgraph.llm.registry import get_backend

    assert isinstance(get_backend("anthropic"), A)
    assert isinstance(get_backend("claude_code"), C)
    with pytest.raises(ValueError):
        get_backend("nonsense")
