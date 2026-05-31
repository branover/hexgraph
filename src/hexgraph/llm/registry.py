"""Backend selection (SPEC §6).

Chosen by `HEXGRAPH_LLM_BACKEND` (default `mock`), overridable per task. Real
backends are imported lazily so the mock path never requires their deps (httpx,
the anthropic SDK, a Claude Code connection).
"""

from __future__ import annotations

import os

from hexgraph.llm.base import LLMBackend
from hexgraph.llm.mock import MockLLMBackend

DEFAULT_BACKEND = "mock"


def get_backend(name: str | None = None) -> LLMBackend:
    """Return a backend instance. `name` overrides the env default."""
    name = (name or os.environ.get("HEXGRAPH_LLM_BACKEND") or DEFAULT_BACKEND).lower()

    if name == "mock":
        return MockLLMBackend()
    if name == "anthropic":
        from hexgraph.llm.anthropic_api import AnthropicAPIBackend  # lazy (M3)

        return AnthropicAPIBackend()
    if name == "claude_code":
        from hexgraph.llm.claude_code import ClaudeCodeBackend  # lazy (M3)

        return ClaudeCodeBackend()
    raise ValueError(
        f"unknown LLM backend {name!r}; expected one of: mock, anthropic, claude_code"
    )
