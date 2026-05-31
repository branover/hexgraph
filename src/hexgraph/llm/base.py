"""The LLMBackend seam (SPEC §6).

`MockLLMBackend`, `AnthropicAPIBackend`, and `ClaudeCodeBackend` are
interchangeable behind this interface. **Task code must never branch on which
backend it is talking to** — the seam is the backend boundary only.

Backends return raw model *text* plus usage metadata. Parsing that text into
validated `Finding`s (and the JSON-repair/retry loop) lives in
`hexgraph.llm.runner`, so the exact same path runs for mock and real backends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable


# --- Exceptions ----------------------------------------------------------------
# The mock raises these *same* types for its error_* scenarios so retry/backoff
# and task-failure paths are exercised offline (SPEC §6, mock-llm-provider §4).


class LLMError(Exception):
    """Base class for all backend errors."""


class RateLimitError(LLMError):
    """Provider returned 429 / rate limit. Retryable with backoff."""


class LLMTimeoutError(LLMError):
    """Request exceeded the deadline. Retryable."""


class TransientServerError(LLMError):
    """5xx / transient server error. Retryable."""


class SchemaValidationError(LLMError):
    """Model output could not be parsed/validated into Finding(s). Triggers JSON-repair retry."""


# --- Data carriers -------------------------------------------------------------


@dataclass
class Usage:
    """Token/cost accounting for one completion.

    `cost_source` tags where the numbers came from: "mock" (always cost_usd=0),
    "anthropic", or "claude_code".
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cost_source: str = "mock"
    cost_usd: float = 0.0


@dataclass
class ToolSpec:
    """A tool advertised to the model: name, natural-language description, and a
    JSON-Schema for its input. HexGraph executes the call (in the sandbox) and
    returns the result — the model never touches the environment directly."""

    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """A tool invocation the model requested. `id` correlates the result back."""

    id: str
    name: str
    input: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMRequest:
    """A request to a backend.

    `template_vars` carries the values the mock's Layer-2 templating fills into
    `{{placeholders}}` (target_name, function, sibling_target_id, ...). The task
    layer builds these from its `TaskContext`; the llm layer stays decoupled
    from tasks.

    For tool-use, `tools` advertises the callable tools and `messages` carries the
    running conversation (provider-neutral turns — see the agent loop). When
    `messages` is set the backend uses it instead of `prompt`.
    """

    task_type: str
    task_id: str
    prompt: str = ""
    system: str | None = None
    model: str | None = None
    mock_scenario: str | None = None
    template_vars: dict[str, Any] = field(default_factory=dict)
    # Stable key for response caching (the context bundle_sha). Set by the engine.
    cache_key: str | None = None
    tools: list[ToolSpec] = field(default_factory=list)
    messages: list[dict[str, Any]] | None = None


@dataclass
class LLMResponse:
    """Raw model output. `text` is the model's message content; for the mock's
    normal scenarios it is the JSON object `{"findings": [...]}`.

    When the model asks to use tools instead of answering, `tool_calls` is
    non-empty and `stop_reason` is "tool_use"; the agent loop runs the calls and
    continues the conversation."""

    text: str
    usage: Usage
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end"


# --- The seam ------------------------------------------------------------------


@runtime_checkable
class LLMBackend(Protocol):
    name: str

    def complete(self, req: LLMRequest) -> LLMResponse:
        """Return one completion. May raise any LLMError subclass."""
        ...

    def stream(self, req: LLMRequest) -> Iterator[str]:
        """Yield the completion in chunks. Default callers can ignore streaming."""
        ...
