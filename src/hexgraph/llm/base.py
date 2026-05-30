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
class LLMRequest:
    """A request to a backend.

    `template_vars` carries the values the mock's Layer-2 templating fills into
    `{{placeholders}}` (target_name, function, sibling_target_id, ...). The task
    layer builds these from its `TaskContext`; the llm layer stays decoupled
    from tasks.
    """

    task_type: str
    task_id: str
    prompt: str = ""
    system: str | None = None
    model: str | None = None
    mock_scenario: str | None = None
    template_vars: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Raw model output. `text` is the model's message content; for the mock's
    normal scenarios it is the JSON object `{"findings": [...]}`."""

    text: str
    usage: Usage


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
