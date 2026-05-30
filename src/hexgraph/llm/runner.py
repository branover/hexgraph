"""Drive a backend to a validated list of Findings, with retry + JSON-repair.

This is the one place that knows about retry policy. Tasks call `run_findings`
and never touch the backend's `complete()` directly, so retry/backoff and the
malformed-then-valid repair path are exercised uniformly for every backend.
"""

from __future__ import annotations

import time
from typing import Callable

from hexgraph.llm.base import (
    LLMBackend,
    LLMRequest,
    LLMError,
    LLMTimeoutError,
    RateLimitError,
    SchemaValidationError,
    TransientServerError,
    Usage,
)
from hexgraph.llm.parsing import parse_findings
from hexgraph.models.finding import Finding

# Errors worth retrying with backoff (transient transport problems).
_RETRYABLE = (RateLimitError, LLMTimeoutError, TransientServerError)


def run_findings(
    backend: LLMBackend,
    req: LLMRequest,
    *,
    max_attempts: int = 3,
    base_delay: float = 0.0,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[Finding], Usage]:
    """Call the backend until it yields schema-valid findings or attempts run out.

    Retries on transient transport errors (rate limit / timeout / 5xx) and on
    parse/validation failures (the JSON-repair path). `base_delay` defaults to 0
    so tests are fast; production callers can raise it for real backoff.

    Raises the last `LLMError` if all attempts fail (caller marks task failed).
    """
    last_exc: LLMError | None = None
    for attempt in range(max_attempts):
        try:
            resp = backend.complete(req)
            findings = parse_findings(resp.text)
            return findings, resp.usage
        except _RETRYABLE as exc:
            last_exc = exc
            _backoff(attempt, base_delay, sleep)
        except SchemaValidationError as exc:
            # JSON-repair: ask again. The malformed_then_valid scenario returns
            # a valid object on the second call.
            last_exc = exc
            _backoff(attempt, base_delay, sleep)

    assert last_exc is not None
    raise last_exc


def _backoff(attempt: int, base_delay: float, sleep: Callable[[float], None]) -> None:
    if base_delay > 0:
        sleep(base_delay * (2**attempt))
