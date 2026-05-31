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
    ToolCall,
    ToolSpec,
    TransientServerError,
    Usage,
)
from hexgraph.llm.parsing import parse_findings
from hexgraph.models.finding import Finding

# Errors worth retrying with backoff (transient transport problems).
_RETRYABLE = (RateLimitError, LLMTimeoutError, TransientServerError)


def _add_usage(a: Usage, b: Usage) -> Usage:
    return Usage(
        input_tokens=a.input_tokens + b.input_tokens,
        output_tokens=a.output_tokens + b.output_tokens,
        cost_source=b.cost_source if b.cost_source != "mock" else a.cost_source,
        cost_usd=round(a.cost_usd + b.cost_usd, 6),
    )


def run_findings_agentic(
    backend: LLMBackend,
    req: LLMRequest,
    *,
    tools: list[ToolSpec],
    tool_runner: Callable[[ToolCall], str],
    max_steps: int = 6,
    max_attempts: int = 3,
    base_delay: float = 0.0,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[list[Finding], Usage, list[dict]]:
    """Drive a tool-use conversation to validated findings.

    The model may call tools (executed by `tool_runner`, which runs them in the
    sandbox); each result is fed back and the loop continues until the model
    answers with findings or the step budget is hit. Strict superset of
    `run_findings`: a backend that returns findings on turn one (e.g. the mock's
    non-tool scenarios) yields the identical result. Returns (findings, total
    usage, transcript)."""
    messages: list[dict] = [{"role": "user", "content": req.prompt}]
    total = Usage(input_tokens=0, output_tokens=0, cost_source="mock", cost_usd=0.0)
    transcript: list[dict] = []

    for step in range(max_steps):
        last = max_steps - 1
        req.messages = messages
        req.tools = [] if step == last else tools  # final step: force an answer
        resp, usage = _complete_retry(backend, req, max_attempts, base_delay, sleep)
        total = _add_usage(total, usage)
        if resp.tool_calls and step != last:
            messages.append({"role": "assistant", "content": resp.text, "tool_calls": resp.tool_calls})
            for call in resp.tool_calls:
                result = tool_runner(call)
                transcript.append({"step": step, "tool": call.name, "input": call.input,
                                   "result_preview": (result or "")[:200]})
                messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": result})
            continue
        findings = _parse_with_repair(backend, req, resp, messages, total, max_attempts, base_delay, sleep)
        return findings[0], findings[1], transcript

    return [], total, transcript  # unreachable (loop returns), keeps type-checkers happy


def _complete_retry(backend, req, max_attempts, base_delay, sleep) -> tuple:
    last_exc: LLMError | None = None
    for attempt in range(max_attempts):
        try:
            resp = backend.complete(req)
            return resp, resp.usage
        except _RETRYABLE as exc:
            last_exc = exc
            _backoff(attempt, base_delay, sleep)
    assert last_exc is not None
    raise last_exc


def _parse_with_repair(backend, req, resp, messages, total, max_attempts, base_delay, sleep):
    """Parse the final text into findings; on a schema error, re-ask (JSON-repair)."""
    for attempt in range(max_attempts):
        try:
            return parse_findings(resp.text), total
        except SchemaValidationError:
            _backoff(attempt, base_delay, sleep)
            messages.append({"role": "assistant", "content": resp.text})
            messages.append({"role": "user", "content": "That was not valid. Reply ONLY with the "
                                                         "findings JSON object: {\"findings\": [...]}."})
            req.messages = messages
            req.tools = []
            resp, usage = _complete_retry(backend, req, max_attempts, base_delay, sleep)
            total = _add_usage(total, usage)
    return parse_findings(resp.text), total  # final attempt; may raise → task fails


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
