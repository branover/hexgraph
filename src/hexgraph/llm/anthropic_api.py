"""AnthropicAPIBackend — BYOK real backend (SPEC §6).

Reads `ANTHROPIC_API_KEY` from env or config (never logged or stored), calls the
Messages API, and maps the SDK's error types onto HexGraph's exception hierarchy
so the shared retry/backoff path works identically to the mock's fault scenarios.
The `client` is injectable so the mapping/parse logic is unit-testable offline.
"""

from __future__ import annotations

from typing import Any, Iterator

from hexgraph.config import get_anthropic_api_key, load_config
from hexgraph.llm.base import (
    LLMError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    RateLimitError,
    TransientServerError,
    Usage,
)
from hexgraph.llm.prompting import system_prompt

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_TOKENS = 4096

# Approximate USD per million tokens (input, output). Best-effort for the cost
# display only — not billing. Unknown models fall back to 0.
_PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-4-8": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    pin, pout = _PRICES.get(model, (0.0, 0.0))
    return round(input_tokens / 1e6 * pin + output_tokens / 1e6 * pout, 6)


class AnthropicAPIBackend:
    name = "anthropic"

    def __init__(
        self,
        client: Any | None = None,
        *,
        api_key: str | None = None,
        default_model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self._client = client
        self._api_key = api_key or get_anthropic_api_key()
        self.default_model = default_model or load_config().model_pref or DEFAULT_MODEL
        self.max_tokens = max_tokens

    def _get_client(self) -> Any:
        if self._client is None:
            if not self._api_key:
                raise LLMError(
                    "no ANTHROPIC_API_KEY found (set the env var or ~/.hexgraph/config.toml). "
                    "Use the default mock backend for offline development."
                )
            try:
                import anthropic
            except ImportError as exc:  # pragma: no cover
                raise LLMError("anthropic SDK not installed; `pip install anthropic`") from exc
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete(self, req: LLMRequest) -> LLMResponse:
        import anthropic

        client = self._get_client()
        model = req.model or self.default_model
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=self.max_tokens,
                system=req.system or system_prompt(req.task_type),
                messages=[{"role": "user", "content": req.prompt}],
            )
        except anthropic.RateLimitError as exc:
            raise RateLimitError(str(exc)) from exc
        except anthropic.APITimeoutError as exc:
            raise LLMTimeoutError(str(exc)) from exc
        except anthropic.APIConnectionError as exc:
            raise TransientServerError(str(exc)) from exc
        except anthropic.APIStatusError as exc:
            status = getattr(exc, "status_code", None)
            if status and 500 <= status < 600:
                raise TransientServerError(str(exc)) from exc
            raise LLMError(str(exc)) from exc

        text = "".join(
            getattr(block, "text", "") for block in resp.content if getattr(block, "type", "") == "text"
        )
        usage = Usage(
            input_tokens=resp.usage.input_tokens,
            output_tokens=resp.usage.output_tokens,
            cost_source="anthropic",
            cost_usd=_estimate_cost(model, resp.usage.input_tokens, resp.usage.output_tokens),
        )
        return LLMResponse(text=text, usage=usage)

    def stream(self, req: LLMRequest) -> Iterator[str]:
        yield self.complete(req).text
