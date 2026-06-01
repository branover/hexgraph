"""MockLLMBackend — a first-class backend, not a test stub (see docs/mock-llm-provider.md).

Three fidelity layers:
  1. Fixture replay   — return the canned JSON at fixtures/<task_type>/<scenario>.json
  2. Templated fill   — fill {{placeholders}} from the request's template_vars so
                        findings reference artifacts that actually exist
  3. Record/replay    — cassette hook left for later (M0-T9, not implemented yet)

Determinism: the hash-fallback scenario pick is seeded from task_id via a stable
hash (not Python's randomized hash()). The mock reports fake token counts tagged
cost_source="mock", cost_usd=0.0.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterator

import yaml

from hexgraph.llm.base import (
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    RateLimitError,
    SchemaValidationError,
    ToolCall,
    TransientServerError,
    Usage,
)
from hexgraph.paths import mock_fixtures_dir

_PLACEHOLDER_RE = re.compile(r"\{\{\s*(\w+)\s*(?:\|([^}]*))?\}\}")

# error_* scenario name -> exception type. The mock raises the SAME types the
# real client raises so retry/backoff and failure paths are tested offline.
_ERROR_MAP = (
    ("rate", RateLimitError),
    ("timeout", LLMTimeoutError),
    ("transient", TransientServerError),
    ("server", TransientServerError),
    ("schema", SchemaValidationError),
)

_DEFAULT_USAGE = Usage(input_tokens=100, output_tokens=20, cost_source="mock", cost_usd=0.0)


class MockLLMBackend:
    name = "mock"

    def __init__(self, fixtures_dir: str | Path | None = None) -> None:
        self.fixtures_dir = Path(fixtures_dir) if fixtures_dir else mock_fixtures_dir()
        self._manifest = self._load_manifest()
        # Per-task attempt counter for the malformed_then_valid retry path.
        self._attempts: dict[str, int] = {}

    # --- public API (the seam) ------------------------------------------------

    def complete(self, req: LLMRequest) -> LLMResponse:
        scenario = self._resolve_scenario(req)

        if scenario.startswith("error_"):
            raise self._exception_for(scenario)

        fixture = self._load_fixture(req.task_type, scenario)

        # Tool-use scenarios: on the first turn (no tool result yet in the
        # conversation) the mock asks to call the fixture's tool(s); once results
        # come back it falls through to emit findings. Drives the agent loop at $0.
        # Scenarios without a "tool_calls" key behave exactly as before (single pass).
        if fixture.get("tool_calls") and req.tools and not self._has_tool_result(req.messages):
            filled = self._fill_templates(fixture["tool_calls"], req.template_vars)
            calls = [ToolCall(id=f"call_{i}", name=tc["name"], input=tc.get("input", {}))
                     for i, tc in enumerate(filled)]
            return LLMResponse(text=str(fixture.get("thinking", "")), usage=_DEFAULT_USAGE,
                               tool_calls=calls, stop_reason="tool_use")

        # PoC-spec fixtures (the `poc` task): return the spec JSON as-is rather than
        # the {"findings": …} envelope, so engine.poc._generate_spec can read it.
        if "poc" in fixture:
            return LLMResponse(text=json.dumps(self._fill_templates(fixture, req.template_vars)),
                               usage=_DEFAULT_USAGE)

        # malformed_then_valid: invalid text on attempt 1, valid object after.
        if "raw_text_first" in fixture and "on_retry" in fixture:
            attempt = self._attempts.get(req.task_id, 0)
            self._attempts[req.task_id] = attempt + 1
            if attempt == 0:
                return LLMResponse(text=str(fixture["raw_text_first"]), usage=_DEFAULT_USAGE)
            fixture = fixture["on_retry"]

        filled = self._fill_templates(fixture, req.template_vars)
        findings = filled.get("findings", [])
        usage = self._usage_from(filled.get("usage"))
        text = json.dumps({"findings": findings})
        return LLMResponse(text=text, usage=usage)

    def stream(self, req: LLMRequest) -> Iterator[str]:
        # Non-streaming mock: emit the whole completion as one chunk.
        yield self.complete(req).text

    # --- scenario resolution (§3 precedence) ----------------------------------

    def _resolve_scenario(self, req: LLMRequest) -> str:
        # 1) explicit per-task arg
        if req.mock_scenario:
            return req.mock_scenario
        # 2) env default
        env = os.environ.get("HEXGRAPH_MOCK_SCENARIO")
        if env:
            return env
        # 3) deterministic hash(task_id) % len(pool) for a realistic demo mix.
        # Exclude error_* scenarios here: faults are reachable explicitly (arg/env),
        # but the auto-pick should land on a *successful* scenario so interactive
        # runs and demos don't fail at random.
        pool = [s for s in self._scenario_pool(req.task_type) if not s.startswith("error_")]
        if not pool:
            return self._default_scenario(req.task_type)
        idx = self._stable_hash(req.task_id) % len(pool)
        return pool[idx]

    def _scenario_pool(self, task_type: str) -> list[str]:
        return list(self._manifest.get(task_type, {}).get("scenarios", []))

    def _default_scenario(self, task_type: str) -> str:
        entry = self._manifest.get(task_type, {})
        return entry.get("default") or "happy_path"

    @staticmethod
    def _stable_hash(value: str) -> int:
        return int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16)

    @staticmethod
    def _has_tool_result(messages: list[dict] | None) -> bool:
        return bool(messages) and any(m.get("role") == "tool" for m in messages)

    # --- fault injection (§4) -------------------------------------------------

    @staticmethod
    def _exception_for(scenario: str) -> Exception:
        for needle, exc_type in _ERROR_MAP:
            if needle in scenario:
                return exc_type(f"mock fault injection: {scenario}")
        return TransientServerError(f"mock fault injection: {scenario}")

    # --- fixtures + templating ------------------------------------------------

    def _load_manifest(self) -> dict[str, Any]:
        path = self.fixtures_dir / "_manifest.yaml"
        if not path.exists():
            return {}
        return yaml.safe_load(path.read_text()) or {}

    def _load_fixture(self, task_type: str, scenario: str) -> dict[str, Any]:
        path = self.fixtures_dir / task_type / f"{scenario}.json"
        if not path.exists():
            raise FileNotFoundError(
                f"no mock fixture for task_type={task_type!r} scenario={scenario!r} at {path}"
            )
        return json.loads(path.read_text())

    def _fill_templates(self, obj: Any, vars: dict[str, Any]) -> Any:
        """Recursively replace {{key|default}} placeholders in all string values."""
        if isinstance(obj, str):
            return self._fill_string(obj, vars)
        if isinstance(obj, list):
            return [self._fill_templates(x, vars) for x in obj]
        if isinstance(obj, dict):
            return {k: self._fill_templates(v, vars) for k, v in obj.items()}
        return obj

    def _fill_string(self, s: str, vars: dict[str, Any]) -> str:
        def repl(m: re.Match[str]) -> str:
            key, default = m.group(1), m.group(2)
            if key in vars and vars[key] is not None:
                return str(vars[key])
            return default if default is not None else ""

        return _PLACEHOLDER_RE.sub(repl, s)

    @staticmethod
    def _usage_from(raw: dict[str, Any] | None) -> Usage:
        raw = raw or {}
        # Mock cost is always zero regardless of what the fixture claims.
        return Usage(
            input_tokens=int(raw.get("input_tokens", _DEFAULT_USAGE.input_tokens)),
            output_tokens=int(raw.get("output_tokens", _DEFAULT_USAGE.output_tokens)),
            cost_source="mock",
            cost_usd=0.0,
        )
