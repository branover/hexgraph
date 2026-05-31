"""ClaudeCodeBackend — use a local Claude Code session (SPEC §6).

Shells out to the `claude` CLI in headless print mode (`-p ... --output-format
json`). Fails clearly if the CLI isn't installed or errors, per the spec ("fail
gracefully if unavailable"). Best-effort: token/cost come from the CLI's JSON if
present, otherwise reported as estimated/zero.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Iterator

from hexgraph.llm.base import (
    LLMError,
    LLMRequest,
    LLMResponse,
    LLMTimeoutError,
    Usage,
)
from hexgraph.llm.prompting import system_prompt

DEFAULT_TIMEOUT = 180


class ClaudeCodeBackend:
    name = "claude_code"

    def __init__(self, binary: str = "claude", timeout: int = DEFAULT_TIMEOUT) -> None:
        self.binary = binary
        self.timeout = timeout

    def _require_cli(self) -> str:
        path = shutil.which(self.binary)
        if path is None:
            raise LLMError(
                f"Claude Code CLI ({self.binary!r}) not found on PATH. Install Claude Code, or use "
                "the mock/anthropic backend."
            )
        return path

    def complete(self, req: LLMRequest) -> LLMResponse:
        cli = self._require_cli()
        cmd = [cli, "-p", req.prompt, "--output-format", "json",
               "--append-system-prompt", req.system or system_prompt(req.task_type)]
        if req.model:
            cmd += ["--model", req.model]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise LLMTimeoutError(f"claude CLI timed out after {self.timeout}s") from exc
        except OSError as exc:
            raise LLMError(f"failed to invoke claude CLI: {exc}") from exc

        if proc.returncode != 0:
            raise LLMError(f"claude CLI failed (exit {proc.returncode}): {proc.stderr.strip()[:300]}")

        # Print mode emits a JSON envelope; the model's answer is in `result`.
        try:
            envelope = json.loads(proc.stdout)
            text = envelope.get("result", proc.stdout)
        except json.JSONDecodeError:
            envelope, text = {}, proc.stdout

        usage_obj = envelope.get("usage") or {}
        return LLMResponse(
            text=text,
            usage=Usage(
                input_tokens=int(usage_obj.get("input_tokens", 0)),
                output_tokens=int(usage_obj.get("output_tokens", 0)),
                cost_source="claude_code",
                cost_usd=float(envelope.get("total_cost_usd", 0.0)),
            ),
        )

    def stream(self, req: LLMRequest) -> Iterator[str]:
        yield self.complete(req).text
