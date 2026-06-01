"""`TaskContext` — the per-run carrier passed to each task's `execute_*` function.

Task dispatch is a plain if/elif over `execute_<type>(...)` functions in
`engine/worker.py` (`execute_recon`, `execute_static_analysis`,
`execute_harness_generation`, `execute_fuzzing`, `execute_poc`, …), one per task
type — there is no handler registry or `TaskHandler` protocol. Each `execute_*`
follows the same shape: gather deterministic facts with sandboxed tools → ask
the LLM to reason over those facts (via the agent loop) → emit findings.
`TaskContext` is the shared bundle those functions consume; it carries tool
output and prompt hints, **never raw target bytes**.

**The LLM never sees raw target bytes** — only tool output (decompilation,
strings, imports) carried in `TaskContext`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hexgraph.llm.base import LLMBackend, LLMRequest


@dataclass
class TaskContext:
    """Everything an `execute_*` task needs for one run. Carries tool output, never raw bytes."""

    task_id: str
    task_type: str
    project_id: str | None = None
    target_id: str | None = None
    target_name: str | None = None
    objective: str | None = None

    # Deterministic facts gathered by sandboxed tools (recon metadata,
    # decompilation, strings, imports). Consumed when building the prompt.
    tool_outputs: dict[str, Any] = field(default_factory=dict)

    # Hints that feed Layer-2 mock templating and real prompts alike.
    function: str | None = None
    sink: str | None = None
    sibling_target_id: str | None = None
    sibling_name: str | None = None
    a_string: str | None = None
    target_format: str | None = None
    arch: str | None = None

    # Backend + model selection (per-task override; no auto-router in v1).
    backend: LLMBackend | None = None
    model: str | None = None
    mock_scenario: str | None = None

    def template_vars(self) -> dict[str, Any]:
        """Values the mock fills into `{{placeholders}}` and real prompts reference.

        Keys mirror the placeholders documented in `_manifest.yaml`. None values
        are dropped so the fixture's literal `{{key|default}}` fallback applies.
        """
        raw = {
            "target_name": self.target_name,
            "target_id": self.target_id,
            "function": self.function,
            "sink": self.sink,
            "sibling_target_id": self.sibling_target_id,
            "sibling_name": self.sibling_name,
            "a_string": self.a_string,
            "format": self.target_format,
            "arch": self.arch,
        }
        return {k: v for k, v in raw.items() if v is not None}

    def build_request(self, *, prompt: str = "", system: str | None = None) -> LLMRequest:
        return LLMRequest(
            task_type=self.task_type,
            task_id=self.task_id,
            prompt=prompt,
            system=system,
            model=self.model,
            mock_scenario=self.mock_scenario,
            template_vars=self.template_vars(),
        )
