"""The task registry seam (SPEC §5).

Every task type (`recon`, `static_analysis`, `reverse_engineering`,
`harness_generation`, `pattern_sweep`) implements the same `TaskHandler`
protocol: `plan() -> run() -> suggest_followups()`. General flow: gather
deterministic facts with sandboxed tools → ask the LLM to reason over those
facts → emit findings.

**The LLM never sees raw target bytes** — only tool output (decompilation,
strings, imports) carried in `TaskContext`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from hexgraph.llm.base import LLMBackend, LLMRequest
from hexgraph.models.finding import Finding, FollowupSuggestion


@dataclass
class ToolStep:
    """One sandboxed tool invocation the handler plans to run."""

    tool: str
    args: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class TaskContext:
    """Everything a handler needs for one run. Carries tool output, never raw bytes."""

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


class TaskHandler(Protocol):
    type: str

    def plan(self, ctx: TaskContext) -> list[ToolStep]:
        """Decide which sandboxed tool steps to run for this target/objective."""
        ...

    def run(self, ctx: TaskContext) -> list[Finding]:
        """Execute the task and emit findings."""
        ...

    def suggest_followups(self, finding: Finding) -> list[FollowupSuggestion]:
        """Propose next tasks the user can launch in one click."""
        ...
