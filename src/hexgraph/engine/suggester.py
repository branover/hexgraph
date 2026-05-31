"""Follow-up suggester seam (P3-5, design §5).

Given a finding (+ its graph context) propose next tasks. The default is a cheap
RuleBasedSuggester. This is the seam where a future **paid** `LLMSuggester`
(entitlement-gated, metered) drops in — `get_suggester()` picks the implementation,
feature code just calls `suggest(...)`. We build only the rule-based one now.
"""

from __future__ import annotations

from typing import Protocol

from hexgraph.db.models import Finding
from hexgraph.models.finding import FollowupSuggestion


class FollowupSuggester(Protocol):
    name: str

    def suggest(self, finding: Finding) -> list[FollowupSuggestion]: ...


class RuleBasedSuggester:
    name = "rule_based"

    def suggest(self, finding: Finding) -> list[FollowupSuggestion]:
        ev = finding.evidence_json or {}
        out: list[FollowupSuggestion] = []
        cat = finding.category
        func = ev.get("function")
        sink = ev.get("sink")

        if cat == "memory-safety":
            if func:
                out.append(FollowupSuggestion(
                    task_type="harness_generation",
                    label=f"Generate a fuzz harness for {func}",
                    params={"function": func},
                ))
            if sink:
                out.append(FollowupSuggestion(
                    task_type="pattern_sweep",
                    label=f"Sweep siblings for the same {sink} sink",
                    params={"sink": sink},
                ))
        elif cat == "annotation" and func:
            out.append(FollowupSuggestion(
                task_type="static_analysis",
                label=f"Static-analyze {func} for memory safety",
                params={"function": func},
            ))
        elif cat in ("command-injection", "unsafe-parsing") and func:
            out.append(FollowupSuggestion(
                task_type="reverse_engineering",
                label=f"Annotate callers of {func}",
                params={"function": func},
            ))
        return out


def get_suggester() -> FollowupSuggester:
    # Future: return an LLMSuggester when entitled (entitlements.allows("suggest.llm")).
    return RuleBasedSuggester()


def suggest_followups(finding: Finding) -> list[FollowupSuggestion]:
    return get_suggester().suggest(finding)
