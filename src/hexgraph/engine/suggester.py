"""Follow-up suggester seam (P3-5, design §5).

Given a finding (+ its graph context) propose next tasks. The default is a cheap
RuleBasedSuggester. This is the seam where a future **paid** `LLMSuggester`
(entitlement-gated, metered) drops in — `get_suggester()` picks the implementation,
feature code just calls `suggest(...)`. We build only the rule-based one now.
"""

from __future__ import annotations

from typing import Protocol

from hexgraph.db.models import Finding, Target
from hexgraph.models.finding import FollowupSuggestion

# Dangerous libc sinks worth a static-analysis follow-up if a target imports them.
# (Mirrors recon.RISKY_SINKS — imported there to keep one source of truth.)
from hexgraph.engine.re.recon import RISKY_SINKS


class FollowupSuggester(Protocol):
    name: str

    def suggest(self, finding: Finding) -> list[FollowupSuggestion]: ...

    def suggest_target(self, target: Target) -> list[FollowupSuggestion]: ...


class RuleBasedSuggester:
    name = "rule_based"

    def suggest_target(self, target: Target) -> list[FollowupSuggestion]:
        """Target-level follow-ups proposed from a target's enriched recon metadata.

        This is the new home for the risky-sink → static_analysis follow-up that the
        old per-target recon FINDING carried in its `suggested_followups`: recon no
        longer mints a finding, but the loop ("recon enriched a binary that imports
        strcpy → static-analyze it") must still surface. The followups API serves
        these per target."""
        meta = target.metadata_json or {}
        kind = (target.kind.value if hasattr(target.kind, "value") else target.kind)
        imports = meta.get("imports", []) or []
        risky = sorted(set(imports) & RISKY_SINKS)
        out: list[FollowupSuggestion] = []
        if risky and kind in ("executable", "shared_library"):
            out.append(FollowupSuggestion(
                task_type="static_analysis",
                label=f"Static-analyze {target.name} for memory safety",
                params={"sink": risky[0]},
            ))
        return out

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


def suggest_target_followups(target: Target) -> list[FollowupSuggestion]:
    """Target-level follow-ups from a target's enriched metadata (e.g. recon found
    risky-sink imports → static-analyze). The home for follow-ups that used to ride
    on the per-target recon finding, now that recon enriches without minting one."""
    return get_suggester().suggest_target(target)
