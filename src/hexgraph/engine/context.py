"""The Context Bundle (P2 — the spine, design §7).

A bundle is the frozen, content-addressed input to one task run: an ordered list
of typed items assembled by walking the graph around the focus and packing them
under a token budget, recording what was dropped. Identical inputs reproduce a
byte-identical bundle (`bundle_sha`), which is the cassette/replay key.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from hexgraph.db.models import ContextBundle, ContextItem, Finding, Project, Target
from hexgraph.engine import cas

ASSEMBLER_VERSION = "1"
DEFAULT_BUDGET = 6000
_WS = re.compile(r"\s+")


def estimate_tokens(text: str) -> int:
    """One deterministic estimator used by the packer, the preview, and display
    (ruling #13): ~chars/4. Offline; approximate by design."""
    return max(1, len(text) // 4)


def _normalize(text: str) -> str:
    return _WS.sub(" ", text).strip()


@dataclass
class _Item:
    kind: str
    text: str
    priority: int
    src_kind: str | None = None
    src_id: str | None = None


@dataclass
class BuiltBundle:
    row: ContextBundle
    prompt: str
    included: list[_Item] = field(default_factory=list)
    dropped: list[_Item] = field(default_factory=list)


def _gather_items(session: Session, project: Project, target: Target, task, ctx) -> list[_Item]:
    items: list[_Item] = []
    meta = target.metadata_json or {}

    if ctx.objective:
        items.append(_Item("objective", ctx.objective, 100, "task", getattr(task, "id", None)))

    items.append(
        _Item(
            "recon_facts",
            f"Target {target.name}: format={target.format} arch={target.arch} "
            f"kind={target.kind.value}; mitigations={meta.get('mitigations', {})}; "
            f"libraries={meta.get('libraries', [])}",
            90, "target", target.id,
        )
    )

    decomp = (ctx.tool_outputs or {}).get("decompilation")
    focus = (decomp or {}).get("focus") if decomp else None
    if focus and focus.get("pseudocode"):
        items.append(_Item("decompilation.focus", f"{focus['name']}:\n{focus['pseudocode']}", 85,
                           "node", None))

    # Feedback loop (design §8): human ground truth flows into agent context.
    prior = session.query(Finding).filter(Finding.target_id == target.id).all()
    confirmed = [f for f in prior if f.status in ("confirmed", "reported")]
    dismissed = [f for f in prior if f.status == "dismissed"]
    other = [f for f in prior if f not in confirmed and f not in dismissed]
    if confirmed:
        items.append(_Item(
            "analyst_confirmed",
            "ANALYST-CONFIRMED (authoritative): " + "; ".join(f"[{f.severity}] {f.title}" for f in confirmed[:10]),
            95, "target", target.id))
    if dismissed:
        items.append(_Item(
            "do_not_report",
            "Analyst DISMISSED — do not re-report: " + "; ".join(f.title for f in dismissed[:10]),
            80, "target", target.id))
    if other:
        items.append(_Item("prior_findings.this_node",
                           "Already reported here: " + "; ".join(f"[{f.severity}] {f.title}" for f in other[:10]),
                           70, "target", target.id))

    imports = meta.get("imports", [])
    if imports:
        items.append(_Item("imports", "Imports: " + ", ".join(imports[:40]), 60, "target", target.id))

    strings = meta.get("strings", [])
    if strings:
        items.append(_Item("strings", "Notable strings: " + " | ".join(strings[:20]), 40,
                           "target", target.id))

    if ctx.sibling_name:
        items.append(_Item("sibling", f"Sibling target available: {ctx.sibling_name}", 30,
                           "target", ctx.sibling_target_id))
    return items


def _pack(items: list[_Item], budget: int) -> tuple[list[_Item], list[_Item]]:
    """Greedy pack by (priority desc, est asc); record drops. Human/objective
    context (high priority) wins; low-priority overflow is dropped."""
    ordered = sorted(items, key=lambda it: (-it.priority, estimate_tokens(it.text)))
    included, dropped, spent = [], [], 0
    for it in ordered:
        t = estimate_tokens(it.text)
        if spent + t <= budget:
            included.append(it)
            spent += t
        else:
            dropped.append(it)
    return included, dropped


def _bundle_sha(included: list[_Item]) -> str:
    basis = ASSEMBLER_VERSION + "\n" + "\n".join(f"{it.kind}\x00{_normalize(it.text)}" for it in included)
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def render_prompt(included: list[_Item]) -> str:
    return "\n\n".join(f"## {it.kind}\n{it.text}" for it in included)


def preview_context(session: Session, project: Project, target: Target, ctx, *, budget: int = DEFAULT_BUDGET) -> dict:
    """Assemble the bundle WITHOUT persisting — for the pre-flight launch preview.
    `ctx.task_id` may be a throwaway id; nothing is written to the DB or CAS."""
    included, dropped = _pack(_gather_items(session, project, target, None, ctx), budget)
    return {
        "prompt": render_prompt(included),
        "bundle_sha": _bundle_sha(included),
        "token_estimate": sum(estimate_tokens(it.text) for it in included),
        "token_budget": budget,
        "items": [{"kind": it.kind, "est_tokens": estimate_tokens(it.text), "preview": it.text[:160]} for it in included],
        "dropped": [it.kind for it in dropped],
    }


def build_context_bundle(
    session: Session, project: Project, target: Target, task, ctx, *, budget: int = DEFAULT_BUDGET
) -> BuiltBundle:
    items = _gather_items(session, project, target, task, ctx)
    included, dropped = _pack(items, budget)
    bundle_sha = _bundle_sha(included)
    token_estimate = sum(estimate_tokens(it.text) for it in included)

    deps = [hashlib.sha256(repr(target.metadata_json or {}).encode()).hexdigest()[:16]]
    if ctx.sibling_target_id:
        deps.append(ctx.sibling_target_id)

    row = ContextBundle(
        project_id=project.id, task_id=task.id, bundle_sha=bundle_sha,
        assembler_version=ASSEMBLER_VERSION, token_estimate=token_estimate, token_budget=budget,
        item_count=len(included), dropped_count=len(dropped), deps_json=deps,
    )
    session.add(row)
    session.flush()

    for i, it in enumerate(included):
        content_ref = cas.put(project, it.text)
        session.add(ContextItem(
            bundle_id=row.id, order_index=i, kind=it.kind, src_kind=it.src_kind, src_id=it.src_id,
            content_ref=content_ref, preview=it.text[:200], est_tokens=estimate_tokens(it.text),
            priority=it.priority, included=True,
        ))
    for it in dropped:
        session.add(ContextItem(
            bundle_id=row.id, order_index=-1, kind=it.kind, src_kind=it.src_kind, src_id=it.src_id,
            content_ref=None, preview=it.text[:200], est_tokens=estimate_tokens(it.text),
            priority=it.priority, included=False,
        ))
    session.flush()

    return BuiltBundle(row=row, prompt=render_prompt(included), included=included, dropped=dropped)
