"""Provenance-embedded report export (P7-3).

A Markdown report over the findings the analyst has promoted (confirmed/reported).
Each finding embeds its provenance — the task, backend/model, and context
bundle_sha that produced it — so the report is auditable. (HTML + optional LLM
"polish" are later additions; this is the offline, deterministic core.)
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Finding, Project, Target, Task

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
REPORTABLE = ("confirmed", "reported")


def build_report_md(session: Session, project_id: str) -> str:
    project = session.get(Project, project_id)
    if project is None:
        raise ValueError("project not found")
    findings = [
        f for f in session.query(Finding).filter(Finding.project_id == project_id).all()
        if f.status in REPORTABLE
    ]
    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.title))

    lines = [f"# HexGraph report — {project.name}", ""]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    lines.append("**Confirmed findings:** " + (", ".join(f"{n} {s}" for s, n in counts.items()) or "none"))
    lines.append("")

    for f in findings:
        ev = f.evidence_json or {}
        target = session.get(Target, f.target_id)
        task = session.get(Task, f.task_id)
        lines += [
            f"## [{f.severity.upper()}] {f.title}",
            f"- **Category:** {f.category}  ·  **Confidence:** {f.confidence}  ·  **Status:** {f.status}",
            f"- **Target:** {target.name if target else f.target_id}",
        ]
        if ev.get("function"):
            lines.append(f"- **Function:** `{ev['function']}`" + (f"  ·  **Sink:** `{ev['sink']}`" if ev.get("sink") else ""))
        lines += ["", f"{f.summary}", "", "**Reasoning:** " + f.reasoning]
        if ev.get("decompiled_snippet"):
            lines += ["", "```c", ev["decompiled_snippet"], "```"]
        if f.human_notes:
            lines += ["", f"**Analyst notes:** {f.human_notes}"]
        # Provenance
        prov = f"task `{f.task_id[:8]}`"
        if task:
            prov += f" ({task.type}, backend={task.backend}, model={task.model or '—'})"
        if task and task.context_bundle_id:
            prov += f", context `{task.context_bundle_id[:8]}`"
        lines += ["", f"_Provenance: {prov}._", "", "---", ""]

    if not findings:
        lines.append("_No confirmed findings yet — accept findings to include them in the report._")
    return "\n".join(lines)
