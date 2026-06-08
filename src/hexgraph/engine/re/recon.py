"""The `recon` task (SPEC §5) — deterministic, NO LLM.

Runs the sandboxed recon probe over a target, records the facts on the target
row, and emits exactly one schema-valid `recon` finding. This alone proves
ingest → graph → findings with zero model calls.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, TargetKind
from hexgraph.db.models import Finding as FindingRow
from hexgraph.db.models import Task
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.tasks import create_task, mark_running, mark_succeeded, write_trace
from hexgraph.models.finding import Evidence, Finding, FollowupSuggestion
from hexgraph.sandbox.executor import Executor, get_executor

# Dangerous libc sinks worth a static-analysis follow-up if imported.
RISKY_SINKS = {"strcpy", "strcat", "sprintf", "gets", "scanf", "system", "popen", "exec", "memcpy"}

_KIND_MAP = {
    "executable": TargetKind.executable,
    "shared_library": TargetKind.shared_library,
    "firmware_image": TargetKind.firmware_image,
}


def apply_facts_to_target(target: Target, facts: dict) -> None:
    target.format = facts.get("format") or target.format
    target.arch = facts.get("arch") or target.arch
    kind = _KIND_MAP.get(facts.get("kind", ""))
    if kind is not None:
        target.kind = kind
    meta = dict(target.metadata_json or {})
    for key in ("sha256", "md5", "size", "mitigations", "imports", "exports", "libraries", "strings"):
        if key in facts:
            meta[key] = facts[key]
    target.metadata_json = meta


def build_recon_finding(facts: dict, target_name: str) -> Finding:
    mit = facts.get("mitigations", {})
    imports = facts.get("imports", [])
    risky = sorted(set(imports) & RISKY_SINKS)
    fmt = facts.get("format", "unknown")
    arch = facts.get("arch", "unknown")

    weak = [k for k in ("canary", "pie") if mit.get(k) is False]
    weak_str = f"weak mitigations ({', '.join(weak)} off)" if weak else "standard mitigations"
    risky_str = f" Imports risky sinks: {', '.join(risky)}." if risky else ""

    followups: list[FollowupSuggestion] = []
    if risky and facts.get("kind") in ("executable", "shared_library"):
        followups.append(
            FollowupSuggestion(
                task_type="static_analysis",
                label=f"Static-analyze {target_name} for memory safety",
                params={"sink": risky[0]},
            )
        )

    return Finding(
        title=f"Attack-surface summary for {target_name}",
        severity="info",
        confidence="high",
        category="recon",
        summary=f"{fmt} {arch} {facts.get('kind', 'binary')} with {weak_str}.{risky_str}",
        reasoning=(
            f"Deterministic recon (no LLM). Mitigations: {mit}. "
            f"Linked libraries: {facts.get('libraries', [])}. "
            f"{len(imports)} imported symbols; risky sinks present: {risky or 'none'}."
        ),
        evidence=Evidence(
            file=target_name,
            strings=(facts.get("strings") or [])[:15],
            extra={
                "format": fmt,
                "arch": arch,
                "kind": facts.get("kind"),
                "mitigations": mit,
                "libraries": facts.get("libraries", []),
                "imports": imports[:40],
                "hashes": {k: facts.get(k) for k in ("sha256", "md5", "size") if k in facts},
            },
        ),
        suggested_followups=followups or None,
    )


def execute_recon(
    session: Session,
    project: Project,
    target: Target,
    task: Task,
    runner: Executor | None = None,
) -> tuple[FindingRow, dict]:
    """Run recon for an existing task row. Returns (finding row, raw facts)."""
    runner = runner or get_executor()
    facts = runner.run_json_probe("recon_probe.py", target.path)
    write_trace(task, "recon_facts.json", facts)

    apply_facts_to_target(target, facts)
    _materialize_recon_nodes(session, project.id, target, facts)
    finding = build_recon_finding(facts, target.name)
    row = persist_finding(
        session,
        project_id=project.id,
        target_id=target.id,
        task_id=task.id,
        finding=finding,
    )
    return row, facts


def _materialize_recon_nodes(session: Session, project_id: str, target: Target, facts: dict) -> None:
    """Materialize a bounded set of symbol + string nodes from recon facts
    (design §3.2: filtered, not thousands of rows)."""
    from hexgraph.engine.graph.nodes import MAX_STRINGS, MAX_SYMBOLS, materialize_string, materialize_symbol

    imports = facts.get("imports", [])[:MAX_SYMBOLS]
    for name in imports:
        materialize_symbol(
            session, project_id=project_id, target_id=target.id, name=name,
            kind="import", is_sink=name in RISKY_SINKS,
        )
    for value in (facts.get("strings", []) or [])[:MAX_STRINGS]:
        materialize_string(session, project_id=project_id, target_id=target.id, value=value)


def run_recon(
    session: Session,
    project: Project,
    target: Target,
    runner: Executor | None = None,
) -> tuple[FindingRow, dict]:
    """Create a recon task and run it. Returns (finding row, raw facts)."""
    task = create_task(session, project=project, target_id=target.id, type="recon", backend="none")
    mark_running(task)
    row, facts = execute_recon(session, project, target, task, runner)
    mark_succeeded(task)
    return row, facts
