"""The `recon` task (SPEC §5) — deterministic, NO LLM.

Runs the sandboxed recon probe over a target and ENRICHES the target: it writes
the recovered facts onto the target row (format/arch/mitigations/imports/…) and
records the raw facts as a durable **Observation** (`result_kind="recon"`), so
they're queryable via `obs_list`/`obs_get` and re-used (analyze-once).

Recon no longer mints a per-target *finding* — recon is ordinary orientation, not
a vulnerability, and a 765-ELF firmware minted 765 of them. Node materialization
is deferred for HIDDEN targets (a hidden target contributes nothing to the curated
graph until revealed; reveal materializes its nodes from the already-stored facts).
The risky-sink → static_analysis follow-up moved to the suggester seam
(`engine/suggester.py::suggest_target_followups`), surfaced per-target via the
followups API.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, TargetKind
from hexgraph.db.models import Task
from hexgraph.engine.observations import content_hash_for, record_observation
from hexgraph.engine.tasks import create_task, mark_running, mark_succeeded, write_trace
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


def recon_summary(facts: dict, target_name: str) -> str:
    """A one-line human summary of the recon facts (the Observation summary + the
    basis for the per-target follow-up label)."""
    mit = facts.get("mitigations", {})
    imports = facts.get("imports", [])
    risky = sorted(set(imports) & RISKY_SINKS)
    fmt = facts.get("format", "unknown")
    arch = facts.get("arch", "unknown")
    weak = [k for k in ("canary", "pie") if mit.get(k) is False]
    weak_str = f"weak mitigations ({', '.join(weak)} off)" if weak else "standard mitigations"
    risky_str = f" Risky sinks: {', '.join(risky)}." if risky else ""
    return f"{fmt} {arch} {facts.get('kind', 'binary')} with {weak_str}.{risky_str}"


def record_recon_observation(session: Session, project: Project, target: Target, facts: dict):
    """Record the raw recon facts as a durable Observation (result_kind 'recon') so
    they're queryable (obs_list/obs_get) and re-used. Replaces the old per-target
    recon finding — recon enriches, it isn't a vulnerability."""
    obs, _cached = record_observation(
        session,
        project_id=project.id,
        target_id=target.id,
        source="recon",
        tool="recon_probe",
        args=None,
        result_kind="recon",
        payload=facts,
        summary=recon_summary(facts, target.name),
        content_hash=content_hash_for(target) or facts.get("sha256"),
    )
    return obs


def execute_recon(
    session: Session,
    project: Project,
    target: Target,
    task: Task,
    runner: Executor | None = None,
) -> dict:
    """Run recon for an existing task row: enrich the target's metadata, record a
    recon Observation, and (for VISIBLE targets only) materialize recon nodes.
    Hidden targets enrich but add nothing to the graph until revealed. Returns the
    raw facts."""
    runner = runner or get_executor()
    facts = runner.run_json_probe("recon_probe.py", target.path)
    write_trace(task, "recon_facts.json", facts)

    apply_facts_to_target(target, facts)
    record_recon_observation(session, project, target, facts)
    # A hidden target contributes nothing to the curated graph — defer node
    # materialization to reveal (`materialize_recon_nodes` runs then, from the
    # already-stored facts, no re-run).
    if target.visible:
        materialize_recon_nodes(session, project.id, target, facts)
    return facts


def materialize_recon_nodes(session: Session, project_id: str, target: Target, facts: dict) -> None:
    """Materialize a bounded set of symbol + string nodes from recon facts
    (design §3.2: filtered, not thousands of rows). Run for a visible target at
    recon time, and on reveal for a target that was hidden when recon ran."""
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
) -> dict:
    """Create a recon task and run it. Returns the raw facts."""
    task = create_task(session, project=project, target_id=target.id, type="recon", backend="none")
    mark_running(task)
    facts = execute_recon(session, project, target, task, runner)
    mark_succeeded(task)
    return facts
