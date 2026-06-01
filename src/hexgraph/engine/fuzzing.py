"""The `fuzzing` task — dynamic, opt-in (design: future dynamic profile).

Takes a harness produced by `harness_generation`, compiles it with libFuzzer +
AddressSanitizer in the sandbox, runs it under configured stop parameters, and
auto-creates one deterministic finding per unique crash (no LLM). An optional
LLM **triage** step (task param `triage`, real backend only) enriches each crash
finding with an exploitability assessment.

Execution is gated by the analysis **policy**: `assert_allows_execution()` raises
unless fuzzing is enabled in Settings, so the static-only default holds. The probe
still runs `--network none`, capped, timed, in a disposable container.
"""

from __future__ import annotations

import os
import tempfile

from sqlalchemy.orm import Session

from hexgraph.db.models import Finding as FindingRow
from hexgraph.db.models import Project, Target, TargetKind, Task, TaskStatus
from hexgraph.engine.assurance import derive_fuzz_assurance
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.tasks import write_trace
from hexgraph.models.finding import Evidence, Finding, FollowupSuggestion
from hexgraph.sandbox.executor import Executor, get_executor

# ASan/libFuzzer crash kind → finding severity.
_SEVERITY = {
    "heap-buffer-overflow": "critical", "stack-buffer-overflow": "critical",
    "heap-use-after-free": "critical", "use-after-free": "critical",
    "global-buffer-overflow": "high", "double-free": "high", "stack-overflow": "high",
    "deadly-signal": "high", "SEGV": "high", "dynamic-stack-buffer-overflow": "critical",
    "out-of-memory": "medium", "memory-leak": "medium", "timeout": "low", "crash": "high",
}


def fuzz_config(task: Task) -> dict:
    """Stop parameters: Settings defaults overridden by per-task params."""
    from hexgraph import settings

    g = settings.resolved()["features"]["fuzzing"]
    p = task.params_json or {}
    return {
        "max_total_time": int(p.get("max_total_time", g["max_total_time"])),
        "max_len": int(p.get("max_len", g["max_len"])),
        "max_crashes": int(p.get("max_crashes", g["max_crashes"])),
        "timeout": int(p.get("timeout", g["timeout"])),
        "triage": bool(p.get("triage", False)),
    }


def resolve_harness(session: Session, target: Target, task: Task) -> tuple[str | None, str | None, str | None]:
    """Find harness source → (source, source_finding_id, function). Order: explicit
    task param → the task's parent finding → the latest harness_generation finding
    for this target."""
    p = task.params_json or {}
    if p.get("harness_source"):
        return p["harness_source"], None, p.get("function")
    if task.parent_finding_id:
        f = session.get(FindingRow, task.parent_finding_id)
        ev = (f.evidence_json or {}) if f else {}
        if ev.get("decompiled_snippet"):
            return ev["decompiled_snippet"], f.id, ev.get("function")
    hg = (
        session.query(Task)
        .filter(Task.target_id == target.id, Task.type == "harness_generation")
        .order_by(Task.created_at.desc()).all()
    )
    for t in hg:
        f = session.query(FindingRow).filter(FindingRow.task_id == t.id).first()
        ev = (f.evidence_json or {}) if f else {}
        if ev.get("decompiled_snippet"):
            return ev["decompiled_snippet"], f.id, ev.get("function")
    return None, None, p.get("function")


def _crash_finding(crash: dict, function: str | None, target_name: str) -> Finding:
    kind = crash.get("kind", "crash")
    sev = _SEVERITY.get(kind, "high")
    where = function or crash.get("function") or "the harness"
    return Finding(
        title=f"Fuzzing crash: {kind} in {where}",
        severity=sev,
        confidence="high",  # a reproduced crash is concrete evidence
        category="memory-safety",
        summary=f"libFuzzer reproduced a {kind} while fuzzing {target_name} via the generated harness.",
        reasoning=crash.get("summary") or f"AddressSanitizer reported {kind}.",
        evidence=Evidence(
            function=function or crash.get("function"),
            reproducer=crash.get("reproducer_sha256"),
            backtrace=[crash["summary"]] if crash.get("summary") else None,
            # LAB-CONFIRMED: the harness fired the bug in isolation (code_present/dynamic) — proven
            # real, but the harness feeds the function directly, so the production input path is NOT
            # established. See engine/assurance.py + docs/design-verification-oracles.md.
            extra={"engine": "libfuzzer", "crash_kind": kind,
                   "reproducer_size": crash.get("reproducer_size"),
                   "faulting_function": crash.get("function"),
                   "assurance": derive_fuzz_assurance()},
        ),
        suggested_followups=[
            FollowupSuggestion(
                task_type="static_analysis",
                label=f"Root-cause {kind} in {where}",
                params={"function": function or crash.get("function") or ""},
            )
        ],
    )


def execute_fuzzing(
    session: Session, project: Project, target: Target, task: Task, runner: Executor | None = None
) -> int:
    """Run a fuzzing campaign for `task`; persist a finding per unique crash.
    Returns the number of crash findings created. Raises PolicyViolation if the
    policy forbids execution, or ValueError if no harness is available."""
    from hexgraph.policy import assert_allows_execution

    assert_allows_execution()  # opt-in gate: raises unless fuzzing is enabled
    runner = runner or get_executor()

    source, src_fid, function = resolve_harness(session, target, task)
    if not source:
        raise ValueError("no fuzz harness available — run a harness_generation task for this target first")
    if src_fid and not task.parent_finding_id:
        task.parent_finding_id = src_fid

    cfg = fuzz_config(task)
    crash_dir = tempfile.mkdtemp(prefix="hexgraph-fuzz-out-")
    fd, src_path = tempfile.mkstemp(suffix=".c", prefix="hexgraph-harness-")
    with os.fdopen(fd, "w") as fh:
        fh.write(source)

    extra_args = [
        f"--max-total-time={cfg['max_total_time']}",
        f"--max-len={cfg['max_len']}",
        f"--max-crashes={cfg['max_crashes']}",
    ]
    mounts: list[tuple[str, str]] = []
    # Link the real library so the harness can call its exported functions.
    if target.kind == TargetKind.shared_library and target.path and os.path.isfile(target.path):
        mounts.append((target.path, "/target.so"))
        extra_args.append("--target-lib=/target.so")

    try:
        result = runner.run_json_probe(
            "fuzz_probe.py", src_path, outdir=crash_dir, extra_args=extra_args,
            requires_execution=True, extra_ro_mounts=mounts or None,
        )
    finally:
        os.unlink(src_path)

    write_trace(task, "fuzz.json", {"config": cfg, "function": function, "result": result})

    if not result.get("compiled"):
        # Build failure isn't a crash; surface it for triage rather than silently 0.
        task.status = TaskStatus.needs_triage
        return 0

    crashes = result.get("crashes", []) or []
    created = 0
    for crash in crashes:
        row = persist_finding(
            session, project_id=project.id, target_id=target.id, task_id=task.id,
            finding=_crash_finding(crash, function, target.name),
        )
        created += 1
        if cfg["triage"]:
            _triage(session, project, target, task, row, crash, source, function)

    from hexgraph.engine.runs import record_run

    record_run(session, project_id=project.id, anchor_kind="target", anchor_id=target.id,
               task=task, bundle_sha=None, finding_count=created)
    return created


def _triage(session, project, target, task, row: FindingRow, crash, harness, function) -> None:
    """Optional LLM step: enrich a crash finding with an exploitability assessment.
    Mock/none backends are skipped (nothing useful to add at $0)."""
    backend_name = task.backend if task.backend not in (None, "none") else project.llm_backend.value
    if backend_name in (None, "none", "mock"):
        return
    try:
        from hexgraph.llm.base import LLMRequest
        from hexgraph.llm.registry import get_backend
        from hexgraph.metering import record_usage

        backend = get_backend(backend_name)
        prompt = (
            f"A libFuzzer + AddressSanitizer run on {target.name} reproduced this crash:\n"
            f"  kind: {crash.get('kind')}\n  function: {crash.get('function') or function}\n"
            f"  report: {crash.get('summary')}\n\nHarness:\n{harness[:4000]}\n\n"
            "Assess exploitability (not exploitable / DoS / memory disclosure / control-flow), "
            "the likely root cause, and the minimal fix. Be concise."
        )
        resp = backend.complete(LLMRequest(task_type="fuzzing", task_id=task.id, prompt=prompt, model=task.model))
        record_usage("task.fuzzing.triage", resp.usage, task_id=task.id)
        ev = dict(row.evidence_json or {})
        extra = dict(ev.get("extra") or {})
        extra["triage"] = resp.text[:4000]
        ev["extra"] = extra
        row.evidence_json = ev
        row.reasoning = (row.reasoning or "") + "\n\nLLM triage:\n" + resp.text[:2000]
    except Exception:  # noqa: BLE001 — triage is best-effort enrichment
        pass
