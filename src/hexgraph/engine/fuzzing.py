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

# ASan/libFuzzer crash kind → baseline finding severity (the floor BY BUG TYPE).
# The deterministic exploitability rating (from the sanitizer report — see
# fuzz_probe.classify_exploitability) refines this: it never drags a known
# memory-corruption type below its baseline, but for the *direction-ambiguous*
# kinds (SEGV / deadly-signal / bare crash) the report-derived rating governs, and
# it can ratchet any type UP to critical (a likely-exploitable controllable write).
_SEVERITY = {
    "heap-buffer-overflow": "critical", "stack-buffer-overflow": "critical",
    "heap-use-after-free": "critical", "use-after-free": "critical",
    "global-buffer-overflow": "high", "double-free": "high", "stack-overflow": "medium",
    "deadly-signal": "medium", "SEGV": "medium", "dynamic-stack-buffer-overflow": "critical",
    "out-of-memory": "low", "memory-leak": "low", "timeout": "low", "crash": "medium",
}

# Exploitability rating → the severity it implies on its own.
_EXPL_SEVERITY = {
    "likely_exploitable": "critical",
    "probably_exploitable": "high",
    "info_leak": "medium",
    "dos": "low",
    "not_exploitable": "low",
    "unknown": "medium",
}
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# The direction-ambiguous ASan kinds where the exploitability rating, derived from
# the actual READ/WRITE in the report, is more informative than the bare type.
_AMBIGUOUS_KINDS = {"crash", "SEGV", "deadly-signal", "timeout", "out-of-memory",
                    "memory-leak", "stack-overflow"}


def _severity_for(kind: str, exploitability: dict | None) -> str:
    """Combine the bug-type baseline with the exploitability rating (deterministic).

    - A `likely_exploitable` rating always pins to critical.
    - For direction-ambiguous kinds (SEGV/crash/…), the report-derived rating wins.
    - Otherwise take the stronger of the type baseline and the rating's implied
      severity, so a write-corruption never reads softer than its type and a
      read-only OOB can still settle at info_leak (medium)."""
    base = _SEVERITY.get(kind, "high")
    rating = (exploitability or {}).get("rating")
    if not rating:
        return base
    expl_sev = _EXPL_SEVERITY.get(rating, "medium")
    if rating == "likely_exploitable":
        return "critical"
    if kind in _AMBIGUOUS_KINDS:
        return expl_sev
    return base if _SEV_RANK[base] >= _SEV_RANK[expl_sev] else expl_sev


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
    task param → the task's parent finding → a managed `source_file(role=harness)`
    promoted for this target (the new home, design §4.3) → the latest
    harness_generation finding's transient `evidence.decompiled_snippet` (the legacy
    back-compat read path, so old findings still drive fuzzing without a backfill)."""
    p = task.params_json or {}
    if p.get("harness_source"):
        return p["harness_source"], None, p.get("function")
    if task.parent_finding_id:
        f = session.get(FindingRow, task.parent_finding_id)
        ev = (f.evidence_json or {}) if f else {}
        if ev.get("decompiled_snippet"):
            return ev["decompiled_snippet"], f.id, ev.get("function")
    # Prefer a promoted managed harness file (durable, navigable).
    project = session.get(Project, target.project_id)
    if project is not None:
        from hexgraph.engine.harness_promote import resolve_managed_harness

        managed, _node_id = resolve_managed_harness(session, project, target.id)
        if managed:
            return managed, None, p.get("function")
    # Legacy fallback: the transient snippet on a harness_generation finding.
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


def resolve_target_sources(target: Target, task: Task) -> list[str]:
    """Host paths of the TARGET's own source files to compile WITH the harness under
    `-fsanitize=fuzzer-no-link,address` (→ coverage-guided fuzzing). Sources come from
    the task param `target_sources` (an explicit operator/agent list) or, for a
    firmware/source-derived target, files recorded under
    `metadata_json["fuzz_target_sources"]`. Each entry must be an existing regular
    file; anything missing is dropped (we degrade to a coverage-blind run, never
    silently claim instrumentation). The harness compiles/parses NOTHING here — the
    sandbox does; this only resolves which files to mount."""
    p = task.params_json or {}
    candidates: list[str] = []
    raw = p.get("target_sources")
    if isinstance(raw, str):
        candidates.append(raw)
    elif isinstance(raw, (list, tuple)):
        candidates.extend(str(x) for x in raw)
    meta = (target.metadata_json or {}).get("fuzz_target_sources")
    if isinstance(meta, (list, tuple)):
        candidates.extend(str(x) for x in meta)
    out: list[str] = []
    for c in candidates:
        if c and os.path.isfile(c) and c not in out:
            out.append(c)
    return out


def crash_finding(crash: dict, function: str | None, target_name: str,
                  *, coverage_instrumented: bool, engine: str = "libfuzzer",
                  campaign_id: str | None = None, reproducer_ref: str | None = None) -> Finding:
    """Build a `fuzz_crash` finding from a probe crash dict. Shared by the single-pass
    `fuzzing` task and the Phase-3 detached campaign reaper (so the envelope is
    identical regardless of engine). `engine`/`campaign_id`/`reproducer_ref` thread the
    campaign provenance + the CAS reproducer (re-runnable via verify_poc) into
    `evidence.extra.fuzz`. The frozen Finding schema is untouched."""
    kind = crash.get("kind", "crash")
    expl = crash.get("exploitability") or {}
    sev = _severity_for(kind, expl)
    where = function or crash.get("function") or "the harness"
    dupes = int(crash.get("dupe_count") or 0)
    engine_label = "AFL++" if engine == "afl" else "libFuzzer"

    # The fuzz envelope — all new structure rides evidence.extra.fuzz (frozen schema
    # untouched). `coverage_instrumented=false` is the honest black-box flag: with no
    # source, the fuzzer mutated against no coverage from the code under test.
    # `reproducer_ref` is the CAS sha of the minimized reproducer BYTES — the
    # one-click-re-verifiable handle wired into verify_poc(reproducer_ref).
    fuzz_extra = {
        "engine": engine,
        "campaign_id": campaign_id,
        "crash_kind": kind,
        "dedup_key": crash.get("dedup_key"),
        "dupe_count": dupes,
        "exploitability": expl or None,
        "coverage_instrumented": bool(coverage_instrumented),
        "reproducer_sha": crash.get("reproducer_sha256"),
        "reproducer_size": crash.get("reproducer_size"),
        "minimized_reproducer_sha": crash.get("minimized_reproducer_sha256"),
        "minimized_reproducer_size": crash.get("minimized_reproducer_size"),
        "reproducer_ref": reproducer_ref,
    }
    rating = expl.get("rating")
    cov_note = ("" if coverage_instrumented
                else " NOTE: only an uninstrumented binary was available, so this was a "
                     "coverage-blind (black-box) run — coverage feedback was not used.")
    dupe_note = f" {dupes} additional crashing input(s) bucketed to the same root cause." if dupes else ""

    return Finding(
        title=f"Fuzzing crash: {kind} in {where}",
        severity=sev,
        confidence="high",  # a reproduced crash is concrete evidence
        category="memory-safety",
        summary=(f"{engine_label} reproduced a {kind} while fuzzing {target_name} via the generated harness"
                 f"{' (coverage-guided, instrumented target)' if coverage_instrumented else ''}."),
        reasoning=((crash.get("summary") or f"AddressSanitizer reported {kind}.")
                   + (f" Deterministic exploitability triage: {rating}." if rating else "")
                   + dupe_note + cov_note),
        evidence=Evidence(
            function=function or crash.get("function"),
            reproducer=crash.get("minimized_reproducer_sha256") or crash.get("reproducer_sha256"),
            backtrace=[crash["summary"]] if crash.get("summary") else None,
            # LAB-CONFIRMED: the harness fired the bug in isolation (code_present/dynamic) — proven
            # real, but the harness feeds the function directly, so the production input path is NOT
            # established. See engine/assurance.py + docs/design-verification-oracles.md.
            extra={"engine": engine, "crash_kind": kind,
                   "reproducer_size": crash.get("reproducer_size"),
                   "faulting_function": crash.get("function"),
                   "fuzz": fuzz_extra,
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


# Back-compat alias (the single-pass path used the private name).
_crash_finding = crash_finding


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

    # Resolve the SAME libFuzzer inputs through the Fuzzer seam (LibFuzzerFuzzer) — a
    # strict superset of the Phase-0 behaviour: identical harness/source/lib/seed
    # resolution + identical fuzz_probe.py invocation, so the single-pass path is byte-
    # for-byte unchanged. (The seam dispatches by SURFACE; the single-pass task pins
    # libfuzzer to preserve behaviour.) The detached campaign path uses the same seam.
    from hexgraph.engine.fuzzers import FuzzCampaignSpec, get_fuzzer

    target_sources = resolve_target_sources(target, task)
    target_lib = (target.path if target.kind == TargetKind.shared_library
                  and target.path and os.path.isfile(target.path) else None)
    sp = (task.params_json or {}).get("seeds")
    seed_paths = [str(x) for x in sp] if isinstance(sp, (list, tuple)) else ([str(sp)] if sp else [])
    spec = FuzzCampaignSpec(
        target_id=target.id, surface="source_lib", engine="libfuzzer",
        harness_source=source, function=function, target_sources=target_sources,
        target_lib=target_lib, seeds=seed_paths,
        max_total_time=cfg["max_total_time"], max_len=cfg["max_len"],
        max_crashes=cfg["max_crashes"],
    )
    prepared = get_fuzzer("source_lib", "libfuzzer").prepare(spec, project, target)
    src_path = prepared.artifact
    try:
        result = runner.run_json_probe(
            prepared.probe, src_path, outdir=crash_dir, extra_args=prepared.extra_args,
            requires_execution=True, extra_ro_mounts=prepared.extra_ro_mounts or None,
        )
    finally:
        if src_path:
            os.unlink(src_path)

    write_trace(task, "fuzz.json", {"config": cfg, "function": function,
                                    "coverage_instrumented": bool(target_sources), "result": result})

    if not result.get("compiled"):
        # Build failure isn't a crash; surface it for triage rather than silently 0.
        task.status = TaskStatus.needs_triage
        return 0

    # The probe is the source of truth for whether instrumentation actually compiled;
    # default to whether we mounted source (back-compat with a probe that omits it).
    coverage_instrumented = bool(result.get("coverage_instrumented", bool(target_sources)))
    crashes = result.get("crashes", []) or []
    created = 0
    for crash in crashes:
        row = persist_finding(
            session, project_id=project.id, target_id=target.id, task_id=task.id,
            finding=_crash_finding(crash, function, target.name,
                                   coverage_instrumented=coverage_instrumented),
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
