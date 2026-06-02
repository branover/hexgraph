"""The detached fuzz-campaign lifecycle (design §5.5, Phase 3) — the keystone.

A campaign launches a DETACHED, long-lived sandbox container (`start_detached` on the
Executor seam; `docker run -d`, same hardening), owned by a durable `fuzz_campaign`
row. The launching task returns IMMEDIATELY (status `running`, `campaign_id`). A
periodic REAPER (a worker job) polls the container, ingests new artifacts into
`fuzz_artifact` + streams crashes → `fuzz_crash` findings (reusing Phase-0 stack-hash
dedup + exploitability + minimization), updates `stats_json`, and finalizes on
completion/stop.

  - **Stop/resume:** stop kills the container preserving the corpus in CAS; resume
    restarts seeded from it (AFL++ resumes natively).
  - **Crash-safe re-attach:** because the container is detached and the row durable, a
    `serve` restart re-attaches the reaper to running containers by `container_name`.
  - **Resource governance:** per-container mem/cpu/pids/wall caps (a ResourceSpec,
    `unconstrained` lifts ONLY mem/cpu/pids — NEVER a security flag); a per-host
    concurrency cap on instances; a corpus disk quota triggering cmin; crashes stream
    as they happen so a 6-hour campaign surfaces the first crash in minutes.

Nobody runs `afl-fuzz` by hand. The operator clicks "Fuzz" / the LLM calls
`start_fuzz_campaign`; HexGraph spawns and reaps. Execution is gated by the EXISTING
exec policy (`assert_allows_execution`, features.fuzzing/poc) — no new gate.
"""

from __future__ import annotations

import glob
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from hexgraph.db.models import (
    EdgeType, FuzzArtifact, FuzzCampaign, Project, Target, TargetKind, Task,
)
from hexgraph.engine import cas
from hexgraph.engine.edges import add_edge
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.fuzzers import FuzzCampaignSpec, get_fuzzer, resolve_engine
from hexgraph.engine.fuzzers.mock import MOCK_PROBE
from hexgraph.engine.fuzzers.shared import derive_dictionary
from hexgraph.sandbox.resources import ResourceSpec, default_resource_spec

# A per-host cap on concurrent fuzzer instances so a coverage explosion / many
# campaigns can't OOM the box (design §5.5 resource governance).
MAX_HOST_INSTANCES = 16
# Per-campaign corpus disk ceiling (bytes) — beyond it the reaper triggers cmin.
CORPUS_QUOTA_BYTES = 512 * 1024 * 1024


class CampaignError(RuntimeError):
    """A campaign could not be started/managed."""


# ── Surface inference ───────────────────────────────────────────────────────────

def infer_surface(target: Target) -> str:
    """Derive the attack surface from the target (design §2.3). An instrumented
    derived target (Phase-2 build, has source) → `source_lib` (coverage-guided). A
    web_app/remote surface → `network`. Else (a plain binary, no source) →
    `binary_only`. The operator/LLM may override the engine within the surface."""
    meta = target.metadata_json or {}
    if meta.get("instrumented") and meta.get("fuzz_target_sources"):
        return "source_lib"
    if target.kind in (TargetKind.web_app, TargetKind.remote):
        return "network"
    if meta.get("fuzz_target_sources"):
        return "source_lib"
    return "binary_only"


# ── Resource resolution (NEVER touches policy.py) ───────────────────────────────

def resolve_resources(override: dict | None) -> ResourceSpec:
    """The campaign ResourceSpec: the Settings global default, overlaid with a
    per-campaign override. `unconstrained` lifts mem/cpu/pids ONLY — the security
    hardening (`--network none`, cap-drop, no-new-privileges, read-only, user) holds
    regardless (asserted in the runner). Resource ≠ permission."""
    base = default_resource_spec()
    if not override:
        return base
    merged = {**base.to_dict(), **{k: v for k, v in override.items() if v is not None}}
    return ResourceSpec.from_dict(merged)


# ── Start a campaign (returns immediately) ──────────────────────────────────────

def start_campaign(session: Session, project: Project, target: Target, *,
                   spec: FuzzCampaignSpec, resources: dict | None = None,
                   task: Task | None = None, executor=None) -> FuzzCampaign:
    """Launch a detached fuzz campaign and return the durable row (status `running`).
    Gated by the EXISTING exec policy (assert_allows_execution). The launch is
    non-blocking: the container fuzzes continuously, the reaper ingests artifacts."""
    from hexgraph.policy import assert_allows_execution
    from hexgraph.sandbox.executor import get_executor

    assert_allows_execution()  # the existing exec gate — NO new gate for campaigns
    executor = executor or get_executor()

    # Validate the surface×engine pair fail-closed (the seam rule).
    engine = resolve_engine(spec.surface, spec.engine)
    spec.engine = None if (os.environ.get("HEXGRAPH_FUZZER") == "mock") else engine

    res = resolve_resources(resources)
    # Host concurrency cap (resource governance). A request ABOVE the cap is refused
    # outright (the operator stated intent we can't honor); within the cap, the new
    # instances must also fit alongside what is already running.
    requested = max(1, int(spec.instances or 1))
    if requested > MAX_HOST_INSTANCES or _running_instances(session) + requested > MAX_HOST_INSTANCES:
        raise CampaignError(
            f"per-host fuzzer concurrency cap reached ({MAX_HOST_INSTANCES} instances) — "
            "stop a running campaign first or request fewer instances")
    spec.instances = requested

    # A campaign's crashes are findings, which anchor to a task (provenance). When no
    # launching task was supplied (API/MCP start), create the backing `fuzzing` task so
    # every fuzz_crash finding has a real task_id and the run is recorded.
    if task is None:
        from hexgraph.engine.tasks import create_task
        task = create_task(session, project=project, target_id=target.id, type="fuzzing",
                           params={"campaign": True, "function": spec.function})

    # Auto-dictionary from the target's strings (best-effort) when none was supplied.
    if not spec.dictionary:
        spec.dictionary = derive_dictionary(session, target)

    fuzzer = get_fuzzer(spec.surface, spec.engine)
    prepared = fuzzer.prepare(spec, project, target)

    container_name = f"hexgraph-fuzz-{uuid.uuid4().hex[:12]}"
    outdir = str(Path(project.data_dir) / "campaigns" / container_name)
    Path(outdir).mkdir(parents=True, exist_ok=True)

    row = FuzzCampaign(
        project_id=project.id, target_id=target.id,
        name=spec.function and f"{target.name}:{spec.function}" or f"{target.name} fuzz",
        surface=spec.surface, engine=prepared.engine,
        harness_node_id=spec.harness_node_id, build_spec_id=spec.build_spec_id,
        task_id=task.id if task else None,
        container_name=container_name, outdir=outdir,
        config_json={**spec.to_dict(), "coverage_instrumented": prepared.coverage_instrumented},
        resources_json=res.to_dict(), status="running",
        stats_json={"execs": 0, "edges_covered": 0, "crash_count": 0, "peak_rss": 0,
                    "last_run_at": _now_iso()},
        instances=requested,
    )
    session.add(row)
    session.flush()

    # Wire the graph: target/harness `fuzzed_by` this campaign.
    add_edge(session, project_id=project.id, src=("target", target.id),
             dst=("fuzz_campaign", row.id), type=EdgeType.fuzzed_by,
             origin="tool", confidence=1.0, created_by_tool="fuzz",
             attrs={"surface": spec.surface, "engine": prepared.engine})

    # Persist the harness path on the config so a resume / re-prepare finds it (the
    # harness bytes live on the managed node / parent finding; the temp .c is ephemeral).
    if prepared.artifact:
        row.config_json = {**row.config_json, "_harness_artifact": prepared.artifact}
        session.flush()

    try:
        if prepared.probe == MOCK_PROBE:
            _launch_mock(row, prepared, spec)
        else:
            handle = executor.start_detached(
                prepared.probe, prepared.artifact, name=container_name, outdir=outdir,
                image=prepared.image, extra_args=prepared.extra_args,
                requires_execution=True, extra_ro_mounts=prepared.extra_ro_mounts,
                resources=res,
            )
            row.container_name = handle.name
    except Exception as exc:  # noqa: BLE001 — a failed launch fails the campaign cleanly
        row.status = "failed"
        row.error = f"{type(exc).__name__}: {exc}"
        row.finished_at = _now()
        session.flush()
        raise CampaignError(str(exc)) from exc

    session.flush()
    return row


def _launch_mock(row: FuzzCampaign, prepared, spec: FuzzCampaignSpec) -> None:
    """Drive the MockFuzzer offline (no Docker): write a deterministic crash artifact +
    stats to the campaign outdir, exactly the shape the reaper ingests. The container
    'completes' immediately — the reaper picks it up on its next tick and finalizes,
    so the FULL lifecycle (running → reap → finalize) is exercised at $0."""
    import hashlib

    outdir = Path(row.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    scenario = spec.function or "crash"
    crashes = []
    if scenario != "clean":
        # A deterministic reproducer + report so the verify tie-in test can re-run it.
        payload = (spec.harness_source or "mock").encode()[:64] or b"MOCKCRASH"
        sha = hashlib.sha256(payload).hexdigest()
        (outdir / f"crash-{sha[:16]}").write_bytes(payload)
        report = (f"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                  f"    #0 0x1 in {scenario} /src/target.c:1\n"
                  f"SUMMARY: AddressSanitizer: heap-buffer-overflow\nWRITE of size 8\n")
        crashes.append({
            "kind": "heap-buffer-overflow", "function": scenario,
            "summary": "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            "reproducer_sha256": sha, "reproducer_size": len(payload),
            "reproducer_b64": __import__("base64").b64encode(payload).decode(),
            "dedup_key": hashlib.sha256(f"heap-buffer-overflow|{scenario}".encode()).hexdigest(),
            "dupe_count": 0,
            "exploitability": {"rating": "likely_exploitable", "access": "WRITE",
                               "signals": ["out-of-bounds WRITE can corrupt adjacent memory"]},
            "minimized_reproducer_sha256": sha, "minimized_reproducer_size": len(payload),
            "coverage_instrumented": prepared.coverage_instrumented,
            "_report": report,
        })
    result = {"compiled": True, "ran": True, "engine": "mock", "done": True,
              "coverage_instrumented": prepared.coverage_instrumented,
              "executions": 1000, "edges_covered": 42, "crash_count": len(crashes),
              "crashes": crashes}
    (outdir / "status.json").write_text(json.dumps(result))
    (outdir / "DONE").write_text("mock")


# ── Reaping (the periodic worker job) ───────────────────────────────────────────

def reap_all(session: Session, *, executor=None) -> int:
    """Reap every live campaign once. Returns the number of crash findings created.
    Called periodically by the worker AND on a serve restart (crash-safe re-attach:
    we re-bind to running containers by `container_name` from the durable row)."""
    rows = (session.query(FuzzCampaign)
            .filter(FuzzCampaign.status.in_(["running", "building"]))
            .all())
    total = 0
    for row in rows:
        try:
            total += reap_campaign(session, row, executor=executor)
        except Exception:  # noqa: BLE001 — one bad campaign must not kill the reaper
            session.rollback()
    return total


def reap_campaign(session: Session, row: FuzzCampaign, *, executor=None) -> int:
    """Poll a campaign's container, ingest NEW artifacts (dedup'd) into fuzz_artifact +
    fuzz_crash findings, update stats, and finalize when the container exits. Idempotent
    — already-ingested dedup buckets are skipped, so polling repeatedly is safe and
    crashes stream as they appear."""
    from hexgraph.sandbox.executor import get_executor

    executor = executor or get_executor()
    project = session.get(Project, row.project_id)
    target = session.get(Target, row.target_id)
    outdir = row.outdir
    is_mock = row.engine == "mock"

    # Read the streamed status.json the probe writes (continuously / on completion).
    status = _read_status(outdir)
    done = False
    if outdir and (Path(outdir) / "DONE").exists():
        # The probe (or the mock launcher) signals completion with a DONE marker.
        done = True
    elif row.container_name and not is_mock:
        # Crash-safe re-attach: poll the detached container by its durable name. If it
        # no longer exists (e.g. removed) or has exited, the campaign is done.
        poll = executor.poll_detached(row.container_name)
        if not poll.get("exists") or not poll.get("running"):
            done = True

    created = 0
    if status:
        created = _ingest_artifacts(session, project, target, row, status)
        _update_stats(row, status)

    if done:
        _enforce_corpus_quota(row)
        # Preserve corpus in CAS (resumable) before tearing down.
        _snapshot_corpus(session, project, row)
        # Preserve the compiled harness/fuzzer binary in CAS so a stored reproducer is
        # genuinely RE-RUNNABLE (the verify_poc tie-in): the reproducer crashes THAT
        # instrumented binary, not the unrelated shipped target.
        _snapshot_fuzzer(session, project, row)
        if row.status != "stopped":
            row.status = "completed" if (status and status.get("compiled", True)) else "failed"
            if status and not status.get("compiled", True):
                row.error = (status.get("stderr") or "compile failed")[:500]
        row.finished_at = _now()
        if row.container_name and not is_mock:
            executor.stop_detached(row.container_name, remove=True)
        from hexgraph.engine.runs import record_run
        if row.task_id:
            t = session.get(Task, row.task_id)
            if t is not None:
                record_run(session, project_id=project.id, anchor_kind="target",
                           anchor_id=target.id, task=t, bundle_sha=None,
                           finding_count=int((row.stats_json or {}).get("crash_count", 0)))
    session.flush()
    return created


def _ingest_artifacts(session, project, target, row, status: dict) -> int:
    """Persist each NEW unique crash as a fuzz_artifact + a fuzz_crash finding, wiring
    the campaign `produced_artifact`→ the finding. Dedup is by `dedup_key`
    (UNIQUE(campaign_id,dedup_key)); a re-seen bucket only bumps dupe_count. Streams —
    so an early crash in a long campaign surfaces immediately."""
    from hexgraph.engine.fuzzing import crash_finding

    created = 0
    coverage = bool(status.get("coverage_instrumented"))
    for crash in status.get("crashes", []) or []:
        key = crash.get("dedup_key")
        if not key:
            continue
        existing = (session.query(FuzzArtifact)
                    .filter(FuzzArtifact.campaign_id == row.id,
                            FuzzArtifact.dedup_key == key).first())
        if existing is not None:
            existing.dupe_count = max(existing.dupe_count, int(crash.get("dupe_count") or 0))
            continue

        # Store the (minimized) reproducer bytes in CAS so it is re-runnable via
        # verify_poc(reproducer_ref). The probe streams bytes as base64 (small,
        # minimized); fall back to the sha when bytes weren't carried.
        content_cas = None
        b64 = crash.get("minimized_reproducer_b64") or crash.get("reproducer_b64")
        if b64:
            import base64
            try:
                content_cas = cas.put(project, base64.b64decode(b64))
            except Exception:  # noqa: BLE001
                content_cas = None

        finding = crash_finding(crash, crash.get("function") or row.config_json.get("function"),
                                target.name, coverage_instrumented=coverage,
                                engine=row.engine, campaign_id=row.id,
                                reproducer_ref=content_cas)
        frow = persist_finding(session, project_id=project.id, target_id=target.id,
                               task_id=row.task_id, finding=finding, finding_type="fuzz_crash")
        art = FuzzArtifact(
            project_id=project.id, campaign_id=row.id, kind="crash",
            content_cas=content_cas,
            size=int(crash.get("minimized_reproducer_size") or crash.get("reproducer_size") or 0),
            sanitizer=crash.get("kind"), dedup_key=key,
            dupe_count=int(crash.get("dupe_count") or 0),
            faulting_function=crash.get("function"),
            exploitability_json=crash.get("exploitability") or {},
            finding_id=frow.id if frow else None,
        )
        session.add(art)
        session.flush()
        if frow is not None:
            add_edge(session, project_id=project.id, src=("fuzz_campaign", row.id),
                     dst=("finding", frow.id), type=EdgeType.produced_artifact,
                     origin="tool", confidence=1.0, created_by_tool="fuzz",
                     attrs={"kind": "crash", "dedup_key": key})
        created += 1
    return created


def _update_stats(row: FuzzCampaign, status: dict) -> None:
    """Update the live campaign stats from the streamed status (monotonic — never
    regress a value if a later poll reports a smaller/absent figure)."""
    stats = dict(row.stats_json or {})
    stats["execs"] = max(int(stats.get("execs") or 0), int(status.get("executions") or 0))
    stats["edges_covered"] = max(int(stats.get("edges_covered") or 0),
                                 int(status.get("edges_covered") or 0))
    stats["crash_count"] = max(int(stats.get("crash_count") or 0),
                               int(status.get("crash_count") or 0))
    if status.get("peak_rss"):
        stats["peak_rss"] = max(int(stats.get("peak_rss") or 0), int(status["peak_rss"]))
    if status.get("coverage_percent") is not None:
        stats["coverage_percent"] = status["coverage_percent"]
    stats["last_run_at"] = _now_iso()
    row.stats_json = stats


# ── Stop / resume ────────────────────────────────────────────────────────────────

def stop_campaign(session: Session, row: FuzzCampaign, *, executor=None) -> FuzzCampaign:
    """Stop a running campaign — kill the container PRESERVING the corpus in CAS
    (resumable). Reaps any final artifacts first so nothing is lost."""
    from hexgraph.sandbox.executor import get_executor

    executor = executor or get_executor()
    # Final ingest of whatever the probe already streamed.
    status = _read_status(row.outdir)
    if status:
        project = session.get(Project, row.project_id)
        target = session.get(Target, row.target_id)
        _ingest_artifacts(session, project, target, row, status)
        _update_stats(row, status)
    _snapshot_corpus(session, session.get(Project, row.project_id), row)
    if row.container_name:
        executor.stop_detached(row.container_name, remove=True)
    row.status = "stopped"
    row.finished_at = _now()
    session.flush()
    return row


def resume_campaign(session: Session, row: FuzzCampaign, *, executor=None) -> FuzzCampaign:
    """Resume a stopped campaign, seeded from the preserved corpus (AFL++ resumes
    natively). Re-prepares from the recorded config + the CAS corpus snapshot and
    launches a fresh detached container under the same row."""
    if row.status not in ("stopped", "completed", "failed"):
        raise CampaignError(f"campaign is {row.status}; only a stopped/completed one resumes")
    project = session.get(Project, row.project_id)
    target = session.get(Target, row.target_id)
    cfg = dict(row.config_json or {})
    # Re-hydrate the spec; the harness bytes come from the managed node / parent (the
    # resolver path); seeds include the preserved corpus snapshot.
    spec = _spec_from_config(session, project, target, row, cfg)
    seed_dir = _restore_corpus(project, row)
    if seed_dir:
        spec.seeds = list(spec.seeds) + [str(p) for p in Path(seed_dir).glob("*") if p.is_file()]
    new = start_campaign(session, project, target, spec=spec,
                         resources=row.resources_json, executor=executor)
    # Fold the resume back onto the SAME logical campaign row (keep one identity): adopt
    # the new container, mark this row running again, and discard the throwaway row.
    row.container_name = new.container_name
    row.outdir = new.outdir
    row.status = "running"
    row.finished_at = None
    row.stats_json = {**(row.stats_json or {}), "last_run_at": _now_iso()}
    # Clean up everything start_campaign created for the throwaway row so resuming
    # doesn't leak a dangling fuzzed_by edge (→ a now-deleted campaign) or an orphan
    # backing task on every resume.
    from hexgraph.db.models import Edge
    (session.query(Edge)
     .filter(Edge.project_id == project.id, Edge.dst_kind == "fuzz_campaign",
             Edge.dst_id == new.id).delete(synchronize_session=False))
    if new.task_id and new.task_id != row.task_id:
        orphan = session.get(Task, new.task_id)
        if orphan is not None:
            session.delete(orphan)
    session.delete(new)
    session.flush()
    return row


def _spec_from_config(session, project, target, row, cfg) -> FuzzCampaignSpec:
    from hexgraph.engine.fuzzing import resolve_harness

    task = session.get(Task, row.task_id) if row.task_id else None
    harness_source = None
    if task is not None:
        harness_source, _fid, _fn = resolve_harness(session, target, task)
    return FuzzCampaignSpec(
        target_id=target.id, surface=row.surface, engine=row.engine,
        harness_source=harness_source, harness_node_id=row.harness_node_id,
        function=cfg.get("function"),
        target_sources=cfg.get("target_sources") or [],
        target_lib=cfg.get("target_lib"),
        seeds=[], dictionary=cfg.get("dictionary") or [],
        max_total_time=int(cfg.get("max_total_time", 60)),
        max_len=int(cfg.get("max_len", 4096)),
        max_crashes=int(cfg.get("max_crashes", 10)),
        instances=int(cfg.get("instances", 1)),
        build_spec_id=row.build_spec_id,
    )


# ── Corpus quota + snapshot (resumability + disk governance) ────────────────────

def _corpus_dir(row) -> Path | None:
    if not row.outdir:
        return None
    d = Path(row.outdir) / "corpus"
    return d if d.is_dir() else None


def _enforce_corpus_quota(row) -> None:
    """If the corpus exceeds the per-campaign quota, drop a marker so the probe/cmin
    trims it (best-effort; the real cmin happens inside the sandbox on resume)."""
    d = _corpus_dir(row)
    if not d:
        return
    total = sum(f.stat().st_size for f in d.glob("*") if f.is_file())
    if total > CORPUS_QUOTA_BYTES:
        (Path(row.outdir) / "CMIN_REQUESTED").write_text(str(total))


def _snapshot_corpus(session, project, row) -> None:
    """Store the corpus in CAS (one tar sha on the row) so a resume can restore it.
    Best-effort; never fatal."""
    d = _corpus_dir(row)
    if not d or project is None:
        return
    try:
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(str(d), arcname="corpus")
        row.corpus_ref = cas.put(project, buf.getvalue())
    except Exception:  # noqa: BLE001
        pass


def _snapshot_fuzzer(session, project, row) -> None:
    """Store the compiled harness/fuzzer binary (`<outdir>/fuzzer`) in CAS on the
    campaign config, so verify_reproducer can replay a crash against the SAME
    instrumented binary that produced it (re-runnable, LLM-free). Best-effort."""
    if not row.outdir or project is None:
        return
    fpath = Path(row.outdir) / "fuzzer"
    if not fpath.is_file():
        return
    try:
        sha = cas.put(project, fpath.read_bytes())
        row.config_json = {**(row.config_json or {}), "fuzzer_cas": sha}
    except Exception:  # noqa: BLE001
        pass


def _restore_corpus(project, row) -> str | None:
    """Extract the CAS corpus snapshot to a temp dir for re-seeding. None if absent."""
    if not row.corpus_ref or project is None:
        return None
    try:
        import io
        import tarfile
        import tempfile

        data = cas.get(project, row.corpus_ref)
        if not data:
            return None
        out = tempfile.mkdtemp(prefix="hexgraph-resume-corpus-")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            tar.extractall(out, filter="data")  # our own trusted snapshot
        inner = Path(out) / "corpus"
        return str(inner) if inner.is_dir() else out
    except Exception:  # noqa: BLE001
        return None


# ── helpers ─────────────────────────────────────────────────────────────────────

def _read_status(outdir) -> dict | None:
    if not outdir:
        return None
    p = Path(outdir) / "status.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _running_instances(session: Session) -> int:
    rows = (session.query(FuzzCampaign)
            .filter(FuzzCampaign.status.in_(["running", "building"])).all())
    return sum(int(r.instances or 1) for r in rows)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def verify_artifact(session: Session, artifact: FuzzArtifact, *, executor=None) -> dict:
    """Re-run a crash artifact's reproducer against the campaign's instrumented harness
    binary (the verify_poc tie-in, design §4.6). The reproducer crashes THAT binary
    (which has the target's objects + ASan), so we materialize the CAS-stored fuzzer +
    the CAS-stored reproducer, run the fuzzer with the reproducer as its input file in
    the sandbox, and check the unforgeable `crash` oracle (signal/ASan abort). LLM-free,
    gated by the existing exec policy. Falls back to verify_reproducer against the
    target binary if the fuzzer binary wasn't preserved.

    Returns the verify result dict (incl. `assurance` — code_present/dynamic)."""
    from hexgraph.policy import assert_allows_execution
    from hexgraph.sandbox.executor import get_executor

    assert_allows_execution()
    executor = executor or get_executor()
    project = session.get(Project, artifact.project_id)
    campaign = session.get(FuzzCampaign, artifact.campaign_id)
    target = session.get(Target, campaign.target_id) if campaign else None
    if not artifact.content_cas:
        raise CampaignError("artifact has no stored reproducer to re-verify")
    repro = cas.get(project, artifact.content_cas)
    if repro is None:
        raise CampaignError("reproducer bytes missing from CAS")

    fuzzer_cas = (campaign.config_json or {}).get("fuzzer_cas") if campaign else None
    if not fuzzer_cas:
        # No preserved harness binary — fall back to running the reproducer as stdin
        # against the target (works when the target IS a runnable binary).
        from hexgraph.engine.poc import verify_reproducer
        return verify_reproducer(session, project, target, reproducer_ref=artifact.content_cas,
                                 function=artifact.faulting_function, runner=executor)

    fuzzer_bytes = cas.get(project, fuzzer_cas)
    if fuzzer_bytes is None:
        from hexgraph.engine.poc import verify_reproducer
        return verify_reproducer(session, project, target, reproducer_ref=artifact.content_cas,
                                 function=artifact.faulting_function, runner=executor)

    import tempfile

    work = tempfile.mkdtemp(prefix="hexgraph-repro-")
    fuzzer_path = os.path.join(work, "fuzzer")
    repro_path = os.path.join(work, "reproducer")
    Path(fuzzer_path).write_bytes(fuzzer_bytes)
    os.chmod(fuzzer_path, 0o755)
    Path(repro_path).write_bytes(repro)
    out = tempfile.mkdtemp(prefix="hexgraph-repro-out-")
    # Run the fuzzer harness with the reproducer as its single input file (libFuzzer/AFL
    # persistent binaries replay a crashing file passed as argv[1]). The `crash` oracle
    # is unforgeable — the process really aborted on this input.
    spec = {"argv": ["/repro/reproducer"], "oracle": {"type": "crash"},
            "env": {"ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0"}}
    result = executor.run_json_probe(
        "poc_probe.py", fuzzer_path, outdir=out,
        extra_args=["--spec", json.dumps(spec)], requires_execution=True,
        extra_ro_mounts=[(repro_path, "/repro/reproducer")],
    )
    from hexgraph.engine.assurance import assurance, CODE_PRESENT, DYNAMIC, UNSPECIFIED
    result["assurance"] = (assurance(CODE_PRESENT, DYNAMIC, UNSPECIFIED,
                                     detail="lab-confirmed: the stored reproducer re-crashed the "
                                            "instrumented harness binary")
                           if result.get("verified") else
                           assurance("unconfirmed", DYNAMIC, UNSPECIFIED))
    return result


# ── Read helpers (API/MCP) ───────────────────────────────────────────────────────

def campaign_to_dict(row: FuzzCampaign) -> dict:
    return {
        "id": row.id, "project_id": row.project_id, "target_id": row.target_id,
        "name": row.name, "surface": row.surface, "engine": row.engine,
        "status": row.status, "instances": row.instances,
        "stats": row.stats_json or {}, "resources": row.resources_json or {},
        "coverage_instrumented": (row.config_json or {}).get("coverage_instrumented"),
        "build_spec_id": row.build_spec_id, "task_id": row.task_id,
        "corpus_ref": row.corpus_ref, "coverage_ref": row.coverage_ref,
        "error": row.error,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }


def artifact_to_dict(a: FuzzArtifact) -> dict:
    return {
        "id": a.id, "campaign_id": a.campaign_id, "kind": a.kind,
        "content_cas": a.content_cas, "size": a.size, "sanitizer": a.sanitizer,
        "dedup_key": a.dedup_key, "dupe_count": a.dupe_count,
        "faulting_function": a.faulting_function,
        "exploitability": a.exploitability_json or {}, "finding_id": a.finding_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def list_campaigns(session: Session, project: Project, *, target_id: str | None = None) -> list[dict]:
    q = session.query(FuzzCampaign).filter(FuzzCampaign.project_id == project.id,
                                           FuzzCampaign.archived.is_(False))
    if target_id:
        q = q.filter(FuzzCampaign.target_id == target_id)
    return [campaign_to_dict(c) for c in q.order_by(FuzzCampaign.created_at.desc()).all()]


def list_artifacts(session: Session, campaign: FuzzCampaign) -> list[dict]:
    arts = (session.query(FuzzArtifact)
            .filter(FuzzArtifact.campaign_id == campaign.id)
            .order_by(FuzzArtifact.created_at.asc()).all())
    return [artifact_to_dict(a) for a in arts]
