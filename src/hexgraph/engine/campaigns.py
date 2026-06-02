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


def resolve_surface_inputs(session, project, target, spec) -> None:
    """Populate the surface-specific spec fields the engine needs when they weren't set
    explicitly (so the API/MCP/UI don't each re-derive them):

      • binary_only (qemu/frida) — `target_binary` (the target ELF, default target.path)
        and, for a foreign-arch firmware child, the parent firmware's extracted rootfs as
        the qemu `-L` `sysroot` (REUSING poc.py's _find_sysroot + filesystem.host_root —
        the proven PoC path).
      • network (boofuzz) — the live device `host`/`port` and the rehosted-device
        `net_container` to join. The host is the rehosted device IP (channel.rehost.ip) /
        a `remote` host / the web base_url host; the port is the campaign's `port` or a
        socket node / channel hint. desock needs the local server binary (target.path)."""
    from pathlib import Path

    if spec.surface in ("binary_only", "file_format") and spec.engine in (None, "qemu", "frida"):
        if not spec.target_binary and target.path:
            spec.target_binary = target.path
        if not spec.sysroot and target.parent_id:
            try:
                from hexgraph.engine.filesystem import host_root
                from hexgraph.engine.poc import _find_sysroot
                fw = session.get(Target, target.parent_id)
                if fw is not None and (fw.metadata_json or {}).get("filesystem"):
                    root = _find_sysroot(host_root(project, fw))
                    if root is not None and Path(str(root)).is_dir():
                        spec.sysroot = str(root)
            except Exception:  # noqa: BLE001 — sysroot is best-effort (degrades to native)
                pass

    if spec.surface == "network":
        if spec.engine == "desock":
            if not spec.target_binary and target.path:
                spec.target_binary = target.path
            return
        # boofuzz (default): resolve the live host/port + the netns to join.
        if not spec.host:
            spec.host = _device_host(target)
        if not spec.net_container:
            spec.net_container = (((target.metadata_json or {}).get("channel") or {})
                                  .get("rehost") or {}).get("container")
        if not spec.port:
            spec.port = _device_port(target)


def _device_host(target) -> str | None:
    """The loopback/private IP of a live device behind this target (mirrors
    surfaces._device_host): a rehosted surface records it under channel.rehost.ip, a
    `remote` target as channel.host, else the web base_url host."""
    ch = (target.metadata_json or {}).get("channel") or {}
    rehost = ch.get("rehost") or {}
    if rehost.get("ip"):
        return rehost["ip"]
    if ch.get("host"):
        return ch["host"]
    base = ch.get("base_url")
    if base:
        from urllib.parse import urlparse
        return urlparse(base).hostname
    return None


def _device_port(target) -> int | None:
    """A default service port for a network target: an explicit channel port, else the
    web base_url port, else None (the caller must supply one)."""
    ch = (target.metadata_json or {}).get("channel") or {}
    if ch.get("port"):
        try:
            return int(ch["port"])
        except (TypeError, ValueError):
            pass
    base = ch.get("base_url")
    if base:
        from urllib.parse import urlparse
        u = urlparse(base)
        return u.port or (443 if u.scheme == "https" else 80)
    return None


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
    Gated by the EXISTING policy tiers — NO new gate (design §5.6):
      • a LIVE-SOCKET network campaign (boofuzz) talks to a service, runs no target
        bytes locally → it rides the EXISTING local-network tier (`features.network` +
        local_tcp_scope, audited), checked in _launch_network — NOT the exec gate;
      • every other campaign (source/binary-only qemu/desock) EXECUTES a target binary in
        the sandbox → the EXISTING exec gate (`features.fuzzing`/`poc`).
    The launch is non-blocking: the container fuzzes continuously, the reaper ingests."""
    from hexgraph.policy import assert_allows_execution
    from hexgraph.sandbox.executor import get_executor

    # Validate the surface×engine pair fail-closed (the seam rule) FIRST, so we know which
    # gate applies (a live-socket boofuzz campaign needs egress, not exec).
    engine = resolve_engine(spec.surface, spec.engine)
    spec.engine = None if (os.environ.get("HEXGRAPH_FUZZER") == "mock") else engine
    is_live_network = (spec.surface == "network" and engine == "boofuzz"
                       and os.environ.get("HEXGRAPH_FUZZER") != "mock")
    if not is_live_network:
        assert_allows_execution()  # the existing exec gate — NO new gate for campaigns
    executor = executor or get_executor()

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

    # Resolve surface-specific inputs the engine needs (binary-only ELF + firmware
    # sysroot; network host/port/netns) from the target/graph when not explicitly set.
    resolve_surface_inputs(session, project, target, spec)

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
        elif prepared.requires_egress:
            # NETWORK-FUZZ (boofuzz): the ONLY place a campaign relaxes --network none.
            # Build the bounded local scope, assert egress + AUDIT the EgressEvent BEFORE
            # launch, then start the detached container on the bridge (or the rehosted
            # device's netns). Refuses any non-loopback/private host (local_tcp_scope).
            handle = _launch_network(session, project, target, row, prepared, spec,
                                     executor=executor, outdir=outdir, resources=res,
                                     container_name=container_name)
            row.container_name = handle.name
        else:
            # Binary-only (qemu/frida) + desock + source: --network none holds.
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
        if isinstance(exc, CampaignError):
            raise
        raise CampaignError(str(exc)) from exc

    session.flush()
    return row


def _launch_network(session, project, target, row, prepared, spec, *, executor, outdir,
                    resources, container_name):
    """Launch a boofuzz network-fuzz campaign on the bounded-egress path (design §5.6).

    The host:port MUST be loopback/private (local_tcp_scope refuses anything else — the
    EXISTING local-network tier, NO new gate); assert_allows_egress checks features.network
    + the per-run allowlist; EVERY launch is audited to EgressEvent (allow OR deny). The
    detached container joins the rehosted device's netns when `net_container` is set."""
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, current_policy,
                                 local_tcp_scope)

    host, port = prepared.egress_host, int(prepared.egress_port or 0)
    scope = local_tcp_scope(host, port)  # raises if the host isn't loopback/private
    dest = next(iter(scope.allow))
    try:
        assert_allows_egress(dest, scope, current_policy())
    except PolicyViolation as exc:
        record_egress(session, project_id=project.id, target_id=target.id, task_id=row.task_id,
                      dest=dest, allowed=False, tool="boofuzz",
                      detail="blocked: network egress not permitted by policy")
        raise CampaignError(str(exc)) from exc
    record_egress(session, project_id=project.id, target_id=target.id, task_id=row.task_id,
                  dest=dest, allowed=True, tool="boofuzz", detail=scope.rationale)

    from hexgraph import settings
    timeout = int(settings.get("features.network.timeout", 30) or 30)
    channel = {"host": host, "port": port, "protocol": spec.protocol,
               "allow": sorted(scope.allow), "timeout": timeout, "outdir": "/out",
               "max_total_time": spec.max_total_time, "max_crashes": spec.max_crashes}
    args = [*prepared.extra_args, "--channel", json.dumps(channel)]
    # requires_execution=False: a live-socket boofuzz campaign runs NO target bytes locally
    # (it's a network client) — it's gated by the egress assert above, not the exec gate.
    return executor.start_detached(
        prepared.probe, prepared.artifact, name=container_name, outdir=outdir,
        image=prepared.image, extra_args=args, requires_execution=False,
        extra_ro_mounts=prepared.extra_ro_mounts, resources=resources,
        allow_network=True, net_container=prepared.net_container,
    )


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
    # A small deterministic line-coverage map so the Source viewer's coverage shading is
    # demonstrable offline ($0). Real campaigns emit this from afl-cov/llvm-cov.
    (outdir / "coverage.json").write_text(json.dumps({
        "percent": 64.0,
        "files": {"target.c": {"covered": [1, 2, 3, 5, 8], "uncovered": [4, 6, 7],
                               "total": 8}},
    }))
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
        _snapshot_coverage(session, project, row)
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
                                reproducer_ref=content_cas, surface=row.surface)
        # Symbolize the ASan report into source-mapped stack frames (best-effort) so the
        # Artifacts triage UI can render a clickable stack (frame → source line). Frames
        # ride evidence.extra.fuzz.frames (frozen schema untouched).
        frames = parse_source_frames(crash.get("_report") or crash.get("summary") or "")
        if frames:
            extra = dict(finding.evidence.extra or {})
            fz = dict(extra.get("fuzz") or {})
            fz["frames"] = frames
            extra["fuzz"] = fz
            finding.evidence.extra = extra
        frow = persist_finding(session, project_id=project.id, target_id=target.id,
                               task_id=row.task_id, finding=finding, finding_type="fuzz_crash")
        # Auto-wire finding → source for the top in-project source frame so "Open in
        # source" / "click a symbolized frame" works without manual linking (best-effort).
        if frow is not None and frames:
            _autolink_top_frame(session, project, frow.id, frames)
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


def _snapshot_coverage(session, project, row) -> None:
    """Store the campaign's line-coverage map (`<outdir>/coverage.json`) in CAS on the
    row (`coverage_ref`) so per-line source shading survives container teardown.
    Best-effort; never fatal."""
    if not row.outdir or project is None:
        return
    p = Path(row.outdir) / "coverage.json"
    if not p.is_file():
        return
    try:
        row.coverage_ref = cas.put(project, p.read_bytes())
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

    Returns the verify result dict (incl. `assurance` — code_present/dynamic).

    A NETWORK crash (a boofuzz service-death) is replayed differently: its reproducer is
    a crashing MESSAGE, so we re-send it over the live socket + a liveness oracle (the
    bounded-egress tcp path) — the service dying again is `input_reachable/dynamic`."""
    from hexgraph.policy import assert_allows_execution
    from hexgraph.sandbox.executor import get_executor

    project = session.get(Project, artifact.project_id)
    campaign = session.get(FuzzCampaign, artifact.campaign_id)
    target = session.get(Target, campaign.target_id) if campaign else None
    if campaign is not None and campaign.surface == "network":
        return _verify_network_artifact(session, project, target, campaign, artifact,
                                        executor=executor)

    assert_allows_execution()
    executor = executor or get_executor()
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


def _verify_network_artifact(session, project, target, campaign, artifact, *, executor=None) -> dict:
    """Replay a NETWORK crash's crashing message over the live socket + a liveness oracle
    (design §5.6). Re-sends the recorded `net_reproducer` payload to the device's port
    (bounded egress, audited via run_tcp_probe), then re-probes that the service went DOWN.
    A confirmed re-kill is `input_reachable/dynamic` (reached + triggered end-to-end). The
    SAME bounded-egress gate as the campaign launch — features.network + local_tcp_scope —
    no new gate, no exec gate (no bytes are executed locally)."""
    from hexgraph.db.models import Finding
    from hexgraph.engine.assurance import (assurance, DYNAMIC, INPUT_REACHABLE, UNCONFIRMED,
                                           UNSPECIFIED)
    from hexgraph.engine.surfaces import run_tcp_probe

    if not artifact.finding_id:
        raise CampaignError("network artifact has no linked finding to re-verify")
    f = session.get(Finding, artifact.finding_id)
    nr = (((f.evidence_json or {}).get("extra") or {}).get("fuzz") or {}).get("net_reproducer") if f else None
    if not nr or not nr.get("payload_b64"):
        raise CampaignError("network artifact carries no re-runnable crashing message")
    import base64
    payload = base64.b64decode(nr["payload_b64"])
    port = int(nr.get("port") or campaign.config_json.get("port") or 0)
    if not port:
        raise CampaignError("network artifact has no service port to replay against")
    # Confirm the service is UP first, send the crashing message, then re-probe that it is
    # DOWN (a fresh connect fails). Each run_tcp_probe handles the egress assert + audit.
    # Replay the reproducer BYTE-EXACT via payload_hex (the str payload field is utf-8
    # re-encoded and would corrupt any non-ASCII byte). The death across a fresh connection
    # is the unforgeable liveness transition.
    pre = run_tcp_probe(session, project, target, port=port, runner=executor)  # banner grab
    if pre.get("ok") is False:
        return {"verified": False, "detail": "service was already down before replay",
                "assurance": assurance(UNCONFIRMED, DYNAMIC, UNSPECIFIED)}
    run_tcp_probe(session, project, target, port=port, payload_hex=payload.hex(),
                  runner=executor)  # the crashing message, byte-exact (audited)
    post = run_tcp_probe(session, project, target, port=port, runner=executor)  # re-probe liveness
    verified = post.get("ok") is False
    return {"verified": verified,
            "detail": ("re-sent the crashing message over the live socket; the service went DOWN"
                       if verified else "the service survived the replay (could not re-confirm the crash)"),
            "output": (post.get("error") or "")[:500],
            "assurance": (assurance(INPUT_REACHABLE, DYNAMIC, UNSPECIFIED,
                                    detail="re-sent the crashing message over the live socket; "
                                           "the service went down again")
                          if verified else assurance(UNCONFIRMED, DYNAMIC, UNSPECIFIED))}


# ── Source-mapped stack frames (the Artifacts triage stack → IDE jump) ───────────

import re as _re

# ASan/libFuzzer frame: `    #2 0x.. in func /path/to/file.c:42:7` (col optional).
_FRAME_RE = _re.compile(
    r"#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>\S+)\s+"
    r"(?P<file>[^\s:]+):(?P<line>\d+)(?::(?P<col>\d+))?")


def parse_source_frames(report: str, *, limit: int = 12) -> list[dict]:
    """Extract source-mapped stack frames `{idx, func, file, line, col}` from an ASan
    report (the symbolized `func file:line` form). Returns [] when frames are only
    module+offset (unsymbolized — e.g. the base sandbox image without llvm-symbolizer).
    Deterministic, pure — the UI renders these as a clickable stack."""
    frames: list[dict] = []
    for m in _FRAME_RE.finditer(report or ""):
        f = m.group("file")
        # Skip sanitizer-runtime / interceptor frames (compiler-rt) — not user source.
        if "compiler-rt" in f or "/sanitizer_common/" in f or f.endswith("interception.h"):
            continue
        frames.append({
            "idx": int(m.group("idx")), "func": m.group("func"),
            "file": f, "line": int(m.group("line")),
            "col": int(m.group("col")) if m.group("col") else None,
        })
        if len(frames) >= limit:
            break
    return frames


def _autolink_top_frame(session, project, finding_id: str, frames: list[dict]) -> None:
    """Best-effort: wire the finding to the topmost frame whose file matches a managed
    source tree (so the analyst can jump from the crash to its source line). Matches a
    frame's basename / suffix against a tree's manifest; silent on no match."""
    from hexgraph.db.models import SourceTree
    from hexgraph.engine.source import link_finding_to_source

    trees = (session.query(SourceTree)
             .filter(SourceTree.project_id == project.id, SourceTree.archived.is_(False)).all())
    if not trees:
        return
    for fr in frames:
        rel_candidates = _rel_candidates(fr["file"])
        for tree in trees:
            files = {e.get("rel") for e in (tree.manifest_json or {}).get("files", [])}
            hit = next((c for c in rel_candidates if c in files), None)
            if hit is None:
                # also try basename suffix-match
                base = rel_candidates[-1]
                hit = next((r for r in files if r and r.endswith("/" + base)), None)
            if hit:
                try:
                    link_finding_to_source(session, project, finding_id=finding_id,
                                           tree=tree, rel=hit, line=fr["line"], col=fr.get("col"))
                except Exception:  # noqa: BLE001 — never fail ingest on a link miss
                    return
                return


def _rel_candidates(path: str) -> list[str]:
    """Candidate manifest-rel paths for an absolute build path (`/src/foo/bar.c` →
    ['src/foo/bar.c', 'foo/bar.c', 'bar.c']) so a frame matches however the tree was
    rooted."""
    p = (path or "").lstrip("/")
    parts = p.split("/")
    return [("/".join(parts[i:])) for i in range(len(parts))]


# ── Promote a crash artifact to a tracked finding / PoC (the triage payoff) ───────

def promote_artifact(session: Session, artifact: FuzzArtifact, *, to_poc: bool = False) -> dict:
    """Promote a crash artifact into a tracked finding (and optionally seed a PoC spec
    from its reproducer). A fuzz_crash already persists a finding at ingest; promoting
    CONFIRMS it (status `confirmed`) so it leaves the triage inbox, and — when
    `to_poc` — stamps `evidence.extra.poc` with a reproducer-backed spec so the existing
    one-click verify path (verify_artifact, LLM-free) can re-prove it. No new finding is
    duplicated; this is the triage → tracked-work transition (design §6.3)."""
    from hexgraph.db.models import Finding

    if not artifact.finding_id:
        raise CampaignError("artifact has no linked finding to promote")
    f = session.get(Finding, artifact.finding_id)
    if f is None:
        raise CampaignError("linked finding not found")
    f.status = "confirmed"
    if to_poc:
        ev = dict(f.evidence_json or {})
        extra = dict(ev.get("extra") or {})
        # A reproducer-backed PoC spec: the verify path re-runs the stored reproducer
        # against the instrumented harness binary via the unforgeable `crash` oracle.
        extra["poc"] = {
            "kind": "fuzz_reproducer",
            "reproducer_ref": artifact.content_cas,
            "campaign_id": artifact.campaign_id,
            "artifact_id": artifact.id,
            "oracle": {"type": "crash"},
            "note": ("Re-runs the campaign's minimized reproducer against the instrumented "
                     "harness binary; 'verified' = the process really crashed on this input."),
        }
        ev["extra"] = extra
        f.evidence_json = ev
    session.flush()
    return {"artifact_id": artifact.id, "finding_id": f.id, "status": f.status,
            "to_poc": to_poc}


# ── Coverage (line-level shading for the Source viewer) ──────────────────────────

def coverage_for(session: Session, campaign: FuzzCampaign) -> dict:
    """Per-file line coverage for the campaign, for source shading (design §6.3).
    Best-effort: reads the campaign's `coverage.json` (the afl-cov/llvm-cov line map the
    fuzz probe writes: `{"files": {rel: {"covered": [..], "total": N}}}`) from the outdir
    or its CAS snapshot. Returns `{available, percent, files}` — `available=False` (no
    shading) when the campaign exposed no line map (honest: aggregate edge counts are
    not a per-line map). The Source viewer tints covered/uncovered lines from this."""
    data = _read_coverage(session, campaign)
    stats_pct = (campaign.stats_json or {}).get("coverage_percent")
    if not data:
        return {"available": False, "percent": stats_pct, "files": {}}
    files = data.get("files") or {}
    # Prefer the map's own percent; fall back to stats only when truly absent (0.0 is valid).
    pct = data["percent"] if data.get("percent") is not None else stats_pct
    return {"available": bool(files), "percent": pct, "files": files}


def _read_coverage(session, campaign) -> dict | None:
    # Prefer a live outdir file; fall back to the CAS snapshot ref.
    if campaign.outdir:
        p = Path(campaign.outdir) / "coverage.json"
        if p.is_file():
            try:
                return json.loads(p.read_text())
            except (OSError, json.JSONDecodeError):
                pass
    if campaign.coverage_ref:
        try:
            project = session.get(Project, campaign.project_id)
            raw = cas.get(project, campaign.coverage_ref)
            if raw:
                return json.loads(raw.decode())
        except Exception:  # noqa: BLE001
            return None
    return None


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


def artifact_to_dict(a: FuzzArtifact, *, session: Session | None = None) -> dict:
    """Serialize an artifact for the triage UI. When a `session` is supplied, fold in the
    linked finding's assurance triple (the two-standards ladder chip), the source-mapped
    stack frames (clickable → IDE), the finding status (so a promoted/confirmed crash
    leaves the inbox), and whether it carries a PoC + verification."""
    d = {
        "id": a.id, "campaign_id": a.campaign_id, "kind": a.kind,
        "content_cas": a.content_cas, "size": a.size, "sanitizer": a.sanitizer,
        "dedup_key": a.dedup_key, "dupe_count": a.dupe_count,
        "faulting_function": a.faulting_function,
        "exploitability": a.exploitability_json or {}, "finding_id": a.finding_id,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }
    if session is not None and a.finding_id:
        from hexgraph.db.models import Finding

        f = session.get(Finding, a.finding_id)
        if f is not None:
            ev = f.evidence_json or {}
            extra = ev.get("extra") or {}
            d["finding"] = {
                "id": f.id, "title": f.title, "severity": f.severity, "status": f.status,
                "verified": bool((extra.get("verification") or {}).get("verified")),
                "has_poc": bool(extra.get("poc")),
            }
            d["assurance"] = extra.get("assurance") or (extra.get("verification") or {}).get("assurance")
            d["frames"] = (extra.get("fuzz") or {}).get("frames") or []
            d["source_ref"] = extra.get("source_ref")
    return d


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
    return [artifact_to_dict(a, session=session) for a in arts]
