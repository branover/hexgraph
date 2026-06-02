"""Phase 3 — coverage-guided fuzzing, the detached campaign lifecycle, the Fuzzer
seam, the ResourceSpec, and the crash→verify tie-in. All offline ($0) via the
MockFuzzer + a fake executor; the real-AFL++ e2e is Docker-gated in test_fuzz_e2e.py.
"""

import pytest

from hexgraph.db.models import (
    Edge, EdgeType, Finding, FuzzArtifact, FuzzCampaign, Target, TargetKind,
)
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.fuzzers import FuzzerError, get_fuzzer, resolve_engine
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel
from hexgraph.policy import PolicyViolation
from hexgraph.sandbox.resources import ResourceSpec
from hexgraph import settings as st

from conftest import fixture_path

HARNESS = "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long n){return 0;}"


def _enable_fuzzing():
    st.update_settings({"features.fuzzing.enabled": True})


def _mock_env(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_FUZZER", "mock")


def _project_with_target(s):
    p = create_project(s, name="camp")
    t = ingest_file(s, project=p, src_path=fixture_path("vuln_httpd"), name="vuln_httpd")
    # Make it an instrumented derived target (source present → source_lib surface).
    t.metadata_json = {**(t.metadata_json or {}), "instrumented": True,
                       "fuzz_target_sources": ["/nonexistent/target.c"]}
    s.flush()
    # A harness_generation finding so resolve_harness finds source.
    hg = create_task(s, project=p, target_id=t.id, type="harness_generation")
    persist_finding(s, project_id=p.id, target_id=t.id, task_id=hg.id, finding=FModel(
        title="harness", severity="info", confidence="low", category="other",
        summary="s", reasoning="r",
        evidence=Evidence(function="cgi_handler", decompiled_snippet=HARNESS)))
    return p, t


# ── The Fuzzer seam (dispatch on surface, fail-closed on a bad pair) ──────────────

def test_seam_dispatch_by_surface_and_engine():
    assert resolve_engine("source_lib") == "afl"            # surface default
    assert resolve_engine("source_lib", "libfuzzer") == "libfuzzer"
    assert get_fuzzer("source_lib", "libfuzzer").name == "libfuzzer"
    assert get_fuzzer("source_lib", "afl").name == "afl"


def test_seam_fail_closed_on_nonsensical_pair():
    with pytest.raises(FuzzerError):
        resolve_engine("source_lib", "boofuzz")      # not valid for source_lib
    with pytest.raises(FuzzerError):
        resolve_engine("binary_only", "libfuzzer")   # libFuzzer can't do binary-only
    with pytest.raises(FuzzerError):
        resolve_engine("no_such_surface")


def test_mock_env_forces_mock_fuzzer(monkeypatch):
    _mock_env(monkeypatch)
    assert get_fuzzer("source_lib", "afl").name == "mock"


# ── ResourceSpec — unconstrained lifts ONLY mem/cpu/pids, never a security flag ───

def test_resourcespec_unconstrained_drops_only_resource_flags():
    rs = ResourceSpec(unconstrained=True)
    assert rs.docker_resource_args() == []        # no --memory/--cpus/--pids-limit
    rs2 = ResourceSpec()
    assert "--memory" in rs2.docker_resource_args()
    assert "--cpus" in rs2.docker_resource_args()
    assert "--pids-limit" in rs2.docker_resource_args()


def test_unconstrained_keeps_all_security_flags():
    """The CRUCIAL invariant: unconstrained relaxes resource ceilings ONLY — every
    security flag still appears in the container args. Audited explicitly (design §5.8a)."""
    from hexgraph.sandbox.runner import SandboxRunner

    r = SandboxRunner()
    args = r._hardening_args(allow_network=False, net_container=None,
                             resources=ResourceSpec(unconstrained=True), secret=False)
    # Resource ceilings ARE gone…
    assert "--memory" not in args and "--cpus" not in args and "--pids-limit" not in args
    # …but every security flag still holds.
    assert "--network" in args and args[args.index("--network") + 1] == "none"
    assert "--read-only" in args
    assert "--cap-drop" in args and "ALL" in args
    assert ("--security-opt", ) and "no-new-privileges" in args
    assert "--user" in args and "1000:1000" in args


def test_resolve_resources_merges_settings_default_and_override(hg_home):
    st.update_settings({"features.fuzzing.resources.mem": "4g"})
    rs = C.resolve_resources({"unconstrained": True})
    assert rs.mem == "4g"                 # from Settings default
    assert rs.unconstrained is True       # from the per-campaign override


# ── The detached campaign lifecycle: start → running → reap → finalize (mock) ─────

def test_campaign_lifecycle_mock(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib",
                                harness_source=HARNESS, function="cgi_handler",
                                target_sources=["/x.c"])
        row = C.start_campaign(s, p, t, spec=spec)
        cid = row.id
        assert row.status == "running"
        assert row.container_name
        # fuzzed_by edge wired.
        e = (s.query(Edge).filter(Edge.type == EdgeType.fuzzed_by.value,
                                  Edge.dst_id == cid).first())
        assert e is not None and e.src_id == t.id

        # Reap → ingest the mock crash → finalize.
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid))
        assert created == 1
        row = s.get(FuzzCampaign, cid)
        assert row.status == "completed"
        assert (row.stats_json or {}).get("crash_count") == 1
        arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).all()
        assert len(arts) == 1
        a = arts[0]
        assert a.kind == "crash" and a.dedup_key and a.content_cas
        assert a.finding_id  # streamed to a fuzz_crash finding
        # produced_artifact edge wired campaign → finding.
        pe = (s.query(Edge).filter(Edge.type == EdgeType.produced_artifact.value,
                                   Edge.src_id == cid).first())
        assert pe is not None and pe.dst_id == a.finding_id


def test_reap_is_idempotent(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        row = C.start_campaign(s, p, t, spec=spec)
        cid = row.id
        assert C.reap_campaign(s, s.get(FuzzCampaign, cid)) == 1
        # A second reap creates NO new artifact/finding (dedup'd).
        assert C.reap_campaign(s, s.get(FuzzCampaign, cid)) == 0
        assert s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).count() == 1


# ── Crash-safe re-attach: a simulated serve restart re-binds the reaper ───────────

def test_crash_safe_reattach(hg_home, monkeypatch):
    """A campaign launched, then the process 'restarts' BEFORE reaping. A fresh
    reap_all (the worker's startup pass) re-binds to the campaign by its durable row +
    container_name and finalizes it — campaigns survive a serve restart (design §5.5)."""
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        cid = C.start_campaign(s, p, t, spec=spec).id

    # NEW session = simulated restart. The reaper re-attaches purely from the durable row.
    with session_scope() as s:
        running = s.query(FuzzCampaign).filter(FuzzCampaign.status == "running").all()
        assert any(c.id == cid for c in running)
        C.reap_all(s)
        row = s.get(FuzzCampaign, cid)
        assert row.status == "completed"
        assert s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).count() == 1


# ── Stop / resume preserves the corpus ────────────────────────────────────────────

class _StopExecutor:
    """A fake executor recording stop_detached + poll calls (mock path needs none of
    these for the FUZZ run, but stop/resume call the executor)."""
    def __init__(self):
        self.stopped = []

    def poll_detached(self, name):
        return {"exists": True, "running": True, "exit_code": None}

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stopped.append(name)

    def start_detached(self, *a, **k):  # pragma: no cover
        from hexgraph.sandbox.runner import DetachedHandle
        return DetachedHandle(name=k["name"], outdir=str(k["outdir"]))


def test_stop_preserves_corpus_then_resume(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    ex = _StopExecutor()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        row = C.start_campaign(s, p, t, spec=spec)
        cid = row.id
        # Seed a corpus dir so the snapshot has something to preserve.
        from pathlib import Path
        cdir = Path(row.outdir) / "corpus"
        cdir.mkdir(parents=True, exist_ok=True)
        (cdir / "input0").write_bytes(b"SEEDDATA")

        C.stop_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        row = s.get(FuzzCampaign, cid)
        assert row.status == "stopped"
        assert row.corpus_ref  # corpus preserved in CAS (resumable)
        assert ex.stopped == [row.container_name] or ex.stopped  # container killed

        # Resume seeds from the preserved corpus + relaunches under the SAME row.
        resumed = C.resume_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        assert resumed.id == cid
        assert resumed.status == "running"
        # Only one campaign row exists (resume folds back, no throwaway row leaks)…
        assert s.query(FuzzCampaign).count() == 1
        # …and NO dangling fuzzed_by edge points at a deleted campaign (every such
        # edge's dst must be the surviving row).
        for e in s.query(Edge).filter(Edge.type == EdgeType.fuzzed_by.value).all():
            assert e.dst_id == cid


# ── Policy: a campaign needs the EXISTING exec gate (no new gate) ─────────────────

def test_campaign_requires_exec_policy(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    # fuzzing NOT enabled → static-only → start must fail closed.
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        with pytest.raises(PolicyViolation):
            C.start_campaign(s, p, t, spec=spec)


# ── Host concurrency cap (resource governance) ────────────────────────────────────

def test_host_concurrency_cap(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"],
                                instances=C.MAX_HOST_INSTANCES + 1)
        # Requesting more than the host cap is rejected (can't OOM the box).
        with pytest.raises(C.CampaignError):
            C.start_campaign(s, p, t, spec=spec)


# ── Surface inference ──────────────────────────────────────────────────────────────

def test_infer_surface(hg_home):
    with session_scope() as s:
        p = create_project(s, name="inf")
        t = ingest_file(s, project=p, src_path=fixture_path("vuln_httpd"), name="b")
        assert C.infer_surface(t) == "binary_only"      # plain binary, no source
        t.metadata_json = {"instrumented": True, "fuzz_target_sources": ["/x.c"]}
        assert C.infer_surface(t) == "source_lib"        # instrumented derived target
        web = Target(project_id=p.id, name="w", path="", kind=TargetKind.web_app)
        s.add(web); s.flush()
        assert C.infer_surface(web) == "network"


# ── LibFuzzer single-pass regression: the seam refactor is byte-identical ─────────

class _FakeRunner:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None):
        self.calls.append({"probe": probe, "extra_args": extra_args,
                           "requires_execution": requires_execution,
                           "mounts": extra_ro_mounts, "resources": resources})
        return self.payload

    def run_probe(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


def test_libfuzzer_single_pass_regression(hg_home):
    """The single-pass `fuzzing` task now routes input resolution through the
    LibFuzzerFuzzer seam, but the fuzz_probe invocation must be UNCHANGED: same probe,
    same flags, same requires_execution, libFuzzer crash → finding."""
    from hexgraph.engine.fuzzing import execute_fuzzing

    _enable_fuzzing()
    payload = {"compiled": True, "ran": True, "coverage_instrumented": False,
               "crashes": [{"kind": "heap-buffer-overflow", "function": "cgi_handler",
                            "summary": "SUMMARY: AddressSanitizer: heap-buffer-overflow",
                            "dedup_key": "k1", "dupe_count": 0,
                            "exploitability": {"rating": "likely_exploitable"},
                            "reproducer_sha256": "abc", "reproducer_size": 4}]}
    with session_scope() as s:
        p, t = _project_with_target(s)
        # Drop the instrumented marker so this is the plain libFuzzer single-pass path.
        t.metadata_json = {}
        s.flush()
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        runner = _FakeRunner(payload)
        created = execute_fuzzing(s, p, t, task, runner=runner)
        assert created == 1
        # The probe + the libFuzzer flags are EXACTLY as the Phase-0 path produced them.
        call = runner.calls[0]
        assert call["probe"] == "fuzz_probe.py"
        assert call["requires_execution"] is True
        assert any(a.startswith("--max-total-time=") for a in call["extra_args"])
        assert any(a.startswith("--max-len=") for a in call["extra_args"])
        # The single-pass path does NOT thread a ResourceSpec (unchanged behaviour).
        assert call["resources"] is None
        f = s.query(Finding).filter(Finding.title.like("Fuzzing crash%")).first()
        assert f is not None
        assert (f.evidence_json["extra"]["fuzz"]["engine"]) == "libfuzzer"


# ── Crash → verify tie-in: a reproducer re-runs via the verify_poc path ───────────

class _CrashRunner:
    """A fake executor whose poc_probe replay reports a crash (the unforgeable oracle)."""
    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None):
        assert probe == "poc_probe.py"
        return {"tool": "poc_probe", "ran": True, "verified": True, "exit_code": 139,
                "output": "AddressSanitizer", "detail": "exit 139 (crash)"}

    def run_probe(self, *a, **k):  # pragma: no cover
        raise NotImplementedError


def test_crash_reproducer_reverify(hg_home):
    """A fuzz crash's CAS-stored minimized reproducer re-runs via verify_reproducer
    (the verify_poc path) — LLM-free, the unforgeable `crash` oracle confirms it, and
    the assurance is code_present/dynamic (an isolated reproducer replay)."""
    from hexgraph.engine import cas
    from hexgraph.engine.poc import verify_reproducer

    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        ref = cas.put(p, b"CRASHING-INPUT-BYTES")
        res = verify_reproducer(s, p, t, reproducer_ref=ref, function="cgi_handler",
                                runner=_CrashRunner())
        assert res["verified"] is True
        a = res["assurance"]
        # An isolated reproducer replay is lab-confirmed: code_present / dynamic.
        assert a["standard"] == "code_present" and a["method"] == "dynamic"


# ── API surface (start/list/get/stop/artifacts), fail-closed without the gate ─────

def test_api_campaign_fail_closed_without_gate(hg_home):
    from fastapi.testclient import TestClient
    from hexgraph.api.app import create_app

    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/campaigns", json={"target_id": tid})
        assert r.status_code == 403  # static-only → fuzzing not permitted


def test_api_campaign_start_list_get_stop(hg_home, monkeypatch):
    from fastapi.testclient import TestClient
    from hexgraph.api.app import create_app

    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/campaigns",
                   json={"target_id": tid, "function": "cgi_handler",
                         "resources": {"unconstrained": True}})
        assert r.status_code == 200, r.text
        camp = r.json()
        cid = camp["id"]
        assert camp["status"] == "running"
        assert camp["resources"]["unconstrained"] is True

        # list
        lst = c.get(f"/api/projects/{pid}/campaigns").json()["campaigns"]
        assert any(x["id"] == cid for x in lst)

        # get (reaps on read → finalizes the mock campaign + ingests its crash)
        got = c.get(f"/api/campaigns/{cid}").json()
        assert got["status"] in ("running", "completed")
        arts = c.get(f"/api/campaigns/{cid}/artifacts").json()["artifacts"]
        assert len(arts) == 1 and arts[0]["dedup_key"]

        # stop is idempotent on an already-finalized campaign
        st_r = c.post(f"/api/campaigns/{cid}/stop")
        assert st_r.status_code == 200


def test_verify_finding_reproducer_reads_ref(hg_home):
    """verify_finding_reproducer pulls reproducer_ref from a fuzz_crash finding's
    evidence.extra.fuzz and re-runs it — the one-click re-verify for a fuzz finding."""
    from hexgraph.engine import cas
    from hexgraph.engine.fuzzing import crash_finding
    from hexgraph.engine.poc import verify_finding_reproducer

    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        ref = cas.put(p, b"REPRO")
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        fin = crash_finding({"kind": "heap-buffer-overflow", "function": "f",
                             "dedup_key": "k", "exploitability": {"rating": "dos"}},
                            "f", t.name, coverage_instrumented=True, engine="afl",
                            campaign_id="c1", reproducer_ref=ref)
        row = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                              finding=fin, finding_type="fuzz_crash")
        res = verify_finding_reproducer(s, p, row, runner=_CrashRunner())
        assert res["verified"] is True
