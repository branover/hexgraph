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


def test_unconstrained_tmpfs_follows_mem():
    """The unconstrained tmpfs size is DERIVED from `mem`, not a hardcoded 2g — so raising
    the memory limit widens the scratch in lockstep. Constrained tmpfs stays independent."""
    assert ResourceSpec().tmpfs_arg() == "512m"                       # constrained: the tmpfs field
    assert ResourceSpec(unconstrained=True).tmpfs_arg() == "2g"       # default mem 2g → 2g (was hardcoded)
    assert ResourceSpec(mem="16g", unconstrained=True).tmpfs_arg() == "16g"   # tracks mem


def test_settings_resources_default_matches_shipped_floor():
    """The shipped `resources.default` in settings.py must equal sandbox/resources.py's
    DEFAULT_* floor (a drift between the two would surprise on a fresh vs. legacy install)."""
    from hexgraph.settings import DEFAULTS
    assert DEFAULTS["resources"]["default"] == ResourceSpec().to_dict()


def test_resource_spec_for_per_container_type(hg_home):
    """resources.default is the shared baseline; resources.<type> diverges only that type's
    overridden keys — the analysis sandbox and build image can differ from each other and
    from the default, while inheriting it for everything they don't set."""
    from hexgraph.sandbox.resources import resource_spec_for
    st.update_settings({
        "resources.default.mem": "3g", "resources.default.cpus": 4,
        "resources.sandbox.mem": "1g",          # sandbox alone shrinks memory
        "resources.build.cpus": 8,              # build alone gets more cpus
    })
    base = resource_spec_for("sandbox")
    assert base.mem == "1g" and base.cpus == 4.0       # mem diverged, cpus inherited
    bld = resource_spec_for("build")
    assert bld.mem == "3g" and bld.cpus == 8.0         # mem inherited, cpus diverged
    dflt = resource_spec_for("default")
    assert dflt.mem == "3g" and dflt.cpus == 4.0       # the shared baseline


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


def test_hardening_mounts_dev_shm_data_only():
    """AFL++ maps its coverage bitmap in /dev/shm; docker's --read-only default is a fixed
    64 MiB, too small → the forkserver child segfaults before the handshake. The runner
    therefore mounts a SIZED tmpfs at /dev/shm. It must stay DATA-ONLY (noexec,nosuid,nodev)
    — that's a resource/IPC fix, NOT a security relaxation (it's stricter than docker's
    writable default)."""
    from hexgraph.sandbox.runner import SandboxRunner

    r = SandboxRunner()
    args = r._hardening_args(allow_network=False, net_container=None,
                             resources=ResourceSpec(), secret=False)
    shm = [args[i + 1] for i, a in enumerate(args)
           if a == "--tmpfs" and args[i + 1].startswith("/dev/shm:")]
    assert shm, "/dev/shm tmpfs must be mounted for AFL++ coverage SHM"
    spec = shm[0]
    assert "noexec" in spec and "nosuid" in spec and "nodev" in spec  # data-only, hardened
    assert "exec" not in spec.split(",")  # never executable — only /scratch + /tmp are
    # The security flags are still all present alongside it.
    assert "--read-only" in args and "--cap-drop" in args and "1000:1000" in args


def test_disable_aslr_swaps_minimal_seccomp_and_keeps_hardening():
    """The ASLR-disable path (ASan source fuzz) adds the MINIMAL custom seccomp profile so
    `setarch -R` (personality(ADDR_NO_RANDOMIZE)) is permitted, and NOTHING else relaxes.
    Default (disable_aslr=False) carries NO `seccomp=` opt (uses docker's default)."""
    import json

    from hexgraph.sandbox.runner import SECCOMP_ASLR_PROFILE, SandboxRunner

    r = SandboxRunner()
    base = r._hardening_args(allow_network=False, net_container=None,
                             resources=ResourceSpec(), secret=False)
    assert not any(a.startswith("seccomp=") for a in base), "default must use docker's seccomp"

    on = r._hardening_args(allow_network=False, net_container=None,
                           resources=ResourceSpec(), secret=False, disable_aslr=True)
    secopts = [on[i + 1] for i, a in enumerate(on) if a == "--security-opt"]
    seccomp = [s for s in secopts if s.startswith("seccomp=")]
    assert len(seccomp) == 1, "disable_aslr must add exactly one custom seccomp profile"
    assert "no-new-privileges" in secopts  # NOT dropped — still hardened
    # Every other security flag is byte-identical to the default path (only seccomp added).
    assert "--network" in on and on[on.index("--network") + 1] == "none"
    assert "--read-only" in on and "--cap-drop" in on and "ALL" in on
    assert "--user" in on and "1000:1000" in on

    # The profile is the minimal one: docker's deny-by-errno default + a SINGLE extra rule
    # allowing ONLY personality(ADDR_NO_RANDOMIZE=0x40000). It must not be unconfined.
    prof = json.loads(SECCOMP_ASLR_PROFILE.read_text())
    assert prof["defaultAction"] == "SCMP_ACT_ERRNO"  # deny-by-default, NOT unconfined
    persona = [s for s in prof["syscalls"] if "personality" in s.get("names", [])]
    vals = {a["value"] for s in persona for a in s.get("args", [])}
    assert 0x40000 in vals, "must allow personality(ADDR_NO_RANDOMIZE)"


def test_resolve_resources_merges_settings_default_and_override(hg_home):
    st.update_settings({"resources.fuzzing.mem": "4g"})
    rs = C.resolve_resources({"unconstrained": True})
    assert rs.mem == "4g"                 # from the fuzzing-type Settings default
    assert rs.unconstrained is True       # from the per-campaign override


def test_resolve_resources_inherits_shared_default(hg_home):
    """The fuzzing type inherits resources.default for any key it doesn't override —
    "all share the same" unless a per-type key diverges it."""
    st.update_settings({"resources.default.mem": "6g", "resources.default.cpus": 5})
    rs = C.resolve_resources(None)
    assert rs.mem == "6g" and rs.cpus == 5.0     # inherited from the shared default
    # A per-type override wins over the shared default for that key only.
    st.update_settings({"resources.fuzzing.cpus": 8})
    rs2 = C.resolve_resources(None)
    assert rs2.mem == "6g" and rs2.cpus == 8.0   # mem still shared, cpus diverged


def test_resolve_resources_honors_legacy_fuzzing_resources(hg_home):
    """A pre-existing settings.json that set features.fuzzing.resources.* (the old
    location) keeps working — resource_spec_for folds the USER-SET legacy values in."""
    # Write the legacy key straight into the managed layer (update_settings no longer
    # accepts it, mirroring an upgraded install that wrote it under the old schema).
    import json
    raw = json.loads(st.settings_path().read_text()) if st.settings_path().exists() else {}
    raw.setdefault("features", {}).setdefault("fuzzing", {})["resources"] = {"mem": "9g"}
    st._cfg.ensure_dirs(); st.settings_path().write_text(json.dumps(raw))
    assert C.resolve_resources(None).mem == "9g"


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


class _RunningExecutor:
    """A fake executor that reports a still-running detached container (so the reaper
    treats a status.json WITHOUT a DONE marker as live progress, not completion)."""
    def __init__(self):
        self.stopped = []

    def poll_detached(self, name):
        return {"exists": True, "running": True, "exit_code": None}

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stopped.append(name)

    def start_detached(self, *a, **k):
        from hexgraph.sandbox.runner import DetachedHandle
        return DetachedHandle(name=k["name"], outdir=str(k["outdir"]))


def test_reap_streaming_partial_status_is_live_then_final(hg_home, monkeypatch):
    """Bug B: a probe that STREAMS status.json mid-run (no DONE marker) is reaped as LIVE
    progress — stats advance, the campaign stays `running`, and crashes are not double-
    ingested when the final DONE write repeats them. The libFuzzer probe now writes such
    partial statuses; this exercises the reaper contract end-to-end without Docker."""
    import json as _json
    from pathlib import Path

    _enable_fuzzing()
    ex = _RunningExecutor()
    with session_scope() as s:
        p, t = _project_with_target(s)
        # A real (non-mock) detached campaign row pointing at a writable outdir we drive
        # by hand, standing in for the container's streamed /out.
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        # Force the libfuzzer engine (not mock) so reap polls the (fake) container.
        monkeypatch.setenv("HEXGRAPH_FUZZER", "")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        cid = row.id
        outdir = Path(row.outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        crash = {
            "kind": "heap-buffer-overflow", "function": "cgi_handler",
            "summary": "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            "reproducer_sha256": "a" * 64, "reproducer_size": 8,
            "reproducer_b64": "QUFBQUFBQUE=",
            "dedup_key": "deadbeef" * 8, "dupe_count": 0,
            "exploitability": {"rating": "likely_exploitable", "access": "WRITE", "signals": []},
            "minimized_reproducer_sha256": "a" * 64, "minimized_reproducer_size": 8,
            "_report": "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 8\n",
        }

        # 1) A PARTIAL streamed status (live progress; NO crashes yet, NO DONE marker).
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer",
             "executions": 100000, "edges_covered": 42, "crash_count": 0,
             "coverage_instrumented": True}))
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        row = s.get(FuzzCampaign, cid)
        assert created == 0  # no crashes in the partial write
        assert row.status == "running"  # NOT finalized — no DONE marker
        assert (row.stats_json or {}).get("execs") == 100000
        assert (row.stats_json or {}).get("edges_covered") == 42

        # 2) A LATER partial: more execs/edges + the first crash appears (still no DONE).
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer",
             "executions": 500000, "edges_covered": 77, "crash_count": 1,
             "coverage_instrumented": True, "crashes": [crash]}))
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        row = s.get(FuzzCampaign, cid)
        assert created == 1  # the new crash ingested once
        assert row.status == "running"
        assert (row.stats_json or {}).get("execs") == 500000
        assert (row.stats_json or {}).get("edges_covered") == 77

        # 3) The FINAL authoritative write REPEATS the same crash + sets DONE → finalize,
        #    monotonic stats, and the crash is NOT double-ingested (dedup by dedup_key).
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer", "done": True,
             "executions": 800000, "edges_covered": 90, "crash_count": 1,
             "coverage_instrumented": True, "crashes": [crash]}))
        (outdir / "DONE").write_text("libfuzzer")
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        row = s.get(FuzzCampaign, cid)
        assert created == 0  # same dedup_key → no second finding
        assert row.status == "completed"
        assert (row.stats_json or {}).get("execs") == 800000
        assert (row.stats_json or {}).get("edges_covered") == 90
        assert s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).count() == 1


# ── F5: the representative is symbolized consistently (re-run verify when frames missing) ─

class _SymbolizingExecutor(_RunningExecutor):
    """A fake executor whose verify replay (poc_probe) returns a SYMBOLIZED ASan report —
    standing in for the fuzz image's llvm-symbolizer. Used to prove the ingest path backfills
    a representative's stack from the verify replay when the streamed `_report` had none."""

    SYMBOLIZED = (
        "==9==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
        "READ of size 4 at 0x602000000010 thread T0\n"
        "    #0 0x4f in real_handler /src/httpd.c:128:9\n"
        "    #1 0x6a in dispatch /src/httpd.c:80:3\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free /src/httpd.c:128:9 in real_handler\n")

    def __init__(self):
        super().__init__()
        self.verify_calls = 0

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None):
        self.verify_calls += 1
        return {"tool": "poc_probe", "ran": True, "verified": True, "exit_code": 1,
                "output": self.SYMBOLIZED, "detail": "re-crashed"}


def test_representative_is_symbolized_via_verify_when_report_lacks_frames(hg_home, monkeypatch):
    """F5 / defect 2: a crash whose streamed `_report` carries NO symbolized frames (only
    module+offset, e.g. the campaign replay missed the symbolizer) gets its backtrace
    BACKFILLED by re-running the SAME symbolizing replay verify uses — so the headline
    representative ends up with frames + a real faulting function instead of null."""
    import json as _json
    from pathlib import Path
    from hexgraph.engine import cas

    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        monkeypatch.setenv("HEXGRAPH_FUZZER", "")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        cid = row.id
        # verify_artifact takes the poc_probe path only when a fuzzer binary was preserved.
        fuzzer_cas = cas.put(p, b"\x7fELF-fake-fuzzer-binary")
        row.config_json = {**(row.config_json or {}), "fuzzer_cas": fuzzer_cas}
        s.flush()
        outdir = Path(row.outdir)
        outdir.mkdir(parents=True, exist_ok=True)

        # An UNSYMBOLIZED report: frames are only module+offset, so parse_source_frames → [].
        crash = {
            "kind": "heap-use-after-free", "function": None,
            "summary": "SUMMARY: AddressSanitizer: heap-use-after-free",
            "reproducer_sha256": "b" * 64, "reproducer_size": 8,
            "reproducer_b64": "QUFBQUFBQUE=",
            "dedup_key": "cafebabe" * 8, "dupe_count": 0,
            "exploitability": {"rating": "likely_exploitable", "access": "READ", "signals": []},
            "minimized_reproducer_sha256": "b" * 64, "minimized_reproducer_size": 8,
            "_report": ("==9==ERROR: AddressSanitizer: heap-use-after-free\n"
                        "READ of size 4 at 0x602000000010\n"
                        "    #0 0x4f (/out/fuzzer+0x4f)\n"),  # module+offset only — NO frames
        }
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer", "done": True,
             "executions": 1000, "edges_covered": 5, "crash_count": 1,
             "coverage_instrumented": True, "crashes": [crash]}))
        (outdir / "DONE").write_text("libfuzzer")

        # allow_replay_backfill=True simulates the background worker reaper (the only context
        # permitted to run the target-executing replay); the on-read HTTP reaps leave it False.
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex,
                                  allow_replay_backfill=True)
        assert created == 1
        assert ex.verify_calls == 1, "the symbolizing replay must run when frames are missing"

        art = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).one()
        f = s.get(Finding, art.finding_id)
        frames = (((f.evidence_json or {}).get("extra") or {}).get("fuzz") or {}).get("frames")
        assert frames, "frames must be backfilled from the verify replay"
        assert frames[0]["func"] == "real_handler" and frames[0]["line"] == 128
        # The artifact's faulting_function (which was null from the probe) is recovered from
        # the symbolized top frame — the central F5 fix (the headline crash had a null one).
        assert art.faulting_function == "real_handler"


def test_representative_with_frames_skips_verify_backfill(hg_home, monkeypatch):
    """The backfill is a fallback only: a crash whose streamed `_report` is already
    symbolized must NOT trigger a (costly) verify replay."""
    import json as _json
    from pathlib import Path

    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        monkeypatch.setenv("HEXGRAPH_FUZZER", "")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        cid = row.id
        outdir = Path(row.outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        crash = {
            "kind": "heap-buffer-overflow", "function": "cgi_handler",
            "summary": "SUMMARY: AddressSanitizer: heap-buffer-overflow",
            "reproducer_sha256": "c" * 64, "reproducer_size": 8,
            "reproducer_b64": "QUFBQUFBQUE=",
            "dedup_key": "feedface" * 8, "dupe_count": 0,
            "exploitability": {"rating": "likely_exploitable", "access": "WRITE", "signals": []},
            "minimized_reproducer_sha256": "c" * 64, "minimized_reproducer_size": 8,
            "_report": ("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                        "    #0 0x49 in cgi_handler /src/httpd.c:42:7\n"),  # already symbolized
        }
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer", "done": True,
             "executions": 1000, "crash_count": 1, "coverage_instrumented": True,
             "crashes": [crash]}))
        (outdir / "DONE").write_text("libfuzzer")
        # allow_replay_backfill=True so the ONLY reason the replay is skipped is the
        # already-present frames, not the worker gate.
        C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 0, "no verify replay when the report already symbolizes"
        art = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).one()
        f = s.get(Finding, art.finding_id)
        frames = (((f.evidence_json or {}).get("extra") or {}).get("fuzz") or {}).get("frames")
        assert frames and frames[0]["func"] == "cgi_handler"


def test_on_read_reap_does_not_execute_target_for_backfill(hg_home, monkeypatch):
    """Safety gate: the on-read reap paths (SPA list-poll / GET / SSE, MCP, stop) reap with
    allow_replay_backfill=False, so an unsymbolized crash must NOT trigger the target-executing
    verify replay in a request thread. The crash is still ingested; symbolization is deferred
    to the background worker reaper."""
    import json as _json
    from pathlib import Path
    from hexgraph.engine import cas

    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        monkeypatch.setenv("HEXGRAPH_FUZZER", "")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        cid = row.id
        fuzzer_cas = cas.put(p, b"\x7fELF-fake-fuzzer-binary")
        row.config_json = {**(row.config_json or {}), "fuzzer_cas": fuzzer_cas}
        s.flush()
        outdir = Path(row.outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        crash = {
            "kind": "heap-use-after-free", "function": None,
            "summary": "SUMMARY: AddressSanitizer: heap-use-after-free",
            "reproducer_sha256": "b" * 64, "reproducer_size": 8,
            "reproducer_b64": "QUFBQUFBQUE=",
            "dedup_key": "cafebabe" * 8, "dupe_count": 0,
            "exploitability": {"rating": "likely_exploitable", "access": "READ", "signals": []},
            "minimized_reproducer_sha256": "b" * 64, "minimized_reproducer_size": 8,
            "_report": ("==9==ERROR: AddressSanitizer: heap-use-after-free\n"
                        "    #0 0x4f (/out/fuzzer+0x4f)\n"),  # module+offset only — NO frames
        }
        (outdir / "status.json").write_text(_json.dumps(
            {"compiled": True, "ran": True, "engine": "libfuzzer", "done": True,
             "executions": 1000, "crash_count": 1, "coverage_instrumented": True,
             "crashes": [crash]}))
        (outdir / "DONE").write_text("libfuzzer")

        # Default flag (on-read context): the crash is still recorded, but no replay runs.
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex)
        assert created == 1
        assert ex.verify_calls == 0, "the on-read reap must not execute the target to backfill"


# ── N5: a later WORKER tick re-symbolizes a rep the on-read reap left with empty frames ──

class _NeverSymbolizingExecutor(_RunningExecutor):
    """A fake executor whose verify replay returns an UNSYMBOLIZED report (module+offset
    only). Stands in for a crash that genuinely can't be symbolized — used to prove the
    worker doesn't re-execute the target on every tick for a hopeless rep."""

    def __init__(self):
        super().__init__()
        self.verify_calls = 0

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None):
        self.verify_calls += 1
        return {"tool": "poc_probe", "ran": True, "verified": True, "exit_code": 1,
                "output": "==9==ERROR: AddressSanitizer: heap-use-after-free\n"
                          "    #0 0x4f (/out/fuzzer+0x4f)\n",  # module+offset only — NO frames
                "detail": "re-crashed"}


def _running_campaign_with_unsymbolized_crash(s, ex, monkeypatch):
    """Start a still-running source_lib campaign, preserve a fuzzer binary so verify takes
    the symbolizing replay path, and stream ONE crash whose `_report` has no frames (no DONE
    marker → the campaign stays `running`, so reap_all revisits it). Returns the campaign id."""
    import json as _json
    from pathlib import Path
    from hexgraph.engine import cas

    p, t = _project_with_target(s)
    spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                            function="cgi_handler", target_sources=["/x.c"])
    monkeypatch.setenv("HEXGRAPH_FUZZER", "")
    row = C.start_campaign(s, p, t, spec=spec, executor=ex)
    cid = row.id
    fuzzer_cas = cas.put(p, b"\x7fELF-fake-fuzzer-binary")
    row.config_json = {**(row.config_json or {}), "fuzzer_cas": fuzzer_cas}
    s.flush()
    outdir = Path(row.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    crash = {
        "kind": "heap-use-after-free", "function": None,
        "summary": "SUMMARY: AddressSanitizer: heap-use-after-free",
        "reproducer_sha256": "b" * 64, "reproducer_size": 8,
        "reproducer_b64": "QUFBQUFBQUE=",
        "dedup_key": "cafebabe" * 8, "dupe_count": 0,
        "exploitability": {"rating": "likely_exploitable", "access": "READ", "signals": []},
        "minimized_reproducer_sha256": "b" * 64, "minimized_reproducer_size": 8,
        "_report": ("==9==ERROR: AddressSanitizer: heap-use-after-free\n"
                    "    #0 0x4f (/out/fuzzer+0x4f)\n"),  # module+offset only — NO frames
    }
    (outdir / "status.json").write_text(_json.dumps(
        {"compiled": True, "ran": True, "engine": "libfuzzer", "done": False,
         "executions": 1000, "edges_covered": 5, "crash_count": 1,
         "coverage_instrumented": True, "crashes": [crash]}))
    # NO DONE marker → the (running) executor keeps the campaign `running`, so reap_all revisits.
    return cid


def _frames_of(s, cid):
    art = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).one()
    f = s.get(Finding, art.finding_id)
    return (((f.evidence_json or {}).get("extra") or {}).get("fuzz") or {}).get("frames"), art


def test_worker_backfills_rep_an_onread_reap_left_unsymbolized(hg_home, monkeypatch):
    """N5: THE RACE. An on-read reap (allow_replay_backfill=False) ingests an unsymbolized
    crash with EMPTY frames and does NOT execute the target. A LATER WORKER reap
    (allow_replay_backfill=True) on the SAME already-ingested bucket runs the backfill and
    fills the frames — closing the race where the worker used to skip the bucket forever."""
    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        cid = _running_campaign_with_unsymbolized_crash(s, ex, monkeypatch)

        # 1) On-read reap: ingests the crash, frames stay empty, target NOT executed.
        created = C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex,
                                  allow_replay_backfill=False)
        assert created == 1
        assert ex.verify_calls == 0, "on-read reap must not execute the target"
        frames, art = _frames_of(s, cid)
        assert not frames, "frames are empty after the on-read reap (the race window)"
        assert art.faulting_function is None

        # 2) A later WORKER reap on the SAME already-ingested bucket backfills the stack.
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1, "the worker must re-symbolize the already-ingested rep"
        frames, art = _frames_of(s, cid)
        assert frames and frames[0]["func"] == "real_handler" and frames[0]["line"] == 128
        assert art.faulting_function == "real_handler"


def test_worker_backfill_attempted_at_most_once_for_unsymbolizable_rep(hg_home, monkeypatch):
    """N5 idempotency: a rep that genuinely can't be symbolized (the replay yields no frames)
    is attempted AT MOST ONCE — the durable `symbolize_attempted` marker stops the worker
    from re-executing the target on every 15s tick forever."""
    _enable_fuzzing()
    ex = _NeverSymbolizingExecutor()
    with session_scope() as s:
        cid = _running_campaign_with_unsymbolized_crash(s, ex, monkeypatch)
        # On-read reap ingests the crash (no replay).
        C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex, allow_replay_backfill=False)
        assert ex.verify_calls == 0

        # First worker tick: ATTEMPTS the replay (executes once) but gets no frames.
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1
        frames, _ = _frames_of(s, cid)
        assert not frames, "the unsymbolizable rep still has no frames"

        # Second + third worker ticks: the marker prevents any further target-executing replay.
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1, "an unsymbolizable rep must be attempted at most once"


def test_worker_backfill_skips_reps_that_already_have_frames(hg_home, monkeypatch):
    """The sweep must not re-do work: a rep already carrying frames (filled on its first
    worker tick) is never re-replayed on a subsequent tick."""
    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        cid = _running_campaign_with_unsymbolized_crash(s, ex, monkeypatch)
        C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex, allow_replay_backfill=False)
        # First worker tick fills the frames (one replay).
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1
        frames, _ = _frames_of(s, cid)
        assert frames
        # Subsequent ticks see frames present → no further replay.
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1, "a rep that already has frames must not be re-symbolized"


def test_worker_backfills_finalized_campaign_rep(hg_home, monkeypatch):
    """The headline-live case: the campaign FINALIZED (DONE) on the on-read reap, so reap_all's
    status filter (running/building) no longer revisits it — yet the sweep, which scans ALL
    crash artifacts, still backfills its under-symbolized rep on a later worker tick."""
    import json as _json
    from pathlib import Path
    from hexgraph.engine import cas

    _enable_fuzzing()
    ex = _SymbolizingExecutor()
    with session_scope() as s:
        cid = _running_campaign_with_unsymbolized_crash(s, ex, monkeypatch)
        # Finalize the campaign on the on-read reap by dropping a DONE marker.
        (Path(s.get(FuzzCampaign, cid).outdir) / "DONE").write_text("libfuzzer")
        C.reap_campaign(s, s.get(FuzzCampaign, cid), executor=ex, allow_replay_backfill=False)
        assert s.get(FuzzCampaign, cid).status in ("completed", "degraded")
        assert ex.verify_calls == 0
        frames, _ = _frames_of(s, cid)
        assert not frames

        # A later worker tick: reap_all skips the finalized campaign in its loop, but the
        # sweep over ALL artifacts still backfills it.
        C.reap_all(s, executor=ex, allow_replay_backfill=True)
        assert ex.verify_calls == 1
        frames, art = _frames_of(s, cid)
        assert frames and frames[0]["func"] == "real_handler"
        assert art.faulting_function == "real_handler"


# ── Degraded / zero-work campaigns surface a WARNING, not a silent "completed" ────

@pytest.mark.parametrize("scenario,expect_note", [
    ("unreachable", "not reachable"),       # boofuzz: service down → ran:False
    ("noexec", "0 execution"),              # ran but did no work
    ("unstable", "reported instability"),   # engine flagged instability
])
def test_degraded_campaign_status_and_warning(hg_home, monkeypatch, scenario, expect_note):
    """A campaign that did 0 work or hit engine degradation finalizes as `degraded`
    (NOT `completed`) and the serializer exposes the WHY (warning/engine_note). This is
    the battle-test fix: an unreachable / 0-exec / degraded run was reporting a clean
    completed/error:null with no signal."""
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        # The mock launcher keys these degraded scenarios off `function`.
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function=scenario, target_sources=["/x.c"])
        cid = C.start_campaign(s, p, t, spec=spec).id
        C.reap_campaign(s, s.get(FuzzCampaign, cid))
        row = s.get(FuzzCampaign, cid)
        assert row.status == "degraded", f"{scenario} should be degraded, got {row.status}"
        d = C.campaign_to_dict(row)
        assert d["status"] == "degraded"
        assert d["warning"], "a degraded campaign must carry a human warning reason"
        assert expect_note.lower() in d["warning"].lower()
        if scenario == "unstable":
            assert d["engine_note"] and "reported instability" in d["engine_note"]


def test_clean_campaign_is_not_degraded(hg_home, monkeypatch):
    """A genuinely-successful run (execs > 0, no note) stays `completed` with no warning —
    the degraded logic must NOT mislabel a real success."""
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="clean", target_sources=["/x.c"])
        cid = C.start_campaign(s, p, t, spec=spec).id
        C.reap_campaign(s, s.get(FuzzCampaign, cid))
        row = s.get(FuzzCampaign, cid)
        assert row.status == "completed"
        d = C.campaign_to_dict(row)
        assert d["warning"] is None and not d["engine_note"]


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


def test_resume_clears_stale_degradation_signal(hg_home, monkeypatch):
    """A degraded campaign that is resumed must NOT carry its stale engine_note/run_error
    into the new run's finalize — else a clean resume would be re-labelled `degraded`."""
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="unstable", target_sources=["/x.c"])
        cid = C.start_campaign(s, p, t, spec=spec).id
        C.reap_campaign(s, s.get(FuzzCampaign, cid))
        row = s.get(FuzzCampaign, cid)
        assert row.status == "degraded" and (row.stats_json or {}).get("engine_note")
        # Resume clears the stale note; the row goes back to running with no engine_note.
        C.resume_campaign(s, row)
        row = s.get(FuzzCampaign, cid)
        assert row.status == "running"
        assert not (row.stats_json or {}).get("engine_note")
        assert not (row.stats_json or {}).get("run_error")


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
