"""Phase 4 — the Source/IDE + Campaigns/Artifacts triage backend surface: source-mapped
stack frames + auto-link to source, the verify/minimize/promote artifact actions, line
coverage serialization, the server-advertised engines endpoint, and the SSE event stream.
All offline ($0) via the MockFuzzer + a fake executor.
"""

import json

import pytest
from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Edge, EdgeType, Finding, FuzzArtifact, FuzzCampaign
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.build.source import create_source_tree, write_source_file

from conftest import SANDBOX_READY, fixture_path
from test_campaigns import HARNESS, _enable_fuzzing, _mock_env, _project_with_target


# ── Source-mapped stack frames ───────────────────────────────────────────────────

def test_parse_source_frames_skips_runtime_and_keeps_user():
    report = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x4e in __asan_memcpy /src/compiler-rt/asan_interceptors.cpp:9\n"
        "    #1 0x5f in cgi_handler /src/target.c:42:7\n"
        "    #2 0x6a in main /src/main.c:10\n"
        "SUMMARY: heap-buffer-overflow\n")
    frames = C.parse_source_frames(report)
    funcs = [f["func"] for f in frames]
    assert "cgi_handler" in funcs and "main" in funcs
    assert "__asan_memcpy" not in funcs  # compiler-rt runtime frame skipped
    cgi = next(f for f in frames if f["func"] == "cgi_handler")
    assert cgi["file"] == "/src/target.c" and cgi["line"] == 42 and cgi["col"] == 7


def test_parse_source_frames_empty_when_unsymbolized():
    # module+offset frames (no `func file:line`) → no source frames (honest).
    assert C.parse_source_frames("    #0 0x55 in (/lib/libc.so+0x1234)\n") == []


def test_ingest_stores_frames_and_autolinks_source(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        # A source tree carrying target.c (the mock report references /src/target.c:1).
        tree = create_source_tree(s, project=p, name="src", origin="scratch")
        write_source_file(s, p, tree, "target.c", "int main(){return 0;}\n")
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        row = C.start_campaign(s, p, t, spec=spec)
        C.reap_campaign(s, s.get(FuzzCampaign, row.id))
        art = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == row.id).first()
        d = C.artifact_to_dict(art, session=s)
        assert d["frames"], "frames parsed from the mock ASan report"
        # the top frame auto-linked to the source tree → source_ref present
        assert d.get("source_ref") and d["source_ref"]["rel"] == "target.c"
        # a located_in edge wired finding → source_file node
        assert s.query(Edge).filter(Edge.type == EdgeType.located_in.value,
                                    Edge.src_id == art.finding_id).count() == 1


# ── verify / minimize / promote ───────────────────────────────────────────────────

def _started(s, monkeypatch):
    p, t = _project_with_target(s)
    spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                            function="cgi_handler", target_sources=["/x.c"])
    row = C.start_campaign(s, p, t, spec=spec)
    C.reap_campaign(s, s.get(FuzzCampaign, row.id))
    return p, t, s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == row.id).first()


def _disable_fuzzing():
    from hexgraph import settings as _st
    _st.update_settings({"features.fuzzing.enabled": False, "features.poc.enabled": False})


def test_promote_artifact_confirms_finding(hg_home, monkeypatch):
    # Plain Promote (to_poc=False) just CONFIRMS the finding — it executes nothing, so it
    # works even after dropping back to static-only (no policy gate on plain promote).
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t, art = _started(s, monkeypatch)
        _disable_fuzzing()  # now static-only — plain promote must STILL work
        res = C.promote_artifact(s, art, to_poc=False)
        assert res["status"] == "confirmed" and res["to_poc"] is False
        f = s.get(Finding, art.finding_id)
        assert f.status == "confirmed"
        assert not ((f.evidence_json.get("extra") or {}).get("poc"))
        # No verification was run (plain promote never executes the target).
        assert not ((f.evidence_json.get("extra") or {}).get("verification"))


# Runs the REAL crash verification (poc_probe in the sandbox), so it needs the image —
# unlike its static-only siblings below, which assert the fail-closed path without executing.
@pytest.mark.skipif(not SANDBOX_READY,
                    reason="requires Docker + the hexgraph-sandbox image (just sandbox-build)")
def test_promote_to_poc_seeds_and_verifies_when_enabled(hg_home, monkeypatch):
    # With execution enabled (fuzzing), Promote→PoC seeds the reproducer-backed PoC spec
    # AND immediately re-runs the LLM-free crash verification — one click → a verified PoC.
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t, art = _started(s, monkeypatch)
        res = C.promote_artifact(s, art, to_poc=True)
        f = s.get(Finding, art.finding_id)
        extra = f.evidence_json.get("extra") or {}
        poc = extra.get("poc")
        assert poc and poc["kind"] == "fuzz_reproducer" and poc["reproducer_ref"] == art.content_cas
        # The verification actually RAN and was recorded onto the finding (durable proof),
        # carrying an assurance triple — not a seed-only no-op. (verified True/False depends
        # on whether the reproducer re-crashes; the mock harness exits cleanly, so the point
        # asserted here is that verification executed + persisted, with assurance.)
        assert res["to_poc"] is True and "verified" in res and res.get("assurance")
        verif = extra.get("verification")
        assert verif is not None and verif["via"] == "promote_to_poc"
        assert verif["assurance"] and verif["verified"] == res["verified"]


def test_promote_to_poc_refuses_under_static_only(hg_home, monkeypatch):
    # The whole point of the gate: with PoC/fuzzing DISABLED (static-only default),
    # Promote→PoC must NOT seed an unverifiable PoC and must NOT execute the target —
    # it raises a PolicyViolation with actionable guidance, before any mutation.
    from hexgraph.policy import PolicyViolation

    _mock_env(monkeypatch)
    _enable_fuzzing()  # enable to PRODUCE the crash artifact...
    with session_scope() as s:
        p, t, art = _started(s, monkeypatch)
        _disable_fuzzing()  # ...then drop back to static-only before promoting
        before_status = s.get(Finding, art.finding_id).status
        with pytest.raises(PolicyViolation):
            C.promote_artifact(s, art, to_poc=True)
        f = s.get(Finding, art.finding_id)
        # Fail-closed: nothing seeded, nothing verified, status untouched.
        assert f.status == before_status
        extra = f.evidence_json.get("extra") or {}
        assert not extra.get("poc") and not extra.get("verification")


def test_api_promote_to_poc_blocked_returns_guidance(hg_home, monkeypatch):
    # The API maps the policy refusal to a clean 403 with guidance (no stack trace).
    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with session_scope() as s:
        p, t, art = _started(s, monkeypatch)
        aid = art.id
    _disable_fuzzing()  # static-only at promote time
    with TestClient(app) as c:
        r = c.post(f"/api/artifacts/{aid}/promote", json={"to_poc": True})
        assert r.status_code == 403
        assert "PoC verification" in r.json()["detail"] and "Settings" in r.json()["detail"]
        # Plain promote still works under static-only.
        r2 = c.post(f"/api/artifacts/{aid}/promote", json={"to_poc": False})
        assert r2.status_code == 200 and r2.json()["status"] == "confirmed"


# ── Coverage serialization ─────────────────────────────────────────────────────────

def test_coverage_serialized_from_mock_campaign(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    with session_scope() as s:
        p, t = _project_with_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="source_lib", harness_source=HARNESS,
                                function="cgi_handler", target_sources=["/x.c"])
        row = C.start_campaign(s, p, t, spec=spec)
        cov_live = C.coverage_for(s, s.get(FuzzCampaign, row.id))
        assert cov_live["available"] and "target.c" in cov_live["files"]
        # After finalize the coverage map is snapshotted to CAS (outdir gone) and still served.
        C.reap_campaign(s, s.get(FuzzCampaign, row.id))
        row = s.get(FuzzCampaign, row.id)
        assert row.coverage_ref  # snapshotted
        cov = C.coverage_for(s, row)
        assert cov["available"] and cov["files"]["target.c"]["covered"]


# ── API surface ─────────────────────────────────────────────────────────────────

def test_api_fuzz_engines_advertised(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        # surface inferred from the (instrumented) target
        r = c.get(f"/api/fuzz/engines?target_id={tid}").json()
        assert r["surface"] == "source_lib"
        assert "afl" in r["engines"] and r["default"] == "afl"
        # explicit surface (Phase 5: binary_only → qemu-mode default + frida alt)
        r2 = c.get("/api/fuzz/engines?surface=binary_only").json()
        assert r2["engines"] == ["qemu", "frida"] and r2["default"] == "qemu"
        # whole matrix when no surface
        r3 = c.get("/api/fuzz/engines").json()
        assert "surfaces" in r3 and "source_lib" in r3["surfaces"]
        # unknown surface → 400
        assert c.get("/api/fuzz/engines?surface=bogus").status_code == 400


# promote(to_poc) + minimize here drive the REAL verify path (poc_probe in the sandbox).
@pytest.mark.skipif(not SANDBOX_READY,
                    reason="requires Docker + the hexgraph-sandbox image (just sandbox-build)")
def test_api_artifact_actions(hg_home, monkeypatch):
    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        camp = c.post(f"/api/projects/{pid}/campaigns",
                      json={"target_id": tid, "function": "cgi_handler"}).json()
        cid = camp["id"]
        c.get(f"/api/campaigns/{cid}")  # reaps on read → ingests the mock crash
        arts = c.get(f"/api/campaigns/{cid}/artifacts").json()["artifacts"]
        assert arts and arts[0].get("assurance")  # the assurance chip data
        aid = arts[0]["id"]
        # promote → confirmed
        pr = c.post(f"/api/artifacts/{aid}/promote", json={"to_poc": True})
        assert pr.status_code == 200 and pr.json()["status"] == "confirmed"
        # coverage endpoint
        cov = c.get(f"/api/campaigns/{cid}/coverage").json()
        assert cov["available"] and cov["files"]
        # minimize/verify share the same path (mock has no fuzzer binary preserved, so it
        # falls back to verify_reproducer against the target — returns a result dict)
        mr = c.post(f"/api/artifacts/{aid}/minimize")
        assert mr.status_code == 200 and "verified" in mr.json()


def test_api_campaign_degraded_status_surfaced(hg_home, monkeypatch):
    """Battle-test fix F: an unreachable / 0-exec / degraded campaign must report a
    DISTINCT `degraded` status (not a clean `completed`) and expose the reason via the
    serializer (`warning` + `engine_note`) so the UI/agent sees the signal."""
    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        camp = c.post(f"/api/projects/{pid}/campaigns",
                      json={"target_id": tid, "function": "unstable"}).json()
        d = c.get(f"/api/campaigns/{camp['id']}").json()  # reap-on-read finalizes
        assert d["status"] == "degraded"
        assert d["warning"] and "reported instability" in d["warning"]
        assert d["engine_note"] and "reported instability" in d["engine_note"]
        # And a clean run is still `completed` with no warning.
        ok = c.post(f"/api/projects/{pid}/campaigns",
                    json={"target_id": tid, "function": "clean"}).json()
        d2 = c.get(f"/api/campaigns/{ok['id']}").json()
        assert d2["status"] == "completed" and d2["warning"] is None


def test_api_egress_audit_log(hg_home, monkeypatch):
    """Battle-test fix M: the egress audit log is queryable over the API (it backs the new
    UI audit panel). Records an allowed + a denied event and reads them back newest-first."""
    from hexgraph.engine.audit import record_egress

    app = create_app()
    with session_scope() as s:
        p, t = _project_with_target(s)
        pid, tid = p.id, t.id
        record_egress(s, project_id=pid, target_id=tid, dest="127.0.0.1:8080",
                      allowed=True, tool="boofuzz", detail="loopback ok")
        record_egress(s, project_id=pid, target_id=tid, dest="8.8.8.8:53",
                      allowed=False, tool="http_probe", detail="blocked: public host")
    with TestClient(app) as c:
        r = c.get(f"/api/projects/{pid}/egress")
        assert r.status_code == 200
        events = r.json()["events"]
        assert len(events) == 2
        assert events[0]["dest"] == "8.8.8.8:53" and events[0]["allowed"] is False
        assert any(e["allowed"] and e["tool"] == "boofuzz" for e in events)
        # missing project → 404
        assert c.get("/api/projects/nope/egress").status_code == 404


def test_api_capabilities_features_fuzzing(hg_home):
    _enable_fuzzing()
    app = create_app()
    with TestClient(app) as c:
        caps = c.get("/api/capabilities").json()
        assert caps["features"]["fuzzing"] is True


def test_api_campaign_nothing_to_fuzz_is_clear_400(hg_home, monkeypatch):
    """A campaign on a target with no harness / no instrumented build must fail with a
    HUMAN 400 body (the UI shows it verbatim) — never a terse internal message or a
    half-created campaign. Covers the source_lib (no harness/sources) case."""
    from hexgraph.engine.targets.ingest import create_project, ingest_file
    from hexgraph.db.session import session_scope as _ss

    _mock_env(monkeypatch)
    _enable_fuzzing()
    app = create_app()
    with _ss() as s:
        p = create_project(s, name="bare")
        # A plain ingested binary with NO harness_generation finding and NO instrumented
        # build / fuzz_target_sources. Forcing surface=source_lib makes "nothing to fuzz"
        # unambiguous (no harness + no sources to compile).
        t = ingest_file(s, project=p, src_path=fixture_path("vuln_httpd"), name="bare_httpd")
        pid, tid = p.id, t.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/campaigns",
                   json={"target_id": tid, "surface": "source_lib"})
        assert r.status_code == 400
        detail = r.json()["detail"]
        # Human, actionable, names the target and tells the operator what to do next.
        assert "Nothing to fuzz" in detail
        assert "bare_httpd" in detail
        assert "harness" in detail.lower()
        # And NO campaign row leaked from the failed pre-flight check.
        assert c.get(f"/api/projects/{pid}/campaigns").json()["campaigns"] == []
