"""Guard the screenshot-showcase seed against bitrot.

`scripts/seed_showcase.py` builds the rich demo project the README/doc screenshots
are captured from (`just showcase` / `just capture`). It must keep running cleanly
on the mock backend, offline ($0, no Docker), and produce the variety the captures
rely on. This is a fast offline test — it does NOT capture screenshots.
"""

import importlib.util
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_seed():
    path = REPO / "scripts" / "seed_showcase.py"
    spec = importlib.util.spec_from_file_location("seed_showcase", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def _mock_fuzzer(monkeypatch):
    # The campaign runs via the offline MockFuzzer and the instrumented rebuild via the
    # offline MockBuilder (no Docker, deterministic, $0).
    monkeypatch.setenv("HEXGRAPH_FUZZER", "mock")
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")


def test_seed_showcase_runs_clean_and_is_rich(hg_home, _mock_fuzzer):
    from hexgraph import settings as st
    from hexgraph.db.models import (
        Edge, Finding, FuzzArtifact, FuzzCampaign, Node, Target, TargetKind,
    )
    from hexgraph.db.session import session_scope

    st.update_settings({"features.fuzzing.enabled": True, "features.poc.enabled": True,
                        "features.build.enabled": True})
    seed = _load_seed()

    with session_scope() as s:
        info = seed.seed(s, reset=True)
        pid = info["project_id"]
        assert info["reused"] is False

        # ── Targets: firmware tree + children + standalone + web_app + service ──────────
        targets = s.query(Target).filter(Target.project_id == pid).all()
        kinds = {t.kind for t in targets}
        assert TargetKind.firmware_image in kinds
        assert TargetKind.executable in kinds
        assert TargetKind.shared_library in kinds
        assert TargetKind.web_app in kinds
        assert TargetKind.service in kinds
        # The firmware has unpacked-FS children + a recorded filesystem manifest.
        fw = next(t for t in targets if t.kind == TargetKind.firmware_image)
        assert (fw.metadata_json or {}).get("filesystem", {}).get("files")
        assert any(t.parent_id == fw.id for t in targets)

        # ── A wide, curated edge variety (the colorful-but-legible graph) ──────────────
        edge_types = {e.type for e in s.query(Edge).filter(Edge.project_id == pid).all()}
        for required in ("contains", "calls", "routes_to", "listens_on", "connects_to",
                         "built_from", "located_in", "instrumented_build_of", "links_against",
                         "taints", "about", "fuzzed_by", "produced_artifact",
                         # The REAL build flow wires these (a from-source instrumented rebuild):
                         "builds", "harnesses"):
            assert required in edge_types, f"missing edge type {required!r}"

        # ── Typed nodes: functions, a sink, sockets, endpoints/params ──────────────────
        node_types = {n.node_type for n in s.query(Node).filter(Node.project_id == pid).all()}
        for required in ("function", "sink", "socket", "endpoint", "param", "string",
                         "source_file"):
            assert required in node_types, f"missing node type {required!r}"

        # ── Findings spanning types + the assurance ladder ─────────────────────────────
        findings = s.query(Finding).filter(Finding.project_id == pid).all()
        assert len(findings) >= 6
        ftypes = {f.finding_type for f in findings}
        assert {"recon", "poc", "vulnerability", "fuzz_crash"} <= ftypes

        def _assurance(f):
            extra = (f.evidence_json or {}).get("extra") or {}
            return extra.get("assurance") or (extra.get("verification") or {}).get("assurance")

        rungs = {(a["standard"], a["method"]) for a in map(_assurance, findings) if a}
        # The ladder variety the AssuranceChip captures rely on.
        assert ("code_present", "static") in rungs
        assert ("code_present", "dynamic") in rungs       # the fuzz crash
        assert ("input_reachable", "static") in rungs
        assert ("input_reachable", "dynamic") in rungs     # the verified PoC

        # A verified PoC finding with a re-runnable repro spec.
        poc = next(f for f in findings if f.finding_type == "poc")
        extra = (poc.evidence_json or {}).get("extra") or {}
        assert extra.get("poc") and extra.get("verification", {}).get("verified") is True

        # ── A finished fuzz campaign with crash artifacts + a coverage map ─────────────
        camp = s.query(FuzzCampaign).filter(FuzzCampaign.project_id == pid).one()
        assert camp.status in ("completed", "degraded")  # finalized, not still running
        arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == camp.id).all()
        crashes = [a for a in arts if a.kind == "crash" and a.content_cas]
        # The triage HERO shot needs a POPULATED crash inbox — several distinct dedup
        # buckets (not the lone MockFuzzer crash), with dupe counts. Lock that in so the
        # seed can't bitrot back to a sparse one-row inbox.
        assert len(crashes) >= 3, "the triage hero needs a populated, multi-bucket crash inbox"
        assert any(a.dupe_count for a in crashes), "crashes should carry dupe counts for triage"

        from hexgraph.engine import campaigns as C
        cov = C.coverage_for(s, camp)
        assert cov["available"] and cov["files"]

        # ── RUNNABILITY: the instrumented target is a REAL build, so "Start a fuzz
        # campaign" actually works (the seeded-row version 400'd "no fuzz harness
        # available"). It must carry a recorded build + a resolvable harness + on-disk
        # target sources — exactly what resolve_harness / resolve_target_sources need.
        import os as _os

        from hexgraph.db.models import Task
        from hexgraph.engine.fuzzing import resolve_harness, resolve_target_sources

        instr = next(t for t in targets if "instrumented" in t.name)
        imeta = instr.metadata_json or {}
        assert imeta.get("instrumented") is True
        assert imeta.get("build_id"), "the instrumented target must come from a recorded build"
        assert imeta.get("sanitizers"), "the instrumented build should record its sanitizers"
        fake = Task(project_id=pid, target_id=instr.id, type="fuzzing", params_json={})
        harness, _fid, _fn = resolve_harness(s, instr, fake)
        assert harness, "a promoted fuzz harness must resolve for the instrumented target"
        srcs = resolve_target_sources(instr, fake)
        assert srcs and all(_os.path.isfile(p) for p in srcs), \
            "fuzz_target_sources must be REAL on-disk files (a real campaign recompiles them)"
        assert C.infer_surface(instr) == "source_lib", \
            "the instrumented target must fuzz as coverage-guided source_lib"


def test_seed_showcase_is_idempotent(hg_home, _mock_fuzzer):
    from hexgraph import settings as st
    from hexgraph.db.session import session_scope

    st.update_settings({"features.fuzzing.enabled": True, "features.build.enabled": True})
    seed = _load_seed()
    with session_scope() as s:
        first = seed.seed(s, reset=True)
    with session_scope() as s:
        again = seed.seed(s, reset=False)
        assert again["reused"] is True
        assert again["project_id"] == first["project_id"]
