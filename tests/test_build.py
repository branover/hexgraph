"""Phase 2 — the Builder seam + build-as-API: the BuildSpec/recipe_sha
reproducibility hashing, the MockBuilder offline path, the policy gate (fail-closed
when features.build is off), the build_spec/build persistence, the instrumented
derived-target registration (the headline §3.3 capability), the migration
round-trip (0013 applies on 0012; fresh init_db works), and the API/MCP surface.

Docker-gated end-to-end (the real build_probe in the hexgraph-build image, proving
SanCov+ASan land in the artifact) lives in test_build_e2e.py."""

import pytest
from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Build, BuildSpec as BuildSpecRow, Edge, EdgeType, EDGE_KINDS, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import builds as B
from hexgraph.engine import source as src
from hexgraph.engine.build import (
    BuildError, BuildPhase, BuildResult, BuildSpec, Instrumentation, MockBuilder,
    assert_env_nonsecret, get_builder, instrumentation_env,
)
from hexgraph.engine.edges import add_edge
from hexgraph.engine.ingest import create_project
from hexgraph.policy import PolicyViolation, assert_allows_build, current_policy
from hexgraph import settings


def _enable_build():
    settings.update_settings({"features.build.enabled": True})


def _src_tree(s, p, *, name="libfoo", with_target=False):
    """A scratch source tree with a trivial Makefile (so detection picks `make`).
    Optionally link it built_from a freshly-registered target."""
    tree = src.create_source_tree(s, p, name=name, origin="scratch", editable=True)
    src.write_source_file(s, p, tree, "Makefile", "all:\n\t: build\n")
    src.write_source_file(s, p, tree, "foo.c", "int foo(int x){return x+1;}\n")
    target = None
    if with_target:
        target = Target(project_id=p.id, name="shipped.bin", path="", kind=None)
        target.kind = __import__("hexgraph.db.models", fromlist=["TargetKind"]).TargetKind.executable
        s.add(target)
        s.flush()
        add_edge(s, project_id=p.id, src=("target", target.id), dst=("source_tree", tree.id),
                 type=EdgeType.built_from, origin="human", confidence=1.0, created_by_tool="test")
    return tree, target


# ── reproducibility hashing (pure, deterministic) ───────────────────────────────

def test_recipe_sha_is_deterministic_and_order_independent():
    instr = Instrumentation(sanitizers=("address", "undefined"), coverage=("sancov",))
    a = BuildSpec(source_tree_id="t", system="make",
                  phases=(BuildPhase(("make", "-j", "4")),), instrumentation=instr,
                  env={"B": "2", "A": "1"})
    # Same recipe, env written in a different order ⇒ same recipe_sha (sorted-key JSON).
    b = BuildSpec(source_tree_id="t", system="make",
                  phases=(BuildPhase(("make", "-j", "4")),), instrumentation=instr,
                  env={"A": "1", "B": "2"})
    assert a.recipe_sha() == b.recipe_sha()
    # round-trips through dict identically
    assert BuildSpec.from_dict(a.to_dict()).recipe_sha() == a.recipe_sha()


def test_recipe_sha_changes_with_each_recipe_component():
    base = BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),))
    h = base.recipe_sha()
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make", "-j2")),)).recipe_sha() != h
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),), env={"X": "1"}).recipe_sha() != h
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),), arch="mips").recipe_sha() != h
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),),
                     base_image="other:latest").recipe_sha() != h
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),),
                     instrumentation=Instrumentation(sanitizers=("memory",))).recipe_sha() != h
    # source_tree_id and timeout/name are NOT part of recipe identity (they don't
    # change what's built), so they DON'T move the hash.
    assert BuildSpec(source_tree_id="OTHER", phases=(BuildPhase(("make",)),)).recipe_sha() == h
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),), timeout=99).recipe_sha() == h


def test_instrumentation_env_is_the_base_image_contract():
    # libFuzzer profile: SanCov + ASan in the target's own objects.
    env = instrumentation_env(Instrumentation(sanitizers=("address",), coverage=("sancov",),
                                              engine="libfuzzer"))
    assert env["CC"] == "clang" and "fuzzer-no-link" in env["CFLAGS"] and "address" in env["CFLAGS"]
    assert env["FUZZING_ENGINE"] == "libfuzzer" and env["SANITIZER"] == "address"
    # AFL++ profile swaps only the compiler/engine — same recipe, different profile.
    afl = instrumentation_env(Instrumentation(engine="afl", coverage=("afl_pcguard",)))
    assert afl["CC"] == "afl-clang-lto" and afl["FUZZING_ENGINE"] == "afl"


# ── secret hygiene: build env is NON-secret by contract ─────────────────────────

@pytest.mark.parametrize("key", ["API_KEY", "MY_TOKEN", "DB_PASSWORD", "SECRET_X", "AUTH"])
def test_secret_env_is_rejected(key):
    with pytest.raises(BuildError):
        assert_env_nonsecret({key: "x"})


def test_nonsecret_env_passes():
    assert_env_nonsecret({"CFLAGS": "-O2", "PREFIX": "/usr", "V": "1"})  # no raise


# ── the policy gate (fail-closed) ───────────────────────────────────────────────

def test_build_gate_fails_closed_by_default(hg_home):
    assert current_policy().allow_build is False
    with pytest.raises(PolicyViolation):
        assert_allows_build()
    # The MockBuilder asserts the gate too — so even the offline builder refuses.
    spec = BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),))
    with pytest.raises(PolicyViolation):
        MockBuilder().build(spec, source_root="/tmp")


def test_build_gate_opens_with_features_build(hg_home):
    _enable_build()
    pol = current_policy()
    assert pol.allow_build is True
    # build alone does NOT permit executing the TARGET (two independent gates, D5).
    assert pol.allow_execution is False
    assert_allows_build()  # no raise


def test_fuzzing_implies_build(hg_home):
    # Enabling exec (fuzzing) implies you'll build, so allow_build lifts too.
    settings.update_settings({"features.fuzzing.enabled": True})
    pol = current_policy()
    assert pol.allow_execution is True and pol.allow_build is True


# ── seam selection ──────────────────────────────────────────────────────────────

def test_get_builder_seam(monkeypatch):
    assert get_builder("mock").name == "mock"
    assert get_builder("sandbox").name == "sandbox"
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    assert get_builder().name == "mock"
    with pytest.raises(ValueError):
        get_builder("nonsense")


# ── detection ────────────────────────────────────────────────────────────────────

def test_detect_build_system(hg_home):
    with session_scope() as s:
        p = create_project(s, name="d")
        tree = src.create_source_tree(s, p, name="cm", origin="scratch", editable=True)
        src.write_source_file(s, p, tree, "CMakeLists.txt", "project(x)\n")
        assert B.detect_build_system(tree) == "cmake"
        proposed = B.propose_build_spec(tree)
        assert proposed["system"] == "cmake" and proposed["phases"]


# ── MockBuilder + persistence + derived target ──────────────────────────────────

def test_run_build_persists_ledger_and_artifacts(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="b")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec.from_dict({**B.propose_build_spec(tree), "artifacts": ["foo.o"]})
        spec_row = B.create_build_spec(s, p, spec)
        assert spec_row.recipe_sha == spec.recipe_sha()
        build = B.run_build(s, p, spec_row, builder=MockBuilder())
        assert build.status == "succeeded"
        assert build.recipe_sha == spec.recipe_sha()
        assert build.toolchain_digest == "mock-clang-18.0.0"
        assert build.source_content_hash == tree.content_hash
        # artifacts homed in CAS (rel → sha)
        assert "foo.o" in build.artifacts_json and len(build.artifacts_json["foo.o"]) == 64
        # the log is in CAS
        assert build.log_cas
        from hexgraph.engine import cas
        assert "mock-builder" in (cas.get_text(p, build.log_cas) or "")


def test_reproducible_build_yields_same_cas_sha(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="repro")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec.from_dict({**B.propose_build_spec(tree), "artifacts": ["a.o"]})
        r1 = B.run_build(s, p, B.create_build_spec(s, p, spec), builder=MockBuilder())
        r2 = B.run_build(s, p, B.create_build_spec(s, p, spec), builder=MockBuilder())
        # same recipe_sha + same source content_hash ⇒ byte-identical artifact ⇒ same CAS sha
        assert r1.recipe_sha == r2.recipe_sha
        assert r1.artifacts_json["a.o"] == r2.artifacts_json["a.o"]


def test_rebuild_registers_instrumented_derived_target(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="derive")
        tree, origin = _src_tree(s, p, with_target=True)
        spec = BuildSpec.from_dict({
            **B.propose_build_spec(tree), "artifacts": ["fuzz_target"],
            "instrumentation": {"sanitizers": ["address"], "coverage": ["sancov"], "engine": "libfuzzer"},
        })
        build = B.run_build(s, p, B.create_build_spec(s, p, spec), builder=MockBuilder())
        assert build.status == "succeeded" and build.derived_target_id
        derived = s.get(Target, build.derived_target_id)
        assert derived is not None
        meta = derived.metadata_json or {}
        assert meta.get("instrumented") is True
        assert meta.get("build_id") == build.id
        assert meta.get("sanitizers") == ["address"]
        assert derived.parent_id == origin.id  # child of the shipped binary
        assert derived.path  # has real bytes on disk for Phase-3 fuzzing
        # wired instrumented_build_of → the original, and build_spec builds → derived
        edges = s.query(Edge).filter(Edge.project_id == p.id).all()
        kinds = {(e.type, e.src_kind, e.dst_kind) for e in edges}
        assert (EdgeType.instrumented_build_of.value, "target", "target") in kinds
        assert (EdgeType.builds.value, "build_spec", "target") in kinds


def test_build_without_linked_target_makes_no_derived_target(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="nolink")
        tree, _ = _src_tree(s, p, with_target=False)
        spec = BuildSpec.from_dict({**B.propose_build_spec(tree), "artifacts": ["x.o"]})
        build = B.run_build(s, p, B.create_build_spec(s, p, spec), builder=MockBuilder())
        # No built_from target → no instrumented_build_of edge, but the build still
        # succeeds and (since there ARE artifacts) registers a standalone derived target.
        assert build.status == "succeeded"
        derived = s.get(Target, build.derived_target_id)
        assert derived is not None and derived.parent_id is None


def test_run_build_failed_when_builder_unavailable(hg_home, monkeypatch):
    _enable_build()
    from hexgraph.engine.build import BuildUnavailable

    class Unavail(MockBuilder):
        def build(self, spec, *, source_root, content_hash=None):
            raise BuildUnavailable("no docker")

    with session_scope() as s:
        p = create_project(s, name="unavail")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec.from_dict(B.propose_build_spec(tree))
        build = B.run_build(s, p, B.create_build_spec(s, p, spec), builder=Unavail())
        assert build.status == "failed" and "no docker" in (build.error or "")


# ── EDGE_KINDS widening for build_spec ──────────────────────────────────────────

def test_edge_kinds_admits_build_spec():
    assert "build_spec" in EDGE_KINDS
    assert EdgeType.instrumented_build_of.value == "instrumented_build_of"
    assert EdgeType.builds.value == "builds"


# ── API surface ──────────────────────────────────────────────────────────────────

def test_api_build_preview_no_gate(hg_home):
    # preview computes, never runs — so it works even with the gate OFF.
    app = create_app()
    with session_scope() as s:
        p = create_project(s, name="api")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/build/preview",
                   json={"source_tree_id": tid, "artifacts": ["foo.o"],
                         "instrumentation": {"sanitizers": ["address"], "coverage": ["sancov"]}})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["recipe_sha"] and body["network"] == "none"
        assert body["injected_env"]["CC"] == "clang"
        assert "fuzzer-no-link" in body["injected_env"]["CFLAGS"]


def test_api_create_build_fails_closed_without_gate(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    app = create_app()
    with session_scope() as s:
        p = create_project(s, name="apigate")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/builds",
                   json={"spec": {"source_tree_id": tid, "artifacts": ["foo.o"]}})
        assert r.status_code == 403, r.text


def test_api_create_build_runs_with_gate(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    app = create_app()
    with session_scope() as s:
        p = create_project(s, name="apirun")
        tree, _ = _src_tree(s, p, with_target=True)
        pid, tid = p.id, tree.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/builds",
                   json={"spec": {"source_tree_id": tid, "artifacts": ["fuzz_target"]}})
        assert r.status_code == 200, r.text
        b = r.json()
        assert b["status"] == "succeeded" and b["derived_target_id"]
        # listed in the ledger
        lst = c.get(f"/api/projects/{pid}/builds").json()["builds"]
        assert any(x["id"] == b["id"] for x in lst)
        # log endpoint
        log = c.get(f"/api/builds/{b['id']}/log").json()
        assert "mock-builder" in log["log"]


def test_capability_table_exposes_build_flag(hg_home):
    from hexgraph.engine.capabilities import capability_table

    assert capability_table()["features"]["build"] is False
    _enable_build()
    assert capability_table()["features"]["build"] is True


# ── MCP run-tool ──────────────────────────────────────────────────────────────────

def test_mcp_build_target_fails_closed(hg_home):
    from hexgraph.engine.mcp_tools import build_target

    with session_scope() as s:
        p = create_project(s, name="mcpgate")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid)
    assert "error" in out and "features.build" in out["error"]


def test_mcp_build_target_runs_with_gate(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    from hexgraph.engine.mcp_tools import build_target, list_builds

    with session_scope() as s:
        p = create_project(s, name="mcprun")
        tree, _ = _src_tree(s, p, with_target=True)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid, artifacts=["fuzz_target"])
    assert out.get("status") == "succeeded" and out.get("derived_target_id")
    listing = list_builds(pid)
    assert listing["builds"] and listing["build_specs"]


def test_mcp_build_target_rejects_secret_env(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    from hexgraph.engine.mcp_tools import build_target

    with session_scope() as s:
        p = create_project(s, name="mcpsecret")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid, artifacts=["foo.o"], env={"API_KEY": "leak"})
    assert "error" in out and "secret" in out["error"].lower()
