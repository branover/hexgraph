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
from hexgraph.engine.build import builds as B
from hexgraph.engine.build import source as src
from hexgraph.engine.build.build import (
    BuildError, BuildPhase, BuildResult, BuildSpec, Instrumentation, MockBuilder,
    assert_env_nonsecret, get_builder, instrumentation_env, normalize_build_phases,
)
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.targets.ingest import create_project
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


@pytest.mark.parametrize("rel", ["/etc/passwd", "../../etc/passwd", "~/secret", "a/../../b"])
def test_artifact_traversal_rejected(rel):
    from hexgraph.engine.build.build import assert_artifacts_contained

    with pytest.raises(BuildError):
        assert_artifacts_contained([rel])


def test_artifact_contained_paths_pass():
    from hexgraph.engine.build.build import assert_artifacts_contained

    assert_artifacts_contained(["fuzz.o", "build/fuzz_target", "a/b/c.so"])  # no raise


def test_build_with_traversal_artifact_fails(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="trav")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec.from_dict({**B.propose_build_spec(tree), "artifacts": ["../../etc/passwd"]})
        with pytest.raises(BuildError):
            B.create_build_spec(s, p, spec)


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
        # Phase 7: source_content_hash is the TRUE byte-content hash (not the cheap
        # size-based manifest hash on the row) — recorded + non-empty.
        assert build.source_content_hash and len(build.source_content_hash) == 64
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
    from hexgraph.engine.build.build import BuildUnavailable

    class Unavail(MockBuilder):
        def build(self, spec, *, source_root, content_hash=None, **kwargs):
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
    from hexgraph.agent.mcp_tools import build_target

    with session_scope() as s:
        p = create_project(s, name="mcpgate")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid)
    assert "error" in out and "features.build" in out["error"]


def test_mcp_build_target_runs_with_gate(hg_home, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    from hexgraph.agent.mcp_tools import build_target, list_builds

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
    from hexgraph.agent.mcp_tools import build_target

    with session_scope() as s:
        p = create_project(s, name="mcpsecret")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid, artifacts=["foo.o"], env={"API_KEY": "leak"})
    assert "error" in out and "secret" in out["error"].lower()


# ── phase parsing: ingest validation + tolerant DB loader ──────────────────────────
# Regression for the src_build phase-parsing bug: a bare-string phase raised an uncaught
# `'str' object has no attribute 'get'`, and a dict without `argv` was silently coerced to
# an empty phase → the probe ran nothing → a ~microsecond "failed"/"succeeded" fake result.

def test_from_dict_is_total_and_never_raises_on_odd_input():
    # The tolerant DB loader must reload ANY recorded shape without raising (it reads
    # historical rows back), incl. the pre-fix `{"argv": [], "shell": false}` no-op phase.
    assert BuildPhase.from_dict({"argv": [], "shell": False}).argv == ()
    assert BuildPhase.from_dict("clang -O1 -o x x.c").argv == ("clang", "-O1", "-o", "x", "x.c")
    assert BuildPhase.from_dict(["make", "-j4"]).argv == ("make", "-j4")
    assert BuildPhase.from_dict({"argv": "cc a.c", "shell": False}).argv == ("cc", "a.c")
    assert BuildPhase.from_dict({"nonsense": 1}).argv == ()      # missing argv → empty, no crash
    assert BuildPhase.from_dict(42).argv == ()                   # odd type → empty, no crash


def test_normalize_accepts_string_list_and_dict_phases():
    phases = normalize_build_phases([
        "clang -O1 -g -o harness harness.c -ldl",       # command string → shlex argv
        ["make", "-j", "4"],                             # explicit argv list
        {"argv": ["cmake", "--build", "build"]},         # {argv} dict
        {"argv": ["build.sh"], "shell": True},           # recorded script phase
    ])
    assert [p.argv for p in phases] == [
        ("clang", "-O1", "-g", "-o", "harness", "harness.c", "-ldl"),
        ("make", "-j", "4"),
        ("cmake", "--build", "build"),
        ("build.sh",),
    ]
    assert phases[3].shell is True
    assert normalize_build_phases(None) == [] and normalize_build_phases([]) == []


@pytest.mark.parametrize("bad,needle", [
    ([""], "empty command string"),                      # blank string
    ([[]], "empty list"),                                # empty argv list
    ([{"shell": True}], "no usable 'argv'"),             # dict missing argv (the silent no-op)
    ([{"argv": []}], "empty 'argv'"),                    # dict with empty argv
    (["cd build && make"], "shell operator"),            # shell operators would mis-split
    (["cat a.c | cc -x c -"], "shell operator"),
    (['a "unbalanced'], "could not parse"),              # unbalanced quotes
    ([123], "unsupported type"),                         # non str/list/dict item
    ("make", "must be a LIST"),                          # a bare string instead of a list
])
def test_normalize_rejects_malformed_phases_with_clear_error(bad, needle):
    with pytest.raises(BuildError) as ei:
        normalize_build_phases(bad)
    assert needle in str(ei.value)


def test_mcp_build_target_accepts_string_phase(hg_home, monkeypatch):
    # A bare-string phase used to crash with `'str'.get`; now it shlex-splits and builds.
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    from hexgraph.agent.mcp_tools import build_target, list_builds

    with session_scope() as s:
        p = create_project(s, name="mcpstr")
        tree, _ = _src_tree(s, p, with_target=True)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid, system="custom",
                       phases=["clang -O1 -g -o harness harness.c -ldl"],
                       artifacts=["harness"])
    assert out.get("status") == "succeeded", out
    # The recorded recipe holds the shlex-split argv (recorded verbatim, explicit-argv).
    spec = list_builds(pid)["build_specs"][0]
    assert spec["recipe"]["phases"][0]["argv"] == [
        "clang", "-O1", "-g", "-o", "harness", "harness.c", "-ldl"]


def test_mcp_build_target_returns_error_on_malformed_phase(hg_home, monkeypatch):
    # A malformed phase returns a clean {"error": ...} — not an unhandled exception.
    monkeypatch.setenv("HEXGRAPH_BUILDER", "mock")
    _enable_build()
    from hexgraph.agent.mcp_tools import build_target

    with session_scope() as s:
        p = create_project(s, name="mcpbad")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    out = build_target(pid, tid, system="custom",
                       phases=[{"cmd": "clang x.c"}], artifacts=["x"])
    assert "error" in out and "phase 0" in out["error"] and "argv" in out["error"]


# ── the '&' background operator + shell=True quote handling (review fixes) ──────────

def test_normalize_rejects_single_ampersand_background_operator():
    # A single '&' (background/list operator) must be rejected too: `echo a & echo b`
    # shlex-splits to ["echo","a","&","echo","b"], echo exits 0, and the build would
    # report a FALSE success while the second command never ran.
    with pytest.raises(BuildError) as ei:
        normalize_build_phases(["echo built & echo also"])
    assert "shell operator" in str(ei.value)


def test_normalize_shell_true_dict_bad_quotes_raises_buildable_error():
    # A shell=True dict whose string argv has unbalanced quotes must raise BuildError
    # (catchable at every ingest seam), never a bare ValueError that escapes the
    # try/except BuildError in build_target / the REST router.
    with pytest.raises(BuildError) as ei:
        normalize_build_phases([{"argv": 'build.sh "unbalanced', "shell": True}])
    assert "could not parse" in str(ei.value)


# ── REST ingest seam validates phases too (parity with the MCP build_target) ───────

def test_api_build_preview_rejects_malformed_phase(hg_home):
    # The UI Build modal / REST preview must reject a dict-without-argv with a clear 400
    # instead of silently recording an empty no-op phase (the fake-success bug).
    app = create_app()
    with session_scope() as s:
        p = create_project(s, name="apibad")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/build/preview",
                   json={"source_tree_id": tid, "phases": [{"cmd": "clang x.c"}],
                         "artifacts": ["x"]})
        assert r.status_code == 400, r.text
        assert "phase 0" in r.text and "argv" in r.text


def test_api_build_preview_accepts_and_splits_string_phase(hg_home):
    # A bare command-string phase shlex-splits into explicit argv on the REST path too.
    app = create_app()
    with session_scope() as s:
        p = create_project(s, name="apistr")
        tree, _ = _src_tree(s, p)
        pid, tid = p.id, tree.id
    with TestClient(app) as c:
        r = c.post(f"/api/projects/{pid}/build/preview",
                   json={"source_tree_id": tid, "system": "custom",
                         "phases": ["clang -O1 -o harness harness.c"], "artifacts": ["harness"]})
        assert r.status_code == 200, r.text
        assert r.json()["phases"][0]["argv"] == ["clang", "-O1", "-o", "harness", "harness.c"]
