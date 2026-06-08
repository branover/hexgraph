"""Phase 7 — supply-chain (bounded audited fetch), cross-compile, build
determinism/cache, OSS-Fuzz import, the editable IDE (revisioned saves + rebuild-
from-revision), and run-to-run coverage diff.

Offline + $0 (the MockBuilder/MockFuzzer paths). Proves the SAFETY invariants:
  - the fetch gate is fail-closed + orthogonal-to-tier + ALLOWLISTED + audited,
  - the compile phase is --network none even with fetch on (fetch-then-offline),
  - cross-compile env injection + the qemu degrade,
  - lockfile/SBOM/reproducibility-badge determinism + cache-key reuse hit/miss,
  - OSS-Fuzz build.sh → BuildSpec mapping,
  - editable-IDE revisioning, read-only enforcement on extracted/vendor trees, and
    rebuild-from-revision,
  - coverage-diff correctness,
  - migration round-trip (0016 on 0015; fresh init_db).
Docker-gated end-to-end (a real fetch + cross build) lives in test_fuzz_phase7_e2e.py.
"""

import pytest

from hexgraph import settings
from hexgraph.db.models import Build, SourceRevision, EgressEvent
from hexgraph.db.session import session_scope
from hexgraph.engine.build import builds as B
from hexgraph.engine.build import source as src
from hexgraph.engine.build.build import (
    BuildPhase, BuildSpec, CROSS_TRIPLES, Instrumentation, MockBuilder, cache_key,
    determinism_env, instrumentation_env, is_reproducible,
)
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.targets.ingest import create_project
from hexgraph.db.models import EdgeType, Target, TargetKind
from hexgraph.policy import (
    PolicyViolation, assert_allows_build_fetch, build_fetch_scope, current_policy,
)


def _enable_build():
    settings.update_settings({"features.build.enabled": True})


def _enable_fetch():
    settings.update_settings({"features.build.enabled": True,
                              "features.build_fetch.enabled": True})


def _src_tree(s, p, *, name="libfoo", with_target=False, fw_meta=None):
    tree = src.create_source_tree(s, p, name=name, origin="scratch", editable=True)
    src.write_source_file(s, p, tree, "Makefile", "all:\n\t: build\n")
    src.write_source_file(s, p, tree, "foo.c", "int foo(int x){return x+1;}\n")
    target = None
    if with_target:
        fw = None
        if fw_meta is not None:
            fw = Target(project_id=p.id, name="fw.bin", path="", kind=TargetKind.firmware_image,
                        metadata_json=fw_meta)
            s.add(fw); s.flush()
        target = Target(project_id=p.id, name="shipped.bin", path="",
                        kind=TargetKind.executable, parent_id=fw.id if fw else None)
        s.add(target); s.flush()
        add_edge(s, project_id=p.id, src=("target", target.id), dst=("source_tree", tree.id),
                 type=EdgeType.built_from, origin="human", confidence=1.0, created_by_tool="test")
    return tree, target


# ── (1) The bounded fetch gate: fail-closed, orthogonal-to-tier, allowlisted, audited ──

def test_build_fetch_gate_fails_closed_by_default(hg_home):
    assert current_policy().allow_build_fetch is False
    with pytest.raises(PolicyViolation):
        assert_allows_build_fetch()


def test_build_fetch_requires_build(hg_home):
    # build_fetch is a sub-capability of build: it is meaningless (and refused) without
    # features.build, even if features.build_fetch is on.
    settings.update_settings({"features.build_fetch.enabled": True})
    assert current_policy().allow_build_fetch is False
    settings.update_settings({"features.build.enabled": True})
    assert current_policy().allow_build_fetch is True


def test_build_fetch_does_not_raise_tier(hg_home):
    # The fetch gate is ORTHOGONAL to the tier ladder (like allow_build): enabling it
    # alone does NOT permit target execution or the local-network tier.
    _enable_fetch()
    pol = current_policy()
    assert pol.allow_build_fetch is True
    assert pol.allow_execution is False
    assert pol.allow_network is False  # fetch is NOT features.network


def test_build_fetch_scope_is_allowlist_only():
    scope = build_fetch_scope(None)  # default registry allowlist
    assert "pypi.org:443" in scope.allow
    assert "crates.io:443" in scope.allow
    # NEVER falls back to "any host" — an arbitrary host is not in the allowlist.
    assert "evil.example.com:443" not in scope.allow
    # explicit host:port honored; a bare host gets 443+80
    custom = build_fetch_scope(["mirror.local:8080", "deb.local"])
    assert "mirror.local:8080" in custom.allow
    assert "deb.local:443" in custom.allow and "deb.local:80" in custom.allow


def test_network_gate_build_fetch_does_not_require_features_network(hg_home):
    """REGRESSION: the runner's egress re-check for a fetch build must use the
    features.build_fetch gate, NOT features.network — else the separate fetch tier could
    never run without also enabling the local-network tier (defeating the gate split)."""
    from hexgraph.sandbox.runner import _assert_network_gate
    # build_fetch ON, network OFF
    _enable_fetch()
    _assert_network_gate("build_fetch")  # no raise — the fetch gate authorizes it
    # the local-network gate is independent and still closed
    with pytest.raises(PolicyViolation):
        _assert_network_gate("network")


def test_network_gate_build_fetch_fails_closed_when_off(hg_home):
    from hexgraph.sandbox.runner import _assert_network_gate
    settings.update_settings({"features.build.enabled": True})  # build on, build_fetch OFF
    with pytest.raises(PolicyViolation):
        _assert_network_gate("build_fetch")


def test_fetch_build_refused_when_gate_off(hg_home):
    # A spec with network='fetch' is refused at the fetch gate even though features.build is on.
    _enable_build()  # build on, build_fetch OFF
    with session_scope() as s:
        p = create_project(s, name="fetchgate")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec(source_tree_id=tree.id, system="cargo",
                         phases=(BuildPhase(("cargo", "build")),),
                         fetch_phases=(BuildPhase(("cargo", "fetch")),), network="fetch")
        with pytest.raises(PolicyViolation):
            MockBuilder().build(spec, source_root="/tmp", content_hash="h",
                                fetch_session=s, project=p)


def test_fetch_build_produces_lockfile_sbom_and_audits(hg_home):
    _enable_fetch()
    with session_scope() as s:
        p = create_project(s, name="fetchok")
        tree, _ = _src_tree(s, p)
        spec = BuildSpec(source_tree_id=tree.id, system="cargo",
                         phases=(BuildPhase(("cargo", "build")),),
                         fetch_phases=(BuildPhase(("cargo", "fetch")),),
                         network="fetch", artifacts=("foo",))
        res = MockBuilder().build(spec, source_root="/tmp", content_hash="h",
                                  fetch_session=s, project=p)
        assert res.ok
        # hash-pinned lockfile + SBOM-lite produced
        assert res.lockfile and all("sha256" in v for v in res.lockfile.values())
        assert res.sbom and all("sha256" in d for d in res.sbom)
        # the fetch egress was AUDITED to the allowlist (allowed EgressEvents, tool=build_fetch)
        evs = s.query(EgressEvent).filter(EgressEvent.tool == "build_fetch").all()
        assert evs and all(e.allowed for e in evs)
        dests = {e.dest for e in evs}
        assert "crates.io:443" in dests


# ── (2) Cross-compilation env injection + degrade ───────────────────────────────

def test_cross_env_injects_target_and_sysroot():
    e = instrumentation_env(Instrumentation(), arch="mips", sysroot="/rootfs")
    assert "--target=mipsel-linux-gnu" in e["CC"]
    assert "--sysroot=/sysroot" in e["CC"]  # the probe mounts the rootfs at /sysroot
    assert e["CROSS"] == "mipsel-linux-gnu" and e["ARCH"] == "mips"
    # native arch ⇒ no cross flags
    n = instrumentation_env(Instrumentation(), arch="x86_64")
    assert "--target=" not in n["CC"] and "CROSS" not in n


def test_cross_arch_without_sysroot_still_targets():
    # No firmware rootfs available ⇒ target triple still injected (degrade path keeps the
    # arch), just no --sysroot (clang uses its bundled headers / fails → native fallback).
    e = instrumentation_env(Instrumentation(), arch="armhf", sysroot=None)
    assert "--target=arm-linux-gnueabihf" in e["CC"]
    assert "--sysroot" not in e["CC"]


def test_cross_recorded_in_recipe_sha():
    base = BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),)).recipe_sha()
    assert BuildSpec(source_tree_id="t", phases=(BuildPhase(("make",)),),
                     arch="mips").recipe_sha() != base


def test_unknown_arch_falls_back_to_native():
    e = instrumentation_env(Instrumentation(), arch="sparc", sysroot="/x")
    assert "--target=" not in e["CC"]  # unknown arch ⇒ native (degrade)


# ── (3) Determinism + cache-key reuse ────────────────────────────────────────────

def test_determinism_env():
    e = determinism_env(source_date_epoch=1000000000, ccache=True)
    assert e["SOURCE_DATE_EPOCH"] == "1000000000"
    assert e["USE_CCACHE"] == "1" and e["CCACHE_DIR"]
    assert determinism_env() == {}  # nothing forced when both off


def test_reproducibility_badge():
    assert is_reproducible("r", "s", "t", "none") is True
    assert is_reproducible("r", None, "t", "none") is False       # missing leg
    assert is_reproducible("r", "s", "t", "fetch") is False       # fetch needs a lockfile
    assert is_reproducible("r", "s", "t", "fetch", {"x": 1}) is True


def test_cache_key_determinism():
    k1 = cache_key("r", "s", "t")
    k2 = cache_key("r", "s", "t")
    assert k1 == k2
    assert cache_key("r", "s", "t", {"a": 1}) != k1   # lockfile changes the key
    assert cache_key("r", None, "t") is None          # incomplete provenance ⇒ no reuse


def test_cache_reuse_hit_and_miss(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="cache")
        tree, _ = _src_tree(s, p, with_target=True)
        spec = BuildSpec.from_dict({**B.propose_build_spec(tree), "artifacts": ["foo"]})
        spec_row = B.create_build_spec(s, p, spec)
        b1 = B.run_build(s, p, spec_row, builder=MockBuilder())
        assert b1.status == "succeeded" and b1.cache_hit is False
        # A second build with the SAME recipe + source ⇒ cache HIT (reuses artifacts, skips build).
        b2 = B.run_build(s, p, spec_row, builder=MockBuilder())
        assert b2.status == "succeeded" and b2.cache_hit is True
        assert b2.artifacts_json == b1.artifacts_json   # same CAS shas reused
        assert b2.derived_target_id is not None          # still registers a usable derived target
        # MISS when the source content changes (the working tree mutated ⇒ new content_hash).
        src.write_source_file(s, p, tree, "foo.c", "int foo(int x){return x+2;}\n")
        b3 = B.run_build(s, p, spec_row, builder=MockBuilder())
        assert b3.cache_hit is False


def test_cache_reuse_can_be_disabled(hg_home):
    _enable_build()
    settings.update_settings({"features.build.cache_reuse": False})
    with session_scope() as s:
        p = create_project(s, name="nocache")
        tree, _ = _src_tree(s, p, with_target=True)
        spec_row = B.create_build_spec(s, p, BuildSpec.from_dict(
            {**B.propose_build_spec(tree), "artifacts": ["foo"]}))
        B.run_build(s, p, spec_row, builder=MockBuilder())
        b2 = B.run_build(s, p, spec_row, builder=MockBuilder())
        assert b2.cache_hit is False  # always rebuilds


# ── (4) OSS-Fuzz build.sh import ─────────────────────────────────────────────────

OSS_FUZZ_SH = """#!/bin/bash -eu
# A representative OSS-Fuzz build.sh
$CC $CFLAGS -c parser.c -o parser.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE parser.o fuzz_parser.cc -o $OUT/fuzz_parser
cp seeds.dict $OUT/fuzz_parser.dict
"""


def test_oss_fuzz_parse_artifacts():
    from hexgraph.engine.build.oss_fuzz import parse_build_sh_artifacts
    arts = parse_build_sh_artifacts(OSS_FUZZ_SH)
    # captured by the BARE name ($OUT is the capture root)
    assert "fuzz_parser" in arts
    # the .dict copy target is excluded (not a fuzz binary)
    assert "fuzz_parser.dict" not in arts


def test_oss_fuzz_import_maps_contract(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="ossfuzz")
        tree, _ = _src_tree(s, p)
        row = B.import_oss_fuzz_build(s, p, tree, build_sh=OSS_FUZZ_SH)
        spec = B.spec_from_row(row)
        # single shell phase pointing at build.sh
        assert len(spec.phases) == 1 and spec.phases[0].shell
        assert spec.phases[0].argv == ("build.sh",)
        # $LIB_FUZZING_ENGINE injected (the one OSS-Fuzz var our contract didn't already set)
        assert "LIB_FUZZING_ENGINE" in spec.env
        # the build.sh is stored in the tree as role=script
        listing = src.list_source_files(s, p, tree)
        roles = {f["rel"]: f["role"] for f in listing["files"]}
        assert roles.get("build.sh") == "script"
        # the fuzz target is captured (by its bare $OUT name)
        assert "fuzz_parser" in spec.artifacts


def test_oss_fuzz_import_refused_on_readonly_tree(hg_home):
    _enable_build()
    with session_scope() as s:
        p = create_project(s, name="ro")
        ro = src.create_source_tree(s, p, name="vendor", origin="git", editable=False)
        with pytest.raises(src.SourceError):
            B.import_oss_fuzz_build(s, p, ro, build_sh=OSS_FUZZ_SH)


# ── (5) Editable IDE: revisioning + read-only enforcement + rebuild-from-revision ──

def _enable_edit():
    settings.update_settings({"features.source.edit": True})


def test_scratch_tree_editable_without_flag(hg_home):
    """SCOPED source-edit: a SCRATCH (HexGraph-authored, ephemeral) tree is editable
    UNCONDITIONALLY — no features.source.edit needed. The friction-killing default."""
    from hexgraph.engine.build import revisions as R
    with session_scope() as s:
        p = create_project(s, name="scratchedit")
        tree, _ = _src_tree(s, p)  # origin="scratch", editable=True
        assert R.is_scratch_tree(tree) is True
        assert R.can_edit_tree(tree) is True   # flag OFF, still editable
        # flag OFF ⇒ a scratch save SUCCEEDS (new behavior)
        rev = R.save_revision(s, p, tree, "h.c", "int main(){}", role="harness")
        assert rev["seq"] == 1
        assert src.read_source_file(p, tree, "h.c")["content"] == "int main(){}"


def test_nonscratch_authored_tree_gated_by_flag(hg_home):
    """An editable-but-NOT-scratch authored tree (e.g. imported source an importer marked
    editable) still requires features.source.edit: refused with the flag off, allowed on."""
    from hexgraph.engine.build import revisions as R
    with session_scope() as s:
        p = create_project(s, name="authoredgate")
        # editable=True but origin != scratch — NOT a scratch tree.
        tree = src.create_source_tree(s, p, name="imported", origin="git", editable=True)
        assert R.is_scratch_tree(tree) is False
        # flag OFF ⇒ refused (still gated)
        assert R.can_edit_tree(tree) is False
        with pytest.raises(PolicyViolation):
            R.save_revision(s, p, tree, "h.c", "int main(){}", role="harness")
        # flag ON ⇒ allowed
        _enable_edit()
        assert R.can_edit_tree(tree) is True
        rev = R.save_revision(s, p, tree, "h.c", "int main(){}", role="harness")
        assert rev["seq"] == 1


def test_save_revision_creates_history(hg_home):
    from hexgraph.engine.build import revisions as R
    _enable_edit()
    with session_scope() as s:
        p = create_project(s, name="edit")
        tree, _ = _src_tree(s, p)
        r1 = R.save_revision(s, p, tree, "h.c", "v1\n", role="harness")
        r2 = R.save_revision(s, p, tree, "h.c", "v2\n", role="harness")
        assert r1["seq"] == 1 and r2["seq"] == 2
        revs = R.list_revisions(s, tree, rel="h.c")
        assert [r["seq"] for r in revs] == [2, 1]  # newest first
        # the working file equals the latest revision
        assert src.read_source_file(p, tree, "h.c")["content"] == "v2\n"
        # the diff is recorded
        assert revs[0]["has_diff"]


def test_edit_refused_on_extracted_or_vendor_tree(hg_home):
    """The riskiest confinement: editing extracted/vendor/imported source is ALWAYS REFUSED
    (with the flag on OR off) — it would break the content_hash build contract. tree.editable
    is the hard structural gate, unchanged by the scoped scratch-tree allowance."""
    from hexgraph.engine.build import revisions as R
    _enable_edit()
    with session_scope() as s:
        p = create_project(s, name="confine")
        for origin in ("extracted", "git", "archive", "upload"):
            ro = src.create_source_tree(s, p, name=f"t-{origin}", origin=origin)
            assert ro.editable is False
            assert R.is_scratch_tree(ro) is False  # read-only ⇒ never scratch
            assert R.can_edit_tree(ro) is False     # never editable even with the flag on
            with pytest.raises(src.SourceError):
                R.save_revision(s, p, ro, "x.c", "tampered", role="code")


def test_revert_is_append_only(hg_home):
    from hexgraph.engine.build import revisions as R
    _enable_edit()
    with session_scope() as s:
        p = create_project(s, name="revert")
        tree, _ = _src_tree(s, p)
        r1 = R.save_revision(s, p, tree, "h.c", "v1\n", role="harness")
        R.save_revision(s, p, tree, "h.c", "v2\n", role="harness")
        rev = R.revert_to_revision(s, p, tree, r1["id"])
        assert rev["seq"] == 3                         # a revert is a NEW revision
        assert src.read_source_file(p, tree, "h.c")["content"] == "v1\n"  # content restored


def test_rebuild_from_revision(hg_home):
    _enable_build()
    settings.update_settings({"features.source.edit": True})
    from hexgraph.engine.build import revisions as R
    with session_scope() as s:
        p = create_project(s, name="rebuildrev")
        tree, _ = _src_tree(s, p, with_target=True)
        spec_row = B.create_build_spec(s, p, BuildSpec.from_dict(
            {**B.propose_build_spec(tree), "artifacts": ["foo"]}))
        # save an edit, then revert + rebuild from the FIRST revision
        r1 = R.save_revision(s, p, tree, "foo.c", "int foo(int x){return x+10;}\n", role="code")
        R.save_revision(s, p, tree, "foo.c", "int foo(int x){return x+20;}\n", role="code")
        build = B.rebuild_from_revision(s, p, spec_row, r1["id"], builder=MockBuilder())
        assert build.status == "succeeded"
        assert build.source_revision_id is not None
        # the working file reverted to the chosen revision's content
        assert "x+10" in src.read_source_file(p, tree, "foo.c")["content"]


# ── (6) Run-to-run coverage diff ─────────────────────────────────────────────────

def _campaign_with_coverage(s, p, tree, target, covered_a, covered_b):
    """Two mock campaigns over the same target with given covered-line sets, so the diff
    is deterministic. We write the coverage.json directly into each campaign's outdir."""
    import json
    from pathlib import Path
    from hexgraph.db.models import FuzzCampaign

    cams = []
    for cov in (covered_a, covered_b):
        c = FuzzCampaign(project_id=p.id, target_id=target.id, surface="source_lib",
                         engine="libfuzzer", status="completed",
                         outdir=str(Path(p.data_dir) / "campaigns" / f"c{len(cams)}"))
        s.add(c); s.flush()
        Path(c.outdir).mkdir(parents=True, exist_ok=True)
        total = max(cov) if cov else 0
        (Path(c.outdir) / "coverage.json").write_text(json.dumps(
            {"percent": 50.0, "files": {"foo.c": {"covered": cov, "total": total}}}))
        cams.append(c)
    return cams


def test_coverage_diff_gained_and_lost(hg_home):
    from hexgraph.engine import campaigns as C
    with session_scope() as s:
        p = create_project(s, name="covdiff")
        tree, target = _src_tree(s, p, with_target=True)
        base, other = _campaign_with_coverage(s, p, tree, target, [1, 2, 3], [2, 3, 4, 5])
        d = C.coverage_diff(s, base, other)
        assert d["available"] is True
        f = d["files"]["foo.c"]
        assert f["gained"] == [4, 5]   # other reached new lines
        assert f["lost"] == [1]        # base had line 1, other didn't
        assert d["summary"]["lines_gained"] == 2 and d["summary"]["lines_lost"] == 1


def test_coverage_diff_unavailable_without_maps(hg_home):
    from hexgraph.db.models import FuzzCampaign
    from hexgraph.engine import campaigns as C
    with session_scope() as s:
        p = create_project(s, name="nocov")
        tree, target = _src_tree(s, p, with_target=True)
        c1 = FuzzCampaign(project_id=p.id, target_id=target.id, status="completed")
        c2 = FuzzCampaign(project_id=p.id, target_id=target.id, status="completed")
        s.add_all([c1, c2]); s.flush()
        d = C.coverage_diff(s, c1, c2)
        assert d["available"] is False


# ── (7) Migration round-trip ─────────────────────────────────────────────────────

def test_migration_0016_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(tmp_path / "rt.db"))
    from alembic import command
    from sqlalchemy import create_engine, inspect
    from hexgraph.db.migrate import _alembic_config
    from hexgraph.db.session import db_url, reset_engine_for_tests

    reset_engine_for_tests()
    cfg = _alembic_config()
    command.upgrade(cfg, "0015_fuzz_environment")
    command.upgrade(cfg, "0016_build_supplychain_source_revision")
    names = set(inspect(create_engine(db_url())).get_table_names())
    assert "source_revision" in names
    cols = {c["name"] for c in inspect(create_engine(db_url())).get_columns("build")}
    assert {"lockfile_json", "sbom_json", "reproducible", "cache_hit", "cache_key",
            "source_revision_id"} <= cols
    command.downgrade(cfg, "0015_fuzz_environment")
    assert "source_revision" not in set(inspect(create_engine(db_url())).get_table_names())
    reset_engine_for_tests()


def test_fresh_init_db_has_phase7_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("HEXGRAPH_DB_PATH", str(tmp_path / "fresh.db"))
    from sqlalchemy import create_engine, inspect
    from hexgraph.db.session import db_url, init_db, reset_engine_for_tests

    reset_engine_for_tests()
    init_db()
    insp = inspect(create_engine(db_url()))
    assert "source_revision" in insp.get_table_names()
    cols = {c["name"] for c in insp.get_columns("build")}
    assert "lockfile_json" in cols and "cache_key" in cols
    reset_engine_for_tests()


# ── API surface (capability flags + endpoints) ───────────────────────────────────

def test_capability_flags_phase7(hg_home):
    from hexgraph.engine.capabilities import capability_table
    feats = capability_table()["features"]
    assert feats["build_fetch"] is False and feats["source_edit"] is False
    _enable_fetch()
    settings.update_settings({"features.source.edit": True})
    feats = capability_table()["features"]
    assert feats["build_fetch"] is True and feats["source_edit"] is True
