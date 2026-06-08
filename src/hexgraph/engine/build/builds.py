"""Build orchestration: persist a recorded recipe, run it via the Builder seam in
the sandbox, ingest the artifacts/log into CAS, and register the instrumented
rebuild as a derived target (design §3.2/§3.3, Phase 2 — build-as-API).

This is the DB/CAS/graph layer on top of `engine/build.py` (the pure seam). It
keeps the Builder free of project/CAS concerns: the Builder produces bytes on
disk, this module homes them in the per-project CAS and writes the durable `build`
ledger + the `build_spec` recipe + the derived-target wiring.

Nobody runs a compiler by hand. The user/LLM authors a `BuildSpec` (a `build_spec`
row) and *requests* a build (`POST /api/builds` / the `build_target` MCP run-tool);
HexGraph runs the recorded recipe, gated by `assert_allows_build()`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import (
    Build, BuildSpec as BuildSpecRow, EdgeType, Project, SourceTree, Target, TargetKind,
)
from hexgraph.engine import cas
from hexgraph.engine.build.build import (
    BUILD_SYSTEMS, BuildError, BuildPhase, BuildSpec, BuildUnavailable, Instrumentation,
    get_builder,
)
from hexgraph.engine.edges import add_edge
from hexgraph.engine.build.source import host_root, tree_content_sha
from hexgraph.policy import PolicyViolation


def settings_get(path: str, default=None):
    from hexgraph import settings
    return settings.get(path, default)


# ── Detection: propose a recipe from a source tree (deterministic, runs no project code) ──
# A lightweight host-side heuristic over the manifest (which build files are
# present). The dedicated build_detect_probe.py does a deeper in-sandbox inspection;
# this is the fast default so the UI/MCP can offer a recipe without a container.

def detect_build_system(tree: SourceTree) -> str:
    files = {f.get("rel", "") for f in (tree.manifest_json or {}).get("files") or []}
    base = {Path(f).name for f in files}
    if "CMakeLists.txt" in base:
        return "cmake"
    if "meson.build" in base:
        return "meson"
    if "Cargo.toml" in base:
        return "cargo"
    if "go.mod" in base:
        return "go"
    if "configure" in base or "configure.ac" in base or "autogen.sh" in base:
        return "autotools"
    if "Makefile" in base or "makefile" in base or "GNUmakefile" in base:
        return "make"
    return "custom"


def _default_phases(system: str) -> list[BuildPhase]:
    """Default ordered, explicit-argv phases for a recognised build system. The
    author can edit these; instrumentation is injected via env (the base-image
    contract), so the SAME phases yield an ASan/SanCov/AFL++ build by swapping only
    the profile."""
    j = ["-j", str(max(1, (os.cpu_count() or 2)))]
    if system == "cmake":
        return [BuildPhase(("cmake", "-S", ".", "-B", "build")),
                BuildPhase(("cmake", "--build", "build", *j))]
    if system == "meson":
        return [BuildPhase(("meson", "setup", "build")),
                BuildPhase(("meson", "compile", "-C", "build"))]
    if system == "autotools":
        return [BuildPhase(("./configure",)), BuildPhase(("make", *j))]
    if system == "cargo":
        # --offline enforces vendored deps this phase (no fetch).
        return [BuildPhase(("cargo", "build", "--release", "--offline"))]
    if system == "go":
        return [BuildPhase(("go", "build", "./..."))]
    if system == "make":
        return [BuildPhase(("make", *j))]
    return []


def propose_build_spec(tree: SourceTree, *, instrumentation: dict | None = None,
                       artifacts: list[str] | None = None) -> dict:
    """A DETECTED, proposed BuildSpec for a source tree (design §3.2 path 1).
    Deterministic; runs no project code. Returns the spec dict (the recorded recipe
    the API/tool would run) so the UI can preview it before launching."""
    system = detect_build_system(tree)
    spec = BuildSpec(
        source_tree_id=tree.id,
        system=system,
        phases=tuple(_default_phases(system)),
        instrumentation=Instrumentation.from_dict(instrumentation or {}),
        artifacts=tuple(artifacts or ()),
        name=f"{tree.name} ({system})",
    )
    return spec.to_dict()


# ── Persistence: the recorded recipe (build_spec) ──────────────────────────────

def create_build_spec(session: Session, project: Project, spec: BuildSpec) -> BuildSpecRow:
    """Persist a recorded recipe as a `build_spec` row (recipe_sha computed). The
    source tree must exist in this project."""
    if spec.system not in BUILD_SYSTEMS:
        raise BuildError(f"system must be one of {BUILD_SYSTEMS}")
    tree = session.get(SourceTree, spec.source_tree_id)
    if tree is None or tree.project_id != project.id:
        raise BuildError("source tree not found in this project")
    from hexgraph.engine.build.build import assert_artifacts_contained, assert_env_nonsecret

    assert_env_nonsecret(spec.env)
    assert_artifacts_contained(spec.artifacts)
    row = BuildSpecRow(
        project_id=project.id, source_tree_id=spec.source_tree_id, name=spec.name,
        system=spec.system, recipe_json=spec.to_dict(),
        instrumentation_json=spec.instrumentation.to_dict(),
        artifacts_json=list(spec.artifacts), base_image=spec.base_image, arch=spec.arch,
        network=spec.network, recipe_sha=spec.recipe_sha(),
    )
    session.add(row)
    session.flush()
    return row


def spec_from_row(row: BuildSpecRow) -> BuildSpec:
    return BuildSpec.from_dict(row.recipe_json or {"source_tree_id": row.source_tree_id})


# ── Execution: run a recorded recipe, persist the build, register derived target ──

def run_build(session: Session, project: Project, spec_row: BuildSpecRow, *,
              builder=None, register_derived: bool = True,
              source_revision_id: str | None = None) -> Build:
    """Execute a recorded `build_spec` in the sandbox via the Builder seam, ingest
    artifacts + log into CAS, persist the `build` ledger row, and (the headline
    capability, §3.3) register the instrumented rebuild as a DERIVED target wired
    `instrumented_build_of`→ the original target. Gated by assert_allows_build()
    (inside the Builder). Returns the build row.

    Phase 7: a bounded FETCH phase (network='fetch', gated by features.build_fetch) runs
    BEFORE an offline compile, producing a hash-pinned lockfile + SBOM-lite; the build
    records a reproducibility BADGE; and a cache-key HIT (same recipe_sha + source
    content_hash + toolchain_digest + lockfile) REUSES a prior CAS artifact and skips the
    rebuild. `source_revision_id` records a rebuild-from-revision launch."""
    from hexgraph.engine.build.build import cache_key as _cache_key, is_reproducible

    spec = spec_from_row(spec_row)
    tree = session.get(SourceTree, spec.source_tree_id)
    if tree is None or tree.project_id != project.id:
        raise BuildError("source tree not found in this project")

    # A TRUE byte-content hash (not the row's cheap size-based manifest hash) — so the
    # reproducibility triple + cache key reflect the ACTUAL bytes built (a same-size edit
    # changes it, preventing a stale-artifact cache hit).
    content_sha = tree_content_sha(project, tree)

    build = Build(
        project_id=project.id, build_spec_id=spec_row.id, source_tree_id=tree.id,
        status="building", recipe_sha=spec_row.recipe_sha,
        instrumentation_json=spec.instrumentation.to_dict(),
        source_revision_id=source_revision_id,
    )
    session.add(build)
    session.flush()

    # ── Cache-key artifact reuse (design §3 determinism). When a prior SUCCEEDED build
    # has the SAME reproducibility key, reuse its recorded artifacts (skip the rebuild).
    # Deterministic + safe: identical inputs ⇒ identical output. Opt-out via cache_reuse.
    if bool(settings_get("features.build.cache_reuse", True)):
        reused = _try_cache_reuse(session, project, tree, build, spec_row, spec, content_sha)
        if reused is not None:
            return reused

    source_root = str(host_root(project, tree))
    builder = builder or get_builder()
    target_id = None
    o = _origin_target(session, project, tree)
    if o is not None:
        target_id = o.id
    try:
        result = builder.build(spec, source_root=source_root, content_hash=content_sha,
                               fetch_session=session, project=project, target_id=target_id,
                               task_id=None)
    except BuildUnavailable as exc:
        build.status = "failed"
        build.error = str(exc)
        session.flush()
        return build
    except (BuildError, PolicyViolation) as exc:
        build.status = "failed"
        build.error = str(exc)
        session.flush()
        return build

    # Ingest the log + artifacts into the per-project CAS (durable, content-addressed).
    if result.log_text:
        build.log_cas = cas.put(project, result.log_text)
    artifacts_cas: dict[str, str] = {}
    artifact_files: dict[str, str] = {}  # rel → host path (for the derived target bytes)
    for rel, host_path in (result.artifact_paths or {}).items():
        try:
            data = Path(host_path).read_bytes()
        except OSError:
            continue
        artifacts_cas[rel] = cas.put(project, data)
        artifact_files[rel] = host_path
    build.artifacts_json = artifacts_cas
    build.source_content_hash = result.source_content_hash
    build.toolchain_digest = result.toolchain_digest
    build.returncode = result.returncode
    build.duration = result.duration
    # Supply-chain provenance + reproducibility badge (Phase 7).
    build.lockfile_json = result.lockfile or {}
    build.sbom_json = result.sbom or []
    build.reproducible = is_reproducible(result.recipe_sha, result.source_content_hash,
                                         result.toolchain_digest, network=spec.network,
                                         lockfile=result.lockfile)
    build.cache_key = _cache_key(result.recipe_sha, result.source_content_hash,
                                 result.toolchain_digest, result.lockfile)
    build.status = "succeeded" if result.ok else "failed"
    if not result.ok:
        build.error = result.error or "build failed (see log)"
    session.flush()

    if result.ok and register_derived and artifacts_cas:
        derived = _register_derived_target(session, project, tree, build, spec, artifact_files,
                                           artifacts_cas)
        if derived is not None:
            build.derived_target_id = derived.id
            session.flush()
    return build


def _try_cache_reuse(session: Session, project: Project, tree: SourceTree, build: Build,
                     spec_row: BuildSpecRow, spec: BuildSpec, content_sha: str) -> Build | None:
    """If a prior SUCCEEDED build shares this build's reproducibility cache key, reuse its
    CAS artifacts (copy them onto this build row, register a fresh derived target) and skip
    the rebuild — mark cache_hit=True. None ⇒ no hit (proceed to build). Keyed on the
    recipe_sha + the TRUE byte-content hash (`content_sha`, not the size-based manifest
    hash) of a PRIOR build with the SAME recipe + source (same recipe_sha + content_sha ⇒
    same toolchain, since the image is part of recipe_sha) — so a same-size edit MISSES."""
    from hexgraph.engine.build.build import cache_key as _cache_key

    if not (spec_row.recipe_sha and content_sha):
        return None
    prior = (session.query(Build)
             .filter(Build.project_id == project.id, Build.status == "succeeded",
                     Build.recipe_sha == spec_row.recipe_sha,
                     Build.source_content_hash == content_sha)
             .order_by(Build.created_at.desc()).first())
    if prior is None or not prior.artifacts_json:
        return None
    key = _cache_key(prior.recipe_sha, prior.source_content_hash, prior.toolchain_digest,
                     prior.lockfile_json)
    # Reuse the prior build's recorded CAS artifacts verbatim.
    build.artifacts_json = dict(prior.artifacts_json or {})
    build.source_content_hash = prior.source_content_hash
    build.toolchain_digest = prior.toolchain_digest
    build.lockfile_json = prior.lockfile_json or {}
    build.sbom_json = prior.sbom_json or []
    build.reproducible = prior.reproducible
    build.cache_key = key
    build.cache_hit = True
    build.returncode = 0
    build.duration = 0.0
    build.log_cas = prior.log_cas
    build.status = "succeeded"
    session.flush()
    # Register a fresh derived target from the reused CAS bytes (so the campaign has a real
    # path), materializing the artifact files back out of CAS.
    artifact_files: dict[str, str] = {}
    import tempfile
    work = Path(tempfile.mkdtemp(prefix="hexgraph-cachereuse-"))
    for rel, sha in (build.artifacts_json or {}).items():
        data = cas.get(project, sha)
        if data is None:
            continue
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        artifact_files[rel] = str(p)
    if artifact_files:
        derived = _register_derived_target(session, project, tree, build, spec, artifact_files,
                                           dict(build.artifacts_json or {}))
        if derived is not None:
            build.derived_target_id = derived.id
            session.flush()
    return build


def _origin_target(session: Session, project: Project, tree: SourceTree) -> Target | None:
    """The target this source tree is `built_from` (the shipped binary we rebuild)."""
    from hexgraph.db.models import Edge

    e = (session.query(Edge)
         .filter(Edge.project_id == project.id, Edge.type == EdgeType.built_from.value,
                 Edge.dst_kind == "source_tree", Edge.dst_id == tree.id)
         .first())
    if e is None or e.src_kind != "target":
        return None
    return session.get(Target, e.src_id)


def _register_derived_target(session, project: Project, tree: SourceTree, build: Build,
                             spec: BuildSpec, artifact_files: dict, artifacts_cas: dict) -> Target | None:
    """Register the instrumented rebuild as a derived target (§3.3). The artifact
    bytes are copied into the project artifacts dir (like ingest_file) so the target
    has a real `path` for Phase-3 coverage-guided fuzzing. Wired `instrumented_build_of`
    → the original target (when the tree is built_from one), and `builds` from the
    build_spec → the derived target. The derived target's metadata records the build
    id + sanitizers + that it's instrumented (distinct from "the shipped binary")."""
    if not artifact_files:
        return None
    # Pick the primary artifact (the first listed, else the first captured).
    rel = next((a for a in spec.artifacts if a in artifact_files), next(iter(artifact_files)))
    src_path = artifact_files[rel]
    origin = _origin_target(session, project, tree)
    name = f"{(origin.name if origin else tree.name)} (instrumented)"
    derived = Target(
        project_id=project.id,
        parent_id=origin.id if origin else None,
        name=name, path="",
        kind=(origin.kind if origin else TargetKind.executable),
        arch=spec.arch,
        metadata_json={
            "instrumented": True, "build_id": build.id, "build_spec_id": build.build_spec_id,
            "sanitizers": list(spec.instrumentation.sanitizers),
            "coverage": list(spec.instrumentation.coverage),
            "engine": spec.instrumentation.engine,
            "source_tree_id": tree.id,
            "artifact_cas": artifacts_cas.get(rel),
            # The source files HexGraph rebuilt — Phase-3 fuzzing reads these to compile
            # the target's own objects with SanCov+ASan (coverage-guided). Populated below
            # (after the derived row exists) from the instrumented tree's code sources.
            "fuzz_target_sources": [],
        },
    )
    session.add(derived)
    session.flush()
    # Copy the artifact bytes into the project's artifacts dir (per-target subdir).
    dst_dir = Path(project.data_dir) / "artifacts" / derived.id
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / Path(rel).name
    try:
        dst.write_bytes(Path(src_path).read_bytes())
        derived.path = str(dst)
    except OSError:
        derived.path = ""
    meta = dict(derived.metadata_json or {})
    meta["size"] = dst.stat().st_size if dst.is_file() else 0
    meta["artifacts"] = artifacts_cas
    # ── Build→fuzz handoff (§3.3): record the TARGET sources HexGraph instrumented +
    # promote the harness so a subsequent start_fuzz_campaign infers source_lib and runs
    # COVERAGE-GUIDED (not binary_only/qemu on a relocatable .o). Without this the
    # documented happy path silently no-ops (battle-test C). Both are best-effort: when no
    # source/harness is resolvable the campaign degrades honestly, never falsely.
    meta["fuzz_target_sources"] = _instrumented_target_sources(project, tree, spec)
    derived.metadata_json = meta
    session.flush()
    _promote_build_harness(session, project, tree, derived)

    # Graph wiring: the derived target is an instrumented rebuild OF the original.
    if origin is not None:
        add_edge(session, project_id=project.id, src=("target", derived.id),
                 dst=("target", origin.id), type=EdgeType.instrumented_build_of,
                 origin="tool", confidence=1.0, created_by_tool="build",
                 attrs={"build_id": build.id, "sanitizers": list(spec.instrumentation.sanitizers)})
    # And the build_spec `builds` the derived target.
    add_edge(session, project_id=project.id, src=("build_spec", build.build_spec_id),
             dst=("target", derived.id), type=EdgeType.builds, origin="tool",
             confidence=1.0, created_by_tool="build", attrs={"build_id": build.id})
    return derived


# C/C++ translation units we can compile under SanCov+ASan for coverage-guided fuzzing.
_C_SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++", ".C")


def _instrumented_target_sources(project: Project, tree: SourceTree, spec: BuildSpec) -> list[str]:
    """The HOST paths of the target's OWN translation units that were instrumented in
    this build — what Phase-3 coverage-guided fuzzing recompiles with
    `-fsanitize=fuzzer-no-link,address` and links into the harness. We take every
    code-role C/C++ source in the tree EXCEPT the harness/poc/script files (those aren't
    "the library under test"): a harness defines `LLVMFuzzerTestOneInput`, not the API
    being fuzzed, and compiling it as a target source would double-define the entry point.
    Returns existing host paths only (a missing file is dropped — resolve_target_sources
    degrades to a coverage-blind run rather than over-claim instrumentation)."""
    root = host_root(project, tree)
    out: list[str] = []
    for f in (tree.manifest_json or {}).get("files") or []:
        rel = f.get("rel")
        role = f.get("role", "code")
        if not rel or role in ("harness", "poc", "script", "build_recipe"):
            continue
        if not str(rel).endswith(_C_SOURCE_EXT):
            continue
        host = root / rel
        if host.is_file():
            out.append(str(host))
    return out


def _promote_build_harness(session, project: Project, tree: SourceTree, derived: Target) -> None:
    """Promote a harness in the built tree to a managed `source_file(role=harness)` + a
    `harness` node `harnesses`→ the DERIVED (instrumented) target, so a subsequent
    start_fuzz_campaign resolves it (resolve_harness → resolve_managed_harness reads the
    `harnesses` edge). Idempotent (promote_harness keys on target+function+finding).
    Best-effort: a tree with no harness-role file is left as-is (the campaign then reports
    'no fuzz harness available' honestly instead of false-greening). Picks the first
    harness-role file in the manifest; ignores a read failure."""
    from hexgraph.engine.harness_promote import promote_harness
    from hexgraph.engine.build.source import read_source_file

    harness_rel = next((f.get("rel") for f in (tree.manifest_json or {}).get("files") or []
                        if f.get("role") == "harness" and f.get("rel")), None)
    if not harness_rel:
        return
    try:
        text = read_source_file(project, tree, harness_rel)
    except Exception:  # noqa: BLE001 — a harness we can't read just isn't promoted
        return
    if text.get("encoding") != "text" or not text.get("content"):
        return
    promote_harness(session, project, derived.id, text["content"],
                    function=Path(harness_rel).stem)


# ── Read helpers (API/MCP) ──────────────────────────────────────────────────────

def build_to_dict(build: Build) -> dict:
    return {
        "id": build.id, "build_spec_id": build.build_spec_id,
        "source_tree_id": build.source_tree_id, "status": build.status,
        "recipe_sha": build.recipe_sha, "source_content_hash": build.source_content_hash,
        "toolchain_digest": build.toolchain_digest, "artifacts": build.artifacts_json or {},
        "log_cas": build.log_cas, "instrumentation": build.instrumentation_json or {},
        "returncode": build.returncode, "duration": build.duration, "error": build.error,
        "derived_target_id": build.derived_target_id,
        # Phase 7 supply-chain provenance + the reproducibility badge.
        "lockfile": build.lockfile_json or {}, "sbom": build.sbom_json or [],
        "reproducible": bool(build.reproducible), "cache_hit": bool(build.cache_hit),
        "cache_key": build.cache_key, "source_revision_id": build.source_revision_id,
        "created_at": build.created_at.isoformat() if build.created_at else None,
    }


def spec_to_dict(row: BuildSpecRow) -> dict:
    return {
        "id": row.id, "project_id": row.project_id, "source_tree_id": row.source_tree_id,
        "name": row.name, "system": row.system, "recipe": row.recipe_json or {},
        "instrumentation": row.instrumentation_json or {}, "artifacts": row.artifacts_json or [],
        "base_image": row.base_image, "arch": row.arch, "network": row.network,
        "recipe_sha": row.recipe_sha,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def list_builds(session: Session, project: Project, *, source_tree_id: str | None = None) -> list[dict]:
    q = session.query(Build).filter(Build.project_id == project.id)
    if source_tree_id:
        q = q.filter(Build.source_tree_id == source_tree_id)
    return [build_to_dict(b) for b in q.order_by(Build.created_at.desc()).all()]


def list_build_specs(session: Session, project: Project, *, source_tree_id: str | None = None) -> list[dict]:
    q = session.query(BuildSpecRow).filter(BuildSpecRow.project_id == project.id,
                                           BuildSpecRow.archived.is_(False))
    if source_tree_id:
        q = q.filter(BuildSpecRow.source_tree_id == source_tree_id)
    return [spec_to_dict(r) for r in q.order_by(BuildSpecRow.created_at.asc()).all()]


# ── Bounded fetch defaults (design §3.5 — features.build_fetch) ─────────────────

def default_fetch_phases(system: str) -> list[BuildPhase]:
    """The default FETCH-phase commands for a build system (run with network ON to the
    allowlist, BEFORE the offline compile). These resolve + download declared deps into a
    vendor dir; the compile then runs --network none. Empty for systems without a fetch
    step (a plain Makefile)."""
    if system == "cargo":
        return [BuildPhase(("cargo", "fetch"))]
    if system == "go":
        return [BuildPhase(("go", "mod", "download"))]
    if system == "meson":
        return [BuildPhase(("meson", "subprojects", "download"))]
    return []


# ── OSS-Fuzz build.sh import (design §3.1/§7) ───────────────────────────────────

def import_oss_fuzz_build(session: Session, project: Project, tree: SourceTree, *,
                          build_sh: str, instrumentation: dict | None = None,
                          artifacts: list | None = None) -> BuildSpecRow:
    """Ingest an OSS-Fuzz `build.sh` into a recorded `build_spec` (stores the script in
    the tree + maps the OSS-Fuzz env contract to ours). Returns the persisted spec row.
    The tree must be editable (the script is written into it as role=script)."""
    from hexgraph.engine.build.oss_fuzz import import_oss_fuzz

    spec = import_oss_fuzz(session, project, tree, build_sh=build_sh,
                           instrumentation=instrumentation, artifacts=artifacts)
    return create_build_spec(session, project, spec)


# ── Rebuild from a source revision (design §6.2 — editable IDE) ─────────────────

def rebuild_from_revision(session: Session, project: Project, spec_row: BuildSpecRow,
                          revision_id: str, *, builder=None) -> Build:
    """Build a recorded recipe from a SPECIFIC editable-IDE revision. Reverts the file to
    that revision's content (append-only — the revert is itself a new revision, so nothing
    is lost), refreshes the tree content_hash, then runs the build recording
    `source_revision_id`. The revert uses the scoped source-edit gate (scratch trees always
    editable; other authored trees need features.source.edit) + features.build (the build).
    The build is reproducible from {recipe_sha + the reverted source content_hash}."""
    from hexgraph.db.models import SourceRevision
    from hexgraph.engine.build import revisions as R

    rev = session.get(SourceRevision, revision_id)
    if rev is None or rev.project_id != project.id:
        raise BuildError("revision not found in this project")
    tree = session.get(SourceTree, rev.source_tree_id)
    if tree is None or tree.id != spec_row.source_tree_id:
        raise BuildError("revision belongs to a different source tree than the build spec")
    R.revert_to_revision(session, project, tree, revision_id)
    # The just-created revision is the new latest; record THAT one as the build's source.
    latest = (session.query(SourceRevision)
              .filter(SourceRevision.source_tree_id == tree.id, SourceRevision.rel == rev.rel)
              .order_by(SourceRevision.seq.desc()).first())
    return run_build(session, project, spec_row, builder=builder,
                     source_revision_id=latest.id if latest else revision_id)
