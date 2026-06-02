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
from hexgraph.engine.build import (
    BUILD_SYSTEMS, BuildError, BuildPhase, BuildSpec, BuildUnavailable, Instrumentation,
    get_builder,
)
from hexgraph.engine.edges import add_edge
from hexgraph.engine.source import host_root


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
    from hexgraph.engine.build import assert_artifacts_contained, assert_env_nonsecret

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
              builder=None, register_derived: bool = True) -> Build:
    """Execute a recorded `build_spec` in the sandbox via the Builder seam, ingest
    artifacts + log into CAS, persist the `build` ledger row, and (the headline
    capability, §3.3) register the instrumented rebuild as a DERIVED target wired
    `instrumented_build_of`→ the original target. Gated by assert_allows_build()
    (inside the Builder). Returns the build row."""
    spec = spec_from_row(spec_row)
    tree = session.get(SourceTree, spec.source_tree_id)
    if tree is None or tree.project_id != project.id:
        raise BuildError("source tree not found in this project")

    build = Build(
        project_id=project.id, build_spec_id=spec_row.id, source_tree_id=tree.id,
        status="building", recipe_sha=spec_row.recipe_sha,
        instrumentation_json=spec.instrumentation.to_dict(),
    )
    session.add(build)
    session.flush()

    source_root = str(host_root(project, tree))
    builder = builder or get_builder()
    try:
        result = builder.build(spec, source_root=source_root, content_hash=tree.content_hash)
    except BuildUnavailable as exc:
        build.status = "failed"
        build.error = str(exc)
        session.flush()
        return build
    except BuildError as exc:
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
            # the target's own objects with SanCov+ASan (coverage-guided).
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
    derived.metadata_json = meta
    session.flush()

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
