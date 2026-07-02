"""Builds: author a recorded recipe, preview it, run it (build-as-API). Gated by
features.build (the build policy gate). Vendored/offline only this phase.

Build-as-API: there is NO free-text command endpoint — the client authors/approves
a `BuildSpec` (a recorded recipe) and *requests* a build; HexGraph runs the recipe
in the sandbox via the Builder seam. A build of a source tree linked to a target
registers an instrumented derived target (the headline capability, §3.3)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from hexgraph.db.models import Build, BuildSpec as BuildSpecRow, Project, SourceTree
from hexgraph.db.session import session_scope
from hexgraph.engine.build import builds as B
from hexgraph.engine.build.build import BuildError, BuildSpec, normalize_build_phases
from hexgraph.policy import PolicyViolation, assert_allows_build

router = APIRouter()


class BuildSpecBody(BaseModel):
    source_tree_id: str
    system: str | None = None
    phases: list | None = None
    instrumentation: dict | None = None
    artifacts: list[str] | None = None
    env: dict | None = None
    arch: str | None = None
    name: str | None = None
    # Phase 7: "none" (vendored/offline, default) | "fetch" (bounded audited deps phase,
    # requires features.build_fetch). `fetch_phases` are the dep-resolution commands.
    network: str | None = None
    fetch_phases: list | None = None


class BuildCreate(BaseModel):
    # Either reference an existing recorded recipe, or inline a spec to record + run.
    build_spec_id: str | None = None
    spec: BuildSpecBody | None = None
    # Phase 7: rebuild from a specific editable-IDE source revision (rebuild-from-revision).
    source_revision_id: str | None = None


class OssFuzzImportBody(BaseModel):
    source_tree_id: str
    build_sh: str
    instrumentation: dict | None = None
    artifacts: list[str] | None = None


def _resolve_sysroot(s, project, tree, arch):
    """For a cross-build (arch != native), the parent firmware's extracted rootfs is the
    clang --sysroot (design §3.4) — REUSING poc._find_sysroot + filesystem.host_root.
    Best-effort: None ⇒ native fallback (degrade-to-qemu)."""
    from hexgraph.engine.build.build import CROSS_TRIPLES

    if not CROSS_TRIPLES.get((arch or "x86_64").lower()):
        return None
    origin = B._origin_target(s, project, tree)
    fw = None
    if origin is not None and origin.parent_id:
        from hexgraph.db.models import Target
        fw = s.get(Target, origin.parent_id)
    if fw is None or not (fw.metadata_json or {}).get("filesystem"):
        return None
    try:
        from pathlib import Path as _P
        from hexgraph.engine.targets.filesystem import host_root as _fs_root
        from hexgraph.engine.findings.poc import _find_sysroot
        root = _find_sysroot(_fs_root(project, fw))
        return str(root) if root and _P(str(root)).is_dir() else None
    except Exception:  # noqa: BLE001
        return None


def _spec_from_body(body: BuildSpecBody, tree: SourceTree, *, session=None, project=None) -> BuildSpec:
    detected = B.propose_build_spec(tree)
    arch = body.arch or "x86_64"
    network = body.network or "none"
    # Validate + normalize user-submitted phases at THIS ingest seam too (the UI Build
    # modal / REST callers), mirroring agent.mcp_tools.build_target — a malformed phase
    # raises a clear BuildError the callers turn into HTTP 400, instead of a dict-without-
    # argv silently recording an empty no-op phase (fake success) or a bare string crashing.
    norm_phases = normalize_build_phases(body.phases) if body.phases is not None else None
    norm_fetch = normalize_build_phases(body.fetch_phases) if body.fetch_phases is not None else None
    default_fetch = []
    if network == "fetch" and body.fetch_phases is None:
        default_fetch = [p.to_dict() for p in B.default_fetch_phases(body.system or detected["system"])]
    sysroot = _resolve_sysroot(session, project, tree, arch) if session is not None else None
    return BuildSpec.from_dict({
        "source_tree_id": tree.id,
        "system": body.system or detected["system"],
        "phases": ([p.to_dict() for p in norm_phases]
                   if norm_phases is not None else detected["phases"]),
        "fetch_phases": ([p.to_dict() for p in norm_fetch]
                         if norm_fetch is not None else default_fetch),
        "instrumentation": body.instrumentation or {},
        "artifacts": body.artifacts or [],
        "env": body.env or {},
        "arch": arch,
        "network": network,
        "sysroot": sysroot,
        "name": body.name or detected.get("name", "build"),
    })


@router.post("/api/projects/{project_id}/build/preview")
def api_build_preview(project_id: str, body: BuildSpecBody):
    """Return the RECORDED recipe (read-only preview) for a spec — phases, fetch phases,
    injected toolchain env (incl. cross --target/--sysroot), recipe_sha, reproducibility
    posture — without running anything. The Build modal calls this so instrumentation/
    arch/dependency-posture toggles regenerate the preview. No gate (it computes)."""
    from hexgraph.engine.build.build import instrumentation_env

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        tree = s.get(SourceTree, body.source_tree_id)
        if tree is None or tree.project_id != project_id:
            raise HTTPException(404, "source tree not found")
        try:
            spec = _spec_from_body(body, tree, session=s, project=p)
        except BuildError as exc:
            raise HTTPException(400, str(exc))
        d = spec.to_dict()
        d["recipe_sha"] = spec.recipe_sha()
        d["injected_env"] = instrumentation_env(spec.instrumentation, arch=spec.arch,
                                                sysroot=spec.sysroot)
        d["network"] = spec.network
        d["cross"] = bool(spec.sysroot)
        return d


@router.post("/api/projects/{project_id}/builds/import-oss-fuzz")
def api_import_oss_fuzz(project_id: str, body: OssFuzzImportBody):
    """Import an OSS-Fuzz `build.sh` into a recorded build_spec (the script is stored in
    the tree as role=script; the OSS-Fuzz env contract maps to ours). Returns the spec.
    The tree must be editable. No build is run (call POST /builds with the returned id)."""
    from hexgraph.engine.build.source import SourceError

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        tree = s.get(SourceTree, body.source_tree_id)
        if tree is None or tree.project_id != project_id:
            raise HTTPException(404, "source tree not found")
        try:
            row = B.import_oss_fuzz_build(s, p, tree, build_sh=body.build_sh,
                                          instrumentation=body.instrumentation,
                                          artifacts=body.artifacts)
        except (BuildError, SourceError) as exc:
            raise HTTPException(400, str(exc))
        return B.spec_to_dict(row)


@router.get("/api/projects/{project_id}/build-specs")
def api_list_build_specs(project_id: str, source_tree_id: str | None = None):
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        return {"build_specs": B.list_build_specs(s, p, source_tree_id=source_tree_id)}


@router.get("/api/projects/{project_id}/builds")
def api_list_builds(project_id: str, source_tree_id: str | None = None):
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        return {"builds": B.list_builds(s, p, source_tree_id=source_tree_id)}


@router.get("/api/builds/{build_id}")
def api_get_build(build_id: str):
    with session_scope() as s:
        b = s.get(Build, build_id)
        if b is None:
            raise HTTPException(404, "build not found")
        return B.build_to_dict(b)


@router.get("/api/builds/{build_id}/log")
def api_build_log(build_id: str):
    """The full build log (from CAS) — the recipe-iteration signal on a failed build."""
    with session_scope() as s:
        b = s.get(Build, build_id)
        if b is None:
            raise HTTPException(404, "build not found")
        from hexgraph.engine import cas

        p = s.get(Project, b.project_id)
        text = cas.get_text(p, b.log_cas) if b.log_cas else None
        return {"build_id": build_id, "log": text or ""}


@router.post("/api/projects/{project_id}/builds")
def api_create_build(project_id: str, body: BuildCreate):
    """Record a recipe (if inlined) + run it in the sandbox. Synchronous (builds are
    bounded by the recipe timeout). Gated by features.build — fails closed (403) when
    off."""
    try:
        assert_allows_build()
    except PolicyViolation as exc:
        raise HTTPException(403, str(exc))
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        if body.build_spec_id:
            spec_row = s.get(BuildSpecRow, body.build_spec_id)
            if spec_row is None or spec_row.project_id != project_id:
                raise HTTPException(404, "build spec not found")
        elif body.spec is not None:
            tree = s.get(SourceTree, body.spec.source_tree_id)
            if tree is None or tree.project_id != project_id:
                raise HTTPException(404, "source tree not found")
            try:
                spec = _spec_from_body(body.spec, tree, session=s, project=p)
                spec_row = B.create_build_spec(s, p, spec)
            except BuildError as exc:
                raise HTTPException(400, str(exc))
        else:
            raise HTTPException(400, "pass build_spec_id or spec")
        try:
            if body.source_revision_id:
                # Rebuild-from-revision (editable IDE): revert the file to the revision,
                # then build (records source_revision_id). Gated by features.source.edit.
                build = B.rebuild_from_revision(s, p, spec_row, body.source_revision_id)
            else:
                build = B.run_build(s, p, spec_row)
        except BuildError as exc:
            raise HTTPException(400, str(exc))
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        return B.build_to_dict(build)
