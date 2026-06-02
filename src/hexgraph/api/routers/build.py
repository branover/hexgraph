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
from hexgraph.engine import builds as B
from hexgraph.engine.build import BuildError, BuildSpec
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


class BuildCreate(BaseModel):
    # Either reference an existing recorded recipe, or inline a spec to record + run.
    build_spec_id: str | None = None
    spec: BuildSpecBody | None = None


def _spec_from_body(body: BuildSpecBody, tree: SourceTree) -> BuildSpec:
    detected = B.propose_build_spec(tree)
    return BuildSpec.from_dict({
        "source_tree_id": tree.id,
        "system": body.system or detected["system"],
        "phases": body.phases if body.phases is not None else detected["phases"],
        "instrumentation": body.instrumentation or {},
        "artifacts": body.artifacts or [],
        "env": body.env or {},
        "arch": body.arch or "x86_64",
        "name": body.name or detected.get("name", "build"),
    })


@router.post("/api/projects/{project_id}/build/preview")
def api_build_preview(project_id: str, body: BuildSpecBody):
    """Return the RECORDED recipe (read-only preview) for a spec — phases, injected
    toolchain env, recipe_sha — without running anything. The Build modal calls this
    so instrumentation toggles regenerate the preview. No gate (it computes, doesn't run)."""
    from hexgraph.engine.build import instrumentation_env

    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        tree = s.get(SourceTree, body.source_tree_id)
        if tree is None or tree.project_id != project_id:
            raise HTTPException(404, "source tree not found")
        try:
            spec = _spec_from_body(body, tree)
        except BuildError as exc:
            raise HTTPException(400, str(exc))
        d = spec.to_dict()
        d["recipe_sha"] = spec.recipe_sha()
        d["injected_env"] = instrumentation_env(spec.instrumentation)
        d["network"] = "none"  # vendored/offline only this phase
        return d


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
                spec = _spec_from_body(body.spec, tree)
                spec_row = B.create_build_spec(s, p, spec)
            except BuildError as exc:
                raise HTTPException(400, str(exc))
        else:
            raise HTTPException(400, "pass build_spec_id or spec")
        try:
            build = B.run_build(s, p, spec_row)
        except BuildError as exc:
            raise HTTPException(400, str(exc))
        except PolicyViolation as exc:
            raise HTTPException(403, str(exc))
        return B.build_to_dict(build)
