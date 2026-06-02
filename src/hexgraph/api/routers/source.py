"""Source trees: list/import, browse the manifest, read a file (IDE viewer),
backfill transient harnesses → managed source_files. Read-only viewing in Phase 1
(no build/exec/edit). Mirrors the firmware unpacked-filesystem endpoints in
`targets.py`."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from hexgraph.db.models import Project, SourceTree, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import source as src
from hexgraph.engine.edges import add_edge
from hexgraph.db.models import EdgeType

router = APIRouter()


class SourceTreeCreate(BaseModel):
    name: str
    origin: str = "scratch"
    target_id: str | None = None  # optional: link target --built_from--> this tree
    editable: bool | None = None


class SourceFileWrite(BaseModel):
    rel: str
    content: str
    role: str = "code"


class FindingSourceLink(BaseModel):
    finding_id: str
    tree_id: str
    rel: str
    line: int | None = None
    col: int | None = None


@router.get("/api/projects/{project_id}/source-trees")
def api_list_source_trees(project_id: str):
    """All managed source trees in a project (id/name/origin/file count + linked targets)."""
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        return {"source_trees": src.list_source_trees(s, p)}


@router.post("/api/projects/{project_id}/source-trees")
def api_create_source_tree(project_id: str, body: SourceTreeCreate):
    """Create an empty managed source tree (files added via the write endpoint).
    Optionally link a target to it with a `built_from` edge."""
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        try:
            tree = src.create_source_tree(s, p, name=body.name, origin=body.origin,
                                          editable=body.editable)
        except src.SourceError as exc:
            raise HTTPException(400, str(exc))
        if body.target_id:
            t = s.get(Target, body.target_id)
            if t is None or t.project_id != project_id:
                raise HTTPException(404, "target not found")
            add_edge(s, project_id=project_id, src=("target", body.target_id),
                     dst=("source_tree", tree.id), type=EdgeType.built_from,
                     origin="human", confidence=1.0, created_by_tool="link-source")
        return {"id": tree.id, "name": tree.name, "origin": tree.origin}


@router.get("/api/source-trees/{tree_id}/files")
def api_source_tree_files(tree_id: str):
    """The tree's file listing for the IDE explorer (rel/size/role + finding/harness flags)."""
    with session_scope() as s:
        tree = s.get(SourceTree, tree_id)
        if tree is None:
            raise HTTPException(404, "source tree not found")
        return src.list_source_files(s, s.get(Project, tree.project_id), tree)


@router.get("/api/source-trees/{tree_id}/file")
def api_source_tree_file(tree_id: str, rel: str):
    """Read one source file for the in-UI viewer (text or hex, bounded, traversal-safe)."""
    with session_scope() as s:
        tree = s.get(SourceTree, tree_id)
        if tree is None:
            raise HTTPException(404, "source tree not found")
        try:
            return src.read_source_file(s.get(Project, tree.project_id), tree, rel)
        except src.SourceError as exc:
            raise HTTPException(400, str(exc))


@router.post("/api/source-trees/{tree_id}/files")
def api_write_source_file(tree_id: str, body: SourceFileWrite):
    """Write a file into an editable (scratch) source tree (path-traversal safe)."""
    with session_scope() as s:
        tree = s.get(SourceTree, tree_id)
        if tree is None:
            raise HTTPException(404, "source tree not found")
        try:
            return src.write_source_file(s, s.get(Project, tree.project_id), tree,
                                         body.rel, body.content, role=body.role)
        except src.SourceError as exc:
            raise HTTPException(400, str(exc))


@router.post("/api/projects/{project_id}/findings/link-source")
def api_link_finding_to_source(project_id: str, body: FindingSourceLink):
    """Wire a finding → its source location (located_in edge + evidence.extra.source_ref).
    The jump-from-finding-to-source link."""
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        tree = s.get(SourceTree, body.tree_id)
        if tree is None or tree.project_id != project_id:
            raise HTTPException(404, "source tree not found")
        try:
            node = src.link_finding_to_source(s, p, finding_id=body.finding_id, tree=tree,
                                              rel=body.rel, line=body.line, col=body.col)
        except src.SourceError as exc:
            raise HTTPException(400, str(exc))
        return {"node_id": node.id, "tree_id": tree.id, "rel": body.rel}


@router.post("/api/projects/{project_id}/backfill-harnesses")
def api_backfill_harnesses(project_id: str):
    """Promote every transient harness_generation snippet to a managed source_file +
    harness node. Idempotent. Old findings still render either way (back-compat read)."""
    with session_scope() as s:
        p = s.get(Project, project_id)
        if p is None:
            raise HTTPException(404, "project not found")
        from hexgraph.engine.harness_promote import backfill_harnesses

        return backfill_harnesses(s, p)
