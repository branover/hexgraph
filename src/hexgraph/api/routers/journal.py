"""The research JOURNAL REST surface (working-memory layer, design §9).

The journal is the freeform, markdown research notebook shared by the human and
the agent (`engine/journal.py`) — the interpreted-narrative store, distinct from
Observations (raw tool output) and findings (substantiated results). These
endpoints back the (later) JournalPanel: a per-project timeline + compose box, a
single-entry get/edit/delete, and a substring search for cross-session re-orient.

Authorship: the agent-only-own rule (an agent may not touch a human's entry) is
enforced on the MCP/agent path (`as_author="agent"`); HUMAN edits via this REST
surface may touch any entry — it's the researcher's own workbench — so these
handlers don't pass an `as_author` restriction. Loopback-only, same trust boundary
as every other router."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from hexgraph.db.models import Project
from hexgraph.db.session import session_scope
from hexgraph.engine import journal as J

router = APIRouter()

# Bound a list/search response even on a heavily-journaled project.
_MAX_LIMIT = 500


class JournalCreate(BaseModel):
    body: str
    # Human entries by default; the agent path forces "agent" at the MCP layer.
    author: str = "human"
    origin_task_id: str | None = None


class JournalUpdate(BaseModel):
    body: str


@router.get("/api/projects/{project_id}/journal")
def api_list_journal(
    project_id: str,
    author: str | None = Query(None, description="filter by author (human|agent)"),
    mentions_kind: str | None = Query(None, description="back-reference: mentioned object kind"),
    mentions_id: str | None = Query(None, description="back-reference: mentioned object id"),
    limit: int = Query(100, ge=1, le=_MAX_LIMIT),
):
    """A project's journal entries, newest first. Filter by `author`, or by a
    mentioned object (`mentions_kind` + `mentions_id`) for the back-reference query
    ("entries mentioning this hypothesis")."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        rows = J.list_journal_entries(
            s, project_id, author=author, mentions_kind=mentions_kind,
            mentions_id=mentions_id, limit=limit)
        return {"entries": rows}


@router.post("/api/projects/{project_id}/journal")
def api_create_journal(project_id: str, payload: JournalCreate):
    """Create a journal entry; mentions in the body are parsed into the join."""
    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            raise HTTPException(404, "project not found")
        try:
            entry = J.add_journal_entry(
                s, project, body=payload.body, author=payload.author,
                origin_task_id=payload.origin_task_id)
        except J.JournalError as exc:
            raise HTTPException(400, str(exc))
        return J.serialize_entry(s, entry)


@router.get("/api/journal/{entry_id}")
def api_get_journal(entry_id: str):
    """One journal entry in full, with its mentions resolved (danglers flagged)."""
    with session_scope() as s:
        out = J.get_journal_entry(s, entry_id)
        if out is None:
            raise HTTPException(404, "journal entry not found")
        return out


@router.patch("/api/journal/{entry_id}")
def api_update_journal(entry_id: str, payload: JournalUpdate):
    """Edit an entry's body (marks it edited, re-parses mentions). The human/REST
    path may edit any entry; the agent-only-own rule lives on the MCP path."""
    with session_scope() as s:
        try:
            entry = J.update_journal_entry(s, entry_id, body=payload.body)
        except J.JournalError as exc:
            # A missing entry reads as 404; a bad body as 400.
            raise HTTPException(404 if "not found" in str(exc) else 400, str(exc))
        return J.serialize_entry(s, entry)


@router.delete("/api/journal/{entry_id}")
def api_delete_journal(entry_id: str):
    """Delete an entry (and its mention rows). Human/REST path: any entry."""
    with session_scope() as s:
        try:
            J.delete_journal_entry(s, entry_id)
        except J.JournalError as exc:
            raise HTTPException(404, str(exc))
        return {"deleted": entry_id}


@router.get("/api/projects/{project_id}/journal/search")
def api_search_journal(
    project_id: str,
    q: str = Query("", description="substring over entry bodies"),
    limit: int = Query(100, ge=1, le=_MAX_LIMIT),
):
    """Substring search over a project's journal bodies, newest first — the
    cross-session memory verb."""
    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "project not found")
        rows = J.search_journal(s, project_id, q, limit=limit)
        return {"entries": rows}
