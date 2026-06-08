"""The research JOURNAL — the interpreted-narrative half of the working-memory
layer (design-working-memory.md §5).

A journal entry is freeform markdown attributed to a `human` or an `agent`,
scoped per project. It holds *story* — the idea you had, what you tried, what
worked or didn't, what you learned — the reasoning the graph and findings don't
capture. It is NOT the Observation store (raw tool output, never interpreted) and
NOT a finding (a substantiated result); the line between those stores is the whole
point of the taxonomy (`record_keeping.RECORD_KEEPING`).

This module is the store + the two disciplines the design locks down:

- **`@`-mentions** (`@[label](kind:id)`) are parsed out of the body on every write
  into `JournalMention` rows, so back-references ("entries mentioning hypothesis H")
  are queryable without scanning markdown. A mention is a lightweight reference, NOT
  a graph edge (design §12). Resolution happens at read time, through the merge
  keeper, so a mention survives `nodemerge` folding a duplicate and greys out (flags
  `dangling`) when its target is archived or gone.
- **The authorship rule** (the permission invariant, §5.2): an agent may add entries
  and edit/delete its OWN (`author="agent"`) entries, but may NEVER touch a human's.
  Enforced here at the agent seam (`update_journal_entry`/`delete_journal_entry` with
  `as_author="agent"`); the human-facing REST path passes `as_author=None` (no
  restriction — it's their workbench).
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import (
    Finding,
    JournalEntry,
    JournalMention,
    Node,
    NodeType,
    Project,
    Target,
    utcnow,
)

# Single sources of truth for the closed value-sets (imported by meta_get_schemas
# and the MCP catalog so the schema enums can never drift from the engine).
AUTHORS = ("human", "agent")
REF_KINDS = ("node", "finding", "target", "hypothesis")

# `@[label](kind:id)` — the mention syntax stored in the markdown body. The label
# may contain anything but a closing bracket; kind is one of REF_KINDS; id is the
# object's uuid (or any non-paren run, so a stale id still parses).
_MENTION_RE = re.compile(r"@\[(?P<label>[^\]]*)\]\((?P<kind>[a-z]+):(?P<id>[^)]+)\)")


class JournalError(ValueError):
    """A journal operation was rejected (bad author/ref kind, missing entry, or an
    authorship-rule violation)."""


# --- mention parsing ----------------------------------------------------------

def parse_mentions(body: str) -> list[tuple[str, str, str]]:
    """Extract `@[label](kind:id)` mentions from a markdown body.

    Returns a deduped list of `(ref_kind, ref_id, label)`, preserving first-seen
    order. Only known `REF_KINDS` are kept — an unknown kind is just prose, not a
    reference. The same `(kind, id)` mentioned twice yields one row (the first label
    wins) so the mention join stays one-per-target-per-entry."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str, str]] = []
    for m in _MENTION_RE.finditer(body or ""):
        kind, rid, label = m.group("kind"), m.group("id").strip(), m.group("label").strip()
        if kind not in REF_KINDS or not rid:
            continue
        key = (kind, rid)
        if key in seen:
            continue
        seen.add(key)
        out.append((kind, rid, label))
    return out


def _sync_mentions(session: Session, entry: JournalEntry) -> None:
    """Replace an entry's `JournalMention` rows with the mentions parsed from its
    current body. Called on create and on every body-changing update so the join
    never drifts from the markdown."""
    session.query(JournalMention).filter(JournalMention.entry_id == entry.id).delete(
        synchronize_session=False
    )
    for kind, rid, label in parse_mentions(entry.body or ""):
        session.add(JournalMention(entry_id=entry.id, ref_kind=kind, ref_id=rid,
                                   label=label or None))


# --- create / read ------------------------------------------------------------

def add_journal_entry(
    session: Session,
    project: Project,
    *,
    body: str,
    author: str,
    origin_task_id: str | None = None,
) -> JournalEntry:
    """Create a journal entry and populate its mention join from the body.

    `author` must be one of `AUTHORS`. `body` is markdown (the four prompts — idea /
    tried / worked / learned — are a convention, not enforced). `origin_task_id`
    records the agent task that produced the entry (None for a human entry)."""
    if author not in AUTHORS:
        raise JournalError(f"author must be one of {list(AUTHORS)}")
    body = (body or "").strip()
    if not body:
        raise JournalError("a journal entry needs a body")
    entry = JournalEntry(
        project_id=project.id, author=author, body=body, origin_task_id=origin_task_id,
    )
    session.add(entry)
    session.flush()
    _sync_mentions(session, entry)
    return entry


def _require_entry(session: Session, entry_id: str) -> JournalEntry:
    entry = session.get(JournalEntry, entry_id)
    if entry is None:
        raise JournalError(f"journal entry {entry_id} not found")
    return entry


def list_journal_entries(
    session: Session,
    project_id: str,
    *,
    author: str | None = None,
    mentions_kind: str | None = None,
    mentions_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """A project's journal entries, NEWEST FIRST, as serialized dicts.

    Filter by `author` (human/agent) and/or by a mentioned object
    (`mentions_kind` + `mentions_id` — the back-reference query that powers "entries
    mentioning hypothesis H"). A mention filter resolves the target through the merge
    keeper too, so an entry that mentioned a now-merged duplicate still matches the
    keeper's id."""
    q = session.query(JournalEntry).filter(JournalEntry.project_id == project_id)
    if author is not None:
        q = q.filter(JournalEntry.author == author)
    if mentions_kind is not None and mentions_id is not None:
        ids = _entry_ids_mentioning(session, project_id, mentions_kind, mentions_id)
        if not ids:
            return []
        q = q.filter(JournalEntry.id.in_(ids))
    rows = q.order_by(JournalEntry.created_at.desc(), JournalEntry.id.desc()).limit(limit).all()
    return serialize_entries(session, rows)


def get_journal_entry(session: Session, entry_id: str) -> dict[str, Any] | None:
    """One entry in full (with resolved mentions), or None if it doesn't exist."""
    entry = session.get(JournalEntry, entry_id)
    return serialize_entry(session, entry) if entry is not None else None


def search_journal(
    session: Session, project: Project | str, q: str, *, limit: int = 100,
) -> list[dict[str, Any]]:
    """Case-insensitive SUBSTRING search over entry bodies in a project, newest
    first — the cross-session memory verb ("what did I try on the CGI handler").
    Searches the interpreted narrative, NOT Observations or findings."""
    project_id = project.id if isinstance(project, Project) else project
    needle = (q or "").strip()
    query = session.query(JournalEntry).filter(JournalEntry.project_id == project_id)
    if needle:
        query = query.filter(JournalEntry.body.ilike(f"%{needle}%"))
    rows = query.order_by(JournalEntry.created_at.desc(), JournalEntry.id.desc()).limit(limit).all()
    return serialize_entries(session, rows)


# --- update / delete (authorship enforced at the agent seam) ------------------

def _check_authorship(entry: JournalEntry, as_author: str | None, verb: str) -> None:
    """Enforce the permission invariant (§5.2). `as_author=None` is the human/REST
    path (may touch anything). `as_author="agent"` is the agent/MCP path and may
    touch ONLY agent-authored entries — never a human's words."""
    if as_author is None:
        return
    if as_author == "agent" and entry.author != "agent":
        raise JournalError(
            f"an agent may not {verb} a human-authored journal entry "
            f"(entry {entry.id} is author={entry.author!r})"
        )


def update_journal_entry(
    session: Session,
    entry_id: str,
    *,
    body: str,
    as_author: str | None = None,
) -> JournalEntry:
    """Edit an entry's body, mark it `edited`, bump `updated_at`, and re-parse its
    mentions. Pass `as_author="agent"` on the agent/MCP path to enforce the
    authorship rule (refuses a human entry); `as_author=None` (the human/REST path)
    may edit anything."""
    entry = _require_entry(session, entry_id)
    _check_authorship(entry, as_author, "edit")
    body = (body or "").strip()
    if not body:
        raise JournalError("a journal entry needs a body")
    entry.body = body
    entry.edited = True
    entry.updated_at = utcnow()
    session.flush()
    _sync_mentions(session, entry)
    return entry


def delete_journal_entry(
    session: Session, entry_id: str, *, as_author: str | None = None,
) -> None:
    """Delete an entry and its mention rows. Pass `as_author="agent"` to enforce the
    authorship rule (refuses a human entry); `as_author=None` (human/REST) may delete
    anything."""
    entry = _require_entry(session, entry_id)
    _check_authorship(entry, as_author, "delete")
    session.query(JournalMention).filter(JournalMention.entry_id == entry.id).delete(
        synchronize_session=False
    )
    session.delete(entry)
    session.flush()


# --- mention resolution (through the merge keeper) ----------------------------

def _resolve_node(session: Session, project_id: str, node_id: str, want_hypothesis: bool):
    """Resolve a node/hypothesis ref to its live row, or None.

    `nodemerge` folds a duplicate INTO a keeper by rewriting edges and deleting the dup
    ROW (no forwarding record for non-edge refs), so a mention of a folded-away dup id
    simply misses here and is flagged dangling — while a mention of the surviving keeper
    resolves byte-stable (the link-stability the design wants). A `hypothesis:` ref must
    point at a hypothesis node; a plain `node:` ref accepts any node type (kind is a
    navigation hint, not a hard gate)."""
    node = session.get(Node, node_id)
    if node is None or node.project_id != project_id:
        return None
    if want_hypothesis and node.node_type != NodeType.hypothesis.value:
        return None
    return node


def _dangling(ref_kind: str, ref_id: str) -> dict[str, Any]:
    """The display dict for an unresolved ref — archived, missing, or cross-project."""
    return {"ref_kind": ref_kind, "ref_id": ref_id, "resolved_id": ref_id,
            "label": None, "dangling": True}


def _node_display(node: Node | None, ref_kind: str, ref_id: str,
                  project_id: str, want_hypothesis: bool) -> dict[str, Any]:
    """Display dict for an already-fetched (or None) node row, applying the SAME gates
    as `_resolve_node` — project scope + the hypothesis-type check + archived→dangling.
    Shared by the single-ref and batch paths so they resolve identically."""
    out = _dangling(ref_kind, ref_id)
    if node is None or node.project_id != project_id:
        return out
    if want_hypothesis and node.node_type != NodeType.hypothesis.value:
        return out
    out["resolved_id"] = node.id
    out["label"] = node.name
    out["dangling"] = bool(node.archived)
    return out


def _finding_display(f: Finding | None, ref_id: str, project_id: str) -> dict[str, Any]:
    """Display dict for an already-fetched (or None) finding row (project-scoped)."""
    out = _dangling("finding", ref_id)
    if f is not None and f.project_id == project_id:
        out["resolved_id"] = f.id
        out["label"] = f.title
        out["dangling"] = False
    return out


def _target_display(t: Target | None, ref_id: str, project_id: str) -> dict[str, Any]:
    """Display dict for an already-fetched (or None) target row. An archived target
    subtree is hidden from the graph → grey it."""
    out = _dangling("target", ref_id)
    if t is not None and t.project_id == project_id:
        out["resolved_id"] = t.id
        out["label"] = t.name
        out["dangling"] = bool(t.archived)
    return out


def resolve_mention(session: Session, project_id: str, ref_kind: str, ref_id: str) -> dict[str, Any]:
    """Resolve one `(ref_kind, ref_id)` to a display dict for rendering.

    Returns `{ref_kind, ref_id, resolved_id, label, dangling}`. `resolved_id` is the
    id the UI should select (the merge keeper's id when different); `dangling` is True
    when the object is archived, missing, or in another project — the future frontend
    greys those rather than crashing. The store keeps the raw `(kind, id)`; this
    resolution is read-time only (design §5.3 link-stability).

    Single-ref convenience (the back-reference filter `_entry_ids_mentioning` calls it);
    serializing MANY entries goes through `_resolve_mentions_batch`/`serialize_entries`,
    which batches the lookups instead of one point query per mention (the N+1 fix)."""
    if ref_kind in ("node", "hypothesis"):
        node = _resolve_node(session, project_id, ref_id,
                             want_hypothesis=(ref_kind == "hypothesis"))
        return _node_display(node, ref_kind, ref_id, project_id,
                             want_hypothesis=(ref_kind == "hypothesis"))
    if ref_kind == "finding":
        return _finding_display(session.get(Finding, ref_id), ref_id, project_id)
    if ref_kind == "target":
        return _target_display(session.get(Target, ref_id), ref_id, project_id)
    return _dangling(ref_kind, ref_id)


def _resolve_mentions_batch(
    session: Session, project_id: str, refs: list[tuple[str, str]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Resolve many `(ref_kind, ref_id)` refs at once, batching by referenced kind.

    Issues ONE `id IN (...)` query per kind present (node/hypothesis share the Node
    table → a single query) instead of a `session.get` per mention, then builds each
    display dict from the fetched rows via the same `_*_display` helpers the single-ref
    path uses. The result is identical to calling `resolve_mention` on each ref — same
    project-scope, hypothesis-type, and archived/missing→dangling rules, including a
    folded-away merge duplicate (whose ROW is gone) degrading to `dangling`. Keyed by the
    raw `(ref_kind, ref_id)`. Bounded at O(kinds) queries no matter how many mentions —
    the fix for the per-mention N+1 in the list/search path."""
    refs = list(dict.fromkeys(refs))  # dedup, preserve order
    node_ids = {rid for kind, rid in refs if kind in ("node", "hypothesis")}
    finding_ids = {rid for kind, rid in refs if kind == "finding"}
    target_ids = {rid for kind, rid in refs if kind == "target"}

    nodes = (
        {n.id: n for n in session.query(Node).filter(Node.id.in_(node_ids)).all()}
        if node_ids else {}
    )
    findings = (
        {f.id: f for f in session.query(Finding).filter(Finding.id.in_(finding_ids)).all()}
        if finding_ids else {}
    )
    targets = (
        {t.id: t for t in session.query(Target).filter(Target.id.in_(target_ids)).all()}
        if target_ids else {}
    )

    resolved: dict[tuple[str, str], dict[str, Any]] = {}
    for kind, rid in refs:
        if kind in ("node", "hypothesis"):
            resolved[(kind, rid)] = _node_display(
                nodes.get(rid), kind, rid, project_id,
                want_hypothesis=(kind == "hypothesis"))
        elif kind == "finding":
            resolved[(kind, rid)] = _finding_display(findings.get(rid), rid, project_id)
        elif kind == "target":
            resolved[(kind, rid)] = _target_display(targets.get(rid), rid, project_id)
        else:
            resolved[(kind, rid)] = _dangling(kind, rid)
    return resolved


def _entry_dict(entry: JournalEntry, mentions: list[dict[str, Any]]) -> dict[str, Any]:
    """Assemble the JSON-able entry dict from an entry row + its resolved mentions."""
    return {
        "id": entry.id,
        "project_id": entry.project_id,
        "author": entry.author,
        "body": entry.body,
        "origin_task_id": entry.origin_task_id,
        "edited": bool(entry.edited),
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
        "mentions": mentions,
    }


def serialize_entry(session: Session, entry: JournalEntry) -> dict[str, Any]:
    """One journal entry as a JSON-able dict, with every mention RESOLVED through the
    merge keeper (danglers flagged). The `mentions` list carries the stored raw ref
    plus the resolved id/label/dangling for the renderer.

    To serialize MANY entries (list/search) call `serialize_entries`, which batches the
    mention resolution; this single-entry path (get-by-id) just delegates to it."""
    return serialize_entries(session, [entry])[0]


def serialize_entries(session: Session, entries: list[JournalEntry]) -> list[dict[str, Any]]:
    """Serialize a batch of entries, resolving every mention with a BOUNDED number of
    queries rather than one point lookup per mention (the N+1 the list/search path hit).

    One query fetches all the entries' mention rows; `_resolve_mentions_batch` then
    resolves the distinct refs in one query per kind. The per-entry output is identical
    to the old per-mention `serialize_entry` (same `mentions` shape and ordering, same
    dangling / merge-fold behavior). A ref is scoped to ITS entry's project, so the batch
    runs per project (one project in the common single-project list/search case)."""
    if not entries:
        return []
    by_id = {e.id: e for e in entries}
    mention_rows = (
        session.query(JournalMention)
        .filter(JournalMention.entry_id.in_(by_id.keys()))
        .all()
    )

    # Group the distinct refs by the project of their owning entry, then resolve each
    # project's refs in one query per kind.
    per_project_refs: dict[str, list[tuple[str, str]]] = {}
    for mr in mention_rows:
        pid = by_id[mr.entry_id].project_id
        per_project_refs.setdefault(pid, []).append((mr.ref_kind, mr.ref_id))
    resolved_by_project = {
        pid: _resolve_mentions_batch(session, pid, refs)
        for pid, refs in per_project_refs.items()
    }

    grouped: dict[str, list[dict[str, Any]]] = {eid: [] for eid in by_id}
    for mr in mention_rows:
        pid = by_id[mr.entry_id].project_id
        resolved = dict(resolved_by_project[pid][(mr.ref_kind, mr.ref_id)])
        resolved["stored_label"] = mr.label
        grouped[mr.entry_id].append(resolved)

    return [_entry_dict(by_id[e.id], grouped[e.id]) for e in entries]


# --- Layer 1: the task-completion seam (auto-journaling) ----------------------

def _draft_session_log(
    *,
    task_type: str,
    target_name: str,
    transcript: list[dict[str, Any]] | None,
    finding_titles: list[str],
    summary: str | None,
) -> str:
    """Draft a deterministic markdown session-log body from a task's tool-call trace +
    its findings + the model's final summary (design §6, Layer 1).

    Deterministic by construction so journaling never depends on the model remembering
    to call a tool, and so the mock/offline path yields a stable entry (just test / just
    demo stay green + zero-token). Skimmable: a one-line header, the tools used, the
    findings produced, and the model's narrative when it gave one."""
    lines = [f"**Session log — {task_type} on {target_name}.**"]

    tools_used: list[str] = []
    seen: set[str] = set()
    for step in transcript or []:
        name = step.get("tool")
        if name and name not in seen:
            seen.add(name)
            tools_used.append(name)
    n_calls = len(transcript or [])
    if tools_used:
        lines.append(f"*Tried:* {n_calls} tool call(s) — {', '.join(tools_used)}.")
    else:
        lines.append("*Tried:* no tool calls (the backend answered directly).")

    if finding_titles:
        shown = "; ".join(finding_titles[:8])
        more = f" (+{len(finding_titles) - 8} more)" if len(finding_titles) > 8 else ""
        lines.append(f"*Worked:* recorded {len(finding_titles)} finding(s) — {shown}{more}.")
    else:
        lines.append("*Worked:* no findings recorded this run.")

    summary = (summary or "").strip()
    if summary:
        lines.append(f"*Learned:* {summary}")

    return "\n\n".join(lines)


def auto_log_task(
    session: Session,
    project: Project,
    *,
    task_id: str | None,
    task_type: str,
    target_name: str,
    transcript: list[dict[str, Any]] | None,
    finding_titles: list[str],
    summary: str | None = None,
) -> JournalEntry | None:
    """Auto-create the closing agent journal entry for a completed LLM/agent task —
    the Layer-1 discipline seam (design §6). Best-effort: returns the entry, or None
    if it couldn't be written (journaling must never break task execution). The body
    is the deterministic draft above; `origin_task_id` ties it to the task so the
    staleness counter and the "what has the agent been doing" story work."""
    try:
        body = _draft_session_log(
            task_type=task_type, target_name=target_name, transcript=transcript,
            finding_titles=finding_titles, summary=summary,
        )
        return add_journal_entry(session, project, body=body, author="agent",
                                 origin_task_id=task_id)
    except Exception:  # noqa: BLE001 — auto-journaling is best-effort, never load-bearing
        return None


# --- staleness (Layer-2 nudge / Layer-3 surfacing) ----------------------------

def last_agent_entry(session: Session, project_id: str) -> JournalEntry | None:
    """The most recent AGENT-authored entry in a project, or None — the anchor the
    Layer-2 context nudge and the Layer-3 staleness surface both read."""
    return (
        session.query(JournalEntry)
        .filter(JournalEntry.project_id == project_id, JournalEntry.author == "agent")
        .order_by(JournalEntry.created_at.desc(), JournalEntry.id.desc())
        .first()
    )


def staleness_nudge(session: Session, project_id: str) -> str | None:
    """The Layer-2 context nudge (design §6): a concise reminder of how stale the
    agent's journal is, injected into a target's task context so the agent records as
    it goes rather than only at the end. Returns a one-line string, or None when the
    journal is fresh (nothing useful to say).

    The staleness signal is the number of TASKS the project has run since the last
    agent journal entry — a DETERMINISTIC count of DB state, NOT wall-clock minutes.
    That's deliberate: the context bundle is content-hashed (its `bundle_sha` is the
    cassette/replay key), so a minutes-since value would make the bundle non-
    reproducible and break replay; a task count is stable for the same DB state and
    still answers "you've done work since you last wrote anything down." Feature-
    tolerant — if the journal table isn't present yet (a not-yet-migrated DB) it
    returns None rather than raising."""
    from hexgraph.db.models import Task

    try:
        last = last_agent_entry(session, project_id)
        if last is None:
            tasks_since = session.query(Task).filter(Task.project_id == project_id).count()
        else:
            tasks_since = (
                session.query(Task)
                .filter(Task.project_id == project_id, Task.created_at > last.created_at)
                .count()
            )
    except Exception:  # noqa: BLE001 — the nudge is advisory, never load-bearing
        return None
    if last is None:
        return ("No agent journal entry yet for this project. As you work, keep a running "
                "journal (journal_add) of what you tried and learned — write at each pivot "
                "or dead end, not just at the end. Invoke the record-keeping guidance.")
    if tasks_since >= 1:
        return (f"{tasks_since} task(s) have run since your last journal entry. Add a journal_add "
                f"line for any new lead, pivot, or dead end since — record as you go, not only at "
                f"task close. Invoke the record-keeping guidance.")
    return None


# --- internal helpers ---------------------------------------------------------

def _entry_ids_mentioning(session: Session, project_id: str, ref_kind: str, ref_id: str) -> set[str]:
    """Ids of entries in a project that mention `(ref_kind, ref_id)`, resolving the
    ref through the merge keeper so a mention of a now-folded duplicate still matches
    the keeper. Used by the back-reference filter."""
    resolved = resolve_mention(session, project_id, ref_kind, ref_id)
    candidates = {ref_id, resolved.get("resolved_id")}
    candidates.discard(None)
    rows = (
        session.query(JournalMention.entry_id)
        .join(JournalEntry, JournalEntry.id == JournalMention.entry_id)
        .filter(JournalEntry.project_id == project_id,
                JournalMention.ref_kind == ref_kind,
                JournalMention.ref_id.in_(candidates))
        .all()
    )
    return {r[0] for r in rows}
