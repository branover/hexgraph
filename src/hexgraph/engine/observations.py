"""The Observation store (Phase O, design §5.2 / §5.6).

Every deterministic tool call writes a durable **Observation**: the call (tool +
normalized args), a short summary, and the FULL payload in CAS (`engine/cas.py`),
scoped to the exact analyzed bytes by `content_hash`. This is the home for results
that aren't promoted into the graph yet — what both agent and user mine to decide
what belongs there — and it gives "analyze once, reuse forever" for free: a repeat
call with the same `(tool, args, content_hash, result_kind)` returns the existing
row flagged `cached` instead of re-running.

Observations are NOT graph nodes; recording one creates ZERO nodes/edges. The link
to the graph is bidirectional by reference only: an enriched node/edge/finding
carries `attrs.provenance = [observation_id, …]` (`add_provenance`) and the
Observation carries `node_refs` back (`add_node_ref`).
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

from sqlalchemy import String, cast, or_
from sqlalchemy.orm import Session

from hexgraph.db.models import Observation, Project, Target
from hexgraph.engine import cas


def _normalize_args(args: dict[str, Any] | None) -> dict[str, Any]:
    """Canonical form of the call args so dedup is order-insensitive. Drops None
    values so an omitted optional arg dedups with an explicit None."""
    return {k: args[k] for k in sorted(args) if args[k] is not None} if args else {}


def _args_key(args: dict[str, Any] | None) -> str:
    return json.dumps(_normalize_args(args), sort_keys=True, default=str)


def _find_fresh(
    session: Session, *, project_id: str, target_id: str, tool: str,
    args: dict[str, Any] | None, content_hash: str | None, result_kind: str,
) -> Observation | None:
    """An existing OK Observation for the identical call against the identical bytes.
    The dedup key is (tool, normalized args, content_hash, result_kind) — the same
    bytes + the same call must yield the same answer (design §5.2)."""
    key = _args_key(args)
    rows = (
        session.query(Observation)
        .filter(
            Observation.project_id == project_id,
            Observation.target_id == target_id,
            Observation.tool == tool,
            Observation.result_kind == result_kind,
            Observation.content_hash == content_hash,
            Observation.status == "ok",
        )
        .all()
    )
    for r in rows:
        if _args_key(r.args_json) == key:
            return r
    return None


def record_observation(
    session: Session,
    *,
    project_id: str,
    target_id: str,
    source: str,
    tool: str,
    args: dict[str, Any] | None,
    result_kind: str,
    payload: Any,
    summary: str,
    status: str = "ok",
    content_hash: str | None = None,
    node_refs: list[Any] | None = None,
    durable: bool = True,
) -> tuple[Observation, bool]:
    """Record one tool call, or reuse a fresh identical one.

    Returns `(observation, cached)`. When an OK Observation already exists for the
    same `(tool, normalized args, content_hash, result_kind)`, returns it with
    `cached=True` and stores nothing new ("analyze once, reuse forever", §5.2).
    Otherwise stores the full `payload` in CAS, sets `result_cas`/`size`, writes the
    row, and returns `cached=False`. Creates NO graph nodes/edges (curation gate).

    **Durability (the survive-a-late-failure contract).** An Observation is RAW,
    reusable tool output — a decompilation/strings/xref/taint/yara result that already
    succeeded. It must survive a later failure of the *task* that produced it (a DB lock
    at the task's final commit, a sandbox error in a subsequent step, …): "analyze once,
    reuse forever" is pointless if a multi-minute decompile is rolled back because a step
    that ran afterwards failed. The task runner (`engine.worker.run_task_sync`) holds ONE
    long-lived `session_scope` across the whole task — unpack, decompile, the agent loop,
    the grounded taint pass — and `session_scope` rolls the WHOLE transaction back on any
    exception, so without this a lock (or any failure) at the very end discards every
    Observation the task already produced.

    So with `durable=True` (the default) this **commits the caller's `session` once the
    Observation row + its always-welcome enrichment are written**, checkpointing all the
    reusable analysis accumulated so far — the Observation substrate AND the curated-graph
    enrichment (both are derived from the real bytes and stand on their own) — so a later
    failure can no longer wipe them. The checkpoint is a plain `session.commit()` (see
    `_checkpoint` for why it is deliberately NOT wrapped in the commit-level write-retry);
    `busy_timeout` (db.session pragmas) is the transient-lock resilience that IS safe here —
    it makes the commit's flush WAIT for the lock rather than fail immediately.

    Why commit the CALLER's session rather than a separate one: SQLite is single-writer.
    The task session holds the write lock continuously once it has flushed any pending
    write, so a second session committing an Observation row concurrently would just hit
    "database is locked" until that lock frees — which is task-duration away. Committing the
    caller's own session is the only checkpoint that actually releases + reacquires the
    lock cleanly mid-task.

    **The synthesized FINDINGS still roll back with a failed task** (the deliberate
    semantics): a task persists its synthesized/LLM findings in a final phase, AFTER its
    investigation has recorded all its Observations, so a failure there (or at the task's
    final commit) rolls back only the post-checkpoint work — the findings — while every
    earlier-checkpointed Observation survives. (The grounded static-core findings a task
    persists UP FRONT, before the agent loop, are derived from the real bytes and are by
    design kept across a later synthesis failure — see `engine.llm_tasks`; checkpointing
    them here matches that intent.)

    `durable=False` keeps the legacy behavior — the row is written on `session` and only
    becomes durable when `session` commits — for callers that genuinely want the
    Observation to share the caller's transaction lifetime (e.g. a unit-of-work test, or a
    flow whose observation should roll back with it)."""
    # Only OK results dedup — re-running after an error must be allowed to retry. The
    # lookup runs on the caller's session so it also sees this task's own just-flushed
    # rows; the durable checkpoint below is what makes a fresh row survive a later failure.
    if status == "ok":
        existing = _find_fresh(
            session, project_id=project_id, target_id=target_id, tool=tool,
            args=args, content_hash=content_hash, result_kind=result_kind,
        )
        if existing is not None:
            return existing, True

    project = session.get(Project, project_id)
    blob = json.dumps(payload, sort_keys=True, default=str)
    # CAS is filesystem-backed (transaction-independent): the payload is durable the
    # moment it's written, regardless of which session commits the row.
    result_cas = cas.put(project, blob) if project is not None else None
    size = len(blob.encode("utf-8"))

    obs = Observation(
        project_id=project_id, target_id=target_id, source=source or "",
        tool=tool, args_json=_normalize_args(args), content_hash=content_hash,
        result_kind=result_kind, result_cas=result_cas, summary=summary or "",
        status=status, size=size, node_refs=list(node_refs or []),
    )
    session.add(obs)
    session.flush()

    # Extract-at-write (design §5.5): distill the always-welcome facts from this
    # payload into the enrichment index, keyed by canonical node identity, and enrich
    # any node/edge that already exists. A node added later pulls the rest at create.
    # Only OK results carry trustworthy facts; extraction never breaks the call. This
    # runs BEFORE the durable checkpoint so the enrichment (also reusable analysis)
    # is checkpointed alongside the Observation row.
    if status == "ok":
        from hexgraph.engine.re import enrichment

        enrichment.extract_and_index(
            session, project_id=project_id, target_id=target_id,
            content_hash=content_hash, result_kind=result_kind, payload=payload,
            source_observation_id=obs.id,
        )

    if durable:
        _checkpoint(session)
    return obs, False


def _checkpoint(session: Session) -> None:
    """Commit the caller's session so the reusable analysis written so far (this
    Observation + its enrichment, and anything else pending on the session) becomes
    durable and can no longer be wiped by a later failure of the long-lived task
    transaction — the durability contract in `record_observation`.

    A plain `session.commit()` ON PURPOSE — NOT wrapped in the write-retry. Retrying a
    commit/flush on THIS session would be a silent data-loss trap: once `commit()` (or its
    final autoflush) fails on a lock, SQLAlchemy rolls the transaction back and EXPUNGES
    the pending objects, so a re-commit would commit an empty transaction and lose the
    Observation while reporting success (the same reason `session_scope` documents that a
    commit lock can't be retried in place — the unit must be rebuilt from scratch, which a
    bare re-commit can't do). The transient-lock resilience that IS safe lives one layer
    down: `busy_timeout` (db.session pragmas) makes the commit's flush WAIT for the
    lock rather than fail immediately, which absorbs ordinary cross-process contention (a
    web-app task vs an MCP server). If the timeout still elapses the lock error propagates
    and the task fails as it would today — but every Observation an EARLIER checkpoint
    already committed is safe, which is the whole improvement over the old single
    end-of-task commit."""
    session.commit()


def _row_dict(obs: Observation) -> dict[str, Any]:
    return {
        "id": obs.id, "project_id": obs.project_id, "target_id": obs.target_id,
        "created_at": obs.created_at.isoformat() if obs.created_at else None,
        "source": obs.source, "tool": obs.tool, "args": obs.args_json or {},
        "content_hash": obs.content_hash, "result_kind": obs.result_kind,
        "summary": obs.summary, "status": obs.status, "size": obs.size,
        "node_refs": obs.node_refs or [],
    }


def list_observations(
    session: Session, target_id: str, *, tool: str | None = None,
    kind: str | None = None, since: datetime | None = None, limit: int = 100,
) -> list[dict[str, Any]]:
    """Prior Observations on a target, newest first (the discoverability read verb).
    Returns row metadata only — call `get_observation(id)` for the full CAS payload."""
    q = session.query(Observation).filter(Observation.target_id == target_id)
    if tool:
        q = q.filter(Observation.tool == tool)
    if kind:
        q = q.filter(Observation.result_kind == kind)
    if since is not None:
        q = q.filter(Observation.created_at >= since)
    rows = q.order_by(Observation.created_at.desc()).limit(limit).all()
    return [_row_dict(r) for r in rows]


def list_observations_for_node(
    session: Session, *, node_id: str, project_id: str,
    target_id: str | None = None, limit: int = 200,
) -> list[dict[str, Any]]:
    """Every Observation whose `node_refs` includes this node — the node's FULL result-set
    (decompile/disasm/xrefs/recover_constant/…), newest first, row metadata only. Scoped to
    the node's target when it has one (the common case); project-wide for cross-target nodes
    (e.g. a shared socket, `target_id=None`). The reverse of the node's `attrs.provenance`,
    and a superset of it. Call `get_observation(id)` for the full CAS payload."""
    q = session.query(Observation)
    q = q.filter(Observation.target_id == target_id) if target_id else q.filter(Observation.project_id == project_id)
    # Narrow in SQL before pulling rows: a node id is a UUID, so a substring match on the
    # JSON `node_refs` text cannot false-positive on another id — the Python check below is
    # the exact confirm. This keeps the fetch bounded even on a busy target/project.
    q = q.filter(cast(Observation.node_refs, String).contains(node_id))
    rows = q.order_by(Observation.created_at.desc()).limit(limit).all()
    return [_row_dict(r) for r in rows if node_id in (r.node_refs or [])]


def get_observation(session: Session, obs_id: str) -> dict[str, Any] | None:
    """One Observation in full, with its payload loaded back from CAS."""
    obs = session.get(Observation, obs_id)
    if obs is None:
        return None
    out = _row_dict(obs)
    payload: Any = None
    if obs.result_cas:
        project = session.get(Project, obs.project_id)
        raw = cas.get_text(project, obs.result_cas) if project is not None else None
        if raw is not None:
            try:
                payload = json.loads(raw)
            except (ValueError, TypeError):
                payload = raw
    out["payload"] = payload
    return out


def search_observations(
    session: Session, *, project_id: str | None = None, target_id: str | None = None,
    query: str, limit: int = 100,
) -> list[dict[str, Any]]:
    """Substring search over tool / summary / result_kind (case-insensitive)."""
    q = session.query(Observation)
    if project_id:
        q = q.filter(Observation.project_id == project_id)
    if target_id:
        q = q.filter(Observation.target_id == target_id)
    needle = (query or "").strip()
    if needle:
        like = f"%{needle}%"
        q = q.filter(
            or_(
                Observation.tool.ilike(like),
                Observation.summary.ilike(like),
                Observation.result_kind.ilike(like),
            )
        )
    rows = q.order_by(Observation.created_at.desc()).limit(limit).all()
    return [_row_dict(r) for r in rows]


def search_decompiled(
    session: Session, target_id: str, *, query: str, limit: int = 50,
) -> list[dict[str, Any]]:
    """Substring search ACROSS recorded decompilation BODIES (pseudocode) on a target —
    which decompiled function(s) contain a string/identifier — by mining the Observation
    store (no re-decompile). Case-insensitive; one hit per function (newest decompilation
    wins). Returns [{observation_id, function, snippet}]."""
    needle = (query or "").strip()
    if not needle:
        return []
    rows = (
        session.query(Observation)
        .filter(Observation.target_id == target_id,
                Observation.result_kind == "decompilation",
                Observation.status == "ok")
        .order_by(Observation.created_at.desc())
        .all()
    )
    if not rows:
        return []
    project = session.get(Project, rows[0].project_id)
    # Case-insensitive search ON THE ORIGINAL body so the match offsets index the original
    # string (lowercasing first can change length for some Unicode chars and shift the
    # snippet off the match). Matching + snippet are both derived from re.search's indices.
    pat = re.compile(re.escape(needle), re.IGNORECASE)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for r in rows:
        if not r.result_cas or project is None:
            continue
        raw = cas.get_text(project, r.result_cas)
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            continue
        focus = payload.get("focus") if isinstance(payload, dict) else None
        if not isinstance(focus, dict):
            continue
        name = focus.get("name") or "?"
        body = focus.get("pseudocode") or ""
        m = pat.search(body)
        if m is None or name in seen:
            continue
        seen.add(name)
        start = max(0, m.start() - 60)
        snippet = body[start:m.end() + 60].replace("\n", " ").strip()
        out.append({"observation_id": r.id, "function": name, "snippet": snippet})
        if len(out) >= limit:
            break
    return out


def observation_index(session: Session, target_id: str) -> dict[str, Any]:
    """A compact roll-up of prior analysis on a target for the context bundle
    (design §5.6.1): per-`result_kind` counts + a handful of recent ids, so an agent
    learns what already exists without guessing. Returns {} when there's nothing."""
    rows = (
        session.query(Observation)
        .filter(Observation.target_id == target_id, Observation.status == "ok")
        .order_by(Observation.created_at.desc())
        .all()
    )
    if not rows:
        return {}
    counts: dict[str, int] = {}
    for r in rows:
        counts[r.result_kind] = counts.get(r.result_kind, 0) + 1
    return {"total": len(rows), "by_kind": counts, "recent_ids": [r.id for r in rows[:10]]}


# --- provenance helpers (used by later PRs; provided + unit-tested here) -------

def add_provenance(attrs: dict[str, Any], observation_id: str) -> dict[str, Any]:
    """Append `observation_id` to `attrs["provenance"]` (a deduped list), so a node/
    edge/finding records WHICH Observations produced or enriched it (design §5.2).
    Mutates and returns `attrs`."""
    prov = list(attrs.get("provenance") or [])
    if observation_id not in prov:
        prov.append(observation_id)
    attrs["provenance"] = prov
    return attrs


def add_node_ref(obs: Observation, ref: Any) -> Observation:
    """Append a back-reference (the function/struct/address/node id the call touched)
    to an Observation's `node_refs` (deduped), the reverse of `add_provenance`."""
    refs = list(obs.node_refs or [])
    if ref not in refs:
        refs.append(ref)
    obs.node_refs = refs
    return obs


def content_hash_for(target: Target) -> str | None:
    """The target's analyzed-bytes hash, used to scope/invalidate Observations to the
    exact binary. Prefers the recon-recorded sha256 in metadata, else the column."""
    meta = target.metadata_json or {}
    return meta.get("sha256") or getattr(target, "content_hash", None)
