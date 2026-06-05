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

from sqlalchemy import or_
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
) -> tuple[Observation, bool]:
    """Record one tool call, or reuse a fresh identical one.

    Returns `(observation, cached)`. When an OK Observation already exists for the
    same `(tool, normalized args, content_hash, result_kind)`, returns it with
    `cached=True` and stores nothing new ("analyze once, reuse forever", §5.2).
    Otherwise stores the full `payload` in CAS, sets `result_cas`/`size`, writes the
    row, and returns `cached=False`. Creates NO graph nodes/edges (curation gate)."""
    # Only OK results dedup — re-running after an error must be allowed to retry.
    if status == "ok":
        existing = _find_fresh(
            session, project_id=project_id, target_id=target_id, tool=tool,
            args=args, content_hash=content_hash, result_kind=result_kind,
        )
        if existing is not None:
            return existing, True

    project = session.get(Project, project_id)
    blob = json.dumps(payload, sort_keys=True, default=str)
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
    # Only OK results carry trustworthy facts; extraction never breaks the call.
    if status == "ok":
        from hexgraph.engine import enrichment

        enrichment.extract_and_index(
            session, project_id=project_id, target_id=target_id,
            content_hash=content_hash, result_kind=result_kind, payload=payload,
            source_observation_id=obs.id,
        )
    return obs, False


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
