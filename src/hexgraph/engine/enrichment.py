"""The always-welcome auto-enrichment machinery (Phase O, design §5.4 / §5.5).

Some tool results are so unambiguous that the researcher is *always* glad they were
applied: a function's recovered address/prototype, the `is_sink` tag on a dangerous
import, the `call_sites` that accumulate on an existing `calls` edge, a struct's
recovered layout. These run automatically — no LLM, no user in the loop — but under
two hard limits: they touch **only objects that already exist** (never mint a node),
and they carry **only whitelisted facts** (never severity, exploitability, a verdict,
a summary, a speculative type — those need judgment).

This module is the *machinery* (the registry + the index + the join). It is wired
to the two lifecycle events by thin hooks:

- **Extract-at-write** — `record_observation` calls `extract_and_index(...)`: a
  per-`result_kind` **extractor** (the registry seam — adding a tool later means
  optionally adding an extractor) distills only whitelisted facts into
  `enrichment_fact` rows keyed by canonical node identity, then enriches any node/edge
  that *already* exists (the forward, node-before-observation direction).
- **Join-at-create** — `get_or_create_node` calls `apply_facts_for_node(...)`: a
  single indexed lookup by the node's `(name, address)` keys merges every waiting
  attribute fact into `attrs` (an idempotent union) and materializes any relationship
  edge whose *other* endpoint now exists (respecting the both-endpoints-exist rule).

Identity is exactly what `engine.nodes.get_or_create_node` computes:
`normalize_symbol_name` for a name subject, the canonical address for an address
subject, and the ordered endpoint pair for a relationship. Cache invalidation is
**passive**: facts are scoped by `content_hash`, so re-ingesting changed bytes yields
a new hash and the stale facts simply never match the new node — there is no eviction.
"""

from __future__ import annotations

import json
from typing import Any, Callable

from sqlalchemy.orm import Session

from hexgraph.db.models import EnrichmentFact, Node
from hexgraph.engine.nodes import normalize_symbol_name
from hexgraph.engine.observations import add_provenance

# --- the always-welcome whitelist (design §5.4) ------------------------------
# ONLY these fact kinds may ever be auto-applied. Anything not listed here is
# refused at extraction AND again at apply, so a payload that smuggles a
# "severity"/"summary"/verdict can never reach a node automatically. The graph's
# judgment calls (severity, exploitability, "this is a vulnerability", summaries,
# speculative types) and NEW nodes are deliberately excluded.

# Whitelisted attribute facts, per node type → the attribute keys the fact may set.
_ATTRIBUTE_WHITELIST: dict[str, set[str]] = {
    "function": {
        "address", "prototype", "signature", "params", "param_count",
        "local_count", "locals", "calling_convention", "demangled_name",
    },
    "symbol": {"is_sink"},
    "struct": {"fields", "layout", "size"},
}

# Whitelisted relationship facts: the edge type a `pair` fact may materialize.
_RELATIONSHIP_WHITELIST: dict[str, str] = {
    # fact_kind -> edge type
    "calls": "calls",
}

# Imports we are willing to auto-tag `is_sink` (the unambiguous dangerous calls).
# Mirrors the dataflow-sink vocabulary; conservative on purpose — auto-enrichment
# never *judges*, so the set is the few imports whose danger is not in question.
DANGEROUS_IMPORTS: frozenset[str] = frozenset({
    "system", "popen", "execve", "execl", "execlp", "execle", "execv",
    "execvp", "execvpe", "exec", "strcpy", "strcat", "sprintf", "vsprintf",
    "gets", "scanf", "memcpy", "wcscpy", "wcscat", "stpcpy",
})


# --- canonical subject keys (MUST match get_or_create_node's identity) --------

def name_key(name: str | None) -> str | None:
    """Canonical key for a `name` subject — the SAME identity get_or_create_node
    stores (decompiler prefixes stripped)."""
    return normalize_symbol_name(name)


def address_key(address: str | None) -> str | None:
    """Canonical key for an `address` subject: lower-cased, whitespace-stripped hex
    (so `0x401200`, `0X401200`, ` 0x401200 ` are one key)."""
    if not address:
        return None
    return str(address).strip().lower()


def pair_key(src_name: str | None, dst_name: str | None) -> str | None:
    """Canonical key for a relationship (`pair`) subject: an ORDERED endpoint pair of
    canonical NAME keys, JSON-encoded. Order is preserved (a directed `A calls B` is
    distinct from `B calls A`). Returns None if either endpoint is missing."""
    a, b = name_key(src_name), name_key(dst_name)
    if not a or not b:
        return None
    return json.dumps([a, b])


def _unpair(subject_key: str) -> tuple[str, str] | None:
    try:
        a, b = json.loads(subject_key)
        return str(a), str(b)
    except (ValueError, TypeError):
        return None


# --- the extracted-fact in-memory shape --------------------------------------

class Fact:
    """One distilled always-welcome fact, before it becomes an `enrichment_fact`
    row. An extractor returns a list of these."""

    __slots__ = ("subject_kind", "subject_key", "node_type", "fact_kind", "fact_json")

    def __init__(self, *, subject_kind: str, subject_key: str, node_type: str,
                 fact_kind: str, fact_json: dict[str, Any]) -> None:
        self.subject_kind = subject_kind
        self.subject_key = subject_key
        self.node_type = node_type
        self.fact_kind = fact_kind
        self.fact_json = fact_json


def _attr_fact(node_type: str, subject_kind: str, subject_key: str | None,
               attrs: dict[str, Any]) -> Fact | None:
    """Build a whitelisted ATTRIBUTE fact, keeping only the allowed keys for the
    type. Returns None if the key is missing or nothing whitelisted survives."""
    if not subject_key:
        return None
    allowed = _ATTRIBUTE_WHITELIST.get(node_type, set())
    kept = {k: v for k, v in attrs.items() if k in allowed and v is not None}
    if not kept:
        return None
    return Fact(subject_kind=subject_kind, subject_key=subject_key,
                node_type=node_type, fact_kind="attrs", fact_json=kept)


# --- the extractor registry (the seam) ----------------------------------------
# result_kind -> extractor(payload) -> list[Fact]. Adding a tool later = optionally
# registering an extractor for its always-welcome facts. NEVER branch on tool/kind
# inside enrichment logic; register an extractor instead.

Extractor = Callable[[Any], list[Fact]]
_REGISTRY: dict[str, Extractor] = {}


def register_extractor(result_kind: str, fn: Extractor) -> None:
    _REGISTRY[result_kind] = fn


def extractor_for(result_kind: str) -> Extractor | None:
    return _REGISTRY.get(result_kind)


def _func_attrs_from(item: dict[str, Any]) -> dict[str, Any]:
    """Pull the whitelisted function attributes out of a decompiler/function-list
    record, normalizing the handful of synonyms tools emit."""
    out: dict[str, Any] = {}
    for src, dst in (
        ("address", "address"), ("addr", "address"),
        ("prototype", "prototype"), ("signature", "signature"),
        ("calling_convention", "calling_convention"), ("cc", "calling_convention"),
        ("demangled_name", "demangled_name"), ("demangled", "demangled_name"),
        ("params", "params"), ("param_count", "param_count"),
        ("locals", "locals"), ("local_count", "local_count"),
    ):
        if src in item and item[src] is not None and dst not in out:
            out[dst] = item[src]
    if "address" in out:
        out["address"] = address_key(out["address"]) or out["address"]
    return out


def _extract_functions(payload: Any) -> list[Fact]:
    """function_list / decompilation → per-function attribute facts (keyed by BOTH
    the name and, when present, the address) + `calls` relationship facts.

    Accepts a focus dict (decompilation), a {"functions": [...]} list, or a bare
    list of function records."""
    facts: list[Fact] = []
    items: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        if payload.get("focus"):
            items.append(payload["focus"])
        elif isinstance(payload.get("functions"), list):
            for f in payload["functions"]:
                if isinstance(f, dict):
                    items.append(f)
    elif isinstance(payload, list):
        items = [f for f in payload if isinstance(f, dict)]

    for item in items:
        name = item.get("name")
        nkey = name_key(name)
        if not nkey:
            continue
        attrs = _func_attrs_from(item)
        if attrs:
            # Key the same attribute fact under the name AND (if known) the address,
            # so a node materialized under either identity picks it up. Idempotent
            # union means matching both is safe.
            nf = _attr_fact("function", "name", nkey, attrs)
            if nf:
                facts.append(nf)
            akey = attrs.get("address")
            if akey:
                af = _attr_fact("function", "address", akey, attrs)
                if af:
                    facts.append(af)
        # `A calls B` relationship facts (decompilation lists callees). The edge
        # materializes only when BOTH endpoints exist (handled at join/apply time).
        for callee in item.get("callees", []) or []:
            cname = callee.get("name") if isinstance(callee, dict) else callee
            site = callee.get("address") if isinstance(callee, dict) else None
            pk = pair_key(name, cname)
            if not pk:
                continue
            fj: dict[str, Any] = {}
            if site:
                fj["call_sites"] = [address_key(site) or site]
            facts.append(Fact(subject_kind="pair", subject_key=pk,
                              node_type="function", fact_kind="calls", fact_json=fj))
    return facts


def _extract_xrefs(payload: Any) -> list[Fact]:
    """xrefs → `is_sink` tags for the dangerous imports that appear. The xref probe
    emits a {sink_name: [...callers]} map; we tag only the known-dangerous names."""
    facts: list[Fact] = []
    sinks = payload.get("sinks") if isinstance(payload, dict) else None
    if not isinstance(sinks, dict):
        return facts
    for sink in sinks:
        nkey = name_key(sink)
        if nkey and nkey in DANGEROUS_IMPORTS:
            f = _attr_fact("symbol", "name", nkey, {"is_sink": True})
            if f:
                facts.append(f)
    return facts


def _extract_structs(payload: Any) -> list[Fact]:
    """structs → recovered layout for program-defined structs. Accepts a list of
    struct records or {"structs": [...]}; skips built-ins flagged `builtin`."""
    facts: list[Fact] = []
    items = payload.get("structs") if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        return facts
    for item in items:
        if not isinstance(item, dict) or item.get("builtin"):
            continue
        nkey = name_key(item.get("name"))
        if not nkey:
            continue
        attrs = {k: item[k] for k in ("fields", "layout", "size")
                 if k in item and item[k] is not None}
        f = _attr_fact("struct", "name", nkey, attrs)
        if f:
            facts.append(f)
    return facts


def _extract_binutils(payload: Any) -> list[Fact]:
    """binutils_facts → `is_sink` tags for the dangerous imports that appear (the same
    always-welcome subset the xref extractor emits, via the SHARED DANGEROUS_IMPORTS
    set — never a broadened whitelist). The binutils probe lists imports under
    `imports`; we tag ONLY the unambiguous dangerous ones — a non-dangerous import
    carries no auto-fact (no verdict for the rest). Mitigation flags are NOT here: they
    describe the TARGET, not a node, so engine.binutils.apply_mitigations_to_target
    records them on the target's metadata, the target analogue of node enrichment."""
    facts: list[Fact] = []
    imports = payload.get("imports") if isinstance(payload, dict) else None
    if not isinstance(imports, list):
        return facts
    for name in imports:
        nkey = name_key(name)
        if nkey and nkey in DANGEROUS_IMPORTS:
            f = _attr_fact("symbol", "name", nkey, {"is_sink": True})
            if f:
                facts.append(f)
    return facts


register_extractor("function_list", _extract_functions)
register_extractor("decompilation", _extract_functions)
register_extractor("call_graph", _extract_functions)
register_extractor("xrefs", _extract_xrefs)
register_extractor("structs", _extract_structs)
register_extractor("binutils_facts", _extract_binutils)


# --- conflict resolution & idempotent merge ----------------------------------

def _merge_attrs(existing: dict[str, Any], incoming: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Idempotent union of whitelisted attribute facts into a node's attrs.

    Returns `(merged, changed)`. Re-applying the same fact is a no-op (changed=False,
    never a double-write). Conflicts resolve most-recent-wins (the later observation's
    value overwrites) — the design's "most-recent / highest-confidence wins,
    provenance retained." `provenance` is preserved and extended by the caller."""
    merged = dict(existing)
    changed = False
    for k, v in incoming.items():
        if k == "provenance":
            continue
        if merged.get(k) != v:
            merged[k] = v
            changed = True
    return merged, changed


# --- forward direction: enrich already-existing objects at write time ---------

def _matching_nodes(session: Session, *, project_id: str, target_id: str,
                    node_type: str, subject_kind: str, subject_key: str) -> list[Node]:
    """Existing, non-archived nodes that a name/address fact applies to."""
    q = (
        session.query(Node)
        .filter(Node.project_id == project_id, Node.target_id == target_id,
                Node.node_type == node_type, Node.archived.is_(False))
    )
    if subject_kind == "name":
        return [n for n in q.all() if name_key(n.fq_name or n.name) == subject_key]
    if subject_kind == "address":
        return [n for n in q.all() if address_key(n.address) == subject_key]
    return []


def _enrich_node_now(session: Session, node: Node, fact: Fact,
                     source_observation_id: str | None) -> bool:
    """Apply one ATTRIBUTE fact to an existing node in place (idempotent). Records the
    source Observation in `attrs.provenance`. Returns True if anything changed.

    The address-fill case is honored: a name-keyed attribute fact carrying `address`
    fills the node's `address` column when it's empty (never overwrites a known one)."""
    merged, changed = _merge_attrs(node.attrs_json or {}, fact.fact_json)
    # Fill the locator column from a recovered address (never downgrade a known one).
    addr = fact.fact_json.get("address")
    addr_filled = bool(addr and not node.address)
    if addr_filled:
        node.address = addr
    if (changed or addr_filled) and source_observation_id:
        add_provenance(merged, source_observation_id)
    if changed or addr_filled:
        node.attrs_json = merged
    return changed or addr_filled


def _materialize_relationship(session: Session, *, project_id: str, target_id: str,
                              fact: Fact, source_observation_id: str | None) -> bool:
    """Draw the relationship edge for a `pair` fact IFF both endpoint nodes already
    exist (the both-endpoints-exist rule). Idempotent: re-applying merges via
    add_edge(merge=True) — list attrs (call_sites) accumulate as a set."""
    pair = _unpair(fact.subject_key)
    if pair is None:
        return False
    edge_type = _RELATIONSHIP_WHITELIST.get(fact.fact_kind)
    if edge_type is None:
        return False
    src_key, dst_key = pair
    src = _lookup_named(session, project_id, target_id, fact.node_type, src_key)
    dst = _lookup_named(session, project_id, target_id, fact.node_type, dst_key)
    if src is None or dst is None:
        return False  # both endpoints must exist
    from hexgraph.db.models import Edge
    from hexgraph.engine.edges import add_edge

    attrs = dict(fact.fact_json)
    if source_observation_id:
        # Accumulate provenance across DISTINCT observations contributing the same
        # edge. add_edge(merge=True) defers to merge_edge_attrs, which only unions
        # attrs the edge schema marks list=True (call_sites) — `provenance` is not in
        # that schema, so a bare merge would OVERWRITE it. Seed the incoming list with
        # the existing edge's provenance first so the overwrite lands on the union
        # (mirrors the node path's add_provenance-reads-existing behavior; §5.2).
        existing = (
            session.query(Edge)
            .filter(Edge.project_id == project_id, Edge.type == edge_type,
                    Edge.src_kind == "node", Edge.src_id == src.id,
                    Edge.dst_kind == "node", Edge.dst_id == dst.id)
            .first()
        )
        if existing is not None:
            attrs["provenance"] = list((existing.attrs_json or {}).get("provenance") or [])
        add_provenance(attrs, source_observation_id)
    add_edge(session, project_id=project_id, src=("node", src.id), dst=("node", dst.id),
             type=edge_type, origin="derived", confidence=1.0,
             created_by_tool="enrichment", attrs=attrs, merge=True)
    return True


def _lookup_named(session: Session, project_id: str, target_id: str,
                  node_type: str, key: str) -> Node | None:
    for n in (
        session.query(Node)
        .filter(Node.project_id == project_id, Node.target_id == target_id,
                Node.node_type == node_type, Node.archived.is_(False))
        .all()
    ):
        if name_key(n.fq_name or n.name) == key:
            return n
    return None


def extract_and_index(session: Session, *, project_id: str, target_id: str,
                      content_hash: str | None, result_kind: str, payload: Any,
                      source_observation_id: str | None) -> int:
    """Extract-at-write (design §5.5). Distill the always-welcome facts from one
    Observation's payload, persist them as `enrichment_fact` rows (keyed by canonical
    identity, deduped so a re-run doesn't pile rows), and enrich any node/edge that
    ALREADY exists right now. Returns the number of fact rows written.

    Safe no-op when there's no extractor for `result_kind` (the registry seam)."""
    extractor = _REGISTRY.get(result_kind)
    if extractor is None:
        return 0
    try:
        facts = extractor(payload)
    except Exception:  # noqa: BLE001 — extraction must never break the tool call
        return 0

    written = 0
    for fact in facts:
        status = _persist_fact(session, project_id=project_id, target_id=target_id,
                               content_hash=content_hash, fact=fact,
                               source_observation_id=source_observation_id)
        if status == "duplicate":
            # Exact-duplicate fact: nothing new to index AND the node already has it
            # (idempotent), so skip the forward-enrich too.
            continue
        if status == "new":
            written += 1
        # status in ("new", "updated"): forward-enrich any node/edge that already
        # exists. On "updated" (a conflicting newer value) this carries the
        # most-recent value onto the live node.
        if fact.subject_kind in ("name", "address"):
            for node in _matching_nodes(
                session, project_id=project_id, target_id=target_id,
                node_type=fact.node_type, subject_kind=fact.subject_kind,
                subject_key=fact.subject_key,
            ):
                _enrich_node_now(session, node, fact, source_observation_id)
        elif fact.subject_kind == "pair":
            _materialize_relationship(
                session, project_id=project_id, target_id=target_id,
                fact=fact, source_observation_id=source_observation_id)
    session.flush()
    return written


def _persist_fact(session: Session, *, project_id: str, target_id: str,
                  content_hash: str | None, fact: Fact,
                  source_observation_id: str | None) -> str:
    """Upsert one enrichment_fact row (one row per subject+kind, deduped on
    target+content_hash+subject+node_type+fact_kind). Returns:

    - `"new"`     — a first-seen fact; a row was added,
    - `"updated"` — a CONFLICT (same subject+kind, different value): the row is merged
                    in place and its `source_observation_id` repointed (most-recent
                    wins; a later decompilation that recovers MORE attrs keeps the
                    earlier ones, list attrs union),
    - `"duplicate"` — an exact re-run; no-op (keeps re-runs from piling rows).

    The mutated `fact.fact_json` (for "updated") reflects the merged value so the
    caller's forward-enrich carries the winning value onto a live node."""
    rows = (
        session.query(EnrichmentFact)
        .filter(EnrichmentFact.target_id == target_id,
                EnrichmentFact.content_hash == content_hash,
                EnrichmentFact.node_type == fact.node_type,
                EnrichmentFact.subject_kind == fact.subject_kind,
                EnrichmentFact.subject_key == fact.subject_key,
                EnrichmentFact.fact_kind == fact.fact_kind)
        .all()
    )
    for r in rows:
        if (r.fact_json or {}) == fact.fact_json:
            return "duplicate"
    if rows:
        row = rows[0]
        merged = dict(row.fact_json or {})
        for k, v in fact.fact_json.items():
            if isinstance(v, list):
                cur = list(merged.get(k) or [])
                for x in v:
                    if x not in cur:
                        cur.append(x)
                merged[k] = cur
            else:
                merged[k] = v  # most-recent scalar wins
        row.fact_json = merged
        row.source_observation_id = source_observation_id or row.source_observation_id
        fact.fact_json = merged  # the caller forward-enriches with the winning value
        return "updated"
    session.add(EnrichmentFact(
        project_id=project_id, target_id=target_id, content_hash=content_hash,
        subject_kind=fact.subject_kind, subject_key=fact.subject_key,
        node_type=fact.node_type, fact_kind=fact.fact_kind, fact_json=fact.fact_json,
        source_observation_id=source_observation_id,
    ))
    return "new"


# --- reverse direction: join waiting facts at node-create ---------------------

def apply_facts_for_node(session: Session, node: Node) -> int:
    """Join-at-create (design §5.5). On node create / promote / address-fill, pull
    every waiting always-welcome fact for this node's `(name, address)` keys with one
    indexed lookup and merge them in (idempotent union — applying a fact twice is a
    no-op). Relationship facts where this node is an endpoint materialize their edge
    IFF the other endpoint now exists. Returns the count of facts applied.

    Facts are scoped by the TARGET's analyzed-bytes `content_hash` (the same value the
    Observation carried, NOT the node's own body-hash): re-ingesting changed bytes
    yields a new target hash, so the stale facts simply never match — passive
    invalidation, no eviction step."""
    # Only the whitelisted typed objects (function/symbol/struct) receive facts;
    # function nodes additionally receive relationship (`calls`) facts. Anything
    # else, or a target-less node, has nothing waiting for it.
    if node.target_id is None or node.node_type not in _ATTRIBUTE_WHITELIST:
        return 0

    chash = _target_content_hash(session, node.target_id)
    nkey = name_key(node.fq_name or node.name)
    akey = address_key(node.address)
    applied = 0

    # Attribute facts keyed under EITHER the name OR the address (a decompilation
    # observation knows both; idempotent union makes applying both safe).
    subj: list[tuple[str, str]] = []
    if nkey:
        subj.append(("name", nkey))
    if akey:
        subj.append(("address", akey))
    for subject_kind, subject_key in subj:
        rows = _facts_for_subject(
            session, target_id=node.target_id, content_hash=chash,
            node_type=node.node_type, subject_kind=subject_kind, subject_key=subject_key)
        for row in rows:
            fact = Fact(subject_kind=subject_kind, subject_key=subject_key,
                        node_type=node.node_type, fact_kind=row.fact_kind,
                        fact_json=row.fact_json or {})
            if _enrich_node_now(session, node, fact, row.source_observation_id):
                applied += 1

    # Relationship facts where this node is an endpoint: re-attempt materialization
    # (the OTHER endpoint may now exist). The pair key is over NAME keys, so only do
    # this for a named node we can key on.
    if nkey and node.node_type == "function":
        for row in _relationship_facts_touching(
            session, target_id=node.target_id, content_hash=chash,
            node_type=node.node_type, name_key_=nkey):
            fact = Fact(subject_kind="pair", subject_key=row.subject_key,
                        node_type=row.node_type, fact_kind=row.fact_kind,
                        fact_json=row.fact_json or {})
            if _materialize_relationship(
                session, project_id=node.project_id, target_id=node.target_id,
                fact=fact, source_observation_id=row.source_observation_id):
                applied += 1

    if applied:
        session.flush()
    return applied


def _target_content_hash(session: Session, target_id: str) -> str | None:
    """The target's analyzed-bytes hash — the scope key facts are written under (see
    observations.content_hash_for). Resolving it here means the join compares like for
    like: a re-ingest that changes the bytes changes this hash, so the stale facts no
    longer match (passive invalidation)."""
    from hexgraph.db.models import Target
    from hexgraph.engine.observations import content_hash_for

    target = session.get(Target, target_id)
    return content_hash_for(target) if target is not None else None


def _facts_for_subject(session: Session, *, target_id: str, content_hash: str | None,
                       node_type: str, subject_kind: str,
                       subject_key: str) -> list[EnrichmentFact]:
    """The indexed lookup (ix_enrichment_fact_subject covers
    target_id+node_type+subject_kind+subject_key); scoped to the node's content_hash
    so stale facts under an old hash never match (passive invalidation)."""
    return (
        session.query(EnrichmentFact)
        .filter(EnrichmentFact.target_id == target_id,
                EnrichmentFact.node_type == node_type,
                EnrichmentFact.subject_kind == subject_kind,
                EnrichmentFact.subject_key == subject_key,
                EnrichmentFact.content_hash == content_hash)
        .all()
    )


def _relationship_facts_touching(session: Session, *, target_id: str,
                                 content_hash: str | None, node_type: str,
                                 name_key_: str) -> list[EnrichmentFact]:
    """Pair facts whose ordered endpoint key contains this node's name key (either
    side). Scoped to the node's content_hash (passive invalidation)."""
    out: list[EnrichmentFact] = []
    for r in (
        session.query(EnrichmentFact)
        .filter(EnrichmentFact.target_id == target_id,
                EnrichmentFact.node_type == node_type,
                EnrichmentFact.subject_kind == "pair",
                EnrichmentFact.content_hash == content_hash)
        .all()
    ):
        pair = _unpair(r.subject_key)
        if pair and name_key_ in pair:
            out.append(r)
    return out
