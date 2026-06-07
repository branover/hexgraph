"""Typed-node materialization (design §3.2).

Nodes are materialized lazily — on reference (a finding attaches, a task launches,
a human pins) — not eagerly for every symbol in a firmware. Identity is
content-addressed (`content_hash`) so renames/findings/edges survive
re-decompilation and match across binaries.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.db.models import Node, NodeType

# Bounded caps so recon never writes thousands of rows (design §3.2 lazy rule).
MAX_SYMBOLS = 60
MAX_STRINGS = 20


def _sha(*parts: str | None) -> str:
    return hashlib.sha256("\x00".join(p or "" for p in parts).encode("utf-8")).hexdigest()


# Decompiler/disassembler namespace prefixes that don't change a symbol's identity
# (radare2 emits `sym.get_param`, `sym.imp.system`, …). `fcn.<addr>` is left alone —
# it names a genuinely-unnamed function, not a prefixed known one.
_NS_PREFIXES = ("sym.imp.", "loc.imp.", "sym.", "imp.", "loc.", "dbg.", "obj.", "reloc.")
NAMED_TYPES = {"function", "symbol", "struct"}


def normalize_symbol_name(name: str | None) -> str | None:
    """Canonical name for a function/symbol/struct: strip decompiler namespace
    prefixes so `sym.get_param` / `imp.get_param` / `get_param` are one identity."""
    if not name:
        return name
    for p in _NS_PREFIXES:
        if name.startswith(p) and len(name) > len(p):
            return name[len(p):]
    return name


# Decompiler auto-generated placeholder names — a genuinely-unnamed identifier the
# tool synthesized from an address, carrying no analyst meaning. radare2 emits
# `fcn.<hex>` / `sub_<hex>`; IDA/Ghidra emit `FUN_<hex>` / `sub_<hex>` / `loc_<hex>`
# (and data stubs `off_`/`byte_`/`word_`/… and `nullsub_<n>`). Each is a known
# keyword followed by an optional `.`/`_` and a pure address/index tail, so a name
# that merely *starts* with one of these words but continues with real text
# (`sub_handler`, `function_table`) is correctly NOT a placeholder. A leading
# namespace prefix (`sym.fcn.00401234`) is stripped first so the tail still matches.
_PLACEHOLDER_RE = re.compile(
    r"^(?:fcn|sub|fun|loc|locret|off|unk|byte|word|dword|qword|nullsub)"
    r"[._]?[0-9a-fA-F]+$",
    re.IGNORECASE,
)
def is_placeholder_name(name: str | None) -> bool:
    """True when `name` is a genuinely-unnamed identifier — a decompiler-synthesized
    placeholder (radare2 `fcn.<hex>`/`sub_<hex>`, IDA/Ghidra `FUN_<hex>`/`sub_<hex>`/
    `loc_<hex>`, …) or empty/whitespace/None. Conservative: anything not a known
    placeholder pattern is treated as a real, analyst-meaningful name (returns False).
    The single reusable predicate for "this object has no real name yet"."""
    if name is None:
        return True
    stripped = name.strip()
    if not stripped:
        return True
    # Match the raw name (catches `fcn.00401234`, `loc.804a010`), then the namespace-
    # normalized form so a prefixed placeholder like `sym.fcn.00401234` (-> `fcn.00401234`)
    # is still caught. We deliberately do NOT treat a bare all-hex remnant as a placeholder:
    # a real symbol can be all-hex (e.g. `deadbeef`, `cafe`), and auto-renaming it would be
    # the exact silent overwrite this predicate exists to prevent.
    if _PLACEHOLDER_RE.match(stripped):
        return True
    canonical = normalize_symbol_name(stripped)
    if canonical and canonical != stripped:
        if _PLACEHOLDER_RE.match(canonical):
            return True
    return False


def get_or_create_node(
    session: Session,
    *,
    project_id: str,
    node_type: NodeType | str,
    name: str,
    target_id: str | None = None,
    fq_name: str | None = None,
    address: str | None = None,
    content_hash: str | None = None,
    attrs: dict[str, Any] | None = None,
    created_by: str = "recon",
    force_hash: bool = False,
) -> Node:
    nt = node_type.value if isinstance(node_type, NodeType) else str(node_type)
    # Canonicalize named-symbol identity + display so decompiler-prefixed names
    # (`sym.get_param`) and bare names (`get_param`) resolve to one node. The raw
    # name is kept in attrs.name_raw so nothing is lost.
    raw_name = name
    if nt in NAMED_TYPES:
        name = normalize_symbol_name(name) or name
        fq_name = normalize_symbol_name(fq_name) if fq_name else None
        if raw_name != name:
            attrs = {**(attrs or {}), "name_raw": raw_name}
    fq = fq_name or name
    q = session.query(Node).filter(Node.project_id == project_id, Node.node_type == nt)
    # Within a target, identity is the locator (target, fq_name) — so the SAME
    # function in two binaries stays two nodes (linkable by `similar_to`).
    # content_hash is a cross-target *matching attribute*, used only when there's
    # no target (e.g. patterns).
    existing = q.filter(Node.target_id == target_id, Node.fq_name == fq).first() if target_id else None
    if existing is None and content_hash and target_id is None:
        existing = q.filter(Node.content_hash == content_hash).first()
    if existing is not None:
        if attrs:
            merged = dict(existing.attrs_json or {})
            merged.update(attrs)
            existing.attrs_json = merged
        # Fill in a location when we now have one and didn't before: recon
        # materializes function nodes with address=None, so a later decompile or a
        # human/agent author must be able to supply it. Never overwrite a known one.
        if address and not existing.address:
            existing.address = address
        # Upgrade to a body hash when one is provided (force_hash); never downgrade.
        if content_hash and (force_hash or not existing.content_hash):
            existing.content_hash = content_hash
        # Re-adding a soft-removed node restores it (and its hidden edges reappear).
        if existing.archived:
            existing.archived = False
        # Join-at-create (design §5.5): pull any waiting always-welcome facts. Run on
        # the existing-node path too so a later address-fill (a name-keyed node that
        # just gained its address) re-looks-up by the address key. Idempotent.
        _apply_waiting_facts(session, existing)
        return existing
    node = Node(
        project_id=project_id, node_type=nt, target_id=target_id, name=name,
        fq_name=fq, address=address, content_hash=content_hash,
        attrs_json=attrs or {}, created_by=created_by,
    )
    session.add(node)
    session.flush()
    # Tie every target-bound node back to the target it lives in (target ─contains→ node)
    # so it's connected in the graph, not floating. This covers functions/symbols/strings/
    # structs AND the dataflow/surface types (input/sink/endpoint/param) — anything with a
    # target_id. Cross-binary nodes (socket) and patterns carry target_id=None by design and
    # are anchored by their semantic edges (listens_on/connects_to, instance_of_pattern);
    # hypotheses are anchored by `about` edges. So the only nodes without a parent edge are
    # the ones that genuinely have no single owning target.
    if target_id and nt not in ("hypothesis", "pattern"):
        from hexgraph.db.models import EdgeType
        from hexgraph.engine.edges import add_edge

        add_edge(
            session, project_id=project_id, src=("target", target_id), dst=("node", node.id),
            type=EdgeType.contains, origin="derived", confidence=1.0, attrs={"declares": nt},
        )
    # Join-at-create (design §5.5): a freshly-promoted node receives the always-welcome
    # facts from tool calls that already happened, and self-wires relationship edges to
    # endpoints already in the graph.
    _apply_waiting_facts(session, node)
    return node


def _apply_waiting_facts(session: Session, node: Node) -> None:
    """Pull and apply this node's waiting enrichment facts (deferred import to avoid a
    cycle: enrichment imports nodes for the canonical-key helpers)."""
    from hexgraph.engine.enrichment import apply_facts_for_node

    apply_facts_for_node(session, node)


def materialize_function(
    session: Session, *, project_id: str, target_id: str | None, name: str,
    address: str | None = None, pseudocode: str | None = None,
    attrs: dict[str, Any] | None = None, created_by: str = "decompile",
) -> Node:
    # Prefer a body hash (matches across binaries); fall back to a locator hash.
    content_hash = _sha(pseudocode) if pseudocode else _sha(target_id, "fn", name)
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.function, name=name,
        target_id=target_id, fq_name=name, address=address,
        content_hash=content_hash, attrs=attrs, created_by=created_by,
        force_hash=bool(pseudocode),  # a real decompiled body upgrades the cross-target hash
    )


def socket_label(kind: str, port: int | str | None, name: str | None) -> str:
    """Human label / identity key for a socket node: 'tcp:8080', a unix path, etc."""
    if name:
        return f"{kind}:{name}"
    if port not in (None, ""):
        return f"{kind}:{port}"
    return f"{kind}:?"


def materialize_socket(
    session: Session, *, project_id: str, kind: str, port: int | str | None = None,
    name: str | None = None, bind_addr: str | None = None, created_by: str = "agent",
    attrs: dict[str, Any] | None = None,
) -> Node:
    """A network/IPC endpoint shared across binaries (so a server's `listens_on`
    and a client's `connects_to` resolve to the SAME node). Identity is
    (project, kind, port|name) via content_hash, with target_id=None so it isn't
    bound to one binary."""
    label = socket_label(kind, port, name)
    base = {"kind": kind, "port": port, "name": name, "bind_addr": bind_addr}
    merged = {**{k: v for k, v in base.items() if v not in (None, "")}, **(attrs or {})}
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.socket, name=label,
        target_id=None, fq_name=label, content_hash=_sha("socket", kind, str(port), name or ""),
        attrs=merged, created_by=created_by,
    )


def materialize_symbol(
    session: Session, *, project_id: str, target_id: str | None, name: str,
    kind: str = "import", library: str | None = None, is_sink: bool = False,
    created_by: str = "recon",
) -> Node:
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.symbol, name=name,
        target_id=target_id, fq_name=name,
        attrs={"kind": kind, "library": library, "is_sink": is_sink},
        created_by=created_by,
    )


def materialize_string(
    session: Session, *, project_id: str, target_id: str | None, value: str,
    created_by: str = "recon",
) -> Node:
    return get_or_create_node(
        session, project_id=project_id, node_type=NodeType.string,
        name=value[:120], target_id=target_id, fq_name=None,
        content_hash=_sha(value), attrs={"value": value[:512]}, created_by=created_by,
    )
