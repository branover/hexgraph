"""MCP tool surface — HexGraph's primitives exposed to an external coding agent
(Claude Code / Codex / gemini-cli) in *driver* mode.

These are the safe, sandboxed operations the agent calls instead of touching the
target itself: read recon facts, decompile/inspect in the `--network none`
sandbox, search the graph, run a HexGraph task, and record findings. Each function
is pure-ish (opens its own session, returns JSON-able dicts) so the logic is
unit-testable without the MCP runtime; `mcp_server.py` wires these to the SDK.

The agent never receives target bytes — only tool output — exactly like the
in-process agent loop. `record_finding` validates against the frozen schema.
"""

from __future__ import annotations

import json

from hexgraph.db.models import Finding, Node, Project, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.findings import is_verified
from hexgraph.models.finding import Finding as FModel


def list_projects() -> list[dict]:
    with session_scope() as s:
        return [{"id": p.id, "name": p.name, "backend": p.llm_backend.value}
                for p in s.query(Project).all()]


def list_targets(project_id: str) -> list[dict]:
    with session_scope() as s:
        rows = s.query(Target).filter(Target.project_id == project_id, Target.archived.is_(False)).all()
        return [{"id": t.id, "name": t.name, "kind": t.kind.value, "arch": t.arch,
                 "parent_id": t.parent_id} for t in rows]


# libc/shell sinks worth pointing a researcher straight at.
_DANGEROUS = {"system", "popen", "execve", "execl", "execlp", "execvp", "exec", "strcpy", "strcat",
              "sprintf", "vsprintf", "gets", "scanf", "sscanf", "memcpy", "alloca", "realpath"}


def target_facts(target_id: str) -> dict:
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        meta = t.metadata_json or {}
        imports = meta.get("imports", [])
        return {"id": t.id, "name": t.name, "kind": t.kind.value, "format": t.format, "arch": t.arch,
                "imports": imports, "exports": meta.get("exports", []),
                "libraries": meta.get("libraries", []), "mitigations": meta.get("mitigations", {}),
                # derived: which imports are classic vuln sinks — start here.
                "dangerous_imports": sorted(set(imports) & _DANGEROUS)}


def list_filesystem(target_id: str) -> dict:
    """List a firmware target's unpacked filesystem (paths, sizes, which are ELFs / already
    child targets). Use it to find config files, scripts, keys, and web assets to inspect —
    then read_file to view one. Returns {unpacked, method, files:[{rel,size,is_elf,added}]}."""
    from hexgraph.engine.filesystem import list_filesystem as _ls

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        return _ls(s.get(Project, t.project_id), t)


def read_file(target_id: str, path: str) -> dict:
    """Read ONE file from a firmware target's unpacked filesystem (a config, script, key,
    web template — NOT the raw binary; decompile_function for code). Bounded (256 KiB),
    path-traversal safe; text is returned as-is, binary as hex. `path` is relative to the
    firmware's extracted root (see list_filesystem). Returns {rel,size,encoding,content,truncated}."""
    from hexgraph.engine.filesystem import FilesystemError, read_file as _read

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return _read(s.get(Project, t.project_id), t, path)
        except FilesystemError as exc:
            return {"error": str(exc)}


def _tool(target_id: str, name: str, args: dict) -> str:
    """Run a sandboxed inspection tool (decompile/strings/…) via the shared registry."""
    from hexgraph.engine.agent_tools import ToolContext, run_tool

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return "error: target not found"
        ctx = ToolContext(session=s, project=s.get(Project, t.project_id), target=t)
        return run_tool(ctx, name, args or {})


def decompile_function(target_id: str, function: str) -> str:
    return _tool(target_id, "decompile_function", {"function": function})


def disassemble(target_id: str, function: str) -> str:
    return _tool(target_id, "disassemble", {"function": function})


def list_functions(target_id: str) -> str:
    return _tool(target_id, "list_functions", {})


def read_imports(target_id: str) -> str:
    return _tool(target_id, "read_imports", {})


def list_strings(target_id: str, pattern: str | None = None) -> str:
    return _tool(target_id, "list_strings", {"pattern": pattern} if pattern else {})


def xrefs(target_id: str, symbol: str | None = None) -> str:
    """Find which functions CALL a symbol/sink and where (cross-references). With no
    `symbol`, map every dangerous sink (system/popen/strcpy/sprintf/…) and who reaches
    it — the fast way to trace from a sink back to the code that can drive it."""
    return _tool(target_id, "xrefs", {"symbol": symbol} if symbol else {})


def _node_dict(n: Node) -> dict:
    return {"id": n.id, "node_type": n.node_type, "name": n.name, "fq_name": n.fq_name,
            "address": n.address, "target_id": n.target_id, "attrs": n.attrs_json or {}}


def get_node(node_id: str) -> dict:
    """Read a node back in full — including its address and attrs (params/notes you
    set). Use this to confirm what you wrote landed."""
    with session_scope() as s:
        n = s.get(Node, node_id)
        return _node_dict(n) if n is not None else {"error": "node not found"}


def list_nodes(project_id: str, target_id: str | None = None, node_type: str | None = None) -> list[dict]:
    """List graph nodes (optionally filtered by target and/or node_type), with
    their address + attrs. The read path for the graph you've been building."""
    with session_scope() as s:
        q = s.query(Node).filter(Node.project_id == project_id, Node.archived.is_(False))
        if target_id:
            q = q.filter(Node.target_id == target_id)
        if node_type:
            q = q.filter(Node.node_type == node_type)
        return [_node_dict(n) for n in q.limit(500).all()]


def list_edges(project_id: str, node_id: str | None = None) -> list[dict]:
    """List edges in the project (or just those touching `node_id`) so you can
    confirm the dataflow/relationships you wired (calls/taints/about/…)."""
    from hexgraph.db.models import Edge
    from sqlalchemy import or_

    with session_scope() as s:
        q = s.query(Edge).filter(Edge.project_id == project_id)
        if node_id:
            q = q.filter(or_((Edge.src_kind == "node") & (Edge.src_id == node_id),
                             (Edge.dst_kind == "node") & (Edge.dst_id == node_id)))
        return [{"id": e.id, "type": e.type, "src_kind": e.src_kind, "src_id": e.src_id,
                 "dst_kind": e.dst_kind, "dst_id": e.dst_id, "attrs": e.attrs_json or {}}
                for e in q.limit(500).all()]


def search(project_id: str, q: str) -> dict:
    from hexgraph.engine.search import search_project

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        return search_project(s, project_id, q)


def list_findings(project_id: str) -> list[dict]:
    """Existing findings, so the agent doesn't re-report what's already known. Each row
    carries `verified` and, for a PoC that ran, a compact `verification` summary
    {verified, detail} so you can see at a glance whether it confirmed — call
    get_finding(id) for the full evidence (incl. the PoC spec in evidence.extra)."""
    with session_scope() as s:
        rows = s.query(Finding).filter(Finding.project_id == project_id).all()
        out = []
        for f in rows:
            ev = f.evidence_json or {}
            row = {"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
                   "status": f.status, "finding_type": f.finding_type,
                   "verified": is_verified(ev), "target_id": f.target_id,
                   "function": ev.get("function")}
            ver = ((ev.get("extra") or {}).get("verification"))
            if ver:
                row["verification"] = {"verified": bool(ver.get("verified")), "detail": ver.get("detail")}
            out.append(row)
        return out


def get_finding(finding_id: str) -> dict:
    """Read ONE finding back in full — including the complete `evidence` (with
    evidence.extra, where verify_poc stores the PoC spec + verification result).
    Use this to confirm a write landed (the finding analog of get_node): after
    verify_poc(finding_id=…), get_finding shows evidence.extra.verification."""
    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return {"error": "finding not found"}
        ev = f.evidence_json or {}
        verified = is_verified(ev)
        return {"id": f.id, "title": f.title, "severity": f.severity, "confidence": f.confidence,
                "category": f.category, "status": f.status, "finding_type": f.finding_type,
                "origin": f.origin, "target_id": f.target_id, "task_id": f.task_id,
                "summary": f.summary, "reasoning": f.reasoning, "evidence": ev,
                "human_notes": f.human_notes, "verified": verified}


def record_finding(project_id: str, target_id: str, finding: dict, task_id: str | None = None,
                   finding_type: str | None = None) -> dict:
    """Persist an agent-produced finding (the `finding` dict must match the frozen
    Finding schema — call get_schemas). `finding_type` is a SEPARATE classifier
    (vulnerability|poc|recon|harness|fuzz_crash|annotation|other) — pass it here,
    NOT inside the finding dict. Pass the given `task_id` in delegate mode."""
    from hexgraph.db.models import Task
    from hexgraph.engine.findings import FINDING_TYPES, persist_finding
    from hexgraph.engine.tasks import create_task

    if finding_type is not None and finding_type not in FINDING_TYPES:
        return {"error": f"invalid finding_type {finding_type!r} (allowed: {list(FINDING_TYPES)})"}
    try:
        model = FModel.model_validate(finding)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"finding does not match the schema: {exc} — call get_schemas; note "
                         "finding_type is a separate record_finding arg, not a finding field."}
    with session_scope() as s:
        project = s.get(Project, project_id)
        target = s.get(Target, target_id)
        if project is None or target is None:
            return {"error": "project or target not found"}
        task = s.get(Task, task_id) if task_id else None
        if task is None or task.project_id != project.id:
            task = create_task(s, project=project, target_id=target.id, type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id,
                              finding=model, finding_type=finding_type)
        row.origin = "agent"
        return {"id": row.id, "title": row.title, "severity": row.severity, "finding_type": row.finding_type}


def propagate_finding(finding_id: str, target_id: str, function: str | None = None,
                      notes: str | None = None) -> dict:
    """N-day propagation: clone an existing finding onto ANOTHER binary (`target_id`)
    that shares the same vulnerable code (see link_same_code) — as a fresh finding to
    triage, wired `derived_from` → the source. Saves re-typing the whole finding dict
    for "the same bug, other binary". Pass `function` to point it at the sibling's
    function name. Returns the new finding id."""
    from hexgraph.db.models import EdgeType, Finding, Task
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Finding as FModelCls

    with session_scope() as s:
        src = s.get(Finding, finding_id)
        target = s.get(Target, target_id)
        if src is None:
            return {"error": "source finding not found"}
        if target is None or target.project_id != src.project_id:
            return {"error": "target not found in the source finding's project"}
        ev = dict(src.evidence_json or {})
        if function:
            ev["function"] = function
        ev.setdefault("extra", {})
        ev["extra"] = {**(ev.get("extra") or {}),
                       "propagated_from": src.id, "propagated_from_target": src.target_id}
        model = FModelCls(
            title=src.title, severity=src.severity, confidence=src.confidence,
            category=src.category,
            summary=(src.summary or "") + f"\n\n[n-day] Same code as finding {src.id} in another binary; "
                    "review/confirm this instance." + (f"\nNotes: {notes}" if notes else ""),
            reasoning=src.reasoning, evidence=ev,
        )
        task = create_task(s, project=s.get(Project, src.project_id), target_id=target.id,
                           type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=src.project_id, target_id=target.id, task_id=task.id,
                              finding=model, finding_type=src.finding_type)
        row.origin = "agent"
        # Wire the n-day link: new instance derived_from the original.
        add_edge(s, project_id=src.project_id, src=("finding", row.id), dst=("finding", src.id),
                 type=EdgeType.derived_from, origin="agent", confidence=0.9, attrs={"by": "n-day propagation"})
        return {"id": row.id, "title": row.title, "target_id": target.id, "finding_type": row.finding_type,
                "status": getattr(row.status, "value", row.status), "derived_from": src.id}


def create_node(project_id: str, node_type: str, name: str, target_id: str | None = None,
                address: str | None = None, attrs: dict | None = None) -> dict:
    """Add a node to the graph (function/symbol/string/struct/input/sink/endpoint/param/
    hypothesis/pattern). Target-bound types REQUIRE target_id (else the node is an orphan)
    and are auto-linked to their target with a `contains` edge. Pass `address` for a code
    node's location, and populate `attrs` with the type's recommended fields — call
    get_schemas first and read node_attribute_schemas[<type>] for what's expected (e.g. a
    function wants {"summary","params":[{"name","type","note"}]}; an input wants {"source"};
    a sink wants {"operation","why"}). DON'T create a `sink` node for a known dangerous call
    (system/strcpy/…) — that's a symbol/function node with is_sink=true. Populating the
    recommended attrs is what makes repeated runs of the same analysis converge."""
    from hexgraph.engine.authoring import InvariantError, create_node as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            n = _create(s, project, node_type=node_type, name=name, target_id=target_id,
                        address=address, attrs=attrs)
        except InvariantError as exc:
            return {"error": str(exc)}
        # Echo back the stored address + attrs: a function node materialized by
        # recon already exists by identity (target, fq_name), so create_node merges
        # into it — the agent sees here whether its address/attrs actually landed.
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "address": n.address,
                "target_id": n.target_id, "attrs": n.attrs_json or {}}


def create_edge(project_id: str, src_kind: str, src_id: str, dst_kind: str, dst_id: str,
                type: str, attrs: dict | None = None, merge: bool = False) -> dict:
    """Connect two graph entities (target|node|finding|task). Both must exist.
    `attrs` carries edge-type-specific facts — call get_schemas to see what's
    meaningful per type (e.g. a `calls` edge's `call_sites`/`arg_constraints`, a
    `listens_on` edge's `address`). With `merge=True`, a repeat of the same
    (src,dst,type) folds into the existing edge: list attributes like `call_sites`
    accumulate instead of drawing a parallel edge."""
    from hexgraph.engine.authoring import InvariantError, create_edge as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            e = _create(s, project, src_kind=src_kind, src_id=src_id, dst_kind=dst_kind,
                        dst_id=dst_id, type=type, attrs=attrs, merge=merge)
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": e.id, "type": e.type, "src_id": e.src_id, "dst_id": e.dst_id,
                "attrs": e.attrs_json or {}}


def update_edge(edge_id: str, attrs: dict, merge: bool = True) -> dict:
    """Add/update attributes on an EXISTING edge (by id). Default `merge=True`
    accumulates list attributes (e.g. append a newly-found `call_sites` address)
    and overwrites scalars; `merge=False` replaces attrs wholesale. See get_schemas
    for the attributes meaningful to each edge type."""
    from hexgraph.db.models import Edge
    from hexgraph.engine.edge_schemas import merge_edge_attrs

    with session_scope() as s:
        e = s.get(Edge, edge_id)
        if e is None:
            return {"error": "edge not found"}
        e.attrs_json = merge_edge_attrs(e.type, e.attrs_json, attrs) if merge else dict(attrs or {})
        return {"id": e.id, "type": e.type, "attrs": e.attrs_json}


def archive_node(project_id: str, node_id: str) -> dict:
    """Soft-remove a node from the graph (reversible). The node and the edges touching
    it are hidden; re-adding the same node (create_node / a task) or restore_node brings
    it and its edges back — nothing is deleted."""
    from hexgraph.engine.removal import archive_node as _archive

    with session_scope() as s:
        try:
            n = _archive(s, project_id, node_id)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "archived": n.archived}


def restore_node(project_id: str, node_id: str) -> dict:
    """Un-archive a previously soft-removed node (its hidden edges reappear)."""
    from hexgraph.engine.removal import restore_node as _restore

    with session_scope() as s:
        try:
            n = _restore(s, project_id, node_id)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "archived": n.archived}


def archive_target(project_id: str, target_id: str) -> dict:
    """Soft-remove a target + its whole subtree (children, nodes, findings) from the graph
    (REVERSIBLE): they're hidden, not deleted; re-ingesting the same bytes, or restore_target,
    brings them back. Use to declutter (e.g. an irrelevant firmware component). Returns how
    many targets were archived. (Whole-project deletion is operator-only — not an MCP tool.)"""
    from hexgraph.engine.targets import archive_target as _archive

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return {"archived": _archive(s, project_id, target_id)}
        except ValueError as exc:
            return {"error": str(exc)}


def restore_target(project_id: str, target_id: str) -> dict:
    """Un-archive a previously soft-removed target subtree (its nodes/findings reappear)."""
    from hexgraph.engine.targets import restore_target as _restore

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            return {"restored": _restore(s, project_id, target_id)}
        except ValueError as exc:
            return {"error": str(exc)}


def delete_edge(edge_id: str) -> dict:
    """Permanently delete one edge (hard delete — re-create it with create_edge to
    bring it back). To remove a node's edges reversibly, archive the node instead."""
    from hexgraph.engine.removal import delete_edge as _del

    with session_scope() as s:
        return {"deleted": _del(s, edge_id), "edge_id": edge_id}


def create_socket(project_id: str, kind: str = "tcp", port: int | str | None = None,
                  name: str | None = None, bind_addr: str | None = None,
                  attrs: dict | None = None) -> dict:
    """Create (or reuse) a SOCKET node — a network/IPC endpoint shared across the
    firmware's binaries. `kind` ∈ tcp|udp|unix|io|netlink|raw|other; give a `port`
    (tcp/udp) or a `name` (unix path / identifier). A server `listens_on` it and a
    client `connects_to` it — both resolve to this ONE node, so you can see which
    binaries talk over the same endpoint. Put the listen/connect code address on
    those edges (create_edge attrs={'address': '0x...'})."""
    from hexgraph.engine.authoring import InvariantError, create_socket as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            n = _create(s, project, kind=kind, port=port, name=name, bind_addr=bind_addr,
                        attrs=attrs, created_by="agent")
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "attrs": n.attrs_json or {}}


def list_sockets(project_id: str) -> list[dict]:
    """List socket endpoints in the project with who listens/connects on each — the
    network map of the firmware (server↔client over shared sockets)."""
    from hexgraph.db.models import Edge, NodeType

    with session_scope() as s:
        socks = (s.query(Node)
                 .filter(Node.project_id == project_id, Node.node_type == NodeType.socket.value)
                 .all())
        out = []
        for n in socks:
            edges = (s.query(Edge)
                     .filter(Edge.project_id == project_id, Edge.dst_kind == "node", Edge.dst_id == n.id,
                             Edge.type.in_(("listens_on", "connects_to")))
                     .all())
            peers = [{"relation": e.type, "src_kind": e.src_kind, "src_id": e.src_id,
                      "address": (e.attrs_json or {}).get("address")} for e in edges]
            out.append({"id": n.id, "name": n.name, "attrs": n.attrs_json or {}, "peers": peers})
        return out


def list_egress(project_id: str) -> list[dict]:
    """The egress audit log — every outbound network action (allowed or denied) the
    bounded-network tier recorded for this project. Durable proof of what HexGraph
    connected to and when."""
    from hexgraph.engine.audit import list_egress as _list

    with session_scope() as s:
        return _list(s, project_id)


def update_finding(finding_id: str, status: str | None = None, severity: str | None = None,
                   confidence: str | None = None, human_notes: str | None = None) -> dict:
    """Update an EXISTING finding in place (don't create a duplicate) — e.g. raise
    confidence/severity and set status='confirmed' after a PoC verifies, or
    'dismissed' if it's a false positive."""
    from hexgraph.db.models import Finding, FindingStatus

    with session_scope() as s:
        f = s.get(Finding, finding_id)
        if f is None:
            return {"error": "finding not found"}
        if status is not None:
            try:
                f.status = FindingStatus(status).value
            except ValueError:
                return {"error": f"invalid status {status!r} (use new|triaging|confirmed|dismissed|reported)"}
        if severity:
            f.severity = severity
        if confidence:
            f.confidence = confidence
        if human_notes is not None:
            f.human_notes = human_notes
        return {"id": f.id, "status": f.status, "severity": f.severity, "confidence": f.confidence}


def link_evidence(hypothesis_id: str, finding_id: str, relation: str) -> dict:
    """Attach a finding to a hypothesis as supporting/refuting evidence. This is how
    you CONFIRM a hypothesis — the hypothesis status is recomputed from its evidence
    (open → supported / refuted / contested). relation = 'supports' | 'refutes'
    ('confirms'→supports and 'contradicts'→refutes are accepted aliases). To pin a
    hard verdict on a verified finding, also call set_hypothesis_status(id,'confirmed')."""
    from hexgraph.engine.hypotheses import HypothesisError, link_evidence as _le, summary

    with session_scope() as s:
        node = s.get(Node, hypothesis_id)
        project = s.get(Project, node.project_id) if node is not None else None
        if project is None:
            return {"error": "hypothesis not found"}
        try:
            _le(s, project, hypothesis_id=hypothesis_id, finding_id=finding_id, relation=relation)
        except HypothesisError as exc:
            return {"error": str(exc)}
        return summary(s, hypothesis_id)


def set_hypothesis_status(hypothesis_id: str, status: str, rationale: str | None = None) -> dict:
    """Pin a hypothesis verdict: confirmed | rejected | open | supported | refuted.
    Pass `rationale` to record WHY (kept as the hypothesis's status_note)."""
    from hexgraph.engine.hypotheses import HypothesisError, set_status, summary

    with session_scope() as s:
        try:
            set_status(s, hypothesis_id, status, rationale=rationale)
            return summary(s, hypothesis_id)
        except HypothesisError as exc:
            return {"error": str(exc)}


def _decompiler_info() -> dict:
    """Which decompiler decompile_function/disassemble use right now, and how to change
    it — so an agent knows it can't flip it itself (the operator does, in Settings)."""
    from hexgraph.sandbox.decompiler import _resolve_name

    active = _resolve_name(None)
    return {
        "active": active,
        "available_default": "radare2",
        "note": "decompile_function / disassemble use the OPERATOR-configured decompiler "
                "automatically — you don't select it. radare2 is the always-available default; "
                "Ghidra is used when the operator enables features.ghidra in Settings AND the "
                "sandbox image was built with Ghidra (`make sandbox-build WITH_GHIDRA=1`). There "
                "is intentionally no MCP tool to toggle this (it's an operator setting). If you "
                "want Ghidra and `active` here is 'radare2', ask the operator to enable it.",
    }


def get_schemas() -> dict:
    """The write-API contract: allowed enums + the Finding shape. Read this before
    record_finding / create_node / create_edge / annotate to avoid guessing."""
    import typing

    from hexgraph.db.models import EdgeType, FindingStatus, NodeType
    from hexgraph.engine.annotations import KINDS as ANN_KINDS, NODE_KINDS as ANN_NODE_KINDS
    from hexgraph.engine.edge_schemas import SOCKET_KINDS, describe_edges
    from hexgraph.engine.node_schemas import describe_nodes
    from hexgraph.engine.findings import FINDING_TYPES
    from hexgraph.models.finding import Finding as FModelCls

    cats = list(typing.get_args(FModelCls.model_fields["category"].annotation))
    sevs = list(typing.get_args(FModelCls.model_fields["severity"].annotation))
    confs = list(typing.get_args(FModelCls.model_fields["confidence"].annotation))
    return {
        "finding": {
            "required": ["title", "severity", "confidence", "category", "summary", "reasoning", "evidence"],
            "severity": sevs, "confidence": confs, "category": cats,
            "evidence_fields": ["function", "file", "address", "line", "decompiled_snippet",
                                "reproducer", "backtrace", "sink", "strings", "extra"],
            "evidence_note": "evidence.extra is a FREE-FORM object — put the PoC spec, verification "
                             "result, CWE, dataflow, etc. there. `reproducer` is a free-text PoC string. "
                             "Top-level evidence keys other than those listed are rejected.",
            "status": [s.value for s in FindingStatus],
        },
        "finding_type": {
            "values": list(FINDING_TYPES),
            "note": "NOT a field of the finding object — pass it as the separate `finding_type` "
                    "argument to record_finding (and read it back via list_findings). Defaults to "
                    "'vulnerability' / is auto-classified from the producing task.",
        },
        "record_finding_signature": "record_finding(project_id, target_id, finding, task_id=None, "
                                    "finding_type=None) — project_id is FIRST, then target_id. Prefer "
                                    "keyword args. For 'the same bug in another binary' use "
                                    "propagate_finding(finding_id, target_id) instead of re-typing it.",
        "node_types": [t.value for t in NodeType if t != NodeType.task],
        "node_attribute_schemas": describe_nodes(),
        "node_attributes_note": "Per node type: what it IS, `use_when` (when to create it vs an "
                                "alternative), and the `recommended` attrs to populate on create_node "
                                "for a complete, consistent graph. KEY RULE: a dangerous library call "
                                "(system/exec/strcpy/sprintf) is a `symbol`/`function` node with "
                                "is_sink=true — do NOT also create a separate `sink` node for it; reserve "
                                "`sink` for an abstract dangerous point that is not already a node. Always "
                                "pass target_id for target-bound types so the node isn't an orphan.",
        "edge_types": [t.value for t in EdgeType],
        "edge_endpoint_kinds": ["target", "node", "finding", "task"],
        "edge_note": "A hypothesis IS a node (node_type='hypothesis'); link a finding to it with "
                     "dst_kind='node' + its id, or better use link_evidence(hypothesis_id, finding_id, "
                     "relation) which also updates the hypothesis status.",
        "edge_attribute_schemas": describe_edges(),
        "edge_attributes_note": "Edges carry attributes (edge.attrs) — the schema above lists what's "
                                "meaningful per type (e.g. a calls edge's call_sites + arg_constraints, a "
                                "listens_on edge's address). Pass them via create_edge(attrs=…); use "
                                "create_edge(merge=True) or update_edge to ACCUMULATE list attrs.",
        "socket": {
            "kinds": list(SOCKET_KINDS),
            "note": "A `socket` node is a network/IPC endpoint SHARED across binaries. Make it with "
                    "create_socket(kind, port|name); a server `listens_on` it and a client "
                    "`connects_to` it (both resolve to the one node). list_sockets shows the map.",
        },
        "link_evidence_relations": ["supports", "refutes", "confirms", "contradicts"],
        "link_evidence_note": "relation is supports|refutes (confirms→supports, contradicts→refutes are "
                              "accepted aliases). The hypothesis status is then recomputed from its "
                              "evidence; pin a hard verdict with set_hypothesis_status(id,'confirmed').",
        "create_node_note": "Function/symbol/struct identity is (target, normalized name) — recon "
                            "pre-materializes function nodes (address=null). create_node on an existing "
                            "one MERGES: it fills a missing address and unions attrs (it won't overwrite "
                            "a known address). The returned address/attrs show what actually landed.",
        "decompiler": _decompiler_info(),
        "annotation_kinds": sorted(ANN_KINDS),
        "annotation_node_kinds": sorted(ANN_NODE_KINDS),
        "annotation_note": "Annotations from an agent land status='proposed' (pending analyst approval).",
    }


def create_hypothesis(project_id: str, statement: str, rationale: str | None = None,
                      target_id: str | None = None) -> dict:
    """Record a research hypothesis (findings can later support/refute it)."""
    from hexgraph.engine.hypotheses import HypothesisError, create_hypothesis as _create, summary

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            node = _create(s, project, statement=statement, rationale=rationale, target_id=target_id)
            return summary(s, node.id)
        except HypothesisError as exc:
            return {"error": str(exc)}


def annotate(project_id: str, node_kind: str, node_id: str, kind: str, value: str) -> dict:
    """Attach a note/tag/rename to a graph entity (lands as an agent proposal)."""
    from hexgraph.engine.annotations import AnnotationError, create_annotation

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        try:
            a = create_annotation(s, project_id, node_kind=node_kind, node_id=node_id,
                                  kind=kind, value=value, origin="agent")
        except AnnotationError as exc:
            return {"error": str(exc)}
        return {"id": a.id, "kind": a.kind, "status": a.status}


def ingest(path: str, name: str | None = None, project_id: str | None = None) -> dict:
    """Ingest a binary/firmware from a local path as a target (firmware unpacks into
    children), running recon in the sandbox. Creates a project if none is given."""
    import os

    from hexgraph.engine.ingest import create_project, ingest_file
    from hexgraph.engine.pipeline import ingest_and_analyze
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not os.path.isfile(path):
        return {"error": f"file not found: {path!r} (resolved from the MCP server's working "
                          f"directory {os.getcwd()!r}). Pass an ABSOLUTE path."}
    with session_scope() as s:
        project = s.get(Project, project_id) if project_id else None
        if project is None:
            project = create_project(s, name=(name or os.path.basename(path)))
        if not docker_available():
            t = ingest_file(s, project, path, name=name)
            return {"project_id": project.id, "root_target_id": t.id, "recon": False,
                    "note": "Docker not running — registered without recon/unpack"}
        summary = ingest_and_analyze(s, project, path, name=name, runner=get_executor())
        return {"project_id": project.id, "root_target_id": summary["root_target_id"],
                "children": summary.get("children", [])}


def register_surface(project_id: str, base_url: str, name: str | None = None,
                     endpoints: list | None = None) -> dict:
    """Register a WEB attack surface (a `web_app` target reached via an HTTP Channel —
    no bytes). Optionally pass an offline route spec `endpoints`:
    [{"method","path","params"?,"handler"?,"auth"?}]. Then run_task(target_id,
    "surface_recon") materialises endpoint/param nodes and `routes_to` edges linking
    each route to its handler function in the firmware. Phase 1 is offline (no egress)."""
    from hexgraph.engine.surfaces import register_web_surface

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            t = register_web_surface(s, project, base_url, name=name, endpoints=endpoints)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": t.id, "name": t.name, "kind": t.kind.value,
                "endpoints": len((t.metadata_json or {}).get("endpoints", []))}


def rehost(target_id: str, brand: str | None = None) -> dict:
    """Boot a FIRMWARE target under full-system emulation and register its live web server
    as a `web_app` surface child — so you can then assess the running device (surface_recon /
    web_recon / http_request / verify_poc), fused to the firmware's static graph. The rehoster
    is auto-selected from the image: qemu+KVM for a full-OS disk image (boots its own kernel),
    FirmAE for a vendor firmware blob (extracts the rootfs + supplies a kernel). Returns
    {surface_id, base_url}. Requires features.rehost (to boot) — and features.network to then
    talk to it. Heavy + best-effort: many images don't boot cleanly; the error says so.

    `brand` (FirmAE path only): the device vendor — linksys/netgear/dlink/tplink/tenda/… —
    FirmAE keys its network-inference NVRAM profiles on it. It's auto-inferred from the
    firmware's strings when present, but if rehost reports it couldn't bring up the device
    network, RETRY with the right brand explicitly (a stripped image won't name its vendor).

    If the booted device exposes SSH/telnet, rehost ALSO auto-registers it as a `remote`
    target (returned as `remote_target_id`) pinned to the emulator — run remote_list_files /
    remote_run on it to enumerate the LIVE device, not just the extracted rootfs (needs
    features.remote). `ports` lists every device port that answered, so you know which
    raw-TCP services are up to test."""
    from hexgraph.engine.rehost import RehostError, rehost_firmware
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            surface = rehost_firmware(s, s.get(Project, t.project_id), t, brand=brand)
        except PolicyViolation:
            return {"error": "rehosting not permitted — enable features.rehost in Settings"}
        except RehostError as exc:
            return {"error": str(exc)}
        ch = (surface.metadata_json or {}).get("channel", {})
        rehost_info = ch.get("rehost") or {}
        return {"surface_id": surface.id, "name": surface.name, "base_url": ch.get("base_url"),
                "rehost": rehost_info,
                "remote_target_id": rehost_info.get("remote_target_id"),
                "ports": rehost_info.get("ports", [])}


def register_remote(project_id: str, host: str, port: int | None = None, username: str = "root",
                    transport: str = "ssh", name: str | None = None) -> dict:
    """Register a LIVE remote device (a physical box on the bench, or a rehosted device) as a
    `remote` target reached over SSH/telnet — then run read-only analysis on it with
    remote_list_files / remote_read_file / remote_run. Credentials are NOT passed here: the
    operator sets them via env (HEXGRAPH_REMOTE_PASSWORD/KEY) or config.toml [remote], read
    only at connect (never stored). Requires features.remote."""
    from hexgraph.engine.remote import register_remote_target

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            t = register_remote_target(s, project, host, port=port, username=username,
                                       transport=transport, name=name)
        except ValueError as exc:
            return {"error": str(exc)}
        return {"id": t.id, "name": t.name, "kind": t.kind.value,
                "channel": (t.metadata_json or {}).get("channel")}


def _remote_op(target_id: str, **kw) -> dict:
    from hexgraph.engine.remote import run_remote
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return run_remote(s, s.get(Project, t.project_id), t, **kw)
        except PolicyViolation:
            return {"error": "remote access not permitted — enable features.remote in Settings"}
        except ValueError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"remote op failed: {exc}"}


def remote_list_files(target_id: str, path: str = "/", max_depth: int = 3,
                      max_entries: int = 2000) -> dict:
    """Enumerate files on a live remote target (SSH/telnet) under `path` (bounded depth/count)
    — like list_filesystem for a box you don't have firmware for. Read-only. features.remote."""
    return _remote_op(target_id, op="list_files", path=path)


def remote_read_file(target_id: str, path: str, max_bytes: int | None = None) -> dict:
    """Read ONE file from a live remote target (bounded; text as-is, binary as hex) — configs,
    scripts, keys, /etc/passwd. Read-only, the device's own bytes. features.remote."""
    return _remote_op(target_id, op="read_file", path=path, max_bytes=max_bytes)


def remote_run(target_id: str, tool: str, path: str | None = None) -> dict:
    """Run ONE allowlisted READ-ONLY recon tool on a live remote target — `tool` in
    {uname,id,ps,netstat,mount,ifconfig,df,env,passwd,release,ls}. No arbitrary shell; a `path`
    (for ls) is shell-quoted. The same kinds of recon we'd run on a rehosted rootfs. features.remote."""
    if tool == "ls":
        return _remote_op(target_id, op="ls", path=path or "/")
    return _remote_op(target_id, op="run_tool", tool=tool, path=path)


def remote_launch(target_id: str, path: str, args: list | None = None) -> dict:
    """Start a service on a live remote/rehosted device that didn't auto-start — by BINARY
    PATH (+ optional args), backgrounded — so its socket comes up and you can test it live
    (e.g. a rehosted firmware's vulnerable daemon that emulation didn't launch). `path` and
    each arg are shell-quoted; this is the one non-read-only remote op (no arbitrary shell).
    Then reach it with tcp_request / verify_poc (a `tcp` spec) on its port. Returns the launch
    output (e.g. the pid). features.remote; egress pinned to the device + audited."""
    return _remote_op(target_id, op="launch", path=path, args=args or [])


def tcp_request(target_id: str, port: int, payload: str | None = None,
                read_bytes: int | None = None) -> dict:
    """Talk to a raw TCP service on a live device (rehosted surface or `remote` target) — the
    non-HTTP analogue of http_request. Connect to the device's `<port>` (reached through the
    emulator netns when rehosted), optionally send `payload` bytes, and read the response
    (bounded). Omit `payload` to just grab a banner. Use it to fingerprint a listening
    `socket`, or to drive a binary-protocol bug; to PROVE one, use verify_poc with a `tcp`
    spec ({transport:"tcp", port, payload:"…{{NONCE}}…", oracle:{type:"response_contains",
    value:"{{NONCE}}"}}) — the probe strips your sent bytes before matching, so a reflected
    payload can't forge it. Bounded to the device's loopback/private host:port, audited.
    Requires features.network."""
    from hexgraph.engine.surfaces import run_tcp_probe
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            return run_tcp_probe(s, s.get(Project, t.project_id), t, port=int(port),
                                 payload=payload, read_bytes=read_bytes)
        except PolicyViolation as exc:
            return {"error": f"not permitted: {exc}"}
        except ValueError as exc:
            return {"error": str(exc)}


def http_request(target_id: str, method: str, path: str, params: dict | None = None,
                 headers: dict | None = None, body=None, json_body: bool = False,
                 session: str | None = None) -> dict:
    """Send ONE crafted HTTP request to a registered web surface and return the response
    (status, headers, and the body, capped at 64 KiB) — your hands for live web testing:
    log in, probe an auth check, fire an injection payload, read what comes back. `body`
    is form-encoded by default; set json_body=true to send it as JSON.

    Pass `session` (any label, e.g. "admin") to keep a COOKIE JAR across calls: cookies the
    server sets are remembered and re-sent on the next http_request with the same label, so
    a free-form auth flow works — log in once, then explore protected routes — without
    copying the session cookie by hand. The response lists the jar's cookie names in
    `session_cookies`. (For a single self-contained PoC, verify_poc's multi-step `steps`
    still carries cookies within one run; `session` is for interactive, multi-call probing.)

    Egress is bounded and audited exactly like web_recon: it runs in the sandbox, follows
    no redirects, and the destination must be the surface's own loopback/private host.
    Requires features.network enabled in Settings."""
    from hexgraph.engine.surfaces import run_http_request
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        req = {"method": method, "path": path, "params": params or None,
               "headers": headers or None, "body": body, "json": bool(json_body)}
        req = {k: v for k, v in req.items() if v is not None}
        try:
            return run_http_request(s, s.get(Project, t.project_id), t, request=req,
                                    http_session=session)
        except PolicyViolation:
            return {"error": "egress not permitted — enable features.network in Settings (bounded, local-only)"}
        except ValueError as exc:
            return {"error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"request failed: {exc}"}


def verify_poc(target_id: str, poc: dict, finding_id: str | None = None) -> dict:
    """Prove an exploit really works and report verified true/false. Two flavours, chosen
    by the target:
    - **binary target** → executes it IN THE SANDBOX. Spec: {argv?, env?, stdin?, timeout?,
      oracle:{type:"output_contains|exit_code|exit_nonzero|crash", value}}. Requires
      features.poc enabled.
    - **web surface** (a web_app registered with register_surface) → sends HTTP step(s).
      Spec: {steps:[{method,path,params?,headers?,body?,json?}, ...],
      oracle:{type:"body_contains|status_is|status_differs", value}}. Cookies carry across
      steps, so an auth flow works (e.g. step 1 POST /api/login with the bypass cred → step
      2 GET the protected route; oracle = body_contains the secret only an authed user
      sees). Requires features.network enabled (bounded local-only egress, audited).

    For an UNFORGEABLE check put {{NONCE}} in BOTH the injected command/payload and an
    `output_contains`/`body_contains` oracle value — HexGraph substitutes a fresh random
    token, so a match proves the injected behaviour actually happened (not something the
    model could fabricate).

    Pass `finding_id` to attach the result to that finding (its evidence.extra.poc +
    .verification) so it shows as `verified` in list_findings — the typed home for a
    confirmed exploit. ALWAYS attach: a confirmed vuln finding must carry its verified PoC."""
    from hexgraph.db.models import Finding
    from hexgraph.engine.poc import verify_poc as _verify
    from hexgraph.policy import PolicyViolation

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        try:
            r = _verify(s, s.get(Project, t.project_id), t, poc)
        except PolicyViolation:
            from hexgraph.engine.poc import _is_web
            return {"error": ("egress not permitted — enable features.network in Settings to verify a web PoC"
                              if _is_web(t) else
                              "execution not permitted — enable features.poc in Settings to verify PoCs")}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"verification failed: {exc}"}
        if finding_id:
            f = s.get(Finding, finding_id)
            if f is not None:
                ev = dict(f.evidence_json or {})
                extra = dict(ev.get("extra") or {})
                # Store the ORIGINAL spec (with its {{NONCE}} placeholder intact), not the
                # nonce-substituted copy verify_poc ran — otherwise the placeholder is gone
                # and a later re-verify carries a stale literal nonce that can never match.
                extra["poc"] = poc
                extra["verification"] = {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                                         "exit_code": r.get("exit_code"), "nonce": r.get("nonce"),
                                         "output": (r.get("output") or "")[:2000]}
                ev["extra"] = extra
                if not ev.get("reproducer"):
                    ev["reproducer"] = json.dumps(poc)
                f.evidence_json = ev
        return {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                "exit_code": r.get("exit_code"), "output": (r.get("output") or "")[:4000],
                "attached_to": finding_id if finding_id else None}


def merge_duplicates(project_id: str) -> dict:
    """Collapse duplicate binaries/nodes (e.g. sym.foo == foo) in a project, moving
    all edges/findings/annotations to the keeper. Safe to call anytime."""
    from hexgraph.engine.nodemerge import merge_duplicates as _merge

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        return _merge(s, project_id)


def link_same_code(project_id: str) -> dict:
    """Cross-target n-day primitive: link function nodes that share identical code
    (same content_hash) across DIFFERENT binaries with a `similar_to` edge. After you
    confirm a bug in one binary, call this to find the same routine reused in other
    firmware components, then check each for the same flaw. Returns the matched pairs."""
    from hexgraph.db.models import Edge, EdgeType
    from hexgraph.engine.crosstarget import link_same_code as _link

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            return {"error": "project not found"}
        created = _link(s, project_id)
        s.flush()

        def findings_about(node_id: str) -> list[str]:
            # Findings attached to this node via an `about` edge.
            rows = (s.query(Edge)
                    .filter(Edge.project_id == project_id, Edge.type == EdgeType.about.value,
                            Edge.src_kind == "finding", Edge.dst_kind == "node", Edge.dst_id == node_id)
                    .all())
            return [r.src_id for r in rows]

        def side(n: Node) -> dict:
            fids = findings_about(n.id)
            return {"node_id": n.id, "target_id": n.target_id, "finding_ids": fids,
                    "has_findings": bool(fids)}

        matches = []
        edges = (s.query(Edge)
                 .filter(Edge.project_id == project_id, Edge.type == EdgeType.similar_to.value)
                 .limit(200).all())
        for e in edges:
            a, b = s.get(Node, e.src_id), s.get(Node, e.dst_id)
            if a is None or b is None:
                continue
            matches.append({"function": a.name, "a": side(a), "b": side(b)})
        return {"edges_created": created, "matches": matches,
                "hint": "If one side has_findings and the other doesn't, the bug likely "
                        "propagates — use propagate_finding(finding_id, target_id) on the bare side."}


def run_task(target_id: str, type: str, objective: str | None = None, params: dict | None = None) -> dict:
    """Run a HexGraph task synchronously (recon/static_analysis/harness_generation/
    fuzzing/…) and return its status + the findings it produced."""
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        project = s.get(Project, t.project_id)
        project_id = project.id
        task = create_task(s, project=project, target_id=t.id, type=type, objective=objective,
                           backend=project.llm_backend.value, params=params or {})
        task_id = task.id
    status = run_task_sync(task_id)
    with session_scope() as s:
        # Fold any duplicate function/symbol nodes (e.g. an agent's `foo` colliding with a
        # decompiler-seeded `sym.foo`) so the graph converges instead of accumulating dupes.
        from hexgraph.engine.nodemerge import merge_duplicate_nodes
        merged = merge_duplicate_nodes(s, project_id)
        findings = s.query(Finding).filter(Finding.task_id == task_id).all()
        out = {"task_id": task_id, "status": status,
               "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in findings]}
        if merged:
            out["nodes_merged"] = merged
        return out


# Tool groups let a user expose only what they need so an agent's context isn't
# polluted with tools they won't use:
#   read  — inspect the graph / target (no side effects)
#   write — populate the graph (findings, nodes, edges, hypotheses, annotations)
#   run   — execute HexGraph tasks in the sandbox (recon/analysis/fuzz)
GROUPS = ("read", "write", "run")

_CATALOG = [
    ("read", "list_projects", list_projects, "List HexGraph projects (id, name, backend) — start here to find the project_id other tools need.",
     {"type": "object", "properties": {}}),
    ("read", "list_targets", list_targets, "List targets in a project (binaries, libraries, firmware children, and web_app surfaces) with id/kind/arch — the entry point for picking what to analyze.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "target_facts", target_facts, "Recon facts for a target (imports/exports/mitigations).",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_functions", list_functions, "List the functions in a target (name + address), discovered in the sandbox — use to find what to decompile next.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "decompile_function", decompile_function, "Decompile one function to pseudo-C in the sandbox (radare2/Ghidra) — the primary way to read a target's logic without touching its bytes.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "disassemble", disassemble, "Disassemble one function to assembly in the sandbox — when you need instruction-level detail the decompiler smooths over.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "read_imports", read_imports, "Imports, libraries, and mitigation flags of a target.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_strings", list_strings, "Notable strings in a target (optional substring filter).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "pattern": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "xrefs", xrefs, "Cross-references: which functions CALL a symbol/sink and where (omit `symbol` to map dangerous sinks, format-string sinks, AND network/socket surface bind/listen/connect/recv). Trace a sink back to its caller, or find listen/connect sites to model as socket nodes.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "symbol": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "search", search, "Search the project graph (findings + functions).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "q": {"type": "string"}}, "required": ["project_id", "q"]}),
    ("read", "list_findings", list_findings, "Existing findings in a project (with finding_type + verified flag).",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "get_finding", get_finding, "Read ONE finding in full incl. complete evidence (evidence.extra holds the verify_poc result) — confirm a write landed (finding analog of get_node).",
     {"type": "object", "properties": {"finding_id": {"type": "string"}}, "required": ["finding_id"]}),
    ("read", "get_node", get_node, "Read a node back in full (address + attrs/params you set) — confirm what you wrote.",
     {"type": "object", "properties": {"node_id": {"type": "string"}}, "required": ["node_id"]}),
    ("read", "list_nodes", list_nodes, "List graph nodes (filter by target/node_type) with address + attrs.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "node_type": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_edges", list_edges, "List edges (optionally those touching a node) to confirm the dataflow/relationships you wired.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_egress", list_egress, "The egress audit log — every outbound network action (allowed/denied) the bounded-network tier recorded for the project.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_sockets", list_sockets, "List socket endpoints (tcp/udp/unix/…) with who listens/connects on each — the firmware's network map (server↔client over shared sockets).",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "list_filesystem", list_filesystem, "List a firmware target's unpacked filesystem (paths/sizes/which are ELFs or already child targets) — find config files, scripts, keys, web assets to read with read_file.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "read_file", read_file, "Read ONE file from a firmware target's unpacked filesystem (config/script/key/web template — NOT the raw binary; use decompile_function for code). Bounded 256 KiB, path-traversal safe; text as-is, binary as hex. `path` is relative to the extracted root (see list_filesystem).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}}, "required": ["target_id", "path"]}),
    ("read", "get_schemas", get_schemas, "The write-API contract: allowed enums, the Finding shape, per-type NODE attribute schemas (what to populate, the sink-vs-symbol rule), edge/socket attribute schemas, and the active decompiler. Read before record_finding/create_node/create_edge/annotate to avoid guessing.",
     {"type": "object", "properties": {}}),
    ("write", "record_finding", record_finding, "Record a new finding (the `finding` dict must match the Finding schema — call get_schemas). `finding_type` is a SEPARATE arg (vulnerability|poc|…), not a finding field. Pass task_id in delegate mode.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "finding": {"type": "object"}, "finding_type": {"type": "string"}, "task_id": {"type": "string"}}, "required": ["project_id", "target_id", "finding"]}),
    ("write", "update_finding", update_finding, "Update an EXISTING finding in place (status/severity/confidence/human_notes) — e.g. confirm it after a PoC verifies. Don't create a duplicate.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "status": {"type": "string"}, "severity": {"type": "string"}, "confidence": {"type": "string"}, "human_notes": {"type": "string"}}, "required": ["finding_id"]}),
    ("write", "create_node", create_node, "Add a node (function/symbol/string/struct/input/sink/endpoint/param/hypothesis/pattern). ALWAYS pass target_id for target-bound types (else it's an orphan); it auto-links to its target. Populate `attrs` with the type's recommended fields from get_schemas.node_attribute_schemas (function->summary+params, input->source, sink->operation+why). A dangerous call (system/strcpy) is a symbol/function node with is_sink=true — NOT a separate `sink` node. Pass `address` for code nodes.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_type": {"type": "string"}, "name": {"type": "string"}, "target_id": {"type": "string"}, "address": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "node_type", "name"]}),
    ("write", "create_edge", create_edge, "Connect two graph entities (target|node|finding|task) with a typed, attributed edge. `attrs` carries edge-type facts (see get_schemas: e.g. calls→call_sites/arg_constraints, listens_on→address). merge=True accumulates list attrs. A hypothesis is a 'node'; or use link_evidence to attach a finding to one.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "src_kind": {"type": "string"}, "src_id": {"type": "string"}, "dst_kind": {"type": "string"}, "dst_id": {"type": "string"}, "type": {"type": "string"}, "attrs": {"type": "object"}, "merge": {"type": "boolean"}}, "required": ["project_id", "src_kind", "src_id", "dst_kind", "dst_id", "type"]}),
    ("write", "update_edge", update_edge, "Add/update attributes on an EXISTING edge by id (merge=True accumulates list attrs like call_sites; merge=False replaces). See get_schemas for per-type attributes.",
     {"type": "object", "properties": {"edge_id": {"type": "string"}, "attrs": {"type": "object"}, "merge": {"type": "boolean"}}, "required": ["edge_id", "attrs"]}),
    ("write", "create_socket", create_socket, "Create/reuse a SOCKET node (network/IPC endpoint shared across binaries). kind=tcp|udp|unix|io|…, give port or name. A server listens_on it, a client connects_to it — both resolve to one node.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "kind": {"type": "string"}, "port": {"type": ["integer", "string"]}, "name": {"type": "string"}, "bind_addr": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id"]}),
    ("write", "create_hypothesis", create_hypothesis, "Record a research hypothesis anchored to a target.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "statement": {"type": "string"}, "rationale": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "statement"]}),
    ("write", "link_evidence", link_evidence, "Attach a finding to a hypothesis as supporting/refuting evidence (recomputes the hypothesis status). relation = supports|refutes. This is how you confirm a hypothesis.",
     {"type": "object", "properties": {"hypothesis_id": {"type": "string"}, "finding_id": {"type": "string"}, "relation": {"type": "string"}}, "required": ["hypothesis_id", "finding_id", "relation"]}),
    ("write", "set_hypothesis_status", set_hypothesis_status, "Pin a hypothesis verdict: confirmed|rejected|open|supported|refuted. Pass `rationale` to record why.",
     {"type": "object", "properties": {"hypothesis_id": {"type": "string"}, "status": {"type": "string"}, "rationale": {"type": "string"}}, "required": ["hypothesis_id", "status"]}),
    ("write", "annotate", annotate, "Attach a note/tag/rename/type_decl to a graph entity (agent proposal, pending analyst approval). For parameters/explanations on a function, prefer create_node attrs.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_kind": {"type": "string"}, "node_id": {"type": "string"}, "kind": {"type": "string"}, "value": {"type": "string"}}, "required": ["project_id", "node_kind", "node_id", "kind", "value"]}),
    ("write", "merge_duplicates", merge_duplicates, "Collapse duplicate binaries/nodes (e.g. sym.foo == foo) in a project, preserving all edges/findings.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "archive_node", archive_node, "Soft-remove a node from the graph (REVERSIBLE): hides the node and the edges touching it. Re-adding the same node (create_node/a task) or restore_node brings it and its edges back — nothing is deleted.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id", "node_id"]}),
    ("write", "restore_node", restore_node, "Un-archive a previously soft-removed node; its hidden edges reappear.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_id": {"type": "string"}}, "required": ["project_id", "node_id"]}),
    ("write", "delete_edge", delete_edge, "Permanently delete ONE edge by id (hard delete — recreate with create_edge to restore). To remove a node's edges reversibly, archive the node instead.",
     {"type": "object", "properties": {"edge_id": {"type": "string"}}, "required": ["edge_id"]}),
    ("write", "archive_target", archive_target, "Soft-remove a target + its whole subtree (children/nodes/findings) from the graph (REVERSIBLE) — declutter an irrelevant component; re-ingesting the bytes or restore_target brings it back. (Whole-project deletion is operator-only, not an MCP tool.)",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "target_id"]}),
    ("write", "restore_target", restore_target, "Un-archive a previously soft-removed target subtree (its nodes/findings reappear).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "target_id"]}),
    ("write", "link_same_code", link_same_code, "Cross-target n-day primitive: link functions with identical code (same content_hash) across DIFFERENT binaries via similar_to edges, and return the matches (each side flags has_findings). Run after confirming a bug to find the same routine reused elsewhere.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "propagate_finding", propagate_finding, "N-day: clone an existing finding onto another binary that shares the same code (per link_same_code) as a fresh finding to triage, wired derived_from→ the source. Avoids re-typing the whole finding for 'same bug, other binary'.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "target_id": {"type": "string"}, "function": {"type": "string"}, "notes": {"type": "string"}}, "required": ["finding_id", "target_id"]}),
    ("run", "verify_poc", verify_poc, "Prove an exploit and report verified true/false. Binary target -> runs it in the sandbox (spec {argv?,env?,stdin?,oracle:{output_contains|exit_code|crash}}, needs features.poc). Web surface -> sends HTTP steps (spec {steps:[{method,path,body?,...}],oracle:{body_contains|status_is|status_differs}}, cookies carry across steps for auth flows, needs features.network). Raw TCP service -> spec {transport:'tcp', port, payload, oracle:{response_contains}} sends payload to the device's port and matches the response (needs features.network); use for a rehosted/remote device's non-HTTP daemon. Put {{NONCE}} in BOTH the payload and the oracle value for an unforgeable check. Pass finding_id to attach the result (always do this for a confirmed vuln).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "poc": {"type": "object"}, "finding_id": {"type": "string"}}, "required": ["target_id", "poc"]}),
    ("run", "http_request", http_request, "Send ONE crafted HTTP request to a registered web surface and return {status,headers,body} (body capped at 64 KiB) — your hands for live web testing (log in, probe an auth check, fire an injection payload, read the response). body is form-encoded unless json_body=true. Pass `session` (any label) to keep a cookie jar across calls so an auth flow works (log in, then explore protected routes) — response lists the jar in session_cookies. Bounded, sandboxed, local-only egress, audited. Requires features.network.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "method": {"type": "string"}, "path": {"type": "string"}, "params": {"type": "object"}, "headers": {"type": "object"}, "body": {}, "json_body": {"type": "boolean"}, "session": {"type": "string"}}, "required": ["target_id", "method", "path"]}),
    ("run", "tcp_request", tcp_request, "Talk to a raw TCP service on a live device (rehosted surface or remote target) — the non-HTTP http_request. Connect to the device's port (through the emulator netns when rehosted), optionally send `payload` bytes, read the bounded response; omit payload to banner-grab. Fingerprint a listening socket, or drive a binary-protocol bug — to PROVE one use verify_poc with a tcp spec (it strips your sent bytes before matching). Bounded to the device host:port, audited. Requires features.network.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "port": {"type": "integer"}, "payload": {"type": "string"}, "read_bytes": {"type": "integer"}}, "required": ["target_id", "port"]}),
    ("run", "remote_launch", remote_launch, "Start a service on a live remote/rehosted device that didn't auto-start, by BINARY PATH (+ optional args), backgrounded — so its socket comes up for live testing (e.g. a rehosted firmware's vulnerable daemon emulation didn't launch). path + args are shell-quoted; the one non-read-only remote op (no arbitrary shell). Then reach it with tcp_request / verify_poc (tcp spec). Requires features.remote; egress pinned + audited.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "args": {"type": "array"}}, "required": ["target_id", "path"]}),
    ("run", "ingest", ingest, "Ingest a binary/firmware from a local path as a target (firmware unpacks into children); creates a project if none given.",
     {"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}, "project_id": {"type": "string"}}, "required": ["path"]}),
    ("run", "run_task", run_task, "Run a HexGraph task and return its findings. Types: recon, static_analysis, harness_generation, fuzzing, poc, surface_recon (offline route->handler map from a supplied spec), web_discover (LIVE crawl that DISCOVERS routes/params from links+forms+common paths — use this on a rehosted/registered surface, needs features.network), web_recon (live liveness probe, needs features.network).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "type": {"type": "string"}, "objective": {"type": "string"}, "params": {"type": "object"}}, "required": ["target_id", "type"]}),
    ("run", "rehost", rehost, "Boot a FIRMWARE target under full-system emulation — auto-selects qemu+KVM for a full-OS disk image (.vmdk/.qcow2/partitioned .img) or FirmAE for a vendor blob (squashfs/cramfs/…) — and register its live web server as a web_app surface child, then assess the running device with surface_recon/web_discover/http_request/verify_poc, fused to the firmware's static graph. For a FirmAE/vendor image, pass `brand` (linksys/netgear/dlink/tplink/tenda/…) if it reports it couldn't bring up the network (FirmAE's profile is vendor-keyed; auto-inferred when the firmware names its vendor). Requires features.rehost (boot) + features.network (assess). Heavy + best-effort.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "brand": {"type": "string"}}, "required": ["target_id"]}),
    ("run", "register_remote", register_remote, "Register a LIVE remote device (physical box or rehosted device) as a `remote` target reached over SSH/telnet — then analyze it read-only with remote_list_files/remote_read_file/remote_run. Creds come from operator env/config (HEXGRAPH_REMOTE_PASSWORD/KEY or config.toml [remote]), never stored. Requires features.remote.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "host": {"type": "string"}, "port": {"type": "integer"}, "username": {"type": "string"}, "transport": {"type": "string"}, "name": {"type": "string"}}, "required": ["project_id", "host"]}),
    ("run", "remote_list_files", remote_list_files, "Enumerate files on a live remote target (SSH/telnet) under `path` (bounded depth/count) — list_filesystem for a box you don't have firmware for. Read-only. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "max_depth": {"type": "integer"}, "max_entries": {"type": "integer"}}, "required": ["target_id"]}),
    ("run", "remote_read_file", remote_read_file, "Read ONE file from a live remote target (bounded; text as-is, binary as hex) — configs/scripts/keys//etc/passwd. The device's own bytes, read-only. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "path": {"type": "string"}, "max_bytes": {"type": "integer"}}, "required": ["target_id", "path"]}),
    ("run", "remote_run", remote_run, "Run ONE allowlisted READ-ONLY recon tool on a live remote target — tool in {uname,id,ps,netstat,mount,ifconfig,df,env,passwd,release,ls}. No arbitrary shell (a path for ls is shell-quoted). Same recon we'd run on a rehosted rootfs. Requires features.remote.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "tool": {"type": "string"}, "path": {"type": "string"}}, "required": ["target_id", "tool"]}),
    ("run", "register_surface", register_surface, "Register a WEB attack surface (web_app target via an HTTP Channel, no bytes); pass an optional offline route spec, then run_task(surface_recon) to map endpoints/params + routes_to→handler edges. Offline (no egress).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "base_url": {"type": "string"}, "name": {"type": "string"}, "endpoints": {"type": "array"}}, "required": ["project_id", "base_url"]}),
]


def catalog(enabled_groups: set[str] | None = None) -> list[dict]:
    """Tool specs for the MCP server, filtered to the enabled groups (default: all).
    Trimming groups keeps the agent's tool list small when only part of HexGraph
    is wanted (e.g. write-only, to populate the graph from a UI-driven session)."""
    groups = set(GROUPS) if enabled_groups is None else enabled_groups
    return [
        {"group": g, "name": n, "fn": fn, "description": d, "schema": sch}
        for (g, n, fn, d, sch) in _CATALOG if g in groups
    ]
