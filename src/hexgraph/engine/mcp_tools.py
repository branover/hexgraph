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
from typing import Any

from hexgraph.db.models import Finding, Node, Project, Target
from hexgraph.db.session import session_scope
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
        q = s.query(Node).filter(Node.project_id == project_id)
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
    """Existing findings, so the agent doesn't re-report what's already known."""
    with session_scope() as s:
        rows = s.query(Finding).filter(Finding.project_id == project_id).all()
        out = []
        for f in rows:
            ev = f.evidence_json or {}
            verified = bool(((ev.get("extra") or {}).get("verification") or {}).get("verified"))
            out.append({"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
                        "status": f.status, "finding_type": f.finding_type, "verified": verified,
                        "target_id": f.target_id, "function": ev.get("function")})
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
        verified = bool(((ev.get("extra") or {}).get("verification") or {}).get("verified"))
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
    """Add a node to the graph (function/symbol/string/struct/hypothesis/pattern/
    input/sink). Enforces the UI invariants (code nodes require an existing target).
    Pass `address` for a function's location in the binary; put parameters and
    explanations in `attrs` (e.g. {"params":[{"name":"host","type":"char*","note":
    "attacker-controlled query field"}], "summary":"..."})."""
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
                type: str, attrs: dict | None = None) -> dict:
    """Connect two graph entities (target|node|finding|task). Both must exist."""
    from hexgraph.engine.authoring import InvariantError, create_edge as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            e = _create(s, project, src_kind=src_kind, src_id=src_id, dst_kind=dst_kind,
                        dst_id=dst_id, type=type, attrs=attrs)
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": e.id, "type": e.type, "src_id": e.src_id, "dst_id": e.dst_id}


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


def get_schemas() -> dict:
    """The write-API contract: allowed enums + the Finding shape. Read this before
    record_finding / create_node / create_edge / annotate to avoid guessing."""
    import typing

    from hexgraph.db.models import EdgeType, FindingStatus, NodeType
    from hexgraph.engine.annotations import KINDS as ANN_KINDS, NODE_KINDS as ANN_NODE_KINDS
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
        "edge_types": [t.value for t in EdgeType],
        "edge_endpoint_kinds": ["target", "node", "finding", "task"],
        "edge_note": "A hypothesis IS a node (node_type='hypothesis'); link a finding to it with "
                     "dst_kind='node' + its id, or better use link_evidence(hypothesis_id, finding_id, "
                     "relation) which also updates the hypothesis status.",
        "link_evidence_relations": ["supports", "refutes", "confirms", "contradicts"],
        "link_evidence_note": "relation is supports|refutes (confirms→supports, contradicts→refutes are "
                              "accepted aliases). The hypothesis status is then recomputed from its "
                              "evidence; pin a hard verdict with set_hypothesis_status(id,'confirmed').",
        "create_node_note": "Function/symbol/struct identity is (target, normalized name) — recon "
                            "pre-materializes function nodes (address=null). create_node on an existing "
                            "one MERGES: it fills a missing address and unions attrs (it won't overwrite "
                            "a known address). The returned address/attrs show what actually landed.",
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
    from hexgraph.engine.pipeline import analyze_target, ingest_and_analyze
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


def verify_poc(target_id: str, poc: dict, finding_id: str | None = None) -> dict:
    """Execute a proof-of-concept against a target IN THE SANDBOX and report whether
    it worked. The spec is {argv?, env?, stdin?, timeout?, oracle:{type,value}};
    put {{NONCE}} in the injected command + the oracle value and HexGraph
    substitutes a fresh random token, so a verified output_contains oracle proves
    real command execution. Requires PoC/fuzzing enabled in Settings.

    Pass `finding_id` to attach the result to that finding (its evidence.extra.poc
    + .verification) so it shows as verified in list_findings — the typed home for
    a confirmed exploit."""
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
            return {"error": "execution not permitted — enable features.poc in Settings to verify PoCs"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"verification failed: {exc}"}
        if finding_id:
            f = s.get(Finding, finding_id)
            if f is not None:
                ev = dict(f.evidence_json or {})
                extra = dict(ev.get("extra") or {})
                extra["poc"] = r.get("spec")
                extra["verification"] = {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                                         "exit_code": r.get("exit_code"), "nonce": r.get("nonce"),
                                         "output": (r.get("output") or "")[:2000]}
                ev["extra"] = extra
                if not ev.get("reproducer"):
                    ev["reproducer"] = json.dumps(r.get("spec"))
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
        task = create_task(s, project=project, target_id=t.id, type=type, objective=objective,
                           backend=project.llm_backend.value, params=params or {})
        task_id = task.id
    status = run_task_sync(task_id)
    with session_scope() as s:
        findings = s.query(Finding).filter(Finding.task_id == task_id).all()
        return {"task_id": task_id, "status": status,
                "findings": [{"id": f.id, "title": f.title, "severity": f.severity} for f in findings]}


# Tool groups let a user expose only what they need so an agent's context isn't
# polluted with tools they won't use:
#   read  — inspect the graph / target (no side effects)
#   write — populate the graph (findings, nodes, edges, hypotheses, annotations)
#   run   — execute HexGraph tasks in the sandbox (recon/analysis/fuzz)
GROUPS = ("read", "write", "run")

_CATALOG = [
    ("read", "list_projects", list_projects, "List HexGraph projects.",
     {"type": "object", "properties": {}}),
    ("read", "list_targets", list_targets, "List targets (binaries) in a project.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("read", "target_facts", target_facts, "Recon facts for a target (imports/exports/mitigations).",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_functions", list_functions, "List functions in a target (sandboxed).",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "decompile_function", decompile_function, "Decompile a function to pseudo-C (sandboxed).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "disassemble", disassemble, "Disassemble a function (sandboxed).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}),
    ("read", "read_imports", read_imports, "Imports, libraries, and mitigation flags of a target.",
     {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "list_strings", list_strings, "Notable strings in a target (optional substring filter).",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "pattern": {"type": "string"}}, "required": ["target_id"]}),
    ("read", "xrefs", xrefs, "Cross-references: which functions CALL a symbol/sink and where (omit `symbol` to map all dangerous sinks). Trace a sink back to the code that reaches it.",
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
    ("read", "get_schemas", get_schemas, "The write-API contract: allowed enums + the Finding shape. Read before record_finding/create_node/create_edge/annotate to avoid guessing field names.",
     {"type": "object", "properties": {}}),
    ("write", "record_finding", record_finding, "Record a new finding (the `finding` dict must match the Finding schema — call get_schemas). `finding_type` is a SEPARATE arg (vulnerability|poc|…), not a finding field. Pass task_id in delegate mode.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "finding": {"type": "object"}, "finding_type": {"type": "string"}, "task_id": {"type": "string"}}, "required": ["project_id", "target_id", "finding"]}),
    ("write", "update_finding", update_finding, "Update an EXISTING finding in place (status/severity/confidence/human_notes) — e.g. confirm it after a PoC verifies. Don't create a duplicate.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "status": {"type": "string"}, "severity": {"type": "string"}, "confidence": {"type": "string"}, "human_notes": {"type": "string"}}, "required": ["finding_id"]}),
    ("write", "create_node", create_node, "Add a node (function/symbol/string/struct/hypothesis/pattern/input/sink). Pass `address` for a function's binary location; put parameters/explanations in `attrs`.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_type": {"type": "string"}, "name": {"type": "string"}, "target_id": {"type": "string"}, "address": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "node_type", "name"]}),
    ("write", "create_edge", create_edge, "Connect two graph entities (target|node|finding|task). A hypothesis is a 'node'; or use link_evidence to attach a finding to one.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "src_kind": {"type": "string"}, "src_id": {"type": "string"}, "dst_kind": {"type": "string"}, "dst_id": {"type": "string"}, "type": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "src_kind", "src_id", "dst_kind", "dst_id", "type"]}),
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
    ("write", "link_same_code", link_same_code, "Cross-target n-day primitive: link functions with identical code (same content_hash) across DIFFERENT binaries via similar_to edges, and return the matches (each side flags has_findings). Run after confirming a bug to find the same routine reused elsewhere.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "propagate_finding", propagate_finding, "N-day: clone an existing finding onto another binary that shares the same code (per link_same_code) as a fresh finding to triage, wired derived_from→ the source. Avoids re-typing the whole finding for 'same bug, other binary'.",
     {"type": "object", "properties": {"finding_id": {"type": "string"}, "target_id": {"type": "string"}, "function": {"type": "string"}, "notes": {"type": "string"}}, "required": ["finding_id", "target_id"]}),
    ("run", "verify_poc", verify_poc, "Execute a proof-of-concept against a target in the sandbox and report verified true/false (use {{NONCE}} in the injected command + oracle for an unforgeable check). Pass finding_id to attach the result. Requires PoC enabled.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "poc": {"type": "object"}, "finding_id": {"type": "string"}}, "required": ["target_id", "poc"]}),
    ("run", "ingest", ingest, "Ingest a binary/firmware from a local path as a target (firmware unpacks into children); creates a project if none given.",
     {"type": "object", "properties": {"path": {"type": "string"}, "name": {"type": "string"}, "project_id": {"type": "string"}}, "required": ["path"]}),
    ("run", "run_task", run_task, "Run a HexGraph task (recon/static_analysis/harness_generation/fuzzing) and return its findings.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "type": {"type": "string"}, "objective": {"type": "string"}, "params": {"type": "object"}}, "required": ["target_id", "type"]}),
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
