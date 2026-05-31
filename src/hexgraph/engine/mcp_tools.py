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

from typing import Any

from hexgraph.db.models import Finding, Project, Target
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


def target_facts(target_id: str) -> dict:
    with session_scope() as s:
        t = s.get(Target, target_id)
        if t is None:
            return {"error": "target not found"}
        meta = t.metadata_json or {}
        return {"id": t.id, "name": t.name, "kind": t.kind.value, "format": t.format, "arch": t.arch,
                "imports": meta.get("imports", []), "exports": meta.get("exports", []),
                "libraries": meta.get("libraries", []), "mitigations": meta.get("mitigations", {})}


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
        return [{"id": f.id, "title": f.title, "severity": f.severity, "category": f.category,
                 "status": f.status, "target_id": f.target_id,
                 "function": (f.evidence_json or {}).get("function")} for f in rows]


def record_finding(project_id: str, target_id: str, finding: dict, task_id: str | None = None) -> dict:
    """Persist an agent-produced finding (validated against the frozen schema).
    Pass the HexGraph `task_id` you were given (delegate mode) to attribute it to
    that task; otherwise a fresh agent_delegate task is created for provenance."""
    from hexgraph.db.models import Task
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.tasks import create_task

    try:
        model = FModel.model_validate(finding)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"finding does not match the schema: {exc}"}
    with session_scope() as s:
        project = s.get(Project, project_id)
        target = s.get(Target, target_id)
        if project is None or target is None:
            return {"error": "project or target not found"}
        task = s.get(Task, task_id) if task_id else None
        if task is None or task.project_id != project.id:
            task = create_task(s, project=project, target_id=target.id, type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id, finding=model)
        row.origin = "agent"
        return {"id": row.id, "title": row.title, "severity": row.severity}


def create_node(project_id: str, node_type: str, name: str, target_id: str | None = None,
                attrs: dict | None = None) -> dict:
    """Add a node to the graph (function/symbol/string/struct/hypothesis/pattern).
    Enforces the same invariants as the UI (code nodes require an existing target)."""
    from hexgraph.engine.authoring import InvariantError, create_node as _create

    with session_scope() as s:
        project = s.get(Project, project_id)
        if project is None:
            return {"error": "project not found"}
        try:
            n = _create(s, project, node_type=node_type, name=name, target_id=target_id, attrs=attrs)
        except InvariantError as exc:
            return {"error": str(exc)}
        return {"id": n.id, "node_type": n.node_type, "name": n.name, "target_id": n.target_id}


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


def verify_poc(target_id: str, poc: dict) -> dict:
    """Execute a proof-of-concept against a target IN THE SANDBOX and report whether
    it worked. The spec is {argv?, env?, stdin?, timeout?, oracle:{type,value}};
    put {{NONCE}} in the injected command + the oracle value and HexGraph
    substitutes a fresh random token, so a verified output_contains oracle proves
    real command execution. Requires PoC/fuzzing enabled in Settings."""
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
        return {"verified": bool(r.get("verified")), "detail": r.get("detail"),
                "exit_code": r.get("exit_code"), "output": (r.get("output") or "")[:4000]}


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
    ("read", "search", search, "Search the project graph (findings + functions).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "q": {"type": "string"}}, "required": ["project_id", "q"]}),
    ("read", "list_findings", list_findings, "Existing findings in a project.",
     {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}),
    ("write", "record_finding", record_finding, "Record a new finding (must match the Finding schema). Pass the given task_id in delegate mode.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "finding": {"type": "object"}, "task_id": {"type": "string"}}, "required": ["project_id", "target_id", "finding"]}),
    ("write", "create_node", create_node, "Add a node (function/symbol/string/struct/hypothesis/pattern) to the graph.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_type": {"type": "string"}, "name": {"type": "string"}, "target_id": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "node_type", "name"]}),
    ("write", "create_edge", create_edge, "Connect two graph entities (target|node|finding|task).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "src_kind": {"type": "string"}, "src_id": {"type": "string"}, "dst_kind": {"type": "string"}, "dst_id": {"type": "string"}, "type": {"type": "string"}, "attrs": {"type": "object"}}, "required": ["project_id", "src_kind", "src_id", "dst_kind", "dst_id", "type"]}),
    ("write", "create_hypothesis", create_hypothesis, "Record a research hypothesis anchored to a target.",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "statement": {"type": "string"}, "rationale": {"type": "string"}, "target_id": {"type": "string"}}, "required": ["project_id", "statement"]}),
    ("write", "annotate", annotate, "Attach a note/tag/rename to a graph entity (agent proposal).",
     {"type": "object", "properties": {"project_id": {"type": "string"}, "node_kind": {"type": "string"}, "node_id": {"type": "string"}, "kind": {"type": "string"}, "value": {"type": "string"}}, "required": ["project_id", "node_kind", "node_id", "kind", "value"]}),
    ("run", "verify_poc", verify_poc, "Execute a proof-of-concept against a target in the sandbox and report verified true/false (use {{NONCE}} in the injected command + oracle for an unforgeable check). Requires PoC enabled.",
     {"type": "object", "properties": {"target_id": {"type": "string"}, "poc": {"type": "object"}}, "required": ["target_id", "poc"]}),
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
