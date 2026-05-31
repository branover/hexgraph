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


def record_finding(project_id: str, target_id: str, finding: dict) -> dict:
    """Persist an agent-produced finding (validated against the frozen schema)."""
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
        # Attribute it to a task so provenance holds (agent-delegate origin).
        task = create_task(s, project=project, target_id=target.id, type="agent_delegate", backend="agent")
        row = persist_finding(s, project_id=project.id, target_id=target.id, task_id=task.id, finding=model)
        row.origin = "agent"
        return {"id": row.id, "title": row.title, "severity": row.severity}


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


# Tool catalog (name → (callable, description, input schema)) for the MCP server.
def catalog() -> list[dict]:
    return [
        {"name": "list_projects", "fn": list_projects, "description": "List HexGraph projects.",
         "schema": {"type": "object", "properties": {}}},
        {"name": "list_targets", "fn": list_targets, "description": "List targets (binaries) in a project.",
         "schema": {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}},
        {"name": "target_facts", "fn": target_facts, "description": "Recon facts for a target (imports/exports/mitigations).",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}},
        {"name": "list_functions", "fn": list_functions, "description": "List functions in a target (sandboxed).",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}},
        {"name": "decompile_function", "fn": decompile_function, "description": "Decompile a function to pseudo-C (sandboxed).",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}},
        {"name": "disassemble", "fn": disassemble, "description": "Disassemble a function (sandboxed).",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}, "function": {"type": "string"}}, "required": ["target_id", "function"]}},
        {"name": "read_imports", "fn": read_imports, "description": "Imports, libraries, and mitigation flags of a target.",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}}, "required": ["target_id"]}},
        {"name": "list_strings", "fn": list_strings, "description": "Notable strings in a target (optional substring filter).",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}, "pattern": {"type": "string"}}, "required": ["target_id"]}},
        {"name": "search", "fn": search, "description": "Search the project graph (findings + functions).",
         "schema": {"type": "object", "properties": {"project_id": {"type": "string"}, "q": {"type": "string"}}, "required": ["project_id", "q"]}},
        {"name": "list_findings", "fn": list_findings, "description": "Existing findings in a project.",
         "schema": {"type": "object", "properties": {"project_id": {"type": "string"}}, "required": ["project_id"]}},
        {"name": "record_finding", "fn": record_finding, "description": "Record a new finding (must match the Finding schema).",
         "schema": {"type": "object", "properties": {"project_id": {"type": "string"}, "target_id": {"type": "string"}, "finding": {"type": "object"}}, "required": ["project_id", "target_id", "finding"]}},
        {"name": "run_task", "fn": run_task, "description": "Run a HexGraph task (recon/static_analysis/harness_generation/fuzzing) and return its findings.",
         "schema": {"type": "object", "properties": {"target_id": {"type": "string"}, "type": {"type": "string"}, "objective": {"type": "string"}, "params": {"type": "object"}}, "required": ["target_id", "type"]}},
    ]
