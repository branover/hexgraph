"""Delegate a task to a coding agent from the UI (driver mode, HexGraph-initiated).

HexGraph launches the configured agent CLI (Claude Code / Codex / gemini-cli) in
headless mode, wired to the `hexgraph` MCP server and the VR skill, then lets it
investigate and record results back into the project. The agent is **restricted**
to HexGraph's sandboxed MCP tools plus read-only built-ins — it must never run the
target itself (it has no access to the bytes anyway; only the MCP tools do, and
those sandbox everything).

The CLI invocation is built per agent; `run_cli` is injectable so the command
construction + result handling are unit-testable without a real agent installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess

from sqlalchemy.orm import Session

from hexgraph.agent.agent_setup import full_skill_markdown, mcp_server_entry
from hexgraph.db.models import Project, Target, Task
from hexgraph.engine.tasks import write_trace

DEFAULT_TIMEOUT = 900


class DelegateError(RuntimeError):
    pass


def agent_config(target: Target) -> dict:
    from hexgraph import settings

    a = settings.resolved()["features"]["agent"]
    return a


def delegate_prompt(project_id: str, target: Target, task_id: str, objective: str | None) -> str:
    """The task brief handed to the agent: the WHOLE skill bundle plus the concrete
    assignment. Delegate mode inlines the full bundle (spine + every capability sub-file)
    because — unlike the deployed VR skill — it never materializes the sub-files the SKILL
    body points to, so without this those pointers would dangle. A headless delegate also
    typically can't spawn sub-agents, so it works the surface serially; the parallel-
    orchestration guidance in the bundle still applies when the agent CAN fan out."""
    obj = (objective or "").strip() or f"Find vulnerabilities in {target.name}."
    return (
        f"{full_skill_markdown()}\n\n---\n\n## Your assignment\n"
        f"project_id: {project_id}\n"
        f"target_id: {target.id}  (name: {target.name})\n"
        f"hexgraph task_id: {task_id}  ← pass this as task_id to finding_record\n\n"
        f"Objective: {obj}\n\n"
        "Use the `hexgraph` MCP tools to investigate this target, then record each "
        "credible finding with finding_record(..., task_id=<the task_id above>). "
        "Do not touch the binary by any other means."
    )


def build_command(cli: str, binary: str, prompt: str, model: str | None = None) -> list[str]:
    """Per-agent headless invocation, restricted to HexGraph MCP + read-only tools.
    The MCP server is registered globally by `hexgraph mcp install`; Claude Code
    also accepts it inline via --mcp-config."""
    entry = mcp_server_entry()
    if cli == "claude":
        cmd = [binary, "-p", prompt, "--output-format", "json",
               "--mcp-config", json.dumps({"mcpServers": {"hexgraph": entry}}),
               # restrict to HexGraph tools + read-only built-ins; no shell on the target
               "--allowedTools", "mcp__hexgraph Read Glob Grep",
               "--disallowedTools", "Bash Write Edit WebFetch"]
        if model:
            cmd += ["--model", model]
        return cmd
    if cli == "codex":
        # Codex reads MCP servers from ~/.codex/config.toml (set via `mcp install`).
        return [binary, "exec", prompt] + (["--model", model] if model else [])
    if cli == "gemini":
        # gemini-cli reads MCP servers from ~/.gemini/settings.json (set via install).
        return [binary, "-p", prompt] + (["-m", model] if model else [])
    raise DelegateError(f"unknown agent CLI {cli!r} (choose claude|codex|gemini)")


def _default_run_cli(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise DelegateError(f"agent CLI not found: {cmd[0]!r}. Install it, or run "
                            "`hexgraph mcp install` for setup.") from exc
    except subprocess.TimeoutExpired as exc:
        raise DelegateError(f"agent timed out after {timeout}s") from exc
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def execute_delegate(session: Session, project: Project, target: Target, task: Task, *, run_cli=None) -> int:
    """Launch the configured coding agent against this target. The agent records
    findings via the MCP finding_record tool (attributed to this task). Returns the
    number of findings produced. Best-effort: a CLI/agent failure marks the task
    failed with the captured output."""
    from hexgraph import settings
    from hexgraph.db.models import Finding

    a = settings.resolved()["features"]["agent"]
    if not a.get("enabled"):
        raise DelegateError("coding-agent delegation is disabled (enable features.agent in Settings)")
    cli = a.get("cli", "claude")
    binary = a.get("binary") or {"claude": "claude", "codex": "codex", "gemini": "gemini"}[cli]
    if shutil.which(binary) is None and run_cli is None:
        raise DelegateError(f"{binary!r} not on PATH; install {cli} or set features.agent.binary")

    prompt = delegate_prompt(project.id, target, task.id, task.objective_text)
    cmd = build_command(cli, binary, prompt, task.model)
    write_trace(task, "delegate_prompt.txt", prompt)
    write_trace(task, "delegate_cmd.json", {"cli": cli, "argv": [cmd[0], "…", *cmd[3:]]})  # omit the long prompt

    runner = run_cli or _default_run_cli
    rc, out, err = runner(cmd, int(a.get("timeout", DEFAULT_TIMEOUT)))
    write_trace(task, "delegate_output.txt", (out + "\n--- stderr ---\n" + err)[:200000])
    if rc != 0:
        raise DelegateError(f"agent exited {rc}: {err.strip()[:500] or out.strip()[:500]}")

    # Findings the agent recorded (via finding_record with this task_id) are already
    # in the DB attributed to this task.
    return session.query(Finding).filter(Finding.task_id == task.id).count()
