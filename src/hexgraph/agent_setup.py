"""Connect a coding agent (Claude Code / Codex / gemini-cli) to HexGraph's MCP
server, and the VR skill that teaches it the workflow + the hostile-target rules.

`hexgraph mcp install [--agent ...]` prints the registration steps; it never edits
the user's agent config silently.
"""

from __future__ import annotations

import json
import shutil

# The agent's standing instructions. Whether HexGraph launches the agent
# (delegate task) or the user drives it themselves, this is the context that makes
# it use HexGraph safely and productively.
SKILL = """\
# HexGraph vulnerability-research agent

You are doing vulnerability research through HexGraph, which exposes a sandboxed
workbench over MCP (server name: `hexgraph`). Use ONLY the `hexgraph` tools to
touch the target — they run every tool inside an isolated, network-less sandbox.

## Hard rules (non-negotiable)
- **Never execute, unpack, or open the target binary yourself.** No Bash/shell on
  the target, no downloading it, no running it. The bytes are hostile. All target
  handling goes through `hexgraph` tools (decompile/disassemble/strings/imports,
  and `run_task` for recon/harness/fuzz).
- **Never exfiltrate target bytes** off the machine.
- Record results only via `record_finding` (it validates the schema). Do not
  invent findings you can't back with tool output.

## Workflow
1. `list_targets(project_id)` → pick the target. `target_facts` / `read_imports`
   for orientation; `list_functions` to see the attack surface.
2. For suspicious functions: `decompile_function` (and `disassemble` if needed).
   Follow callees. Look for memory-safety, injection, unsafe parsing, hardcoded
   secrets, weak auth.
3. To go deeper, `run_task` (e.g. `static_analysis`, `harness_generation`, then
   `fuzzing` to confirm a crash) — HexGraph runs these in the sandbox.
4. Check `list_findings(project_id)` first so you don't duplicate known issues.
5. `record_finding(project_id, target_id, finding, task_id=<provided>)` for each
   credible issue. Include evidence: function, sink, a decompiled snippet, and
   clear reasoning. Severity/confidence honest.

A finding object looks like:
{"title": "...", "severity": "critical|high|medium|low|info",
 "confidence": "high|medium|low", "category": "memory-safety|command-injection|...",
 "summary": "...", "reasoning": "...",
 "evidence": {"function": "...", "sink": "...", "decompiled_snippet": "..."}}
"""


def skill_markdown() -> str:
    """The VR skill as a Claude Code skill file (YAML frontmatter + body)."""
    return (
        "---\n"
        "name: hexgraph-vr\n"
        "description: Vulnerability research through HexGraph's sandboxed MCP tools — "
        "inspect targets, decompile, run analysis/fuzz tasks, and record findings/nodes/edges. "
        "Use whenever analyzing a binary or firmware that has been ingested into HexGraph.\n"
        "---\n\n"
        + SKILL
    )


def write_skill(base_dir: str) -> str:
    """Write the skill to <base_dir>/hexgraph-vr/SKILL.md and return the path."""
    import os

    d = os.path.join(base_dir, "hexgraph-vr")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "SKILL.md")
    with open(path, "w") as fh:
        fh.write(skill_markdown())
    return path


def mcp_command() -> tuple[str, list[str]]:
    """How to launch the MCP server, as an ABSOLUTE command the agent can spawn.

    The agent (Claude Code/Codex) runs this with its own PATH/cwd, so bare names
    like `hexgraph`/`python` won't resolve to this install. Prefer the absolute
    path to the `hexgraph` console script; otherwise use this interpreter
    (`sys.executable` — e.g. the venv's python, which has HexGraph installed)."""
    import sys

    exe = shutil.which("hexgraph")
    if exe:
        return exe, ["mcp"]
    return sys.executable, ["-m", "hexgraph.cli", "mcp"]


def mcp_server_entry() -> dict:
    cmd, args = mcp_command()
    return {"command": cmd, "args": args}


AGENTS = ("claude", "codex", "gemini")


def install_help(agent: str | None = None) -> str:
    """Human-readable registration steps for one agent (or all)."""
    entry = mcp_server_entry()
    cmd_str = entry["command"] + " " + " ".join(entry["args"])
    blocks = []

    if agent in (None, "claude"):
        blocks.append(
            "Claude Code:\n"
            f"  claude mcp add hexgraph -- {cmd_str}\n"
            "  # or add to .mcp.json / ~/.claude.json:\n"
            "  " + json.dumps({"mcpServers": {"hexgraph": entry}}) + "\n"
            "  Restrict it to HexGraph + read-only tools when delegating:\n"
            '    --allowedTools "mcp__hexgraph Read Glob Grep" --disallowedTools "Bash"'
        )
    if agent in (None, "codex"):
        blocks.append(
            "Codex CLI (~/.codex/config.toml):\n"
            "  [mcp_servers.hexgraph]\n"
            f"  command = {json.dumps(entry['command'])}\n"
            f"  args = {json.dumps(entry['args'])}"
        )
    if agent in (None, "gemini"):
        blocks.append(
            "gemini-cli (~/.gemini/settings.json):\n"
            "  " + json.dumps({"mcpServers": {"hexgraph": entry}})
        )

    if not blocks:
        return f"unknown agent {agent!r}; choose one of {AGENTS}"
    import sys

    header = (
        "Register HexGraph as an MCP server with your coding agent. Then point\n"
        "the agent at a project and let it use the `hexgraph` tools.\n\n"
        f"First install the MCP SDK INTO THIS ENVIRONMENT (note the venv's pip):\n"
        f"  {sys.executable} -m pip install \"mcp\"\n"
        f"Confirm it's wired up (lists the tools and exits — no client needed):\n"
        f"  {cmd_str} --check\n"
        f"(`{cmd_str}` with no flag prints a 'ready, waiting for a client' line to stderr then\n"
        f" blocks — that's correct; your agent launches it. `hexgraph serve` (the web UI) can run\n"
        f" at the same time; they're separate processes sharing the DB.)\n\n")
    footer = ("\n\nInstall the VR skill so the agent knows the workflow + the hostile-target rules:\n"
              "  hexgraph mcp install --write-skill .claude/skills   # Claude Code (project-local)\n"
              "  hexgraph mcp install --write-skill ~/.claude/skills  # Claude Code (global)\n"
              "(For Codex/gemini, paste the same guidance into AGENTS.md / your system prompt — "
              "print it with `hexgraph mcp install --print-skill`.)")
    return header + "\n\n".join(blocks) + footer
