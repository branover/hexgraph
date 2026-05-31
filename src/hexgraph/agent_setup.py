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

You do vulnerability research through HexGraph (MCP server `hexgraph`), a sandboxed
workbench. Use ONLY the `hexgraph` tools to touch the target — they run every tool
inside an isolated, network-less sandbox.

**The graph + findings are shared, durable memory — they are your real
deliverable, not just your final chat message.** Everything useful you learn
should be written back as nodes, edges, findings, hypotheses, and annotations, so:
- the human analyst can review your reasoning, triage it, and decide which
  follow-up tasks to launch;
- a future agent run picks up where you left off instead of re-deriving the same
  facts (no duplicated effort).

## Hard rules (non-negotiable)
- **Never execute, unpack, or open the target binary yourself.** No Bash/shell on
  the target, no downloading it, no running it. The bytes are hostile. All target
  handling goes through `hexgraph` tools.
- **Never exfiltrate target bytes** off the machine.
- Back every claim with tool output; don't invent findings.

## 1. Read what's already known FIRST
Before analyzing anything, orient on prior work so you don't repeat it and you can
see where to go next:
- `list_targets(project_id)`, `target_facts`, `read_imports` — scope + recon facts.
- `list_findings(project_id)` — what's already found, confirmed, or **dismissed**
  (don't re-report dismissed issues).
- `search(project_id, q)` — locate functions/strings/findings by keyword.
Let the existing graph and any open findings/hypotheses steer your next move: pick
up unfinished threads, follow related findings to siblings, and target functions
that haven't been analyzed yet.

## 2. Investigate (all sandboxed)
- `list_functions`, then `decompile_function` / `disassemble` the suspicious ones;
  follow callees and `list_strings`. Trace untrusted input → dangerous sink.
- Go deeper with `run_task` (`static_analysis`, `harness_generation`, `fuzzing`),
  and **`verify_poc`** to PROVE exploitability (a confirmed PoC is the gold bar).

## 3. Capture EVERYTHING useful, as you go (this is the point)
Don't wait until the end, and don't keep insights only in chat. Record:
- `record_finding(project_id, target_id, finding, task_id=<provided if given>)` —
  every credible issue. Evidence: function, sink, a decompiled snippet, clear
  reasoning, and the verified PoC spec when you have one.
- `create_node` — pin the functions/symbols/strings/structs you reasoned about
  (even benign-but-relevant ones), and `hypothesis` nodes for open questions.
- `create_edge` — wire the relationships you uncovered: `calls`, `references`,
  `reads`/`writes`, and **`taints`** for an untrusted-input → sink dataflow path
  (e.g. an input string → parsing function → the dangerous sink). Connect findings
  to the functions/inputs they concern.
- `create_hypothesis` for theories worth testing; later findings `supports`/
  `refutes` them so the open-question set stays live.
- `annotate` — add renames / notes / tags to nodes (e.g. a clearer function name,
  a "reachable pre-auth" note, a CWE tag) so the next analyst/agent doesn't
  re-derive them.

Aim: someone opening the project afterward should see the attack surface, the
input→sink paths, what's confirmed vs still open, and the obvious next tasks —
without having to re-read the binary. Leave unfinished threads as hypotheses or
unanalyzed function nodes so the user can launch follow-up tasks on them.

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
