"""Connect a coding agent (Claude Code / Codex / gemini-cli) to HexGraph's MCP
server, and the VR skill that teaches it the workflow + the hostile-target rules.

`hexgraph mcp install [--agent ...]` prints the registration steps. The setup wizard
(`hexgraph setup`) can also PERFORM the registration for you — `register_agent()` edits
the chosen agent's own config file directly and idempotently. Either way this is a
local filesystem edit only: no network, and no secret (the MCP command carries no key;
the server reads any key from env / config.toml at run time).

The skill content (the spine + capability sub-files) and its emission helpers live in
`vr_skill` — the single source of truth shared by the deployed skill, the delegate-task
brief, and `--print-skill`. They are re-exported here for back-compat.
"""

from __future__ import annotations

import json
import shutil

# Re-exported: the VR skill content + the helpers that render/emit it. `SKILL` is the
# spine body; `write_skill` emits the spine + every sub-file; `full_skill_markdown` is the
# whole bundle as one document (for consumers that can't read on-demand sub-files).
from hexgraph.agent.vr_skill import (  # noqa: F401
    SKILL,
    SUBFILES,
    full_skill_markdown,
    skill_markdown,
    write_skill,
)


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

# The server name is fixed (mirrors mcp_server.py's hardcoded "hexgraph"); registering
# the same name twice is a no-op, which is what makes registration idempotent.
SERVER_NAME = "hexgraph"

# Where each agent looks for its config, per scope. "user" is the agent's global config
# (under $HOME); "project" is a per-project file the agent reads when launched in that
# directory. Codex has no per-project MCP file, so it is user-only.
#   kind: "json" → merge `{mcpServers: {hexgraph: entry}}` into the file's top-level
#                  `mcpServers` map (Claude Code, gemini-cli).
#   kind: "toml" → ensure a `[mcp_servers.hexgraph]` table (Codex).
SCOPES = ("user", "project")


def agent_config_target(agent: str, scope: str, project_dir: str | None = None) -> tuple[str, str]:
    """Resolve (path, kind) for an agent+scope. `kind` is "json" or "toml".

    Raises ValueError for an unsupported agent/scope combination (e.g. Codex project).
    For a project scope, `project_dir` defaults to the current working directory.
    """
    import os

    home = os.path.expanduser("~")
    proj = os.path.abspath(project_dir or os.getcwd())
    if agent == "claude":
        if scope == "user":
            return os.path.join(home, ".claude.json"), "json"
        return os.path.join(proj, ".mcp.json"), "json"
    if agent == "gemini":
        if scope == "user":
            return os.path.join(home, ".gemini", "settings.json"), "json"
        return os.path.join(proj, ".gemini", "settings.json"), "json"
    if agent == "codex":
        if scope == "user":
            return os.path.join(home, ".codex", "config.toml"), "toml"
        raise ValueError("Codex has no per-project MCP config; use user scope")
    raise ValueError(f"unknown agent {agent!r}; choose one of {AGENTS}")


def _register_json(path: str, entry: dict) -> bool:
    """Idempotently ensure `mcpServers.hexgraph == entry` in a JSON config file.

    Returns True if the file was changed (False if the entry was already identical).
    Preserves every other key in the file. Creates the file/dirs if absent.
    """
    import os

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    data: dict = {}
    if os.path.exists(path):
        try:
            with open(path) as fh:
                txt = fh.read().strip()
            data = json.loads(txt) if txt else {}
        except (json.JSONDecodeError, OSError):
            # Don't clobber an unparseable user config silently.
            raise RuntimeError(f"{path} is not valid JSON — refusing to overwrite it")
    if not isinstance(data, dict):
        raise RuntimeError(f"{path} top level is not a JSON object — refusing to edit it")
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise RuntimeError(f"{path} 'mcpServers' is not an object — refusing to edit it")
    if servers.get(SERVER_NAME) == entry:
        return False
    servers[SERVER_NAME] = entry
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    return True


def _register_toml(path: str, entry: dict) -> bool:
    """Idempotently ensure a `[mcp_servers.hexgraph]` table in a Codex TOML config.

    Returns True if changed. Reads the existing file with tomllib to detect an already
    identical entry; otherwise appends a fresh table block (Codex reads the last one).
    We APPEND rather than rewrite so we never disturb the user's hand-authored TOML.
    """
    import os

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    existing_text = ""
    if os.path.exists(path):
        with open(path) as fh:
            existing_text = fh.read()
        try:
            import tomllib

            parsed = tomllib.loads(existing_text)
            cur = parsed.get("mcp_servers", {}).get(SERVER_NAME)
            if cur == {"command": entry["command"], "args": entry["args"]}:
                return False
            if cur is not None:
                # An entry exists but differs — appending a duplicate table is invalid
                # TOML, so refuse rather than corrupt the file. The user can fix it.
                raise RuntimeError(
                    f"{path} already has a different [mcp_servers.{SERVER_NAME}] — "
                    "edit it by hand or remove it, then re-run setup")
        except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
            pass
    block = (
        f"\n[mcp_servers.{SERVER_NAME}]\n"
        f"command = {json.dumps(entry['command'])}\n"
        f"args = {json.dumps(entry['args'])}\n"
    )
    sep = "" if (not existing_text or existing_text.endswith("\n")) else "\n"
    with open(path, "a") as fh:
        fh.write(sep + block)
    return True


def register_agent(agent: str, scope: str = "user", project_dir: str | None = None) -> dict:
    """Register HexGraph's MCP server with `agent` at `scope`, editing the agent's own
    config file directly (no dependency on the agent's CLI being installed).

    Idempotent: re-running with the same install is a no-op. Returns a small result
    dict: {agent, scope, path, changed, command}. Raises ValueError/RuntimeError on an
    unsupported combination or an unparseable existing config.

    This performs ONLY a local filesystem edit of the agent's config — no network, no
    secret. The MCP command itself carries no secret (the server reads keys from env /
    config.toml at run time, never from this registration).
    """
    entry = mcp_server_entry()
    path, kind = agent_config_target(agent, scope, project_dir)
    if kind == "json":
        changed = _register_json(path, entry)
    else:
        changed = _register_toml(path, entry)
    return {
        "agent": agent,
        "scope": scope,
        "path": path,
        "changed": changed,
        "command": entry["command"] + " " + " ".join(entry["args"]),
    }


def default_skill_dir() -> str:
    """The default destination for the VR skill: the user-global Claude skills dir."""
    import os

    return os.path.join(os.path.expanduser("~"), ".claude", "skills")


# The skill bundle's spine file — its presence under <base>/hexgraph-vr marks an install.
_SKILL_DIR_NAME = "hexgraph-vr"
_SKILL_SPINE = "SKILL.md"


def detect_skill_dirs(project_dir: str | None = None) -> list[str]:
    """Base dirs where the VR skill is ALREADY installed (so a refresh can regenerate it
    in place, never inventing a new location).

    A base counts as installed when `<base>/hexgraph-vr/SKILL.md` exists. We check the
    user-global dir (`~/.claude/skills`) and the project-local `./.claude/skills`; pass
    `write_skill(base)` each one to refresh it. Returns an ordered, de-duplicated list."""
    import os

    proj = os.path.abspath(project_dir or os.getcwd())
    candidates = [default_skill_dir(), os.path.join(proj, ".claude", "skills")]
    out: list[str] = []
    for base in candidates:
        if base not in out and os.path.isfile(os.path.join(base, _SKILL_DIR_NAME, _SKILL_SPINE)):
            out.append(base)
    return out


def detect_registrations(project_dir: str | None = None) -> list[dict]:
    """Every place the `hexgraph` MCP server is ALREADY registered, so a refresh can
    re-affirm them (idempotent; fixes a command path that moved when the venv was
    recreated). Read-only — performs no edits.

    Scans the JSON agent configs we can manage (claude/gemini, user + project) AND
    Claude Code's per-project "local" scope inside `~/.claude.json`
    (`projects.<dir>.mcpServers`, where `claude mcp add` writes by default). Codex's TOML
    is reported but not auto-rewritten (appending a duplicate table is invalid TOML).

    Returns [{agent, scope, path, current}] — `current` is True iff the registered entry
    already equals `mcp_server_entry()` (nothing to do). Never raises."""
    import os

    want = mcp_server_entry()
    home = os.path.expanduser("~")
    proj = os.path.abspath(project_dir or os.getcwd())
    found: list[dict] = []

    def _json_entry(path: str) -> dict | None:
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        servers = data.get("mcpServers")
        if isinstance(servers, dict) and isinstance(servers.get(SERVER_NAME), dict):
            return servers[SERVER_NAME]
        return None

    # claude/gemini user + project (the scopes register_agent manages directly).
    for agent in ("claude", "gemini"):
        for scope in ("user", "project"):
            try:
                path, kind = agent_config_target(agent, scope, proj)
            except ValueError:
                continue
            if kind != "json" or not os.path.isfile(path):
                continue
            entry = _json_entry(path)
            if entry is not None:
                found.append({"agent": agent, "scope": scope, "path": path,
                              "current": entry == want})

    # Claude Code "local" scope: ~/.claude.json → projects.<abspath>.mcpServers.hexgraph
    claude_json = os.path.join(home, ".claude.json")
    if os.path.isfile(claude_json):
        try:
            with open(claude_json) as fh:
                data = json.load(fh)
            projects = data.get("projects") if isinstance(data, dict) else None
            if isinstance(projects, dict):
                for pdir, pcfg in projects.items():
                    servers = pcfg.get("mcpServers") if isinstance(pcfg, dict) else None
                    if isinstance(servers, dict) and isinstance(servers.get(SERVER_NAME), dict):
                        found.append({"agent": "claude", "scope": f"local:{pdir}",
                                      "path": claude_json, "current": servers[SERVER_NAME] == want})
        except (OSError, json.JSONDecodeError):
            pass

    # Codex TOML (report-only; we never rewrite the user's hand-authored TOML on refresh).
    try:
        cpath, _ = agent_config_target("codex", "user")
        if os.path.isfile(cpath):
            import tomllib

            with open(cpath, "rb") as fh:
                parsed = tomllib.load(fh)
            cur = parsed.get("mcp_servers", {}).get(SERVER_NAME)
            if cur is not None:
                want_toml = {"command": want["command"], "args": want["args"]}
                found.append({"agent": "codex", "scope": "user", "path": cpath,
                              "current": cur == want_toml})
    except Exception:  # noqa: BLE001 — codex detection is best-effort (tomllib / read errors)
        pass

    return found


def refresh_registrations(project_dir: str | None = None) -> list[dict]:
    """Re-affirm every detected `hexgraph` MCP registration to the CURRENT launch command,
    so a version refresh keeps them pointing at this install (no-op when already current).

    Updates only JSON configs (claude user/project + claude per-project local, gemini
    user/project); a Codex entry that has drifted is reported with `action="manual"`
    rather than rewritten (appending a duplicate TOML table would be invalid). Idempotent.

    Returns [{agent, scope, path, action}] where action ∈ {unchanged, updated, manual}."""
    import os

    want = mcp_server_entry()
    proj = os.path.abspath(project_dir or os.getcwd())
    results: list[dict] = []
    for reg in detect_registrations(project_dir):
        agent, scope, path = reg["agent"], reg["scope"], reg["path"]
        if reg["current"]:
            results.append({**reg, "action": "unchanged"})
            continue
        if agent == "codex":
            results.append({**reg, "action": "manual"})  # don't rewrite hand-authored TOML
            continue
        if scope.startswith("local:"):
            pdir = scope.split(":", 1)[1]
            try:
                with open(path) as fh:
                    data = json.load(fh)
                data["projects"][pdir]["mcpServers"][SERVER_NAME] = want
                with open(path, "w") as fh:
                    json.dump(data, fh, indent=2)
                    fh.write("\n")
                results.append({**reg, "action": "updated"})
            except (OSError, KeyError, json.JSONDecodeError):
                results.append({**reg, "action": "manual"})
            continue
        # claude/gemini user|project — register_agent rewrites the entry idempotently. Pass the
        # SAME project root detect_registrations used (NOT dirname(path) — gemini's config is
        # nested under .gemini/, so dirname would double the path).
        try:
            register_agent(agent, scope=scope, project_dir=proj if scope == "project" else None)
            results.append({**reg, "action": "updated"})
        except (ValueError, RuntimeError):
            results.append({**reg, "action": "manual"})
    return results


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
    footer = ("\n\nInstall the VR skill so the agent knows the workflow + the hostile-target rules\n"
              "(emits SKILL.md + the capability sub-files):\n"
              "  hexgraph mcp install --write-skill .claude/skills   # Claude Code (project-local)\n"
              "  hexgraph mcp install --write-skill ~/.claude/skills  # Claude Code (global)\n"
              "(For Codex/gemini, paste the whole bundle into AGENTS.md / your system prompt — "
              "print it with `hexgraph mcp install --print-skill`.)")
    return header + "\n\n".join(blocks) + footer
