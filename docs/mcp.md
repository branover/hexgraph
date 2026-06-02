# Coding-agent integration (MCP)

HexGraph integrates with coding agents in two directions, both keeping target bytes in the sandbox.
LLM tasks themselves use a tool-use **agent loop** over a plain BYOK key (the model directs, HexGraph
runs the tools) — Claude Code / Codex are an *alternative* backend/driver, never required.

## Driver mode — an agent drives HexGraph

`hexgraph mcp` (stdio) exposes HexGraph's sandboxed primitives so an external agent (Claude Code /
Codex / gemini-cli) inspects targets, populates the graph (findings / nodes / edges / hypotheses /
annotations), and runs sandboxed tasks.

```bash
.venv/bin/pip install "mcp"     # the MCP SDK (one-time)
.venv/bin/hexgraph mcp install  # prints the exact registration command for your agent
```

The MCP server speaks JSON-RPC over **stdio**; your agent spawns it on demand. Run by hand it prints a
"ready" line to stderr and blocks (correct) — confirm with `hexgraph mcp --check`. The **web UI and
the MCP server run at the same time** (separate processes sharing the WAL-mode SQLite DB), so an
agent's findings appear in the UI on reload and vice versa.

Tools are grouped **read / write / run** and gated by `features.mcp.{read,write,run}` (Settings →
Coding-agent tools, or `--tools`) so the agent's context stays small:

- **read** — `list_*`, `get_node`, `get_finding`, `xrefs`, `list_sockets`, `list_filesystem` /
  `read_file`, `list_source_trees` / `read_source_file`, `list_builds` / `coverage_diff`,
  `archive_node` / `restore_node` / `delete_edge` / `archive_target` / `restore_target`.
- **write** — `record_finding`, `create_node`, `create_edge`, `create_socket`, `create_hypothesis`,
  `link_same_code`, `propagate_finding`, `import_source_tree`, `link_finding_to_source`,
  `save_source_revision`, `import_oss_fuzz`, …
- **run** — `ingest`, `run_task`, `verify_poc`, `verify_fuzz_artifact`, `start_fuzz_campaign`,
  `build_target`, …

Call **`get_schemas` first** — it advertises the Finding shape, node/edge vocab, per-type
node-attribute schemas (with the sink-vs-symbol rule), edge-attribute schemas, socket kinds, and the
active decompiler.

```bash
hexgraph mcp install [--agent claude|codex|gemini]   # print registration steps
hexgraph mcp install --write-skill .claude/skills    # also install the VR skill
hexgraph mcp --tools read,write                      # serve a restricted tool set
```

## Delegate mode — HexGraph drives the agent

Opt-in `features.agent` + an `agent_delegate` task: HexGraph launches the configured agent CLI
headless, wired to the MCP server + the VR skill, **restricted to HexGraph's sandboxed tools** (no
shell on the target). Launch it from the UI Run menu.

```bash
hexgraph config set features.agent.enabled true
```

## Worktree note

The MCP registration **bakes an absolute interpreter/script path with no env**, and the server name
is hardcoded `"hexgraph"`. So `cd`-ing between git worktrees does **not** change which code or DB the
agent's MCP tools use. To test MCP changes that live only in a worktree, register a uniquely-named
server pinned to that worktree's python + `HEXGRAPH_HOME` (see `CLAUDE.md` for the exact command).
