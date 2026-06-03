# Coding-agent integration (MCP)

HexGraph integrates with coding agents in two directions, and both keep target bytes inside the
sandbox. Worth saying up front: LLM tasks already run a tool-use agent loop over a plain BYOK key (the
model directs, HexGraph runs the tools), so Claude Code and Codex are an *alternative* backend or
driver, never a requirement.

## Driver mode: an agent drives HexGraph

`hexgraph mcp` (over stdio) exposes HexGraph's sandboxed primitives so that an external agent (Claude
Code, Codex, or gemini-cli) can inspect targets, populate the graph with findings, nodes, edges,
hypotheses, and annotations, and run sandboxed tasks.

```bash
.venv/bin/pip install "mcp"     # the MCP SDK (one-time)
.venv/bin/hexgraph mcp install  # prints the exact registration command for your agent
```

The setup wizard can do this for you. When you run `hexgraph setup` interactively it offers to
register the MCP server with the agent of your choice (for this project or globally) and to install
the VR skill, so you usually do not need to wire it up by hand. The commands above are the manual path
if you skipped that step or want to script it.

The MCP server speaks JSON-RPC over stdio, and your agent spawns it on demand. Run it by hand and it
prints a "ready" line to stderr and then blocks, which is correct; confirm it with `hexgraph mcp
--check`. The web UI and the MCP server run at the same time, as separate processes sharing the
WAL-mode SQLite database, so an agent's findings show up in the UI on reload, and yours show up for the
agent the same way.

The tools are grouped into **read**, **write**, and **run**, and each group is gated by
`features.mcp.{read,write,run}` (in Settings → Coding-agent tools, or via `--tools`), which keeps the
agent's context small:

- **read** covers the `list_*` family, `get_node`, `get_finding`, `xrefs`, `list_sockets`,
  `list_filesystem`/`read_file`, `list_source_trees`/`read_source_file`, and
  `list_builds`/`build_log`/`coverage_diff`.
- **write** covers `record_finding`, `update_finding`, `create_node`, `create_edge`, `create_socket`,
  `create_hypothesis`, `link_same_code`, `propagate_finding`, `import_source_tree`,
  `link_finding_to_source`, `save_source_revision`, `import_oss_fuzz`, and more. It also
  holds the graph-removal tools — the reversible `archive_node`/`restore_node`/`archive_target`/`restore_target`
  and the hard `delete_edge` — plus `delete_finding` for clearing a junk finding outright
  (a hard, irreversible delete that also removes the edges and annotations touching it, and
  detaches any task or fuzz artifact that referenced it); to set a finding aside reversibly
  instead, call `update_finding(status='dismissed')`.
- **run** covers `ingest`, `add_file_as_target` (promote a file from an unpacked firmware into
  its own target), `run_task`, `verify_poc`, `verify_fuzz_artifact`,
  `start_fuzz_campaign`/`resume_fuzz_campaign`, `build_target`, and more.

Call **`get_schemas` first.** It advertises the Finding shape, the node and edge vocabulary, the
per-type node-attribute schemas (including the sink-versus-symbol rule), the edge-attribute schemas,
the socket kinds, and the active decompiler.

```bash
hexgraph mcp install [--agent claude|codex|gemini]   # print registration steps
hexgraph mcp install --write-skill .claude/skills    # also install the VR skill
hexgraph mcp --tools read,write                      # serve a restricted tool set
```

## Delegate mode: HexGraph drives the agent

Turn on `features.agent` and you get an `agent_delegate` task. HexGraph launches the configured agent
CLI headless, wired to the MCP server and the VR skill, and restricted to HexGraph's sandboxed tools,
with no shell on the target. You launch it from the UI Run menu.

```bash
hexgraph config set features.agent.enabled true
```

## A note on worktrees

The MCP registration bakes in an absolute interpreter and script path with no environment, and the
server name is hardcoded as `"hexgraph"`. The practical consequence is that `cd`-ing between git
worktrees does *not* change which code or database the agent's MCP tools use. To test MCP changes that
live only in a worktree, register a uniquely-named server pinned to that worktree's python and its own
`HEXGRAPH_HOME`. The exact command is in `CLAUDE.md`.
