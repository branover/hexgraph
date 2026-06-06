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
  `list_filesystem`/`read_file`, `list_source_trees`/`read_source_file`, `fuzz_status`,
  `list_builds`/`build_log`/`coverage_diff`, and the observation read verbs
  `list_observations`/`get_observation`/`search_observations` (see the next section).
- **write** covers `create_project` (start an empty, source-first project), `record_finding`,
  `update_finding`, `create_node`, `create_edge`, `create_socket`,
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

### Tool results, the substrate, and the curation contract

There are two stores behind the tools, and it helps to keep them apart from the start. Every
deterministic tool call you make, a decompilation, a function listing, an xref, a strings or structs
dump, gets recorded as a durable **Observation** scoped to the exact bytes of the target. That body of
Observations is the *substrate*: the exhaustive, queryable record of everything you have looked at. The
**graph**, on the other hand, stays a curated set of *results*: the functions you are actually
investigating, the sinks that matter, the taint path behind a finding. HexGraph deliberately does not
dump the whole program into the graph, because that is the explosion the curation contract exists to
prevent.

What that means for an agent driving HexGraph over MCP comes down to a few rules the tool descriptions
already state, and `get_schemas` spells out in its `substrate_vs_graph` and `observations` sections:

- **Query verbs add nothing to the graph.** `list_functions`, `xrefs`, `disassemble`, `list_strings`
  and the rest return their results as tool output and quietly record an Observation. They create no
  nodes and no edges. An enumeration is an answer, not a pile of graph objects.
- **Enrichment of existing objects is automatic and free.** When a call recovers something unambiguous
  about an object that is *already* a node, a function's recovered prototype and address, the `is_sink`
  tag on a dangerous import, the call sites on an existing `calls` edge, HexGraph attaches it in place
  with no further action from you. It only ever deepens nodes that already exist, and it never makes a
  judgment call (no severity, no "this is a vulnerability", no new node).
- **Promotion is deliberate.** A new node enters the graph only by an explicit act: `decompile_function`
  promotes the one function you asked about, `create_node`/`create_edge`/`record_finding` add the
  results you decide are worth keeping. Decompiling a function lists its callees in the result and draws
  `calls` edges only to callees already in the graph; it does not spawn a node per callee. A single call
  is also capped by a per-call promotion budget, and if a promotion would exceed it the overflow comes
  back as promotable results with an explicit "capped" note rather than being silently dropped.
- **Check before you re-run.** Because results persist, call `list_observations(target_id)` before
  paying to re-run an expensive analysis, and pull a prior payload back with `get_observation(id)`
  rather than recomputing it. An identical call against identical bytes is served from the existing
  Observation and flagged `cached`. The three read verbs are `list_observations(target_id, tool?,
  kind?, limit?)` for the newest-first index of metadata, `get_observation(id)` for one Observation in
  full including its complete payload from content-addressed storage, and `search_observations(query)`
  for a substring search over tool, summary, and result kind across a project or a single target. Every
  tool result also carries a one-line reuse hint pointing you at them.

The fuller, user-facing tour of all this lives in [observations.md](observations.md).

### Annotations are proposals; a rename is confirmed by a human

`annotate` lets a driving agent attach a note, a tag, a type declaration, or a function
**rename** to a graph entity, and an agent's annotation lands as a *proposal*. It is recorded
against the node, but on its own it changes nothing else. The rename is where that distinction
matters most. When you confirm a proposed rename in the web UI, HexGraph writes it into the
persistent Ghidra project and re-decompiles, so the new name sticks for every later decompile
and the graph reflects the fresh result. That approval is deliberately a person's call rather
than the agent's: there is no MCP verb for an agent to confirm its own rename. So the loop is
simply the agent proposes, you confirm, and the round-trip completes — the agent is never left
guessing whether its rename took, and a human stays in the loop on the names that become the
shared vocabulary of the analysis.

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
