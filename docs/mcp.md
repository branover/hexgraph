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

Every tool is named `<domain>_<verb>`, so an agent can route to the right one from the name alone
without fetching its schema. The domains are `proj` (projects), `target` (the target lifecycle and
every tool that creates a target, including rehosting), `re` (static reverse engineering), `fs` (a
target's unpacked filesystem), `obs` (the Observation store), `graph` (the curated node/edge/hypothesis
graph), `finding` (findings, n-day, and proving), `src` (source trees and builds), `fuzz` (campaigns),
`net` (live network interaction and the egress log), `task` (the task runner), and `meta` (schemas and
health). Closed value sets — node and edge types, finding severities, task types, the remote recon
allowlist, and so on — are real schema `enum`s generated from the codebase's own definitions, so an
agent can't pass a value the engine doesn't understand.

The tools are also grouped into **read**, **write**, and **run**, and each group is gated by
`features.mcp.{read,write,run}` (in Settings → Coding-agent tools, or via `--tools`), which keeps the
agent's context small:

- **read** covers the listing and inspection verbs across the domains, `graph_get_node`, `finding_get`, `re_xrefs`, `graph_list_sockets`,
  `fs_list`/`fs_read_file`, `src_list_trees`/`src_read_file`, `fuzz_status`,
  `src_list_builds`/`src_build_log`/`fuzz_coverage_diff`, the observation read verbs
  `obs_list`/`obs_get`/`obs_search` (see the next section), and the `meta` health checks
  `meta_check_decompiler` and `meta_check_features` (preflight the optional features before you lean on one).
- **write** covers `proj_create` (start an empty, source-first project), `finding_record`,
  `finding_update`, `graph_create_node`, `graph_create_edge`, `graph_create_socket`,
  `graph_create_hypothesis`, `finding_link_same_code`, `finding_propagate`, `src_import_tree`,
  `finding_link_to_source`, `src_save_revision`, `src_import_oss_fuzz`, and more. It also
  holds the graph-removal tools — the reversible `graph_archive_node`/`graph_restore_node`/`target_archive`/`target_restore`
  and the hard `graph_delete_edge` — plus `finding_delete` for clearing a junk finding outright
  (a hard, irreversible delete that also removes the edges and annotations touching it, and
  detaches any task or fuzz artifact that referenced it); to set a finding aside reversibly
  instead, call `finding_update(status='dismissed')`.
- **run** covers `target_ingest`, `target_promote_file` (promote a file from an unpacked firmware into
  its own target), `task_run`, `finding_verify_poc`, `fuzz_verify_artifact`,
  `fuzz_start`/`fuzz_resume`, `src_build`, and more.

Call **`meta_get_schemas` first.** It advertises the Finding shape, the node and edge vocabulary, the
per-type node-attribute schemas (including the sink-versus-symbol rule), the edge-attribute schemas,
the socket kinds, and the active decompiler.

Before you lean on a tool whose dependency can drift, run **`meta_check_features`** during your orient
step. It preflights the features whose runtime dependency can diverge from what's configured (FLOSS,
YARA, angr, and Ghidra/emulation). FLOSS and YARA are always-on static tools, so they report
availability only, `available` when their dependency is present or `broken` when it isn't; the gated
features (angr, Ghidra/emulation) add a `disabled` state when their gate is off. That `broken` state is
the one worth catching early: a tool whose sandbox image is stale reads as fine in Settings yet errors
the first time you call it, and the check hands you the exact rebuild command (`just sandbox-build`,
`just angr-build`) instead of letting you find out mid-analysis. The companion **`meta_check_decompiler`**
does the same honest verification for whichever decompiler is configured.

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
already state, and `meta_get_schemas` spells out in its `substrate_vs_graph` and `observations` sections:

- **Query verbs add nothing to the graph.** `re_list_functions`, `re_xrefs`, `re_disassemble`, `re_list_strings`
  and the rest return their results as tool output and quietly record an Observation. They create no
  nodes and no edges. An enumeration is an answer, not a pile of graph objects.
- **Enrichment of existing objects is automatic and free.** When a call recovers something unambiguous
  about an object that is *already* a node, a function's recovered prototype and address, the `is_sink`
  tag on a dangerous import, the call sites on an existing `calls` edge, HexGraph attaches it in place
  with no further action from you. It only ever deepens nodes that already exist, and it never makes a
  judgment call (no severity, no "this is a vulnerability", no new node).
- **Promotion is deliberate.** A new node enters the graph only by an explicit act: `re_decompile_function`
  promotes the one function you asked about, `graph_create_node`/`graph_create_edge`/`finding_record` add the
  results you decide are worth keeping. Decompiling a function lists its callees in the result and draws
  `calls` edges only to callees already in the graph; it does not spawn a node per callee. A single call
  is also capped by a per-call promotion budget, and if a promotion would exceed it the overflow comes
  back as promotable results with an explicit "capped" note rather than being silently dropped.
- **Check before you re-run.** Because results persist, call `obs_list(target_id)` before
  paying to re-run an expensive analysis, and pull a prior payload back with `obs_get(id)`
  rather than recomputing it. An identical call against identical bytes is served from the existing
  Observation and flagged `cached`. The three read verbs are `obs_list(target_id, tool?,
  kind?, limit?)` for the newest-first index of metadata, `obs_get(id)` for one Observation in
  full including its complete payload from content-addressed storage, and `obs_search(query)`
  for a substring search over tool, summary, and result kind across a project or a single target. Every
  tool result also carries a one-line reuse hint pointing you at them.

The fuller, user-facing tour of all this lives in [observations.md](observations.md).

### Annotations are proposals; a rename is confirmed by a human

`graph_annotate` lets a driving agent attach a note, a tag, a type declaration, or a function
**rename** to a graph entity, and an agent's annotation lands as a *proposal*. It is recorded
against the node, but on its own it changes nothing else. The rename is where that distinction
matters most. When you confirm a proposed rename in the web UI, the graph takes the new name;
and when headless Ghidra is the active backend, HexGraph also writes the rename back into the
persistent Ghidra project and re-decompiles, so the name sticks for every later decompile and
the graph reflects the fresh result (with the radare2 backend there is no project to update, so
the rename lands on the graph alone). That approval is deliberately a person's call rather
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
