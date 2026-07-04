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
graph), `journal` (the freeform research notebook), `finding` (findings, n-day, and proving), `src`
(source trees and builds), `fuzz` (campaigns), `net` (live network interaction over HTTP, raw TCP, and
raw UDP, plus the egress log),
`task` (the task runner), and `meta` (schemas and
health). Closed value sets — node and edge types, finding severities, task types, the socket kinds,
and so on — are real schema `enum`s generated from the codebase's own definitions, so an
agent can't pass a value the engine doesn't understand.

The tools are also grouped into **read**, **write**, and **run**, and each group is gated by
`features.mcp.{read,write,run}` (in Settings → Coding-agent tools, or via `--tools`), which keeps the
agent's context small:

- **read** covers the listing and inspection verbs across the domains. `finding_list` returns
  findings newest-first, paginated (`limit`/`offset`, where `limit=0` means no limit) and
  filterable (`finding_type`/`status`/`severity`/`target_id`/`verified`); it default-excludes the
  per-child `recon` findings (ingest mints one per child target — easily hundreds), so pass
  `include_recon=true` (or `finding_type='recon'`) to see them. The `verified` flag lives in the
  finding's evidence JSON rather than a SQL column, so when you filter on it the paging runs over
  the verified-filtered set — page two of verified findings is reachable and a full page comes
  back whenever enough match. Also `graph_get_node`, `finding_get`, `re_xrefs`, `graph_list_sockets`,
  `graph_list_hypotheses` (the hypothesis worklist — statement, evidence status, work_state, evidence counts; your "what am I chasing" orient),
  `graph_stats` (per-type node/edge tallies — a cheap before/after count without listing every node),
  `proj_doctor` (reconcile the on-disk project dirs against the DB — orphan dirs with no project,
  or DB projects whose dir is missing; read-only unless you pass `clean=true` to delete the orphans),
  `fs_list`/`fs_read_file`, `src_list_trees`/`src_read_file`, `fuzz_status`,
  `src_list_builds`/`src_build_log`/`fuzz_coverage_diff`, the observation read verbs
  `obs_list`/`obs_get`/`obs_search` (see the next section), the journal read verbs
  `journal_list`/`journal_get`/`journal_search` (see the working-memory section below), and the
  `meta` health checks
  `meta_check_decompiler` and `meta_check_features` (preflight the optional features before you lean on one).
- **write** covers `proj_create` (start an empty, source-first project), `finding_record`,
  `finding_update`, `graph_create_node`, `graph_set_node_attr` (set one attr — e.g. `is_sink` — on an existing node), `graph_create_edge`, `graph_create_socket`,
  `graph_create_hypothesis` (records an open question on the worklist) with `graph_set_hypothesis_status`
  (pin a verdict and/or move the investigating/parked/done work-state) and `graph_close_hypothesis`
  (check one off — work_state→done plus the evidence verdict), the journal authoring verbs
  `journal_add`/`journal_update`/`journal_delete`, `finding_link_same_code`, `finding_propagate`, `src_import_tree`,
  `finding_link_to_source`, `src_save_revision`, `src_import_oss_fuzz`, and more. It also
  holds the graph-removal tools — the reversible `graph_archive_node`/`graph_restore_node`/`target_archive`/`target_restore`
  and the hard `graph_delete_edge` — plus `finding_delete` for clearing a junk finding outright
  (a hard, irreversible delete that also removes the edges and annotations touching it, and
  detaches any task or fuzz artifact that referenced it); to set a finding aside reversibly
  instead, call `finding_update(status='dismissed')`. It also holds the visibility verbs
  `target_set_visible` (reveal or re-hide one target) and `target_reveal_dir` (reveal every
  hidden firmware child under a rootfs directory prefix) — see the hidden-children note below.
- **run** covers `target_ingest`, `target_promote_file` (promote a file from an unpacked firmware into
  its own target), `task_run`, `finding_verify_poc`, `fuzz_verify_artifact`,
  `fuzz_start`/`fuzz_resume`, `src_build`, and more. `target_ingest` returns a bounded summary
  (the child count plus a preview of the first ~20 children, since firmware can unpack into
  hundreds); call `target_list(project_id)` for the full target tree.

**Firmware children are hidden by default.** A real firmware unpacks into hundreds of ELFs, so
unpack registers each as a child target but keeps it **hidden** — it's recorded, searchable, and
addressable, and recon still **enriches** it (its facts land on the target and as a `recon`
Observation, queryable via `obs_list`/`obs_get`), but a hidden child contributes nothing to the
curated graph and mints no finding. `target_list(project_id)` returns only the visible targets;
pass `include_hidden=true` (or browse the rootfs with `fs_list`, whose entries now carry
`added`/`revealed`) to find the children worth analyzing, then reveal them: `target_set_visible`
for one, or `target_reveal_dir(firmware_target_id, "usr/sbin")` for a whole directory at once.
Revealing flips the target visible and materializes its recon nodes from the already-stored facts
(no re-run), so it joins the graph. Recon's old risky-sink → static-analysis follow-up now surfaces
per target from the suggester (the firmware's own findings are unaffected).

When a binary PoC needs to feed raw, non-printable bytes (an angr-solved serial, a binary stdin
payload), `finding_verify_poc` takes byte-faithful `argv_b64` and `stdin_b64` fields: each is base64
that HexGraph decodes back to exact bytes and feeds to the target, instead of the text `argv`/`stdin`
that would mangle a byte like `0x06` or `0x0f`. The byte fields take precedence over their text
siblings and pair with an `output_contains`/`exit_code`/`crash` oracle. There is a direct handoff from
the solver, too: call `finding_verify_poc(target_id, {"oracle": {…}}, finding_id=<solver finding>)` with
no input in the spec, and HexGraph reconstructs the recovered reaching-input from the finding's
`evidence.extra.solver` (honoring its `input_model`) so the solved input runs as a real `argv[1]` and
you can confirm end to end that it reaches the sink.

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
`just angr-build`) instead of letting you find out mid-analysis. It also returns `image_stale`, a
proactive hint that the sandbox image predates `docker/sandbox.Dockerfile` (so it may silently lack newer
tools even when a per-feature probe still passes) — rebuild with `just sandbox-build`. The companion
**`meta_check_decompiler`** does the same honest verification for whichever decompiler is configured.

```bash
hexgraph mcp install [--agent claude|codex|gemini]   # print registration steps
hexgraph mcp install --write-skill .claude/skills    # also install the VR skill
hexgraph mcp --tools read,write                      # serve a restricted tool set
```

The VR skill is a small always-loaded spine (`SKILL.md`) plus a set of capability sub-files —
`static-analysis.md`, `dynamic-analysis.md`, `fuzzing.md`, `proving.md`, and `record-keeping.md`.
The spine teaches the whole engagement arc (ingest a path, orient, decompose the attack surface
across parallel sub-agents, prove, and synthesize) and routes the agent to the matching sub-file
when it enters a phase, so the deep methodology for fuzzing or live-surface assessment only costs
context when it is actually being used. `--write-skill` emits the whole set into the skill
directory; `--print-skill` prints the entire bundle as one document for a Codex or gemini system
prompt that cannot read the sub-files on demand.

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
- **A CFG blind spot has a fallback.** When both `re_disassemble` (which needs a defined function) and
  `re_decompile_at` (the function containing an address) return "not found" because the call graph has a
  hole at that address, `re_disassemble_range(target, 0x67158)` disassembles the raw byte range there
  with no function required, so you can still read the instructions. It is a query like the rest, bytes
  to instructions clamped to a generous ceiling, recorded as an Observation, and it adds nothing to the graph.
- **Cross-references reuse the warm analysis.** With headless Ghidra as the active backend, `re_xrefs`,
  `re_function_xrefs`, `re_data_xrefs` and `re_call_graph` answer from the persistent Ghidra project's
  reference index, the same analyze-once project the decompile verbs build, instead of re-analyzing the
  whole binary on every call. On a large target that is the difference between an instant answer and a query
  that never finishes, and an unknown symbol comes back as "not found" right away rather than after a long
  wait. With the radare2 backend, or before a first analysis has warmed the project, the verbs fall back to
  a fresh cross-reference pass.
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
- **Truncation is recoverable, never silent.** The body-returning tools (`re_decompile_function`,
  `re_decompile_at`, `re_disassemble`, `re_disassemble_range`, `re_search_decompiled`) inline at most about 6000 characters so
  your context stays bounded, but the full body always lives in the Observation. When a result is cut,
  the marker tells you both ways to get the rest: re-call the same tool with a larger `max_chars`
  (clamped to a generous ceiling, so one call can pull a whole long function), or read the recorded
  Observation in full with `obs_get(<id>)`, which is uncapped. So a long decompilation can never quietly
  hide a sink in its tail — raise `max_chars` rather than guessing from the head. `re_list_strings`
  applies the same discipline to a `strings(1)` grep: it filters the target's *full* string table (not a
  small sample), so a real command template like `.cgi`, a format string `%s`, or a config key like
  `aes` is found wherever it lives in the binary, and a broad match is paged with `offset`/`limit` that
  report the total and the next offset rather than clipping silently. For strings hidden behind a decode
  routine or built on the stack, `re_floss_strings` recovers what a plain pass misses, but only on x86/
  amd64 PE targets; on an ELF or other firmware it falls back to a plain static pass, so reach for the
  `re_list_strings` grep there.

The fuller, user-facing tour of all this lives in [observations.md](observations.md).

### The research journal: a working memory shared with the human

The `journal_*` tools back a freeform, markdown research notebook that the agent and the human share.
It is the place for the *story* the graph and findings don't capture: the idea you had, what you tried,
what worked or didn't, and what you learned. Keep it apart from the two stores it is easy to confuse
with. It is not the Observation store, which holds raw tool output recorded automatically; if you catch
yourself pasting a decompilation or a strings dump into a journal entry, stop, because that output
already lives as an Observation and the entry should say what it *meant*. And it is not a finding, which
is a substantiated result; a journal entry is interpreted narrative, not a structured claim.

The most valuable thing the journal buys you is cross-session memory. A later session re-orients in a
single call with `journal_search("what did I try on the CGI handler")` or `journal_list(project_id)`,
instead of re-deriving everything from the graph. `journal_get(entry_id)` reads one entry in full, with
its `@`-mentions resolved. An entry's body can `@[label](kind:id)`-mention any node, finding, target, or
hypothesis, which renders as a clickable link in the UI and survives a later merge or archive of the
object it points at, greying out rather than breaking.

Two rules shape how an agent writes to it. First, authorship: `journal_add` always records the entry as
the agent (you cannot post as the human), and `journal_update` and `journal_delete` refuse a
human-authored entry outright. The journal is a trust artifact, so the human's words stay exactly as
they wrote them, while you remain free to add and revise your own. Second, cadence: write a short,
skimmable line at each meaningful pivot or dead end and at task close, not one dump at the end. HexGraph
backs that up structurally rather than relying on you to remember. When an LLM or agent task finishes it
auto-drafts a closing session-log entry from the tool-call trace and the findings, and the task context
carries a running nudge when the journal has gone stale, so journaling is part of finishing a task the
way emitting findings is, not an optional courtesy call.

### Annotations are proposals; renaming a real name is confirmed by a human

`graph_annotate` lets a driving agent attach a note, a tag, a type declaration, or a function
**rename** to a graph entity. Notes, tags, and type declarations from an agent land as a
*proposal*: recorded against the node, but on their own they change nothing else.

Renames are handled with one deliberate exception. If the node still carries a decompiler
placeholder, one of those auto-generated `fcn.00401234` / `FUN_00401abc` / `sub_401000` names
that says nothing about what the function actually does, then an agent naming it applies right
away. There is nothing meaningful to overwrite, so on a binary with hundreds of unnamed
functions the agent can label them as it understands them without waiting on a click for each
one. The change is still fully auditable and reversible: the annotation row records that the
agent made it, and the old placeholder is kept in the node's `name_history`. Renaming a function
that *already* has a real, analyst-given name is the higher-stakes case, and there it still lands
as a proposal for a person to confirm. A human rename, of course, always applies.

When a rename does take effect, on a placeholder immediately or on a real name once you confirm
it in the web UI, the graph takes the new name. With headless Ghidra as the active backend,
HexGraph also writes the rename back into the persistent Ghidra project and re-decompiles, so the
name sticks for every later decompile and the graph reflects the fresh result; with the radare2
backend there is no project to update, so the rename lands on the graph alone. There is still no
MCP verb for an agent to confirm its own rename of a real name, so a human stays in the loop on
the names that become the shared vocabulary of the analysis, while the cheap, pure-value-add work
of naming the unnamed no longer waits on anyone.

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
