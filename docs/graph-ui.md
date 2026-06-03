# The typed graph & web UI

HexGraph records every analysis result in a typed graph backed by SQLite, and you browse that graph
through a loopback-only, three-pane web UI (`hexgraph serve`, then open http://127.0.0.1:8765).

![The typed knowledge graph of a firmware engagement](images/graph.png)

## The three panes

On the left is the **target tree**: the target you ingested and any firmware children it produced.
Each row has a launcher, where you pick a task type and, on the mock backend, a scenario, and then hit
**Run**. Firmware targets also show a browsable unpacked filesystem, and any file in it can be promoted
to a child target.

The center pane switches between two views with a segmented control. The **Graph** view renders the
targets, functions, sockets, hypotheses, harnesses, and findings as typed nodes joined by typed edges
(`contains`, `calls`, `taints`, `listens_on`, `built_from`, `located_in`, `harnesses`, and more),
drawn offline with Cytoscape.js. Click an edge and you see its attributes: call sites, ports,
addresses. The **Source** view is the in-browser IDE, covered in [build-from-source.md](build-from-source.md).

On the right is the **findings** panel. Every finding is typed (vulnerability, poc, recon, harness,
fuzz_crash, and so on) and filterable; click one to see its evidence, its reasoning, any verification,
and the follow-ups it suggests.

![A function node selected — connected edges light up, inspector opens](images/graph-selected.png)

Selecting a node lights up its connected edges and opens the inspector, where you can decompile,
annotate, or run a task. When a finding suggests a follow-up, clicking it opens a pre-filled launch
modal for the next task, and **Confirm** or **Dismiss** lets you triage. Dismiss is the gentle,
reversible option: the finding stays in the graph, greyed, and you can bring it back at any time. When
a finding is pure noise you never want to see again, the **Delete** button (set apart on its own,
behind a quick "delete permanently?" confirm) removes it for good, along with every edge and
annotation attached to it. The **Add node** and **Add edge** tools let you author functions, sockets,
hypotheses, and typed edges by hand.

![The findings panel, grouped by target with severity + type chips](images/findings-list.png)

Removing things is reversible by default. Archiving a node or a whole target subtree declutters the
graph, and re-adding the same entity brings it back. Individual edges, individual findings (the
Delete button described above), and whole projects, by contrast, are hard deletes. **Merge dupes**
folds duplicate functions, strings, and targets into a single
keeper, and it also runs automatically after every LLM task.

## The firmware's unpacked filesystem

Firmware targets keep their extracted rootfs around (in `metadata_json["filesystem"]`, with the files
on disk under the project's data dir). The detail panel lets you browse it, and any file can be
promoted to a child target.

![Browsing a firmware's extracted rootfs](images/filesystem-browser.png)

Extraction happens in the sandbox and covers the usual cases: bare squashfs (via sasquatch or
unsquashfs), cpio, partitioned full-OS disk images (via The Sleuth Kit), and wrapped vendor firmware
(via recursive binwalk, which in turn drives jefferson, ubi_reader, or sasquatch for nested JFFS2,
UBIFS, or cramfs).

## The data model

The store is SQLite through SQLAlchemy, with UUID ids and WAL mode so the UI and an agent's MCP server
can share the database from separate processes at the same time. Foreign-key enforcement is
deliberately off, because edges and annotations are polymorphic string references rather than FKs.

- A **`project`** owns a **`target`** tree linked by `parent_id`. A target is a *reachable surface*:
  either a byte target with a `path`, or a dynamic `web_app` or `service` surface reached through a
  Channel stored in `metadata_json` (see
  [dynamic-surfaces-rehosting-remote.md](dynamic-surfaces-rehosting-remote.md)).
- A **`node`** is a typed sub-file or conceptual entity: a `function`, `symbol`, `string`, `struct`,
  `hypothesis`, `pattern`, `input`, `sink`, `endpoint`, `param`, or `source_file`. A `socket` node is
  special: it is a network or IPC endpoint shared across binaries, identified by `(project, kind,
  port|name)`, so that a server that `listens_on` it and a client that `connects_to` it resolve to the
  same node. `NodeType` is a String column, which makes new vocabulary zero-migration.
- An **`edge`** is one polymorphic, typed, attributed relationship between any two entities (target,
  node, finding, or task): `contains`, `links_against`, `calls`, `reads` and `writes`, `taints`,
  `bypasses`, `listens_on` and `connects_to`, `routes_to` (route to handler), `similar_to`,
  `derived_from`, `about`, and so on. Edges carry type-specific attributes, and
  `engine/edge_schemas.py` is the registry of what is meaningful for each type (the `call_sites` and
  `arg_constraints` on a `calls` edge, say, or the `address` and `backlog` on a `listens_on` edge).
  That registry is guidance rather than a hard schema: unknown keys pass through, but list attributes
  merge as sets, so repeated edges accumulate `call_sites` instead of clobbering them.
- A **`task`** and a **`finding`** round it out. `task.status` is an Enum; `finding.status` is a plain
  String.

The graph is relational, and Neo4j is out of scope. Node identity for functions, symbols, and structs
is the *normalized* name within a target, with decompiler prefixes stripped, so `sym.get_param` and
`get_param` are the same node.

## The Finding schema is frozen

Every task and every backend, the mock included, emits exactly the shape defined in
`src/hexgraph/schemas/finding.schema.json` (shipped inside the package), and a contract test enforces
it. New structure goes in the DB envelope (`finding_type`, `evidence.extra`, and the like), never in
the frozen schema itself. The `finding_type` (one of `vulnerability`, `recon`, `harness`,
`fuzz_crash`, `poc`, `annotation`, or `other`, classified from the task that produced it) drives the
sort and filter controls in the findings panel.

## Mock scenarios

On the mock backend, the launcher offers a set of scenarios on `sbin/httpd`:
`static_analysis/critical_overflow` (a critical overflow plus a `related_to` edge to `libupnp.so`),
`/no_findings`, `/malformed_then_valid` (which exercises the JSON-repair retry), `reverse_engineering`,
`pattern_sweep` (a sibling match), `error_rate_limit` and `error_timeout` (graceful failure), and a
default scenario that always succeeds. For the three fidelity layers and the contract test, see
[design/mock-llm-provider.md](design/mock-llm-provider.md).
