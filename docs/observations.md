# Tool Results: the observation store

When HexGraph (or an agent driving it) analyzes a target, it runs a lot of deterministic tools in the
sandbox: it decompiles functions, lists the function inventory, traces cross-references, pulls strings
and structs. Each of those calls produces a result, and historically those results lived only as long
as the tool output that carried them. The observation store fixes that. Every deterministic tool call
is now recorded as a durable **Tool Result**, kept around so that you, or a later agent, can find it,
read it again, and reuse it instead of paying to recompute it.

## What a Tool Result is

A Tool Result records one tool call against one target: which tool ran, the arguments it ran with, a
short summary of what came back, and the full payload. The payload itself is kept in HexGraph's
content-addressed store rather than inline in the database, so even a large decompilation listing
doesn't bloat the project, and two identical runs share the same stored bytes. Each result is scoped to
the exact bytes of the target it was run against, by a content hash, so a result always tells you what
binary it actually describes.

A useful side effect of recording the call is that HexGraph can recognize a repeat. Ask for the same
analysis, with the same arguments, against the same bytes, and instead of re-running the tool HexGraph
hands back the result it already has, marked as cached. The intent is "analyze once, reuse forever": the
expensive work happens the first time and never again unless the bytes change.

## Why the graph stays small

The thing to understand about Tool Results is that they are deliberately *not* graph nodes. There are
two separate stores here, and keeping them apart is what makes HexGraph usable on real firmware.

The observation store is the **substrate**: the exhaustive, queryable record of everything that has been
looked at on a target. It can get large, and that is fine, because it is meant to. The **graph**, by
contrast, is a curated set of *results*. It holds the functions you are actually investigating, the
sinks that matter, the taint path behind a finding, and the findings themselves, the reasoning trail of
an engagement rather than a transcript of the whole program. If every function listing and every xref
dropped a swarm of nodes into the graph, the graph would become a copy of the binary and stop being
useful as a map of your thinking. So enumerations stay in the substrate as Tool Results, and only the
things you choose to keep become graph nodes.

That choice is explicit. A new node enters the graph because someone, you or the agent, decompiled
*that* function, recorded a finding on it, or added it by hand. Decompiling a function is the common
case: it promotes that one function and connects it to other functions already in the graph, but it
won't drag in fifty callee nodes behind it. The callees it found are listed in the result, ready to be
promoted if you actually want them.

## Enrichment quietly deepens what's already there

There is one kind of update that happens with no decision required, because it is the kind of update you
would always want. When a tool recovers something unambiguous about an object that is *already* in your
graph, HexGraph attaches it in place. A function node picks up its recovered prototype, address,
parameter and local counts, calling convention, and demangled name. A dangerous import such as `system`
or `strcpy` gets tagged as a sink. An existing `calls` edge accumulates the call sites where one
function calls another. A program-defined struct gains its recovered layout.

This enrichment is careful about its limits. It only ever touches objects that already exist; it never
creates a node. And it only ever applies plain, factual recoveries, never a judgment call, so it will
never decide a severity, label something a vulnerability, or write a summary on your behalf. Those need
a person or the model. Enrichment just makes the nodes you already curated a little richer, and it
records which Tool Result it drew each fact from, so the provenance is auditable.

It also works backwards in time. Facts recovered by a tool call that already happened are remembered, so
a node you add *later* picks them up automatically the moment it is created, without HexGraph having to
re-scan every prior result. Promote a function today and, if it was decompiled last week, its prototype
and address are already waiting for it. As more functions are promoted, the call edges among them fill
themselves in from those earlier results, so the curated graph's connectivity grows without ever growing
past the set of nodes you actually kept.

When the target's bytes change, the old facts simply stop matching. Re-ingesting a changed binary gives
it a new content hash, and because every Tool Result and every recovered fact is scoped by that hash,
the stale ones quietly fall out of scope rather than lingering as wrong answers. There is no cache to
flush.

## Finding prior results

Tool Results are only useful if you can find them, so HexGraph surfaces them in a few ways.

When a task runs, the context it assembles includes a compact index of prior analysis on the target,
something like "12 decompilations, a call graph, xrefs, a strings pass", so an agent learns what already
exists without having to guess. Every tool result also comes back with the id of the Tool Result it was
recorded as and a one-line nudge to check the store before re-running.

If you are driving HexGraph through its MCP tools, three read verbs let you mine the store directly.
`obs_list` gives you the newest-first index of prior results on a target, optionally filtered
by tool or by kind, returning the metadata for each. `obs_get` loads one result in full,
including its complete payload pulled back from storage, which is how you reuse a prior decompilation or
xref instead of paying to run it again. `obs_search` does a substring search across the tool
name, summary, and kind, over a whole project or a single target. The pattern these encourage is the
same one HexGraph follows internally: look before you compute, reuse the result if it is there, and
promote into the graph only the few results that carry your reasoning.

For more on how this contract shapes an agent's behavior over MCP, see [mcp.md](mcp.md); for the graph
the curated results live in, see [graph-ui.md](graph-ui.md).
