# Design: Curatable, filesystem-hierarchical targets & active-set graph visibility

Status: phased plan, approved for implementation. Phase 1 (the filesystem-hierarchical
targets pane) ships first as a frontend-only change; Phases 2–4 follow as separate PRs that
read this document as their reference.

Scope: how HexGraph presents and curates a *real* firmware's hundreds of child targets, in
both the left TARGETS pane and the graph. It covers the targets-pane navigation problem, the
upstream clutter problem (we currently materialize tens of thousands of nodes we then have to
hide), and the unifying visibility rule that ties curation to what the graph shows. It builds
on the graph-presentation work (see [`design-graph-presentation.md`](design-graph-presentation.md))
and specifically on PR #88's skeleton-first rendering.

---

## 0. The problem

Point HexGraph at a real firmware image and the numbers get large fast. IoTGoat, for example,
auto-extracts on the order of **250 ELF child targets** (every binary in the rootfs), and our
default deep recon turns each one into roughly **52 nodes** (functions, strings, symbols,
structs, …). That is about **13,000 nodes** for one firmware before the operator has expressed
any interest in any particular binary.

This lands as two *distinct* problems that are easy to conflate:

1. **Targets-pane navigation and curation at scale.** The left TARGETS pane renders the
   firmware's children with a recursive `TreeRow` keyed on `parent_id`. Firmware extraction
   (`engine/unpack.py`) names each child by its rootfs-relative path (`sbin/httpd`,
   `usr/sbin/telnetd`, `lib/libupnp.so`), so the children come back as a **flat indented list
   of hundreds of siblings**, each merely *labeled* with its path. There is no folder
   structure, no rollup, no way to collapse a directory you don't care about. The operator
   scrolls a 250-row wall to find `httpd`.

2. **Manufacturing clutter we then have to hide.** Deep recon on every child is what produces
   the ~13k nodes. The graph is then built from a graph that contains all of them, and a
   pile of presentation machinery exists largely to *hide* what we should not have made in the
   first place.

These are related but not the same, and the fix has two halves: make the pane navigable
(Phase 1), and **stop manufacturing the clutter** by deferring deep analysis until the operator
asks for it (Phase 2), then make graph visibility follow that same single curation signal
(Phase 3).

**What is already solved, and what isn't.** PR #88's skeleton-first rendering already tamed the
graph *render* at scale: above a size threshold the browser loads only the skeleton (rooms +
shared sockets + aggregated meta-edges, ~25 nodes at rest) and fetches a room's interior lazily
on expand, so the browser never holds 13k nodes at once. That solved *rendering* cost. It did
**not** solve (a) the pane being a 250-row flat scroll, nor (b) the fact that we still *compute
and persist* 13k nodes up front. This feature solves both.

---

## 1. Principles

These four principles govern every phase. When a later decision is ambiguous, resolve it by
the principle.

- **Don't manufacture what you'll only hide.** The cheapest node is the one never created.
  Deep node materialization is deferred (lazy) for auto-extracted firmware children, not
  produced eagerly and then suppressed.
- **Curation is a single lever; visibility follows it.** We already have several ways for
  something to be present-but-hidden (archive, graph scope, the layer panel). Adding a fourth
  overlapping mechanism would make the model incoherent. There is **one** notion of which
  targets are "in play" (the active set), and graph visibility is derived from it, not stacked
  on top of it.
- **Never hide that something exists.** This is a security tool, and silent omission is a lie.
  When something relevant is present but not loaded, we show a **stub with a count** ("+212
  more in `usr/bin/`", "1 cross-edge into an un-analyzed binary"), never an empty space that
  implies nothing is there.
- **Visibility is earned by active ownership or a live edge.** A node shows up because an
  active target owns it, or because it is connected (one hop) to something already visible.
  Nothing is visible merely because the view happens to be empty otherwise.

---

## 2. Phase 1 — filesystem-hierarchical targets pane (frontend only)

**Goal:** turn the flat 250-row sibling list under a firmware into a navigable tree of
collapsible directory folders, derived entirely client-side from the child targets' path-style
names. No backend, schema, or API change.

**The key observation:** firmware children are *already* named by their rootfs-relative path
(`sbin/httpd`, `usr/sbin/upnpd`, `lib/libupnp.so`). That string is a free filesystem hierarchy
— we just have to render it as one. Split each child's name on `/`; the leading segments are
directories and the final segment is the file.

### 2.1 What it does

When a target has children whose names contain `/`, the pane groups those children into
collapsible **directory folders** built from the path segments:

```
firmware.bin                         (the firmware root — unchanged)
  ▸ lib/            (1)              folder, collapsed, child count
  ▾ sbin/           (1)
      httpd                          leaf target row — full per-target behavior
  ▾ usr/sbin/       (2)
      telnetd
      upnpd
```

- **Directories are pure UI grouping.** They are *not* target rows, carry no id, and never hit
  the backend. The folder tree is derived from the existing target list the pane already holds.
- **Folders are collapsible**, each showing a **child count** and a **rolled-up status badge**
  (the worst finding severity among descendants, falling back to an analyzed/un-analyzed rollup
  in later phases). Keep the rollup simple in Phase 1; richer status is Phase 2/3 territory.
- **Sort:** directories first (alphabetical), then leaf targets (alphabetical), at every level.
- **Leaf rows preserve all existing per-target behavior** — click to select/scope, the Run
  launcher menu, Fuzz, Remove, finding-count badge, the `child`/`scoped`/`sel` styling.
- **Non-firmware targets are untouched.** A target whose children have plain names (no `/`)
  renders exactly as today. The firmware root itself still renders as the top node; its
  filesystem folders nest beneath it.
- **Default collapsed state** uses a heuristic so a huge firmware opens calm rather than fully
  expanded (e.g. collapse directories when the firmware has many children, or beyond a shallow
  depth). The operator expands what they care about.

### 2.2 Constraints and non-regressions

Frontend-only. No backend/schema/policy change. Must not regress the resizable panels (#85) or
skeleton-first graph load (#88). The flat rendering for non-firmware projects must be unchanged.
Visually it stays consistent with the current pane — same indentation idiom, the `child` CSS
class, chevrons that look native to the existing design.

### 2.3 Why frontend-only is the right first step

The directory structure is *latent in data we already have*, so Phase 1 buys the biggest
usability win (a navigable pane) at zero backend risk, and it stands alone usefully even if
Phases 2–4 slip. It also establishes the folder UI that Phase 2's "analyze directory" action
and Phase 3's per-directory view toggle will hang off of.

---

## 3. Phase 2 — cheap-vs-deep recon split + lazy materialization (backend)

**Goal:** stop manufacturing the ~13k nodes up front. Firmware extraction still creates a child
target *row* for every binary and runs **cheap** recon on each, but **defers deep node
materialization** until the operator activates a target.

### 3.1 Cheap recon vs deep recon

When firmware is extracted, every child target gets **cheap recon**: the lightweight facts
needed for the pane and for triage, computed without the expensive per-function/string/symbol
node explosion. Cheap recon covers:

- classification (executable / library / script / data),
- format and architecture,
- mitigations (NX, PIE, RELRO, canary, …),
- imports,
- network-facing detection (does it bind a socket / look like a service).

That is enough to populate the pane, show a meaningful status rollup, and let the operator
decide what's worth a closer look. **Deep recon** — materializing function/string/symbol/struct
nodes and the call graph — is what's deferred.

**Deferral applies only to auto-extracted firmware children.** A target the operator
*explicitly ingests* (a single file upload, the `ingest` CLI, an added child from the filesystem
browser) recons **fully, as today**. This keeps `just demo`, single-file flows, and the entire
existing test suite behaving exactly as they do now — the lazy path is reached only on the
firmware-extraction code path.

### 3.2 The activate / analyze action

A new **"analyze" (activate)** action deep-materializes a deferred target on demand, exposed in
three places that all route to one engine function:

- **API:** an endpoint to analyze a single target.
- **MCP:** a corresponding tool so an external agent can activate a target it wants to inspect.
- **Pane:** a button on a deferred leaf row, plus **"analyze directory"** on a folder to
  activate a whole subtree at once.

Activation is **idempotent** — activating an already-materialized target (or re-running over a
subtree) is a no-op for the already-done parts. "Analyze directory" walks the folder's leaf
descendants and activates each.

### 3.3 Tracking materialization state

Materialization state is **durable and queryable**: a new `target` column (with an Alembic
`revision --autogenerate` migration), not a `metadata_json` field, precisely because the pane
and the graph filter on it and we want to query/index it cheaply. A sensible shape is a small
enum/string — e.g. `recon_level` ∈ {`none`, `cheap`, `deep`} or an explicit
`materialized` boolean alongside the cheap-recon marker. (Final column name/shape is a Phase 2
implementation detail; the requirement is that it is a first-class queryable column with a
migration.)

### 3.4 Cross-target sweeps

Cross-target operations (same-code linking, merge-dupes, cross-target analysis) operate over
**materialized** targets — they can only relate nodes that exist. Where a sweep would clearly
benefit from more targets being materialized, it should **offer to materialize first** (a
materialize-then-sweep affordance) rather than silently skipping un-analyzed binaries.

---

## 4. Phase 3 — active-set visibility model + graph filtering

**Goal:** unify curation and graph visibility under one rule, so that what you see in the graph
is exactly the consequence of what you've put "in play" — not a separate stack of hide toggles.

### 4.1 The active set

A target is **active** if it is either:

- **materialized** (deep-recon'd via Phase 2), **or**
- toggled on by an **explicit per-target or per-directory "view" switch** in the pane.

The explicit view toggles are persisted like Saved Lenses — in `settings.json` / `localStorage`,
no DB change. The union of those two sources is the active set.

### 4.2 The visibility rule

Given the active set, graph visibility is fully derived:

1. **A node owned by an active target → visible** (still subject to its node-type layer in the
   layer panel; activation gates *membership*, the layer panel gates *type*).
2. **A shared node** (`target_id = None`, e.g. a `socket` shared across binaries) → **visible
   iff it has an edge to a visible node.** This is one-hop edge inheritance: the firmware's
   network map appears exactly where it connects to something you're looking at.
3. **A node owned by an inactive / un-materialized target → hidden**, *but* if an active target
   has a **cross-edge** to it, that owning target is rendered as a **collapsed stub with a count
   affordance** — never silent omission. Clicking the stub is how you bring it in (Phase 4).

That third clause is the security-honesty guarantee in graph form: if `httpd` (active) calls
into `libupnp.so` (not analyzed), you see a stub node telling you the edge and the target exist,
with a count, and a one-click path to analyze it.

### 4.3 Extending the skeleton/room endpoints

PR #88's `/graph/{id}/size`, `/graph/{id}/skeleton`, and `/graph/{id}/room/{targetId}` endpoints
are extended to **respect the active set and emit stubs**. The skeleton's rooms reflect active
targets; cross-edges to inactive targets come back as stub descriptors with counts so the client
can render the affordance. The lazy room-expand path is unchanged in spirit — it just now also
knows which rooms are "real" vs stubbed.

### 4.4 Consolidating with existing controls — one coherent model, not four

This is the crux. Today the codebase has several present-but-hidden mechanisms; Phase 3 makes
their relationship explicit rather than adding a fourth overlapping one:

| Control | What it means | Persistence | Reversible? |
| --- | --- | --- | --- |
| **archive** (`target.archived` / `node.archived`) | **Durable removal** — this is not part of my engagement; hide it everywhere until I re-add the bytes | DB column | yes, by re-adding |
| **graph `scope`** | A **transient** active set of exactly **{one target}** — "show me just this one right now" | URL / view state | yes, clear scope |
| **layer panel** | Visibility **by node-type** (functions on, strings off, …) — orthogonal to membership | view state / lens | yes |
| **active set** (new) | Which targets are **in play** = materialized ∪ explicit view toggles; drives graph membership | materialization column + settings | yes |

The clean reading: **archive** is durable curation (does this belong in the engagement at all),
**active set** is "what am I working on right now" (a generalization of `scope` from {one
target} to {a chosen set}), and the **layer panel** is an orthogonal type filter that composes
on top. `scope` becomes the degenerate single-target case of the active set. Phase 3 documents
this relationship in `docs/graph-ui.md` and reconciles the controls so the operator perceives
one model.

### 4.5 What we deliberately drop: reachability BFS as a visibility filter

An earlier idea was to compute reachability (a BFS from active nodes) and hide anything not
reachable. We **drop** that as a *hiding* rule, for two reasons. First, it mostly duplicates
membership: the overwhelming majority of nodes belong to exactly one target, so "reachable from
the active set" and "owned by an active target" coincide for them — the BFS buys little. Second,
it is *risky*: a relevant finding on a loosely-connected node could get hidden because no path
happened to reach it, which is exactly the silent-omission failure this design forbids. The
**one-hop "touches a visible node" rule (clause 2 above) captures the genuinely useful part** —
pulling in shared sockets and direct cross-edges — without the cost or the hiding risk.

The reachability *engine* itself is not going away; it stays where it belongs, in source→sink
taint/flow analysis. We are only declining to repurpose it as a presentation hide-filter.

---

## 5. Phase 4 — polish & consolidation (may fold into Phase 3)

The affordances that make the active-set model feel direct:

- **Activate-from-graph:** click a stub node → materialize that target and show it inline.
- **Activate-whole-directory** from the graph/pane.
- **Search-to-activate:** find a binary that lives in an unloaded room and activate it straight
  from the search result.
- Final affordance/count polish, and the **final reconciliation** of scope / archive / active
  set in the UI and in `docs/graph-ui.md`, plus showcase-seed coverage so the docs screenshots
  exercise the grouped pane and the stub affordance.

---

## 6. Non-goals

- **Neo4j** or any graph-database backend. The graph stays relational SQLite. (Out of scope,
  unchanged from the project-wide constraint.)
- **Reachability BFS as a hiding rule** (see §4.5). The taint/flow reachability engine is
  unaffected.
- **Changing the frozen finding schema.** All new structure lives in DB columns / the envelope.
- **Per-user / multi-tenant active sets.** HexGraph is a single-operator local tool; the active
  set is a single global notion per project, persisted in that operator's settings/localStorage.

---

## 7. Phasing summary

- **Phase 1 (this PR):** filesystem-hierarchical targets pane — frontend only, derived
  client-side from existing child names. Makes the pane navigable.
- **Phase 2:** cheap-vs-deep recon split + lazy materialization (deferred only for auto-extracted
  firmware children) + an idempotent activate action (API/MCP/pane, plus analyze-directory) +
  a durable, migrated materialization column. Stops manufacturing the clutter.
- **Phase 3:** the active-set visibility model + graph filtering + skeleton/room stub emission +
  explicit consolidation of archive / scope / layers / active-set into one documented model.
  Drops reachability-as-hiding.
- **Phase 4:** activate-from-graph / -directory / -search, count affordances, final
  reconciliation + docs + showcase coverage.
