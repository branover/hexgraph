# Design: Graph Presentation — making the dense graph parseable and inviting

Status: approved for phased implementation. This is the canonical synthesis of a five-lens
design council (information architecture, layout/technique, interaction/navigation, visual
legibility, complementary views). It supersedes the individual lens proposals.

Scope: a **density-and-organization redesign** of the project graph view
(`frontend/src/components/GraphView.tsx` + its host `frontend/src/pages/Workspace.tsx`),
grounded in Cytoscape.js and HexGraph's real node/edge vocabulary
(`frontend/src/api.ts`: `Graph`/`GraphNode`/`GraphEdge`; the `KIND`/`NODE_T`/`SEV`/`EDGE_C`
color maps and `NODE_SHAPE` in `GraphView.tsx`). No backend, schema, or migration change is
required for the core of this plan; everything derives client-side from the existing `/graph`
payload and `settings.json` prefs (see the seam note in §10).

---

## 0. The problem and the governing principle

### The problem (the eyes-on diagnosis the council agreed on)

The graph reads beautifully at SMALL (~15 nodes) and MEDIUM (~40), and falls off a cliff at
LARGE (~178 nodes / ~599 edges) and PATHOLOGICAL (~500 / ~2005), where it becomes an
undifferentiated hairball: a flat plane of equal-weight 26px dots, one global `dagre LR` pass
that letterboxes the clump into the upper-center with wasted black margins, edges as the
dominant ink, no entry point for the eye, type-color dissolving into soup because hues no
longer have enough pixels to register, and a selection highlight (`.lit` on connected edges)
that is swallowed whole by the surrounding mesh.

Root causes, in one line each:

1. **One flat plane of N peers.** The data is deeply hierarchical (`firmware ⊃ executable/library ⊃ function/endpoint/socket`; `finding —about→ node`; `socket` shared across binaries) but the view renders it flat.
2. **One fixed layout for all sizes.** `dagre LR` is right for one binary's call flow, wrong for 12 binaries' worth of meshes at once.
3. **Edges are the dominant ink.** Mostly structural (`contains`/`references`) cobweb drowns the semantic (`taints`/`routes_to`/`listens_on`) signal.
4. **No visual hierarchy.** Uniform 26px nodes ⇒ the eye lands nowhere.
5. **Highlight without suppression.** Brightening the focus does nothing when the rest stays at full strength.
6. **The graph is asked to be the table of contents and the triage list** — jobs the already-scalable left target-tree and right findings-list do better.

### The governing principle

> **Human parsability beats completeness — but never at the cost of information.**
> The graph keeps every node, every edge, and every type color. What changes is *how much
> competes for the eye at once*: the screen is **calm by default and loud only where you are
> looking.** At every zoom level, the dominant ink on screen should be the thing the user is
> currently focused on — not the resting hairball.

Three layered mechanisms realize this, coarse→fine, composing cleanly:

- **Structure** — express the latent hierarchy as visible structure (compound "island" nodes per target; a default that opens collapsed to the skeleton; a Map overview for the most complex targets).
- **Layout & semantic zoom** — pick the layout by graph shape, spread unrelated subgraphs into separated islands, and render detail as a function of zoom (level-of-detail) so color and labels only ever fight for space when few enough elements are present for them to win.
- **Focus & navigation** — replace passive highlight with **focus = isolate the neighborhood, mute everything else, auto-frame it**, made reversible by a breadcrumb/back stack and driven by search and the side panels.

**Hard constraints honored throughout:** type color-coding is kept and actively *defended*
(this is not a de-coloring); same information, no loss (off-focus is muted, never deleted; the
whole graph is always one click away); Cytoscape-native primitives only.

---

## 1. The default complex-target experience

A complex target must **open inviting, not intimidating.** The default is chosen by a single
data-driven rule computed from the already-fetched graph (`graph.nodes.length + graph.edges.length`):

| Tier | Approx size | Default view on open |
|---|---|---|
| **SMALL** | ≤ ~40 nodes | **Full graph, today's behavior, unchanged.** It already reads beautifully — this is the bar everything else must reach. Auto-expand the single firmware so a 15-node graph never looks over-abstracted. |
| **MEDIUM** | ~40–80 | **Graph, skeleton-collapsed** to target islands, with the islands auto-expanded if total stays under the SMALL ceiling. Effectively today's good frame. |
| **LARGE / PATHOLOGICAL** | > ~80 nodes | **Skeleton-first graph by default**, with an **opt-in Map overview** available (see decision D6). Either way the first frame is ~10–25 labeled, spaced, finding-weighted *rooms*, never the raw mesh. |

The headline promise, stated as the maintainer would: **open a LARGE target cold and within
two seconds your eye should rest on the firmware root and the red/orange high-severity rollups;
the screen should feel like a calm set of countable, labeled rooms — something you want to dive
into.** The raw 500-node subgraph is never the *default*; it is something you *navigate into*.

### The skeleton (the default frame for LARGE/PATHOLOGICAL)

Render, by default, only the **structural skeleton**:

- **Each byte target** (`executable`, `shared_library`, `web_app`, `service`) becomes a **Cytoscape compound parent node** — a labeled, rounded "island" box, tinted at low alpha with its `KIND` color (firmware purple, executable blue, library teal…) and a 1.5px same-hue border. The firmware image is the grandparent compound. A 12-binary firmware shows as **12 labeled boxes inside one box**, not 178 dots.
- **Each collapsed island shows a summary chip:** `binston_003 · 14 fn · 2 ⚠`. The `⚠` is a **finding-severity rollup** — the island's border/badge takes the max-severity `SEV` tint (red/orange), so the eye is pulled to the binary with the critical finding *before anything is expanded*. This is the missing entry point.
- **Card size ∝ finding weight** (critical=4 … info=1, summed): the most dangerous binary is literally the biggest, most saturated card; finding-free libraries are small and muted. This is the only place a target's color is deliberately desaturated, and it is the sanctioned mute (reserve saturation for what matters).
- **Cross-target semantic/structural edges are promoted to the skeleton** and **aggregated**: parallel `links_against`/`references`/`connects_to` edges between two islands collapse into a single weighted meta-edge with a count (`links_against ×7`), width ∝ count. So the first frame already tells the structural story (these 12 binaries, this one links that one, this socket is shared by three) without the 599 individual edges.
- **Shared `socket` nodes** (`target_id = null`, cross-binary) belong to no single island. They render in a **dedicated "network bus" lane** between the islands (keeping their hexagon + pink), making the firmware's network map a first-class, separately-readable region.
- The interior of an island (functions, strings, symbols, params, sinks) only materializes when the user **drills in / expands** that island.

This single move converts the PATHOLOGICAL smudge into ~12–25 calm, countable rooms. Below the
SMALL node ceiling we auto-expand so the skeleton never over-abstracts a small graph.

---

## 2. Grouping, layering, and filtering

These are three orthogonal levers. **Grouping** reorganizes the canvas; **layering** shows/hides
whole *classes* of element; **filtering** subtracts by *value*. They compose.

### 2.1 Grouping (how the canvas is organized) — a first-class, switchable facet

A **"Group by"** toolbar control (next to Filter). Grouping is just a recomputed `data.parent`
assignment fed to the same render — cheap, no re-fetch:

- **By target** *(default)* — compound islands per binary/library/web_app, nested in the firmware. The dominant, recommended view.
- **By node type** — compound boxes per type (all `function`s, all `endpoint`s, all `socket`s). Answers "show me every network endpoint across the firmware" without binary boundaries.
- **By finding** — invert the graph around findings: each finding diamond becomes a parent containing the nodes it is `about`/`taints`. The triage view: "here are the 9 findings and the code each one touches."
- **None (flat)** — today's behavior, for genuinely small graphs or power users.

**Collapse/expand is first-class** (via `cytoscape-expand-collapse`, built on compound nodes),
replacing today's hand-rolled double-tap descendant-hiding (`GraphView.tsx:49–83, 149`):

- Islands are **collapsed by default at LARGE/PATHOLOGICAL**, **expanded at SMALL/MEDIUM**.
- **Collapse all** (back to skeleton) and **Expand all** controls. Expand-all is gated to a visible-node ceiling (warn above ~150) so the hairball can't be accidentally re-summoned.
- Expanding an island re-runs layout **scoped to that island's children only** (see §3), so its functions appear inside the box, the box grows, and siblings reflow incrementally rather than the whole graph relaying out.

### 2.2 Layering (which classes of element are on the canvas) — a proper layer panel

Recast today's two ad-hoc toggles (functions, findings) into a composable **layer panel**:

**Node-type layers** (each a toggle with its legend color swatch — the full vocab):
`function · symbol · string · struct · endpoint · socket · param · input · sink · hypothesis · pattern · finding`.
Defaults preserve today's policy, generalized: `symbol`, `string`, `param` **off** by default;
`function` off in the skeleton and auto-on when you expand a binary; everything else on.

**Edge-class layers** (the single biggest density lever — edges are the dominant ink):

- **Structural** — `contains`, `located_in`, `references`, `links_against`, `built_from`.
- **Call graph** — `calls` (its own toggle; turning it off alone de-hairballs a binary's interior dramatically).
- **Semantic / security** — `taints`, `bypasses`, `routes_to`, `listens_on`, `connects_to` (default emphasized — these carry the finding).
- **Provenance** — `produced_artifact`, `instrumented_build_of`, `fuzzed_by`, `derived_from`.

A user investigating taint toggles off call/structural/provenance and sees **only the colored
`taints`/`routes_to` paths** across the firmware — color fully readable because the canvas is now
sparse. (The findings layer keeps its existing tri-state: all / unresolved / none.)

### 2.3 Filtering (value facets) — a filter chip rail, subtractive-by-fade-first

A collapsible **filter chip rail** for *value* facets, distinct from class layers:

- **Severity** (info→critical) threshold.
- **Target** multiselect (others collapse + fade).
- **Finding type** (`vulnerability`/`recon`/`fuzz_crash`/`poc`/… — the real `finding_type` field).
- **Edge origin / confidence** (the `origin`/`confidence` fields already on `GraphEdge`) — e.g. hide low-confidence inferred edges.

**Fade-first:** a filtered-out element first **fades to context opacity**, and only fully hides on
a second explicit "hide" toggle. The user never silently loses information — they always see
"there's more behind this," honoring the no-loss constraint.

---

## 3. Layout, semantic zoom, auto-fit, and spreading

One layout cannot serve 15 nodes and 2005. **Pick the layout by graph shape and grouping, and
lay out hierarchically.**

### 3.1 Layout by context

Add **`cytoscape-fcose`** (force-directed, compound-aware, fast on thousands of nodes; handles
PATHOLOGICAL where cola stalls). Keep **`dagre`** (scoped). Add **`concentric`** (core) for hub
views.

- **Skeleton / overview** → **`fcose`** with high `nodeSeparation`, `tile: true`, `packComponents: true`, and a healthy `componentSpacing`. fcose (a) respects compound parents, packing children inside their box, and (b) **spreads disconnected components apart** — twelve binaries with no edges between them get tiled across the canvas with breathing room instead of stacked into the upper third. This directly fixes "spread unrelated subgraphs as distinct islands."
- **Inside one expanded/focused binary** → **`dagre LR` scoped to that subgraph** (`eles: island.descendants()`). The left-to-right call-flow reading direction that already works beautifully at SMALL is exactly right *inside* one binary, without relaying the whole graph.
- **Hub focus** → **`concentric`**: a focused high-degree node centered, neighbors ringed by hop distance — so a degree-25 hub's neighbors are placed *around* it, on-screen, instead of running off into the dark.

Layout is chosen by **context (skeleton vs in-binary vs hub-focus)**, never by guessing on raw
node count alone.

### 3.2 Kill the letterbox / spend empty canvas on separation

The letterboxing is a `fit()` artifact: `dagre` produces a wide-flat aspect that `fit` shrinks to
width, leaving vertical margin. fcose with `tile` + `packComponents` produces a squarer aspect that
fills the pane. As a backstop: after layout, if the bounding box uses **< ~55%** of the viewport
area, nudge `componentSpacing`/`nodeRepulsion` up and re-run once — spend empty canvas on
separation (literal breathing room). Target utilization **55–80%**.

### 3.3 Semantic zoom (level-of-detail) — defend color, reveal detail on approach

A debounced `cy.on('zoom')` handler toggles style classes by `cy.zoom()` thresholds. Three tiers:

- **Far (z < ~0.4): ISLANDS ONLY.** Hide intra-island detail; show the labeled `KIND`-tinted island boxes + aggregated inter-island ribbons + the socket bus + severity pips. **Edge labels off** (they are the label-collision culprit). Color reads because the ink is ~15 big tinted boxes, not 500 dots.
- **Mid (~0.4–1.0): STRUCTURE.** Show node shapes/fills; node labels only for high-importance nodes + the `ALWAYS_LABEL` semantic edges; suppress `function`/`string` labels.
- **Near (> ~1.0): FULL DETAIL.** All labels, edge labels, attrs hints (`×N` call sites, `@addr`, `:port`) — today's behavior.

Pair with `min-zoomed-font-size` so labels never render sub-legibly — they disappear cleanly
rather than colliding into mush.

### 3.4 Auto-fit / auto-zoom behavior

Auto-zoom is **scoped and intent-driven, never a surprise.** It fires only on an explicit
navigation act:

- **Expanding / focusing / soloing an island, or selecting a search result** → `cy.animate({ fit: { eles: <focus set>, padding: 40–60 } }, { duration: 300–350 })`. You land framed inside a clean readable subgraph.
- On first open it fits the **skeleton** (the islands), not the full element set, so the default frame is the rooms.
- Auto-zoom does **not** fire on plain selection/hover (those use class-based emphasis only — §4), so the camera never jumps under the user unexpectedly.

---

## 4. Focus, hide, and navigation interactions

This is where the diagnosis is sharpest. Replace passive highlight with an active focus model,
three element classes managed centrally:

- **`.focus`** — the selected node + its chosen N-hop neighborhood: full saturation, full/enlarged size, crisp labels, edges at width 2.5+ with labels. Color does maximal work here.
- **`.context`** (the default off-focus mute) — everything else: **desaturated to ~12–25% opacity** (`opacity` + `background-blacken`), labels dropped, edges thinned to hairlines, `events: "no"` so they don't steal taps. **Present** (structure/orientation preserved) but visually receding. **Hue is preserved at low alpha** — this is muting, not de-coloring.
- **`.dim-hidden`** — collapsed-away groups shown only as a small ghost chip; and the explicit hard-hide path below.

### 4.1 Interaction inventory

- **Hover** (`mouseover`/`mouseout`) → transient preview: `.hl` the node + direct edges + their endpoints, `.dim` the rest, turn on the hovered node's edge labels (read relationship *types* on glance). No reframe, no commit. The 200ms answer to "what is this connected to?" before deciding where to focus.
- **Single-click** → select + inspector + ring (today's behavior, kept).
- **Double-click a node** → **focus**: `.focus` the node + 1-hop neighborhood, `.context` the rest, auto-frame, push a breadcrumb. (Collapse/expand moves to the `▸` badge + context menu, freeing double-click for the high-value gesture.)
- **Double-click / "Focus this" on an island** → **solo**: that binary expands fully with scoped `dagre LR`, every other island collapses to a chip and fades to `.context`, the viewport auto-fits the focused subgraph. The rest is still there, one click away — never destroyed. `Esc`/background → un-solo; fcose re-spreads everyone.
- **`+k` expand chip** on focus-boundary nodes (reusing the `▸N` badge pattern) / press `E` → **expand one hop** (`node.neighborhood()` + `cy.add`, local re-layout with `randomize:false` so existing nodes barely move). A **hop slider (1–3)** grows the neighborhood at once, bounded so it can never re-summon the whole graph in one click. The expand chip's hover sub-menu offers **typed expansion** (`expand: calls · routes_to · taints · all`) driven by the real `EDGE_C` vocab — traverse the graph the way the data is shaped.
- **`Hide rest` toggle** in the focus bar → upgrades `.context` → `display:none` for a truly empty canvas (PATHOLOGICAL). Reversible in one keystroke.
- **Right-click context menu** (`cytoscape-cxtmenu`) gathers the verbs: Focus neighborhood · Expand neighbors (typed) · Isolate (focus + hide rest) · Collapse/Expand subtree · Hide this node (reversible — adds to a `manuallyHidden` set surfaced as a `"3 hidden ↺"` chip, never a silent loss) · Reveal in inspector. On empty canvas: Back to overview · Fit.

### 4.2 Reversibility — the focus stack & breadcrumbs

Focus without a way back is a trap. A **focus stack** (`useState<FocusFrame[]>`) is surfaced as a
**breadcrumb bar** pinned top-left of the canvas:

```
[ Overview ] › R7000 firmware › binston_003 › fn_handle_request        [↺ reset]
```

- Every focus/solo/expand act **pushes a frame** `{anchorId, hop, label, viewport}`.
- Click any crumb → pop to that frame (restores its focus set + viewport). `Esc`/`Backspace` → pop one. `↺` → Overview.
- Frames serialize into the URL via the existing `setUrl` primitive (`?focus=<id>&hop=1`), so a focused view is **shareable and reload-restorable** — reload lands you back in the neighborhood, not the hairball.

### 4.3 Search drives the graph

Search exists (`doSearch`) but today only drops a ring into the hairball. Wire it to **focus**:
picking a result calls `focusOn(id)` — auto-expand the path to it if it is inside a collapsed
island, enter focus on it, fade the rest, auto-frame, push a breadcrumb `Overview › <result>`.
"Find `system@` and show me its world" becomes one action. (`Shift+Enter` = select-only for users
who know where they are.)

### 4.4 Importance-driven node sizing (the entry point)

Stop drawing every node at 26px. Size by a cheap importance score computed once at build:

| Tier | What | Size | Treatment |
|---|---|---|---|
| **Anchors** | targets / project root | 38–44px | full saturation, crisp border, always-labeled, optional type glyph |
| **Hubs** | degree ≥ ~8 | `mapData(degree)` 30→40px | slight underlay glow |
| **Detail** | everything else | 22px | label on zoom/hover/focus only |

Findings keep the diamond + `SEV` ramp, sized up for critical/high. Now the eye lands on the
firmware root and the hubs before any interaction.

---

## 5. Visual legibility at density (mute, never de-color)

Color is **kept and defended**, never removed. The mutes live entirely in the focus/context
classes and the resting register; the type→color maps (`KIND`/`NODE_T`/`SEV`/`EDGE_C`) are
untouched.

- **Resting edges recede.** Resting edge opacity `0.55 → 0.32`, width `1.6 → 1.2`. **Structural** edges (`contains`/`references`, the `#46506a`/`#3b4458` grays) drop to `~0.18` and lose arrowheads at rest — they are scaffolding, not signal. This is the biggest LARGE win: pushing back the gray cobweb lets the colored semantic edges separate out. Node fills stay fully saturated (small dots, cheap ink); **edges carry the mute, not nodes** — so we reduce busyness, not color.
- **Shape redundancy.** Extend `NODE_SHAPE` so every type is shape-distinct (e.g. `struct`→barrel, `hypothesis`→pentagon, `pattern`→hollow-diamond), and put a small monochrome **type glyph** on *anchors only* (chip=firmware, terminal=executable, globe=web_app, plug=socket). Three redundant channels (color + shape + glyph on the important nodes) keep types tellable apart when nodes shrink below hue-resolution and for colorblind/low-contrast viewers — without weakening color for anyone.
- **Label discipline (ink-on-demand).** Node labels via `text-opacity: mapData(zoom, …)` — colored shapes when far, labels fade in when they fit; anchors and `.focus` nodes exempt. Edge labels only on `.focus` + `ALWAYS_LABEL` edges and only above a zoom floor. Keep the dark label halo, bump to opacity 0.9 + 3px padding so the few labels shown never sit illegibly on an edge.
- **The legend stays and sharpens.** Keep the dynamic legend (driven from the same color maps, showing only present types). Upgrade: render each chip with its actual **shape** filled with its type color (teaches the shape+color pairing); **hover a chip → preview-focus that type** (`.focus`/`.context`); **click → persistent isolate-by-type** (extends today's per-type hide beyond findings+functions). The legend becomes the discoverable home for show/hide-by-type with zero new chrome. Contrast pass: brighten the structural-gray legend swatches (so the legend reads) even while their canvas edges are de-emphasized.

The off-focus mute is exactly the secondary color refinement the brief blesses: applied via
Cytoscape classes (opacity/blacken/label), never by editing the palette.

---

## 6. Complementary views and the panel relationship

The node-link graph is superb at "show me how *this* set of things connects" and bad at being a
table of contents or a triage queue. HexGraph **already ships the scalable views the graph
lacks** — the left target-tree and right findings-list stay legible at PATHOLOGICAL. The design
makes them *drivers of graph focus* and adds a small set of complementary center-pane views,
**introduced only at the tiers that need them.**

### 6.1 Center-pane view switcher

Extend the existing `Graph ⇆ Source` toggle (`switchView`, URL-synced) into:

```
[ Map ]  [ Graph ]  [ Table ]  [ Matrix ]  [ Source ]
```

- **Graph** — the node-link view (this whole doc). Always *scoped* on a complex target (a scope chip `Scope: httpd · 2 hops [×]`); clearing scope on a complex target returns to the skeleton/Map, never dumps the raw mesh. The whole graph is reachable via an explicit "Overview (everything)" action that warns at PATHOLOGICAL.
- **Map** — a compound "territory" overview: one finding-weighted card per target, `fcose`-spread, **no intra-target edges drawn at rest** (cross-target ribbons on a toggle). This *is* the skeleton frame from §1, surfaced as its own named view for the complex tiers. Tap a card → side panel filters to that target; double-tap → drill into the scoped Graph for that binary.
- **Table** — sortable/filterable **Nodes** and **Edges** tables (type swatch · name · type · target · degree · #findings; and type · source · target · attrs · origin · confidence). The honest tool for "178 functions" and the only fully usable surface at PATHOLOGICAL — answer "the 3 highest-degree functions in httpd" in two clicks. Row click → reveal in scoped Graph. Plain React over the already-fetched `graph`, virtualized.
- **Matrix** — an adjacency matrix for the one genuinely dense relationship: cross-binary `links_against`/`similar_to`/`references` (N×N over a *small* N of targets, zero crossings at any tier). Cell click → scoped Graph of that pair.
- **Source** — unchanged.

### 6.2 Saved Lenses (named views)

A *Lens* = `{ view, scope, filters, layout }`, persisted in `settings.json` (the managed,
writable prefs seam — no schema/migration) and deep-linkable (`?lens=attack-surface`). Three
auto-seeded lenses give a complex target several inviting entry points: **Attack surface**
(sockets/endpoints/params + their `routes_to`/`listens_on`/`taints` edges), **Findings only**
(findings + `about` targets), **Per-binary** (the Map).

### 6.3 Panels drive, center displays (no duplication)

| Panel | Role | Change |
|---|---|---|
| **Left: target tree** | Table of contents / hierarchy navigator. | Clicking a row **also scopes the center view** (today it only selects); show the same finding-weight severity dots used on the Map for at-a-glance hotness. |
| **Right: findings/tasks** | Triage queue (already the most legible thing). | Clicking a finding **scopes + reveals** its evidence neighborhood in the center view (extends today's `reveal`). |
| **Center: view switcher** | The display surface, always showing a *scope chosen by the side panels*, never the whole universe by default at scale. | The redesign. |

The graph stops trying to be the tree or the list, and becomes what it is uniquely good at.

---

## 7. Key decisions (recommendation + trade-off)

Each is shipped as an **atomic, revertable merge** and surfaced to the maintainer.

### D1 — Default-collapsed/grouped vs show-all at scale
**Recommendation: default-collapsed to the target skeleton for LARGE/PATHOLOGICAL; unchanged
show-all for SMALL/MEDIUM (auto-expand below the node ceiling).**
*Rationale:* the flat plane is the root cause; the skeleton is the single highest-leverage fix and
turns the smudge into countable rooms. *Trade-off:* an extra interaction (expand/drill) to see a
binary's interior, and a (small) risk of over-abstracting a borderline-MEDIUM graph — mitigated by
the auto-expand-below-ceiling rule and the always-available "Full"/"Expand all" escape. Collapse is
non-destructive and one click reverses it.

### D2 — How aggressively to mute off-focus
**Recommendation: two-stage. Resting graph is *calm* (structural edges ~0.18, semantic ~0.32, node
fills full color). Focus mutes the off-focus set to `.context` ~12–25% opacity + desaturate +
drop labels, hue preserved. A `Hide rest` toggle hard-hides for PATHOLOGICAL.**
*Rationale:* contrast is created by *suppression*, which works at any density, while keeping faded
context preserves "you are here." *Trade-off:* aggressive muting can feel like information vanished
— countered by keeping hue at low alpha (still faintly visible), the breadcrumb (path is on
screen), and making hard-hide an explicit opt-in, not the default.

### D3 — Whether to add non-graph views, and when
**Recommendation: yes — add Table and Matrix, but introduce them as *opt-in tabs* surfaced
prominently only at LARGE/PATHOLOGICAL; Map is the §1 skeleton given a name. Do NOT change the
default away from Graph for SMALL/MEDIUM.**
*Rationale:* a node-link diagram is the wrong representation for "many of the same type" or "dense
N×N"; tables/matrices scale infinitely and make PATHOLOGICAL fully usable. *Trade-off:* more
surface area to build and learn; mitigated by phasing them last (Phase 5), reusing existing
search/filter idioms and the color maps, and keeping Graph the default everywhere it works.

### D4 — Default view for a complex target
**Recommendation: skeleton-collapsed Graph by default at LARGE/PATHOLOGICAL (D1), with the Map
view available and offered. SMALL/MEDIUM keep today's full graph.**
*Rationale:* the skeleton and the Map are the same structure; defaulting to the in-Graph skeleton
keeps one mental model (you are always "in the graph," just zoomed to its rooms) while the Map tab
exists for users who want the pure overview. *Trade-off:* a Map-as-hard-default (the views lens's
stronger position) would more decisively prevent any hairball, but at the cost of a second mental
model and a heavier first build; chosen against for cohesion, revisited if assessment shows the
in-graph skeleton still reads busy.

### D5 — Auto-zoom behavior
**Recommendation: auto-zoom (animated `fit`) fires only on explicit navigation — expand/solo an
island, select a search result, click a crumb. Never on plain hover/select; never a full-graph
auto-fit at scale (fit the skeleton/focus set instead).**
*Rationale:* scoped auto-framing is the payoff that turns a 500-node target into a clean local
view; unsolicited camera moves are disorienting. *Trade-off:* the user must act to get the framed
view (vs the camera always tracking selection) — accepted, because predictable cameras beat clever
ones.

### D6 — Compound islands as the structural primitive
**Recommendation: yes — render targets as Cytoscape compound parent nodes (`cytoscape-expand-collapse`
+ `cytoscape-fcose`), grouping by target as default, switchable to type/finding/none.**
*Rationale:* the hierarchy is already in the data; compounds make it the primary visual structure
and let color read at the cluster scale. *Trade-off:* new frontend deps and a more complex render
path than today's flat list; mitigated by these being well-maintained Cytoscape-ecosystem
extensions and by the flat ("None") grouping remaining as a fallback.

### D7 — Layout engine
**Recommendation: context-adaptive — `fcose` (compound, spread) for the skeleton/overview,
`dagre LR` scoped inside an expanded binary, `concentric` for hub focus. Keep `dagre`.**
*Rationale:* no single layout serves 15 and 2005 nodes; each is used where it wins. *Trade-off:*
more layout code paths to maintain and tune; mitigated by choosing on a small set of explicit
contexts (skeleton / in-binary / hub-focus), not a continuous heuristic.

### D8 — Keep type color-coding (hard constraint, recorded as a decision)
**Recommendation: keep all color-coding; defend it via edge-mute + size ramp + shape/glyph
redundancy + semantic-zoom. The ONLY color change is desaturating off-focus/finding-free elements.**
*Rationale:* color is the prized differentiator that already reads at SMALL/MEDIUM; the problem is
density, not palette. *Trade-off:* none material — this is a constraint, surfaced so a reviewer
confirms no merge quietly de-colors the graph.

---

## 8. Phased implementation plan

Each phase is **independently shippable as an atomic, reviewed merge**, ordered
lowest-risk/highest-value first. Each phase carries before/after Playwright captures (§9) and a
`docs/ui-backlog.md` entry, and lands behind the merge gate (review subagent + `just test`). All
phases are client-side (`frontend/`) over the existing `/graph` payload unless noted.

**Phase 1 — Visual legibility (no structural change).** Edge-ink recede (structural vs semantic),
importance-driven node sizing, shape redundancy + anchor glyphs, label discipline (`mapData(zoom)`),
legend shape swatches + hover-preview/click-isolate-by-type. *Pure style/`mapData` over today's flat
graph; zero new deps; immediately improves every tier; trivially revertable.* **Highest value per
risk — ship first.**

**Phase 2 — Focus & navigation (live-instance, no rebuild).** Replace `.lit`-only with
`.focus`/`.context` classes + N-hop neighborhood + scoped auto-frame; hover preview; focus stack +
breadcrumb (URL-serialized); search-drives-focus; right-click verb menu; reversible hide chip.
*Operates on the live `cy` instance via class toggles + `animate({fit})`; no new deps; fixes the
drowned-highlight directly.*

**Phase 3 — Compound islands + grouping + expand/collapse.** Introduce `cytoscape-fcose` +
`cytoscape-expand-collapse` (+ optional `cytoscape-cxtmenu`); render targets as compound parents;
skeleton-collapsed default at LARGE/PATHOLOGICAL with finding-severity rollups + size-by-weight;
"Group by" control; collapse-all/expand-all; aggregated cross-target meta-edges; socket bus lane.
*The headline structural fix; the largest single phase — gate carefully; the flat "None" grouping
is the fallback if anything regresses.*

**Phase 4 — Layout-by-context + semantic zoom.** fcose-spread skeleton with tile/pack + the
canvas-utilization backstop; scoped `dagre LR` on island expand; `concentric` hub view; the
zoom-threshold LOD class switching. *Builds on Phase 3's compounds; kills the letterbox and protects
color at every zoom.*

**Phase 5 — Layer panel + filter chip rail + complementary views.** Generalize toggles into the
node-type/edge-class layer panel; the value-facet filter rail (fade-first); the Table and Matrix
views; the Map as a named view; Saved Lenses (in `settings.json`); panels-drive-scope wiring.
*Most surface area, lowest urgency; each sub-piece (layers, filters, Table, Matrix, Lenses) is itself
an independently shippable merge.*

*(Optional later, not required to ship the UX): a scoped-graph backend endpoint so PATHOLOGICAL
never ships 500 nodes/2005 edges to the client — a pure performance optimization behind a seam, with
a migration only if it touches a model.)*

---

## 9. UI ASSESSMENT PLAN (measured, not vibes)

Per CLAUDE.md "Assessing the UI visually": Playwright + headless Chromium
(`p.chromium.launch(args=["--no-sandbox"])`, `goto(..., wait_until="networkidle")` + a short
`wait_for_timeout` so Cytoscape/fcose settle), an **isolated `HEXGRAPH_HOME`** + spare
`HEXGRAPH_PORT`, mock backend, offline. **View the PNGs with the Read tool** and judge **as a
human, not a parser.** Record every result + before/after pair in `docs/ui-backlog.md`.

### 9.1 Complexity tiers (the fixtures)

Seed one deterministic project per tier into the isolated home (extend `scripts/seed_showcase.py`;
add a `--graph-tiers` mode or a sibling seed script, guarded by a test like
`tests/test_showcase_seed.py` so the tiers don't bit-rot):

| Tier | Target size | Shape |
|---|---|---|
| **SMALL** | ~15 nodes / ~20 edges | one binary, a handful of functions + one finding |
| **MEDIUM** | ~40 / ~60 | one binary, full call graph + sockets + 2–3 findings |
| **LARGE** | ~178 / ~599 | firmware ⊃ ~12 binaries, cross-target links, shared sockets, several findings incl. a critical |
| **PATHOLOGICAL** | ~500 / ~2005 | dense firmware, high-degree hubs (degree 15–25), 2000+ edges, findings across binaries |

Capture **before** (current `GraphView`) and **after** (each phase) the *same* tiers + states, so
every comparison is a true A/B.

### 9.2 Captures per tier (before/after each phase)

For each tier, shoot: **(a) default-open frame**; **(b) one node focused** (deep-link
`?focus=<highest-degree-hub>`); **(c) one island soloed/expanded** (LARGE/PATH); **(d) hover
preview** (scripted `mouseover`); **(e) search-to-focus** (type a name → Enter); **(f) a
layer/filter state** (toggle off calls+structural, keep `taints`/`routes_to`); plus a zoom sweep
(fit→close) on MEDIUM/LARGE for the label/LOD check.

### 9.3 Human-parsability criteria (judged as a human)

- **Eye-flow / entry point (3-second glance):** open each tier cold — does the eye *land* somewhere (the firmware root, the biggest/most-saturated card, the red critical diamonds), or *slide off*? Landing = pass.
- **Breathing room:** islands/clusters are visibly separated, the graph fills 55–80% of the pane (no upper-third clump, no edge-to-edge cramp, no letterbox margin).
- **Can-you-find-X:** at LARGE/PATHOLOGICAL, can a human, in one glance, *count the binaries* and *point to the one with the critical finding*? In Table, find the top-3 highest-degree functions in seconds?
- **Inviting-not-overwhelming:** the gut check — *does this frame make me want to dive in, or away?* The default LARGE/PATHOLOGICAL frame must read as **as calm as today's MEDIUM** — because the skeleton *is* a MEDIUM-sized view regardless of DB size.
- **Focus works at density:** focusing the degree-25 hub turns the smudge into a clean local diagram (≤~20 colored, labeled, shaped nodes) with the rest a clearly-subordinate ghost.
- **Color survives:** at every zoom/LOD threshold, type *hues* on nodes and the few shown edges are distinguishable (blue executable vs teal library island; red finding pip vs orange). Reduced busyness, untouched palette.

### 9.4 Judging checklist (pass/fail, per capture)

For each after-capture, mark Pass/Fail with the one-line reason:

1. **[Eye lands]** I can name what my eye hit first within 3 seconds. *(headline metric)*
2. **[Calm default]** The default LARGE/PATHOLOGICAL frame is indistinguishable in calmness from today's MEDIUM frame.
3. **[Countable rooms]** At LARGE/PATHOLOGICAL I can count the binaries and point to the critical-finding one at a glance.
4. **[Breathing room]** 55–80% canvas utilization; clusters separated; no letterbox; no cramp.
5. **[Focus pops]** Focused neighborhood is the obvious subject; off-focus is a faint, present backdrop (not gone, not competing).
6. **[Auto-frame]** Drilling/soloing/search lands me framed on a readable subgraph; the camera never jumped unsolicited.
7. **[Reversible]** Breadcrumb shows the path; one click/Esc returns; nothing feels lost.
8. **[Color kept]** Hues are distinguishable at this zoom; no element lost its type color (only off-focus is desaturated).
9. **[Labels behave]** Labels appear only where they fit; no overprint; semantic-edge labels readable when focused.
10. **[SMALL/MEDIUM unregressed]** These tiers look identical-or-better than today.
11. **[Squint/blur test]** Heavily blur the default frame: it still communicates "a few important hot things here" (clear hierarchy); the old hairball blurs to a uniform stain.
12. **[No-loss]** Every node/edge is still reachable (expand/Full/Table); a determined user can always get the whole graph.

The single most important pass/fail image is **PATHOLOGICAL-default**: if it opens as a calm,
countable set of labeled rooms instead of visual static, the redesign has done its job — same
information, finally organized so a human's eye flows in instead of sliding off.

---

## 10. Constraints, seams, and grounding

- **No backend / schema / migration change** for Phases 1–5 (Saved Lenses use the existing `settings.json` managed-prefs seam, presence-only/non-secret). The optional scoped-graph endpoint is a later performance seam.
- **Cytoscape-native only.** New frontend deps: `cytoscape-fcose`, `cytoscape-expand-collapse`, optional `cytoscape-cxtmenu`; keep `dagre`. All else is core APIs (`mapData`, style classes, `neighborhood()`, `animate({fit})`, compound `parent` data, `background-image`/`background-blacken`).
- **Color-coding kept** (`KIND`/`NODE_T`/`SEV`/`EDGE_C`/`NODE_SHAPE` untouched); same information, no loss; human parsability > completeness. Loopback/sandbox/secret/policy invariants are unaffected (frontend-only).

Grounding files: `frontend/src/components/GraphView.tsx` (Cytoscape setup, color/shape maps L11–31,
dagre layout L134, `.lit` highlight L137–152, hand-rolled collapse L49–83, fit/zoom L188–189);
`frontend/src/pages/Workspace.tsx` (three-panel layout, `view` Graph⇆Source switcher,
`reveal()`/`setUrl()` deep-link primitives, left `TreeRow` + right `FindingsPanel` wiring, dynamic
legend); `frontend/src/api.ts` (`Graph`/`GraphNode`/`GraphEdge` L87–89; `parent_id` hierarchy L4;
`origin`/`confidence` on edges L88; `/search`).
