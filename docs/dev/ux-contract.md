# HexGraph UX behavior contract

This is a **living document**. It is the source of truth for the two-role UX assessment
(`.claude/skills/ux-assessment/SKILL.md`): a deliberate walkthrough where one agent populates a
project the way an analyst would, and a second agent opens the UI cold and walks this contract
entry by entry, scoring each interaction.

**The living rule (see CLAUDE.md):** any PR that changes UI behavior MUST update this file in the
same PR — add the new interaction, edit the changed one, retire the removed one. A PR that changes
a UI interaction without touching this contract is incomplete, the same way a model change without a
migration is incomplete. The PR-review gate checks for it. The assessment's self-audit step (the
researcher flags entries that no longer match the code, and surfaces that exist but aren't catalogued)
is the backstop that keeps the doc honest between merges.

This contract documents **intended** behavior, cross-checked against the design docs
(`docs/design/design-graph-presentation.md`, `docs/design/design-curatable-targets.md`,
`docs/graph-ui.md`, `docs/design/design-fuzzing-and-source.md`,
`docs/design/design-verification-oracles.md`, `docs/design/design-dynamic-surfaces.md`) and the
design principles in CLAUDE.md. Where the current build diverges from intent, the entry states the
**intended** behavior — the assessment is meant to *catch* that divergence and file it as a
deviation. That is the whole point: this is the spec the implementation is held to, not a transcript
of what it happens to do today.

---

## How to read an entry

Every interaction has a stable ID (`GRAPH-07`, `FIND-03`, …). IDs are permanent: if an interaction is
removed, mark the entry **RETIRED** rather than reusing the number, so old assessment reports still
resolve. Each entry carries:

- **Steps** — the precise gesture(s) to perform, in order.
- **Functional result** — what should happen in the UI.
- **Backend effect** *(flagged 🔌 when present)* — what the interaction must do on the server/DB
  beyond redrawing, and how to verify it (an API call, a DB row, a settings change, a launched task).
  An interaction that *looks* like it worked but didn't persist/launch is a **functional failure**,
  not a pass — the screenshot is evidence, never the check.
- **Qualitative expectations** — what "good" looks like on the dimensions below (only the ones that
  bite for this interaction).
- **Principle** — the design principle the interaction embodies (so a reviewer can tell intent from
  accident).
- **Prereq** — the state that must exist for the interaction to be testable. Every Prereq traces to a
  row in the **State Coverage Matrix** at the end, which the VR-analyst sequence guarantees.

---

## Assessment dimensions (score every interaction on the ones that apply)

These are scored 1–5 (or pass / minor / major / blocker), with a one-line reason. Defined once here;
entries reference them by name.

1. **Functional** — does it do what it should, *including the backend effect*? State persisted, API
   called, task launched, file written. Not "did the button depress."
2. **Intuitive / discoverable** — could a first-time researcher find and understand this without
   reading docs? Is the affordance where the eye expects it? Is the label honest about what happens?
3. **Feedback** — does it clearly signal that it happened / is happening? Loading spinner, success
   toast, inline confirmation, progress, error text. Silence after an action is a feedback failure.
4. **Aesthetics** — alignment, spacing, hierarchy, polish, a modern feel. Not cramped, not ugly, not
   dated. Judged as a human seeing it for the first time would (see CLAUDE.md "judge as a human").
5. **Consistency** — same patterns/affordances/wording as the rest of the app. A second "Delete"
   that behaves unlike the first is a consistency failure.
6. **Forgiveness / safety** — destructive actions confirm; mistakes are recoverable; errors are
   legible and tell you what to do next. Reversible-vs-irreversible is visually distinct.
7. **Friction** — is the path efficient, or are there needless clicks / modals / scrolls / re-entry
   of data the app already knows?
8. **Overall experience** — the gut check: does this invite the researcher to keep going, or make them
   want to bounce? Calm and confident, or busy and confusing?

---

## SURFACE 0 — Projects & app shell

**PROJ-01 — List projects**
- Steps: open `/`.
- Functional: a grid of project cards, each showing name · backend · short id · target count · finding count.
- 🔌 Backend: `GET /api/projects` then a per-project `GET /api/projects/{id}` to enrich counts. The
  counts must be *real* (match the DB), not placeholders.
- Qualitative: cards land calm, scannable; skeleton cards while loading (Feedback); the grid breathes
  rather than cramming (Aesthetics).
- Principle: a calm table-of-contents entry point.
- Prereq: ≥1 project exists.

**PROJ-02 — Create a project**
- Steps: click **New project** → the inline form drops in → type a name, pick a backend (mock /
  anthropic / claude_code) → **Create** (or Enter in the name field).
- Functional: navigates straight into the new project's workspace.
- 🔌 Backend: `POST /api/projects` creates the row; verify the project then appears in `GET /api/projects`.
- Qualitative: name field autofocuses (Friction); Enter submits (Friction); Create disabled until a name
  is typed (Forgiveness); the form animates in rather than jumping (Aesthetics).
- Principle: low-friction creation.
- Prereq: none.

**PROJ-03 — Delete a project (IRREVERSIBLE)**
- Steps: hover a project card → click the trash ✕ in its corner → confirm the native dialog.
- Functional: the card disappears from the grid.
- 🔌 Backend: `DELETE /api/projects/{id}` removes the project AND its on-disk data; verify it's gone from
  `GET /api/projects`.
- Qualitative: the confirm text names the project and says "cannot be undone" and lists what's lost
  (targets, findings, graph, on-disk data) — Forgiveness; the ✕ click must not also navigate into the
  card (Consistency — it stops propagation).
- Principle: destructive actions confirm and are explicit about scope.
- Prereq: a disposable project exists.

**SHELL-01 — Header / cost / nav**
- Steps: in a workspace, read the header.
- Functional: shows the project name, a **backend chip** (`mock`) and a separate **cost chip** (`$0 · mock`),
  a `local · 127.0.0.1` chip, and a settings gear / home link.
- 🔌 Backend: cost reflects `detail.cost` from `GET /api/projects/{id}`.
- Qualitative: `$0 · mock` reads as reassuring (zero spend), not alarming; the gear is discoverable.
- Principle: zero-token-spend default is visible.
- Prereq: any project open.

**SHELL-02 — Resize a side panel**
- Steps: drag the vertical splitter between the left/center or center/right panes.
- Functional: the pane resizes live; the center graph takes/*yields* the space.
- 🔌 Backend: none (widths persist to `localStorage`).
- Qualitative: the splitter has a visible grip + resize cursor (Discoverable); drag is smooth, no jank
  (Aesthetics); the size survives a reload (Feedback that it persisted).
- Principle: a researcher arranges their own workspace.
- Prereq: any project open.

**SHELL-03 — Collapse / restore a side panel**
- Steps: double-click a splitter, or click the chevron collapse button in a pane header → then click the
  collapsed edge tab to restore.
- Functional: the pane collapses to a thin labeled edge tab; clicking the tab restores it to its prior width.
- Qualitative: the collapsed tab is clearly labeled ("Targets" / "Findings") so it's obviously restorable
  (Discoverable, Forgiveness); the center reflows to use the freed space.
- Principle: focus the workspace without losing the panel.
- Prereq: any project open.

**SHELL-04 — Maximize the right (findings/detail) pane**
- Steps: click the expand/fit button in the findings pane header.
- Functional: findings + detail fill the screen (a two-pane max view); the button toggles back.
- Qualitative: clearly reversible (Forgiveness); the icon flips to a "restore" affordance (Feedback).
- Principle: a triage-focused mode.
- Prereq: any project open.

**SHELL-05 — Detail section drag / expand within the right pane**
- Steps: drag the horizontal splitter between the findings list and the Detail section; or click the
  Detail expand toggle.
- Functional: the Detail box grows/shrinks; expand gives Detail the whole right pane.
- Qualitative: consistent with the other splitters (Consistency).
- Prereq: a finding or node selected (so Detail has content).

---

## SURFACE 1 — Targets pane (left)

**TGT-01 — Add a target (upload)**
- Steps: click **Add** in the Targets header → pick a file.
- Functional: a busy badge ("analyzing <name>…") appears; on completion the target appears in the tree.
- 🔌 Backend: `POST` add-target ingests + recons the bytes; verify a new `target` row and (with recon) its
  nodes. On mock/no-Docker the bytes still ingest.
- Qualitative: the busy state is visible the whole time (Feedback); an ingest error surfaces as a legible
  message, not a silent no-op (Forgiveness).
- Principle: point it at a binary → it ingests.
- Prereq: none (a fixture binary on disk).

**TGT-02 — Select a target → scope + detail**
- Steps: click a target row.
- Functional: the row highlights (`sel`); the graph **scopes** to that target (a scope crumb appears,
  others fade/frame); the Detail shows the NodeInspector for the target (recon facts, imports, exports).
- 🔌 Backend: none beyond the already-loaded graph; in skeleton mode scoping a target **fetches its room
  interior** (`GET /graph/{id}/room/{targetId}`).
- Qualitative: one click does both select + scope, and clicking again clears scope (Friction, Forgiveness);
  scope is *not* applied in Source/Matrix views (Consistency — those don't scope-frame).
- Principle: panels drive, center displays.
- Prereq: ≥1 target.

**TGT-03 — Firmware directory folders (expand/collapse)**
- Steps: for a firmware with path-named children (e.g. `usr/sbin/telnetd`), click a `▸ folder` row.
- Functional: the folder expands to its subdirs (alpha) then leaf files (alpha); the chevron rotates;
  click again to collapse.
- 🔌 Backend: none — folders are pure client-side grouping derived from child names, never target rows.
- Qualitative: a large firmware opens **collapsed** (calm), a small one opens its top folders
  (Discoverable); each folder shows a child count and a rolled-up finding badge (hot if any
  high/critical descendant) — Aesthetics + at-a-glance triage.
- Principle: a real firmware's hundreds of children are navigable, not a flat 250-row wall.
- Prereq: a firmware target with path-named children + findings on some children.

**TGT-04 — Folder severity rollup badge**
- Steps: observe a folder containing a target that has a high/critical finding.
- Functional: the folder badge shows the descendant finding count and is tinted "hot".
- Qualitative: the eye is pulled to the hot folder before expanding (Discoverable, the entry point).
- Principle: surface heat at the folder level.
- Prereq: a firmware with a finding under a folder.

**TGT-05 — Per-target finding-count badge**
- Steps: observe a leaf target row that has findings.
- Functional: a count badge on the row, hot-tinted if it has a high/critical finding.
- Prereq: a target with findings.

**TGT-06 — Run menu (kind-valid tasks only)**
- Steps: click **Run ▾** on a target row.
- Functional: a portal popover lists ONLY the task types valid for that target's kind; each row has a
  one-line summary; hovering a row shows a richer explanation popover. Picking one opens the LaunchModal.
- 🔌 Backend: the allowed list comes from `GET /api/capabilities` keyed by kind; a `web_app`/`service`/`remote`
  surface shows only its surface tasks (or none), **never** byte `recon`. Verify the menu matches the kind.
- Qualitative: the menu never offers a task that would 400 (Forgiveness); the hover explanations make each
  task discoverable to a newcomer (Discoverable); the menu renders in a portal so it's never clipped by the
  cramped pane (Aesthetics).
- Principle: the menu is honest per kind.
- Prereq: targets of several kinds (byte binary, firmware, web_app, service).

**TGT-07 — Fuzz a target from the Run menu**
- Steps: Run ▾ → **Fuzz campaign…** (shown only when `features.fuzzing` is on and the target isn't a raw
  firmware image).
- Functional: opens the Fuzz modal (see FUZZ surface).
- Qualitative: there is exactly ONE fuzz path (the Run menu row + the modal) — no duplicate standalone
  fuzz button on the row (Consistency).
- Principle: one fuzz entry, surface-aware.
- Prereq: `features.fuzzing` on; a fuzzable target.

**TGT-08 — Remove a target (reversible soft-remove)**
- Steps: click the trash ✕ on a target row → confirm.
- Functional: the target (and its subtree) disappears from the tree, graph, findings, and search; the
  confirm explains it's hidden not deleted, and re-adding the same bytes restores it.
- 🔌 Backend: the remove endpoint sets `target.archived`; verify the target's nodes/findings vanish from
  `GET /api/projects/{id}` and `/graph` but the row still exists.
- Qualitative: confirm copy is explicit that it's reversible (Forgiveness — distinct from the IRREVERSIBLE
  project delete); the ✕ click doesn't also select the row (Consistency).
- Principle: graduated, reversible removal.
- Prereq: a disposable target.

**TGT-09 — Surface targets render flat (no folder folding)**
- Steps: observe a `web_app` / `service` / `remote` target whose label coincidentally has a slash.
- Functional: it renders as a flat leaf row, NOT folded into a directory folder.
- Principle: only filesystem byte children fold into folders.
- Prereq: a surface target.

**TGT-10 — Firmware filesystem browser + add-file-as-target**
- Steps: select a firmware target → in its NodeInspector open the FilesystemBrowser → browse the unpacked
  tree → add a file as a child target.
- Functional: the file is added as a new child target and appears in the tree.
- 🔌 Backend: `GET` the firmware filesystem listing; the add-file call creates a child `target`. Verify the row.
- Qualitative: the FS browser reads like a file explorer (Discoverable); adding is one action (Friction).
- Principle: any file in the firmware is promotable to a curated target.
- Prereq: a firmware with an unpacked filesystem.

**TGT-11 — Ghidra import (bridge mode)**
- Steps: with Ghidra bridge enabled, click the **Ghidra** button in the Targets header → the import modal.
- Functional: lists programs open in the connected Ghidra; importing one creates a target.
- 🔌 Backend: the Ghidra bridge endpoints; verify a target is created on import.
- Qualitative: shown ONLY when bridge mode is configured (Consistency — no dead button otherwise).
- Principle: Ghidra is an optional, gated seam.
- Prereq: `features.ghidra` = bridge, a reachable Ghidra (intended; assessment notes if unverifiable offline).

---

## SURFACE 2 — Graph canvas (center, default view)

These are the densest set. The governing principle (design-graph-presentation §0): **calm by default,
loud only where you are looking; every node/edge/color kept, mute never deletes.**

**GRAPH-01 — Default frame at each tier**
- Steps: open a project cold at SMALL / MEDIUM / LARGE / PATHOLOGICAL / REAL.
- Functional: SMALL/MEDIUM = the full graph (rooms auto-expanded). LARGE/PATHOLOGICAL = skeleton-collapsed
  to ~10–25 labeled, finding-weighted *rooms*. REAL (skeleton mode) = rooms only, a "skeleton · N rooms" badge
  + a hint to double-click a room to load its interior; the browser never holds ~13k nodes.
- 🔌 Backend: `GET /graph/{id}/size` decides skeleton vs full; skeleton mode uses `GET /graph/{id}/skeleton`.
- Qualitative (the headline metric): within ~3 seconds the eye should *land* on the firmware root and the
  red/orange high-severity rollups; the frame feels as calm as a MEDIUM graph regardless of DB size
  (Overall, Aesthetics). A blurred PATHOLOGICAL frame still reads "a few hot rooms here," not uniform static.
  Concretely: the severity *glow* on a collapsed room card is RESERVED for **high/critical** (medium gets a
  faint tint; low/info just a colored border; clean rooms recede), and at far zoom the cross-room meta-edge
  ribbons dim to context — so a handful of hot rooms pop out of a large skeleton instead of every
  finding-bearing room (or a wall of semantic ribbons) washing the whole ring one warm colour.
- Principle: open inviting, not intimidating.
- Prereq: projects across tiers (incl. a REAL firmware-scale one).

**GRAPH-02 — Right-click a NODE → app verb menu**
- Steps: right-click a content node (function/finding/socket/…) — try clicking the node's edge, not just
  its center.
- Functional: the app's verb menu appears (Focus neighborhood · Expand one hop · Reveal in panel · Hide this
  node). The **native browser menu must NOT appear**. The menu is anchored at the **cursor**, not the node's
  center — its top-left corner sits where you clicked (`evt.renderedPosition`), nudged inward only if it would
  spill off the canvas edge.
- Qualitative: the menu is compact, sized to fit, not clipped (Aesthetics); it lands under the pointer so the
  first verb is a tiny travel away (Direct manipulation); native-menu suppression is absolute anywhere on the
  canvas (Consistency, Forgiveness).
- Principle: HexGraph owns the right-click everywhere on the canvas; a context menu opens at the cursor.
- Prereq: a graph with content nodes.

**GRAPH-03 — Right-click a ROOM → room verb menu**
- Steps: right-click a compound room (target island), off its center.
- Functional: a room-specific menu (Expand/Collapse room · Reveal in panel), anchored at the cursor (not the
  room's center). No native menu.
- Principle: verbs are element-type-aware; the menu opens where you click.
- Prereq: a compound (grouped) graph.

**GRAPH-04 — Right-click empty canvas → no native menu**
- Steps: right-click the empty background.
- Functional: the native browser context menu does NOT appear; the app menu closes.
- Principle: native contextmenu suppressed on the whole graph-wrap (capture phase), not just on hit elements.
- Prereq: any graph.

**GRAPH-05 — Scroll-to-zoom responsiveness**
- Steps: scroll the wheel over the canvas.
- Functional: zooms in/out; a single notch is a clearly-felt step (not sluggish, not jumpy/overshooting).
- Qualitative: the responsiveness feels right to a hand (Overall) — `wheelSensitivity` tuned to ~1.4.
- Principle: direct manipulation feels immediate.
- Prereq: any graph.

**GRAPH-06 — Hover a node → emphasize + recede**
- Steps: hover a content node.
- Functional: the node + its closed neighborhood (and its parent room's border) light up (`.hl`); the rest
  gently recedes to ~0.28 opacity (`.hl-dim`) — present, not deleted. Hovering a ROOM lights the room + its
  whole subtree, never a filled blob over the group.
- Qualitative: the hovered thing POPS by contrast; the backdrop stays a parseable, present ghost (never
  inverted, never smothered) — the no-loss mute (Aesthetics, Overall). **Hue is preserved** at low alpha.
- Principle: emphasize what you point at; mute, don't de-color.
- Prereq: a graph with neighborhoods.

**GRAPH-07 — Single-click a node → select + inspector + ring**
- Steps: click a content node.
- Functional: it selects (blue ring), connected edges light (`.lit`), and the Detail shows its inspector
  (NodeInspector for nodes, the rich Inspector for findings). The camera does NOT jump.
- 🔌 Backend: selecting a finding pulls `GET /api/findings/{id}` for the full record.
- Qualitative: predictable camera (Forgiveness) — selection never auto-frames.
- Principle: select is passive; auto-zoom only on explicit navigation.
- Prereq: any graph.

**GRAPH-08 — Double-click a node → focus neighborhood**
- Steps: double-click a content node.
- Functional: focus mode — the node + its 1-hop neighborhood go `.focus` (full saturation/labels), the rest
  goes `.context` (faint, present, events off), a concentric re-arrange centers the anchor, the camera glides
  to frame the focus set, and a breadcrumb crumb is pushed. The URL gains `?focus=<id>`.
- Qualitative: the smudge becomes a clean local diagram; the rest is an obvious subordinate ghost
  (design §9.4 "Focus pops"); the camera animates rather than teleporting (Aesthetics).
- Principle: focus = isolate + mute + auto-frame, reversibly.
- Prereq: a node with neighbors.

**GRAPH-09 — Double-click a room → expand/collapse (or drill in Map)**
- Steps: double-click a compound room; then expand a SECOND sibling room next to it.
- Functional (Graph view): toggles the room open/closed; expanding glides the camera to the room and the
  interior fades+scales in (no teleport); collapsing glides back to the skeleton. In skeleton mode, expanding
  fetches the interior on demand. (Map view: double-tap DRILLS into the scoped Graph for that binary instead.)
  An expanded room is placed so it **does not overlap any already-expanded sibling** — a post-layout
  separation pass pushes sibling-room bounding boxes apart (the per-room dagre interior re-flow grows a room
  past the footprint fcose reserved, so without it a freshly-expanded room lands on top of its neighbor).
- 🔌 Backend: skeleton-mode expand → `GET /graph/{id}/room/{targetId}` merges the interior.
- Qualitative: the open animation lets you *watch* the room open (Feedback, Aesthetics) — issue-3 teleport
  is the failure to catch. Two or more open rooms read as distinct, gutter-separated islands, never a single
  overlapping smear (Aesthetics, Legibility).
- Principle: navigation acts auto-frame; expansion is staged, never a yank; open rooms never overlap.
- Prereq: a grouped graph (LARGE+ for skeleton).

**GRAPH-10 — Drag a node**
- Steps: drag a content node to a new position.
- Functional: the node moves and stays; edges follow.
- Prereq: any graph.

**GRAPH-11 — Pan the canvas**
- Steps: drag the empty background.
- Functional: the viewport pans; any open menu closes on pan.
- Prereq: any graph.

**GRAPH-12 — Click an edge → edge inspector**
- Steps: click an edge (a direct one, not an aggregated meta-edge).
- Functional: the edge lights (`.lit`); the Detail shows the edge inspector (type, src→dst kinds, origin,
  confidence, attributes) with a **Delete edge** action.
- 🔌 Backend: none to inspect (the edge is in the loaded graph). Delete is EDGE-DEL below.
- Qualitative: a meta-edge (aggregated `×N`) is correctly NOT clickable as a single edge (Consistency).
- Principle: edges are first-class, inspectable.
- Prereq: a graph with direct edges.

**GRAPH-13 — Zoom + / − / fit controls**
- Steps: use the +/fit/− segmented cluster in the flat control row along the bottom-right.
- Functional: + zooms in, − zooms out (animated), fit frames all visible elements.
- Qualitative: this is the ONLY +/− pair (the skeleton toggle uses a chip glyph, not +/−) —
  Consistency (issue-4: two identical +/− pairs is the failure). ALL the buttons sit in ONE flat row
  along the bottom — the action icons (layers / filter / skeleton / draw) then this zoom cluster — each
  sized to itself, never stretched to a shared width.
- Principle: one zoom cluster, no duplicate affordances.
- Prereq: any graph.

**GRAPH-14 — Group-by switch**
- Steps: change the labelled **GROUP BY** select (target / type / finding / none (flat)).
- Functional: the canvas reorganizes into compound rooms by the chosen facet; "none (flat)" is the
  ungrouped graph. Expanding a node/room works in EVERY facet, by-type included, without error.
- Qualitative: switching is instant (client-side, no refetch) — Friction; the selector carries a
  "GROUP BY" label (so it reads as what it does), sits on its own row above the button row, and is sized
  to its own content rather than dictating the rail width (Aesthetics).
- Principle: grouping is a first-class, switchable, clearly-labelled facet.
- Prereq: a graph with targets + findings.

**GRAPH-15 — Layer panel: toggle node types**
- Steps: open the Layers panel (hex icon) → toggle a node type (e.g. `string`, `symbol`).
- Functional: that node-type class shows/hides on the canvas; the panel lists only types actually present.
- Qualitative: `symbol` / `string` / `param` are OFF by default; `source_file` is OFF by default (it's
  scaffolding); a reset appears when non-default (Forgiveness). The button goes primary when non-default
  (Feedback).
- Principle: layering shows/hides whole classes; defaults keep the canvas calm.
- Prereq: a graph with several node types incl. strings/symbols.

**GRAPH-16 — Layer panel: toggle edge classes**
- Steps: in the Layers panel, toggle an edge class (structural / call graph / semantic / provenance).
- Functional: edges of that class are dropped/restored; turning off structural+calls de-hairballs a binary
  so the colored semantic edges read.
- Principle: edges are the dominant ink — the single biggest density lever.
- Prereq: a graph with varied edge types.

**GRAPH-17 — `source_file` layer off by default**
- Steps: open a graph that has `source_file` nodes; observe they're hidden by default; toggle the layer on.
- Functional: source_file nodes appear only when explicitly enabled.
- Principle: default-off for scaffolding node types.
- Prereq: a graph with source_file nodes.

**GRAPH-18 — Filter chip rail: severity threshold**
- Steps: open the filter rail (funnel icon) → pick a minimum severity.
- Functional: findings below the threshold **fade** (fade-first default), keeping context; the rest stay full.
- Qualitative: fade-first never silently deletes; hue preserved (no-loss, D8).
- Principle: filtering subtracts by value, fade-first.
- Prereq: findings spanning severities.

**GRAPH-19 — Filter chip rail: target multiselect**
- Steps: add a target to the filter via the `+ target…` select.
- Functional: elements not belonging to a selected target fade; a removable chip appears for each picked target.
- Prereq: ≥2 targets in the graph.

**GRAPH-20 — Filter chip rail: finding-type filter**
- Steps: pick a finding type (vulnerability / recon / fuzz_crash / poc / …).
- Functional: only findings of that type stay full; others fade. The select shows only types present.
- Prereq: findings of ≥2 types.

**GRAPH-21 — Filter fade ⇆ hide mode**
- Steps: click the fade/hide mode chip.
- Functional: toggles between fade (default, context-preserving) and hard-hide (removes filtered elements).
- Qualitative: hide is an explicit opt-in, not the default (Forgiveness, no-loss).
- Prereq: an active filter.

**GRAPH-22 — Clear filters**
- Steps: click the "clear ↺" chip on the rail.
- Functional: all value filters reset; the rail hides if it was only open for filters.
- Prereq: an active filter.

**GRAPH-23 — Expand all / Collapse all rooms**
- Steps: open the filter/options menu (or the skeleton toggle button) → Expand all / Collapse all (skeleton).
- Functional: Collapse-all returns to the skeleton (a glided re-fit); Expand-all reveals interiors, gated by
  a confirm above ~200 nodes (and in skeleton mode expands only container rooms, never every leaf).
- Qualitative: the ceiling confirm prevents accidentally re-summoning the hairball (Forgiveness).
- Principle: never let the hairball back by accident.
- Prereq: a grouped graph.

**GRAPH-24 — Color-coding survives (D8)**
- Steps: at every tier and every LOD/zoom, inspect node fills and edge colors.
- Functional: type hues stay distinct (purple firmware, blue executable, teal library, red findings, …);
  red is reserved for severity/findings, never a node fill. Off-focus is desaturated (alpha), never
  de-colored.
- Qualitative: the legend swatch shape+color matches the canvas (Consistency).
- Principle: keep and defend color (D8) — only off-focus is muted.
- Prereq: a graph with varied types + severities.

**GRAPH-25 — Semantic-zoom (LOD) tiers**
- Steps: zoom from far (skeleton) → mid → near on a LARGE graph.
- Functional: FAR = readable room cards, no interior/edge labels; MID = node shapes + hub/anchor labels +
  semantic-edge labels + leaf labels once individuated; NEAR = full detail (every label, edge labels, `×N` /
  `@addr` / `:port` hints).
- Qualitative: labels appear only where they fit (no overprint mush); a zoomed-in single binary is NOT a
  field of anonymous dots (issue-6 is the failure — leaves stay labelled once resolvable).
- Principle: detail as a function of zoom; defend color by reducing what competes.
- Prereq: a LARGE/MEDIUM graph.

**GRAPH-26 — Skeleton-first load at REAL scale**
- Steps: open the REAL (~250-target / ~13k-node) project.
- Functional: only the skeleton loads (rooms + sockets + meta-edges); a hint + "skeleton · N rooms" badge;
  the browser never receives the full node set.
- 🔌 Backend: `GET /graph/{id}/skeleton`; room interiors fetched lazily only on expand.
- Qualitative: opens fast and calm despite the DB size (Overall) — the curatable-targets promise.
- Principle: don't ship 13k nodes to the client.
- Prereq: a firmware-scale project.

**GRAPH-27 — Loose `socket` "network bus" lane**
- Steps: observe shared `socket` nodes (cross-binary, `target_id=null`).
- Functional: they sit in a distinct pink-hexagon bus lane between islands, always labeled; a server
  `listens_on` and a client `connects_to` resolve to the SAME socket node.
- Principle: the firmware's network map is a first-class region.
- Prereq: shared sockets across ≥2 binaries.

**GRAPH-28 — Aggregated cross-room meta-edges**
- Steps: at the skeleton, observe edges between rooms.
- Functional: parallel cross-target edges collapse into one weighted ribbon with a `×N` count, width ∝ count;
  semantic meta-edges (links_against/taints/listens_on…) stay visible+labeled, purely-structural ones recede.
- Principle: the first frame tells the structural story without 599 individual edges.
- Prereq: a LARGE graph with cross-target edges.

**GRAPH-29 — Importance-driven node sizing**
- Steps: observe node sizes.
- Functional: anchors (targets) are biggest + always-labeled + carry a type glyph; hubs (degree ≥8) ramp
  30→40px with a glow; detail nodes are 22px, labeled on zoom/hover/focus. Findings are diamonds on the SEV
  ramp, sized up for critical/high.
- Qualitative: the eye lands on anchors/hubs/critical findings first (the entry point).
- Principle: size encodes importance.
- Prereq: a graph with a hub + a critical finding.

**GRAPH-30 — Legend: present-only, shape+color**
- Steps: read the legend below the canvas.
- Functional: lists only node/edge types actually present; each chip carries its type SHAPE filled with its
  type COLOR; findings chip is a red diamond.
- Principle: the legend teaches the shape+color pairing and is the single source of truth.
- Prereq: any graph.

**GRAPH-31 — Legend chip hover → preview-isolate by type**
- Steps: hover a legend chip.
- Functional: that type is transiently isolated (the rest dims); leaving restores.
- Principle: the legend is the discoverable home for isolate-by-type.
- Prereq: any graph.

**GRAPH-32 — Legend chip click → pin isolate by type**
- Steps: click a legend chip; click again to clear.
- Functional: the type stays isolated (pinned) until clicked again; un-pinning clears immediately even while
  hovered.
- Qualitative: a pinned chip is visually distinct (Feedback).
- Prereq: any graph with ≥2 types.

**GRAPH-33 — Breadcrumb focus stack**
- Steps: after focusing (GRAPH-08), read the breadcrumb top-left; click a crumb; click ↺ / Overview.
- Functional: `Overview › crumb › crumb`; a crumb pops to that frame; ↺ / Overview clears to the full graph;
  the scope crumb (from TGT-02) shows alongside with its own ✕.
- 🔌 Backend: the focus id + hop serialize to the URL (shareable/reload-restorable).
- Qualitative: the path is always on screen → nothing feels lost (Forgiveness, the reversibility promise).
- Principle: focus without a way back is a trap.
- Prereq: a focused or scoped graph.

**GRAPH-34 — Focus hop +/- and clear (focus bar)**
- Steps: with a focus active, use the top-right focus bar's −/+ to change hop radius (1–3) and **clear**.
- Functional: more/fewer hops grow/shrink the focused neighborhood; clear returns to the full graph and
  restores resting positions.
- Qualitative: hop is bounded 1–3 so it can't re-summon the whole graph (Forgiveness).
- Prereq: a focused graph.

**GRAPH-35 — Hide a node (reversible) + restore chip**
- Steps: right-click a node → **Hide this node** → then click the "N hidden · restore ↺" chip.
- Functional: the node + its edges hide; a restore chip appears bottom-left; clicking it restores all hidden.
- Qualitative: never a silent loss — the chip makes hidden state visible and one-click reversible (no-loss).
- Principle: hide is reversible and surfaced.
- Prereq: any graph.

**GRAPH-36 — Reveal in panel (from verb menu)**
- Steps: right-click a node/room → **Reveal in panel**.
- Functional: selects the underlying entity and shows it in the Detail pane.
- Prereq: any graph.

**GRAPH-37 — Draw an edge (drag-to-connect)**
- Steps: click the draw-edge (link) button on the rail → drag from a source node to a target node.
- Functional: completing the drag opens the Add-edge modal prefilled with both endpoints; cancel exits draw mode.
- 🔌 Backend: the edge is created only when the modal is submitted (EDGE-NEW), not on drag complete.
- Qualitative: the button reads as active while in draw mode (Feedback); rooms can't be endpoints (the drag
  refuses) — Forgiveness.
- Principle: author relationships visually.
- Prereq: ≥2 connectable nodes.

**GRAPH-38 — Graph meta badge (node/room count, loading)**
- Steps: read the top-left graph badge.
- Functional: shows `N nodes`, or `skeleton · N rooms` in skeleton mode, plus a "loading N rooms…" badge
  while interiors fetch.
- Qualitative: honest about what's loaded (Feedback) — skeleton shows ROOM count, not the not-loaded node count.
- Prereq: any graph; a skeleton for the loading badge.

---

## SURFACE 3 — Center-pane view switcher + alternative views

**VIEW-01 — View switcher (Map / Graph / Table / Matrix / Source)**
- Steps: click each segment of the view switcher.
- Functional: the center pane swaps view; Graph is the default; selection state is shared (a finding stays
  selected across views); the URL gains `?view=…`.
- Qualitative: switching is instant and keeps context (Friction, Consistency).
- Principle: a mode, not a route.
- Prereq: any project.

**VIEW-02 — Map view (territory overview)**
- Steps: switch to Map (try it at SMALL and at a tier where Graph auto-expands interiors).
- Functional: every leaf room is a force-collapsed finding-weighted card regardless of tier; intra-room detail
  (functions/strings) is never drawn; only semantic cross-target ribbons + the socket bus show; double-tap a
  card drills into the scoped Graph for that binary. A pure *container* room (a firmware grandparent with no
  interior content of its own) MAY expand just far enough to reveal its child-binary CARDS — but a binary that
  merely also has a child variant room (e.g. httpd + its instrumented build) must stay collapsed, or expanding
  it leaks its own functions and Map collapses back into Graph.
- Qualitative: Map is genuinely DISTINCT from the by-target Graph (issue-8: Map ≡ Graph is the failure). The
  distinction is most visible at SMALL/MEDIUM, where Graph shows interiors and Map shows only cards; at
  skeleton scale both are collapsed and converge, which is expected.
- Principle: the skeleton given its own named view.
- Prereq: a multi-target project (incl. one where a binary has a derived/instrumented child target).

**VIEW-03 — Table view (Nodes tab)**
- Steps: switch to Table → Nodes tab → sort by a column (degree, findings) → filter by text.
- Functional: a sortable/filterable node table (swatch · name · type · target · degree · #findings); row
  click reveals the node in the Graph; honors the same layer/filter/scope facets as the graph.
- Qualitative: the scalable answer to "the 3 highest-degree functions in httpd" in two clicks (the
  PATHOLOGICAL-usable surface); sort carets are clear (Feedback).
- Principle: a table is the right tool for "many of the same type."
- Prereq: a target with many functions.

**VIEW-04 — Table view (Edges tab)**
- Steps: Table → Edges tab → sort/filter.
- Functional: edges table (type · source · target · origin · confidence · ×count); honors layer/scope.
- Prereq: a graph with varied edges.

**VIEW-05 — Matrix view**
- Steps: switch to Matrix → pick a relationship (links_against / references / similar_to / connects_to).
- Functional: an N×N target adjacency; cells shaded by count; cell click reveals that target/pair in the
  Graph; the selector lists only relationships actually present; needs ≥2 targets (else a clear empty note).
- Qualitative: zero edge crossings at any tier (the dense-N×N answer the graph hairballs on).
- Principle: a matrix for the one genuinely dense cross-binary relationship.
- Prereq: ≥2 targets with cross-target edges.

**VIEW-06 — Saved Lenses: save current view**
- Steps: open the Lenses menu → **Save current view…** → name it.
- Functional: captures {view, scope, group-by, findings, layers, filters, focus}; the lens appears in the menu
  and becomes the active badge.
- 🔌 Backend: `PATCH /api/settings` writes `ui.lenses`; verify it persists in `GET /api/settings` and survives
  reload. The URL gains `?lens=<name>`.
- Qualitative: a lens is a one-click way back to a curated view (Friction).
- Principle: named, deep-linkable views, persisted in settings (no DB change).
- Prereq: a customized view state.

**VIEW-07 — Saved Lenses: apply / delete**
- Steps: pick a saved lens to apply; click the trash to delete one.
- Functional: applying restores the full captured state; deleting removes it; a manual facet change after
  applying drops the active-lens badge (it diverged).
- 🔌 Backend: apply reads `ui.lenses`; delete `PATCH`es the updated list.
- Prereq: ≥1 saved lens.

**VIEW-08 — Deep-link a lens / focus / view on reload**
- Steps: copy a URL with `?lens=` / `?focus=&hop=` / `?view=` → reload / open fresh.
- Functional: the view restores to that lens/focus/view.
- Principle: the view is addressable and reload-restorable.
- Prereq: a saved lens / a focused view.

---

## SURFACE 4 — Findings list + Inspector (right)

**FIND-01 — Findings list: render + severity summary**
- Steps: open the Findings tab.
- Functional: findings sorted by severity, grouped by target (toggleable); a severity-count summary row.
- 🔌 Backend: from `detail.findings` (`GET /api/projects/{id}`).
- Qualitative: scannable; severity color rail per card; calm at hundreds of findings (Aesthetics).
- Prereq: findings exist.

**FIND-02 — Findings list: filter (text / severity / status / type / tag) + group toggle**
- Steps: use the filter bar (text search, severity, status, finding-type, tag selects) and the group/ungroup toggle.
- Functional: the list filters live; type/tag selects appear only when >1 value exists; group toggles
  per-target grouping.
- Qualitative: filters compose; counts shown per severity option (Feedback).
- Prereq: findings spanning severities/types/statuses.

**FIND-03 — Select a finding → Inspector**
- Steps: click a finding card (in the list, or its diamond in the graph).
- Functional: the Detail shows the full Inspector — severity/category/confidence/status chips, finding-type,
  ✓ verified PoC chip when applicable, the lifecycle pills, summary, reasoning, evidence, hypotheses,
  annotations, next steps.
- 🔌 Backend: `GET /api/findings/{id}` for the full record + `GET` suggestions.
- Qualitative: the most information-dense panel, but it should read in sections, not as a wall (Aesthetics).
- Prereq: a finding with rich evidence (PoC, assurance, source_ref).

**FIND-04 — Assurance chip / line**
- Steps: on a finding with assurance, read the assurance line.
- Functional: shows `standard · method · precondition` with the lab-confirmed (code_present/dynamic) vs
  reachable (input_reachable) distinction made legible and color-coded; a verified PoC shows the green chip.
- Qualitative: the honesty crux — a static/suspected finding must NOT read as confirmed (Forgiveness/honesty).
- Principle: assurance is honest about what was actually proven.
- Prereq: findings across the assurance ladder (static, reachable, lab-confirmed, verified).

**FIND-05 — Confirm a finding**
- Steps: click **Confirm**.
- Functional: status → confirmed; the lifecycle pills advance; the chip updates.
- 🔌 Backend: `POST /api/findings/{id}/status` (confirmed); verify the status persists in `GET`.
- Qualitative: immediate visible status change (Feedback); reversible by re-setting status (Forgiveness).
- Prereq: a finding.

**FIND-06 — Dismiss a finding (reversible)**
- Steps: click **Dismiss**.
- Functional: status → dismissed; the row stays, greyed; restorable by setting another status.
- 🔌 Backend: status set; verify. The finding is NOT deleted (still in `GET`).
- Qualitative: explicitly reversible ("set aside reversibly") — distinct from Delete (Forgiveness).
- Principle: dismiss is reversible triage.
- Prereq: a finding.

**FIND-07 — Delete a finding (IRREVERSIBLE)**
- Steps: click **Delete** → the two-step inline confirm → **Yes, delete**.
- Functional: the finding vanishes from the list, the Inspector clears, and its diamond + `about` edge leave
  the graph.
- 🔌 Backend: `DELETE /api/findings/{id}` removes the row + cleans polymorphic refs; verify the finding count
  drops and it's gone from `GET`.
- Qualitative: set apart (right-aligned, dashed danger border) so it's not a foot-gun next to Dismiss;
  two-step confirm; copy says IRREVERSIBLE and points to Dismiss for the reversible path (Forgiveness, the
  whole reason it's distinct from Dismiss).
- Principle: irreversible destruction is visually and procedurally distinct from reversible triage.
- Prereq: a disposable finding.

**FIND-08 — Inline-edit a finding (every field)**
- Steps: click **Edit** → change title / severity / confidence / category / status / summary / reasoning →
  **Save** (or **Discard**).
- Functional: the fields become editable; Save persists and re-renders; Discard reverts.
- 🔌 Backend: `PATCH /api/findings/{id}`; verify each changed field in `GET`.
- Qualitative: a save error surfaces inline (Forgiveness); Discard is always available.
- Principle: the analyst curates the finding.
- Prereq: a finding.

**FIND-09 — Bulk confirm / dismiss**
- Steps: tick several finding checkboxes → use the bulk Confirm / Dismiss bar.
- Functional: all picked findings change status at once; selection clears.
- 🔌 Backend: bulk status; verify each.
- Qualitative: a "N selected" count + a clear bar (Feedback); the checkbox click doesn't open the finding
  (Consistency).
- Prereq: ≥2 findings.

**FIND-10 — Jump to source from a finding**
- Steps: on a finding with a source_ref, click **Open in source (line N)**.
- Functional: switches to the Source view, opens the right tree+file, scrolls to and highlights the line.
- Principle: finding → source is one click.
- Prereq: a finding with a `source_ref` (tree_id + rel + line).

**FIND-11 — Highlight components in graph**
- Steps: click **Components** on a finding.
- Functional: the nodes the finding is about are highlighted/selected in the graph.
- 🔌 Backend: `GET` the finding's components.
- Prereq: a finding with `about` edges.

**FIND-12 — PoC panel: verify / re-verify**
- Steps: on a finding with a PoC spec, read the PoC section (plain-language steps, oracle, repro command) →
  click **Verify PoC** (or **Re-verify** if already verified).
- Functional: runs the verification; the status flips to ✓ verified / ✗ not verified with a detail line and
  the assurance updates.
- 🔌 Backend: `POST` verify-finding; gated by `features.poc` (binary) / `features.network` (web). With the
  gate OFF, it must return clear policy guidance, never a fake "confirmed". Verify the result persists.
- Qualitative: the honest outcome — verified shows green with the assurance standard/method; a failed
  re-confirm is a muted note, not a success; a disabled gate is clear guidance (Forgiveness/honesty, the
  no-hardcoded-confirmed rule).
- Principle: "verified" means the injected behaviour really happened, via an unforgeable nonce.
- Prereq: a finding with a PoC spec; `features.poc` on to verify a binary PoC.

**FIND-13 — Copy reproduction command**
- Steps: click the copy icon on the repro command block.
- Functional: copies the command to the clipboard; the icon flips to a check briefly.
- Qualitative: a clear copied-confirmation (Feedback).
- Prereq: a finding with a `repro_command`.

**FIND-14 — Copy decompiled snippet**
- Steps: click the copy icon on the Decompiled block.
- Functional: copies; check feedback.
- Prereq: a finding with a `decompiled_snippet`.

**FIND-15 — Next-steps follow-ups → launch**
- Steps: click a **Next steps** suggestion.
- Functional: opens the LaunchModal prefilled (objective/params + parent-finding link); launching runs the task.
- 🔌 Backend: the follow-up's task; the launched task links to the parent finding. Verify a new task appears.
- Qualitative: the two suggestion sources (finding's own + rule-based) are deduped so no near-identical
  buttons twice (Consistency).
- Principle: a finding spawns the next task.
- Prereq: a finding with suggested follow-ups.

**FIND-16 — Hypotheses: new from finding / link existing**
- Steps: click **New from finding** (prompt for a statement) → it's created with the finding as supporting
  evidence; or pick an existing hypothesis and **supports** / **refutes**.
- Functional: a hypothesis node is created/linked; the graph gains it.
- 🔌 Backend: create-hypothesis + link-evidence; verify the hypothesis node + the evidence edge.
- Principle: findings feed hypotheses.
- Prereq: a finding; (for link) an existing hypothesis.

**FIND-17 — Annotations: add note / tag / rename + confirm/reject proposed**
- Steps: in a finding/node/target Detail, add a note/tag (rename for function nodes) → for an
  agent-proposed annotation, Confirm or Reject it.
- Functional: the annotation appears; proposed ones show confirm/reject; rejected ones strike through.
- 🔌 Backend: create-annotation + set-status; verify.
- Principle: human curation layered over agent output.
- Prereq: an entity; (for confirm/reject) a proposed annotation.

---

## SURFACE 4b — Tool Results panel + provenance (Phase O Observations)

The Observation store (design §5.6) surfaced for the user: every deterministic tool call on a
target (decompile / list / xrefs / taint / strings / structs) is recorded as a durable "Tool
Result". The panel lets a researcher browse and read those prior results before re-running, and a
node/finding shows the tool results it was derived from. Read/browse only — results persist here and
do **not** auto-populate the graph (promoting a result is a separate, deliberate act, deferred to a
later PR).

**OBS-01 — Tool Results panel on a target**
- Steps: select a target in the Targets pane (or its node in the graph) → in its NodeInspector scroll
  to the **Tool Results** section.
- Functional: a count and a list of the target's recorded tool results, newest first; each row shows
  the result kind, the tool, an error tag when failed, a relative time, and a one-line summary.
- 🔌 Backend: `GET /api/projects/{id}/targets/{targetId}/observations` (row metadata only, bounded);
  the rows must match the recorded `observation` table for that target. Empty state when none exist.
- Qualitative: rows read as calm, scannable cards in the app's card idiom (Aesthetics/Consistency);
  the empty state explains how results get here rather than showing a bare "none" (Discoverable); the
  panel sits naturally below the recon facts, not bolted on (Aesthetics).
- Principle: tool results are never lost — they're discoverable per target.
- Prereq: a target with ≥1 recorded observation.

**OBS-02 — Filter the Tool Results by tool / kind**
- Steps: in the Tool Results section, use the **tool** and/or **kind** select(s).
- Functional: the list filters live; a select appears only when >1 distinct value exists; "all …"
  clears it.
- Qualitative: filters compose; controls match the findings-filter idiom (Consistency); a too-narrow
  filter shows a clear "no tool results match" rather than an empty void (Feedback).
- Principle: a busy target's results stay navigable.
- Prereq: a target with observations spanning ≥2 tools or kinds.

**OBS-03 — View a raw tool-result payload**
- Steps: click a Tool Results row.
- Functional: a modal opens showing the result's metadata (tool, kind, args, summary, status, the
  analyzed-bytes hash, recorded time/source, size) and the full **raw payload**, pretty-printed and
  scrollable, with a copy button.
- 🔌 Backend: `GET /api/observations/{obsId}` — the full payload, faithfully restored from CAS (the
  list/search responses deliberately omit it). Verify the payload matches what the tool recorded.
- Qualitative: the payload is the point — it's legible (monospace, wrapped, bounded height) and
  copyable (Feedback); the modal dismisses on backdrop click / ✕ (Friction); it never blocks on a
  huge blob (the single-get is the only place the payload is fetched).
- Principle: the researcher can always read exactly what a tool produced.
- Prereq: a target with ≥1 recorded observation.

**OBS-04 — Provenance link on a node**
- Steps: select a graph node enriched from a tool call (its `attrs.provenance` is non-empty) → in its
  NodeInspector read **Derived from these tool results**.
- Functional: a list of the tool results that produced/enriched the node; clicking one opens its raw
  payload (OBS-03). The section renders nothing when there's no provenance.
- 🔌 Backend: each `attrs.provenance` id resolved via `GET /api/observations/{obsId}`; a missing/pruned
  id shows an "unavailable" stub rather than erroring.
- Qualitative: the link makes the graph auditable — "where did this come from" is one click
  (Discoverable); it's clearly read-only, distinct from authoring controls (Consistency).
- Principle: the graph stays curated, but every curated fact is traceable back to its tool result.
- Prereq: a node carrying `attrs.provenance`.

**OBS-05 — Provenance link on a finding**
- Steps: select a finding whose `evidence.extra.provenance` is non-empty → in the Inspector read
  **Derived from these tool results**.
- Functional: same as OBS-04, for a finding; clicking a row opens the raw payload; absent when the
  finding has no provenance.
- 🔌 Backend: resolved via `GET /api/observations/{obsId}`.
- Qualitative: consistent with the node provenance block (Consistency); does not crowd the already
  dense Inspector — it sits after the analyst notes (Aesthetics).
- Principle: a finding is traceable to the grounded results behind it.
- Prereq: a finding carrying `evidence.extra.provenance`.

---

## SURFACE 5 — Tasks panel + task detail

**TASK-01 — Tasks list: sort / filter**
- Steps: open the Tasks tab → sort (newest/oldest/by type/by cost/by findings) → filter by type.
- Functional: the list re-orders/filters; each row shows type · status · time · finding count · backend ·
  model · cost.
- 🔌 Backend: from `GET /api/projects/{id}/tasks`.
- Prereq: ≥1 task.

**TASK-02 — Select a task → detail (provenance, traces, findings, re-run)**
- Steps: click a task row.
- Functional: the Detail shows status/backend/model/cost chips, a failure block if failed, provenance
  (context bundle id, params), trace files (click to view), the findings it produced, and a **Re-run** button.
- 🔌 Backend: `GET` task detail + traces; Re-run launches a new task — verify a new task id appears.
- Qualitative: a failed task leads with its error (Feedback), not a bare "failed" badge.
- Prereq: a task with findings + traces.

**TASK-03 — Clear finding-less tasks**
- Steps: click **Clear** in the Tasks bar → confirm intent.
- Functional: tasks with no findings are removed from the list.
- 🔌 Backend: the clear-tasks endpoint; verify.
- Qualitative: it only clears finding-less tasks (the label says so) — Forgiveness.
- Prereq: ≥1 finding-less task.

**TASK-04 — Launch a task (LaunchModal)**
- Steps: from a Run menu (TGT-06), set objective / focus function / model / effort / budget cap / mock
  scenario (mock only) → read the live context preview → **Launch agent**.
- Functional: launches; the workspace shows a "running task…" badge, polls, then reloads with the new task +
  any findings.
- 🔌 Backend: `POST` launch; the context preview is `POST` preview-task (token estimate + items + dropped).
  Verify a task row and (on mock) deterministic findings appear.
- Qualitative: the context preview makes "what will be sent" legible BEFORE spending (the zero-surprise
  promise); `$0 (mock)` vs `est ≤ $cap` is honest (Forgiveness); the modal closes and the running badge is
  the running feedback.
- Principle: a deliberate, previewed launch — never a blind fire.
- Prereq: a target with a valid task kind.

---

## SURFACE 6 — Fuzz campaigns + artifacts/triage

**FUZZ-01 — Fuzz modal (engine / surface / target picker / seeds / dict / stop / resources)**
- Steps: open the Fuzz modal (TGT-07 or Campaigns "New campaign") → pick the target (switchable when a list
  is supplied) → read the server-advertised engine list + inferred surface → set focus fn / seeds /
  dictionary / stop conditions / resources (incl. unconstrained) → network fields appear only for a network
  surface.
- Functional: the modal reflects the target's surface; engines come from the server, never hardcoded;
  network-surface fields show only when relevant.
- 🔌 Backend: `GET /api/fuzz/engines?target_id=…` for the engine list/surface; a bad proto_spec JSON errors
  inline before sending.
- Qualitative: the lede sets expectation (detached, hardened sandbox, reaped automatically); the resources
  note is explicit that ceilings are not a security relaxation (honesty); fields are grouped, aligned cards
  (Aesthetics).
- Principle: surface-aware, server-driven, sandbox-honest.
- Prereq: `features.fuzzing` on; a fuzzable (ideally instrumented) target.

**FUZZ-02 — Start a campaign (actually launches)**
- Steps: in the Fuzz modal, click **Start campaign**.
- Functional: the modal closes; the Campaigns tab opens to the new campaign (status running/building).
- 🔌 Backend: `POST` start-campaign launches a DETACHED container (or the mock fuzzer offline); verify a
  campaign row with a non-terminal status appears, not a 400 "no harness".
- Qualitative: the "starting…" button state is the launch feedback.
- Principle: a campaign actually runs — never a fake row.
- Prereq: an instrumented/fuzzable target (the seed builds one for real).

**FUZZ-03 — Live campaign progress**
- Steps: watch a running campaign row in the Campaigns tab.
- Functional: execs / edges / crashes / coverage climb mid-run (SSE, polling fallback); a covering campaign
  shows edges > 0.
- 🔌 Backend: `GET /api/campaigns/{id}/events` (SSE) or polling `GET /api/campaigns/{id}`.
- Qualitative: live numbers are the in-progress feedback; a running pill has a pulsing dot.
- Principle: you watch it work, you don't run it by hand.
- Prereq: a running campaign (or a finished one to read its final stats).

**FUZZ-04 — Degraded / 0-exec distinct state + engine_note**
- Steps: observe a campaign that did 0 work or ran a degraded engine.
- Functional: a distinct amber **degraded** state with a WHY (engine_note / warning) — visually unlike a
  clean green "completed".
- Qualitative: a no-op must never read as a clean zero-crash success (the battle-test confusion — honesty).
- Principle: don't let a no-op pass as success.
- Prereq: a degraded campaign (intended; note if not seedable offline).

**FUZZ-05 — Crash triage inbox (dedup / exploitability / minimized)**
- Steps: select a campaign → the Artifacts/triage view → inspect a crash group.
- Functional: crashes grouped by dedup bucket (one rep + `+N dupes`), each with sanitizer/severity, faulting
  function, an exploitability rating, and a source-mapped stack.
- 🔌 Backend: `GET` campaign artifacts.
- Qualitative: the inbox reads like a triage queue (Aesthetics); dupes are folded, not a flat wall.
- Principle: crashes are triaged, not dumped.
- Prereq: a finished campaign with crashes.

**FUZZ-06 — Reproduce a crash**
- Steps: click **Reproduce** on a crash group.
- Functional: replays the stored reproducer against the instrumented harness; shows ✓ reproduced / ✗ not.
- 🔌 Backend: `POST` verify-artifact (LLM-free); verify the result.
- Prereq: a crash with stored content.

**FUZZ-07 — Minimize a crash**
- Steps: click **Minimize**.
- Functional: re-verifies the minimized reproducer; shows the outcome.
- 🔌 Backend: `POST` minimize-artifact; verify.
- Prereq: a crash.

**FUZZ-08 — Promote a crash to a finding**
- Steps: click **Promote**.
- Functional: the crash becomes a tracked finding; the group shows its status.
- 🔌 Backend: `POST` promote (to_poc=false); verify a finding is created/linked.
- Prereq: a crash with a finding_id.

**FUZZ-09 — Promote → PoC (policy-gated, honest)**
- Steps: click **Promote → PoC**.
- Functional (gate ON): seeds the PoC AND re-runs the reproducer now; a distinct green "Verified PoC" banner
  with the assurance standard/method on success, a muted "couldn't re-confirm" note on failure. (Gate OFF):
  a clear policy-guidance error pointing to Settings — nothing seeded/executed.
- 🔌 Backend: `POST` promote (to_poc=true); the policy seam (`assert_allows_execution`) gates it BEFORE
  seeding; with PoC disabled it 403s with guidance. Verify the verification result / the guidance.
- Qualitative: NO hardcoded "promoted → confirmed" regardless of outcome (the fix this whole flow exists for —
  honesty/Forgiveness).
- Principle: a PoC is verified, never assumed.
- Prereq: a crash; toggle `features.poc` to exercise both paths.

**FUZZ-10 — Open the finding from a crash**
- Steps: click **Finding** on a promoted crash.
- Functional: opens that finding's Inspector.
- Prereq: a promoted crash.

**FUZZ-11 — Stop / Resume a campaign**
- Steps: on a running campaign click **Stop**; on a stopped/completed one click **Resume**.
- Functional: status changes accordingly.
- 🔌 Backend: stop/resume endpoints; verify the status.
- Qualitative: the row click into triage and the Stop/Resume buttons don't conflict (stopPropagation) —
  Consistency.
- Prereq: a running and a stopped campaign.

**FUZZ-12 — Coverage shading in source**
- Steps: in Source view, pick a campaign in the coverage-shading picker.
- Functional: covered lines shade green, uncovered amber, in the open file; a legend explains; a "no per-line
  map" note if absent.
- 🔌 Backend: `GET` campaign coverage.
- Principle: coverage links the fuzzer to the source.
- Prereq: a campaign with a coverage map + a matching source file.

**FUZZ-13 — Symbolized stack frame → jump to source**
- Steps: in a crash group, click the top (symbolized) stack frame.
- Functional: jumps to the Source view at that frame's file/line.
- Prereq: a crash with a symbolized top frame + a `source_ref`.

---

## SURFACE 7 — Source / Build

**SRC-01 — Source tree switcher + file browse (read-only)**
- Steps: switch to Source → pick a tree in the dropdown → open a file.
- Functional: a file explorer + a syntax-highlighted, read-only code view; the tree shows origin + editability
  + linked-to-target; a binary file renders as hex.
- 🔌 Backend: `GET` source trees / files / a file's content.
- Qualitative: reads like an IDE pane (Aesthetics); read-only is clearly labeled (Consistency).
- Prereq: a managed source tree.

**SRC-02 — Edit a source file (scratch trees by default; other authored trees gated)**
- Steps: open a HexGraph-authored file in a **scratch** tree (your promoted harnesses/PoCs, origin=scratch) →
  **Edit** → change → **Save revision**. No feature flag needed. For an **other** authored tree (e.g. imported
  source marked editable), the Edit affordance only appears with `features.source.edit` on.
- Functional: a textarea editor; Save creates a NEW revision (never in-place); the revisions list grows.
  Scratch trees show Edit by default (the scoped source-edit design — they're ephemeral, authored, and exist to
  be iterated on); imported/extracted/vendor source stays read-only ALWAYS; other editable-but-not-scratch
  authored trees show Edit only with the flag. The Edit button is driven by the per-tree `can_edit` flag the
  API reports (which folds the scoped gate), not the global feature flag alone.
- 🔌 Backend: `GET` source trees returns `can_edit` per tree; `POST` save-source-revision; verify a new
  revision row. A scratch save succeeds with `features.source.edit` OFF; a non-scratch authored save is
  refused (403) with it off and succeeds with it on; a read-only tree is refused either way.
- Qualitative: "Save revision" wording makes the append-only model clear (Forgiveness); read-only and
  flag-gated files have no Edit button (Consistency); iterating on a harness in place is friction-free.
- Principle: edits are append-only revisions; scratch (authored, ephemeral) trees are editable by default,
  other authored trees stay opt-in, read-only trees are never editable.
- Prereq: a scratch authored file (no flag), OR `features.source.edit` on for another editable authored tree.

**SRC-03 — Revert to a revision**
- Steps: in the revisions list, click **revert** on an older revision.
- Functional: the working file reverts to that revision (append-only).
- 🔌 Backend: `POST` revert; verify.
- Prereq: a file with ≥2 revisions.

**SRC-04 — Build modal (instrumentation / engine / arch / deps / artifacts / recipe preview)**
- Steps: with `features.build` on, in Source click **Build (instrumented)** → toggle sanitizers / SanCov /
  engine / arch / deps posture / artifacts / custom phases → read the live recorded-recipe preview.
- Functional: the recipe preview regenerates server-side as you change the profile; there is NO free-text
  command box; the injected toolchain env + recipe_sha show; the fetch posture is disabled unless
  `features.build_fetch`.
- 🔌 Backend: `POST` build-preview on each change; the preview is server-computed.
- Qualitative: the lede is explicit that compile is always `--network none` and fetch is a separate audited
  phase (honesty); the recipe is read-only/reproducible (the no-arbitrary-command promise).
- Principle: build-as-recorded-recipe, reproducible, sandbox-honest.
- Prereq: `features.build` on; a buildable source tree.

**SRC-05 — Build (actually compiles — libfuzzer AND afl)**
- Steps: in the Build modal, **Build (sandboxed)**.
- Functional: the build runs the recorded recipe in the sandbox; the Builds list gains a row.
- 🔌 Backend: `POST` create-build runs the real recipe (mock builder offline for the seed); verify a build row
  appears for the chosen engine.
- Qualitative: a "building…" state is the in-progress feedback.
- Principle: a real build, for either engine.
- Prereq: `features.build` on (the seed uses the offline MockBuilder).

**SRC-06 — Failed build → detail modal (error + full log)**
- Steps: click a FAILED build row in the Builds list.
- Functional: a detail modal leads with the recorded error + the full build log (CAS-backed) — not a dead-end
  badge; explains the usual causes.
- 🔌 Backend: `GET` build log.
- Qualitative: a failure is never a dead end — the error and log tell you why (Forgiveness, the whole reason
  this modal exists).
- Principle: a failed build is debuggable, not a bare badge.
- Prereq: a failed build — exercisable offline: the seed's A9b drives a build that fails (e.g. a recipe whose
  artifact path won't exist), so the Builds list shows a real failed row alongside the succeeded one; assert
  the modal's error + log contents.

**SRC-07 — Succeeded build → detail (artifacts + provenance)**
- Steps: click a SUCCEEDED build row.
- Functional: the detail shows captured artifacts (with CAS hashes), the reproducibility triple (recipe_sha ·
  source content · toolchain), supply-chain posture (reproducible / cached / locked), and the instrumented
  derived target registration.
- 🔌 Backend: `GET` build log + the build row.
- Qualitative: the provenance reads as a trust artifact, not noise (Aesthetics).
- Principle: a build is reproducible and provenanced.
- Prereq: a succeeded build (the seed produces one).

**SRC-08 — Build badges in the Builds list**
- Steps: read a build row's badges.
- Functional: status + reproducible / cached / locked / instrumented badges; a failed row reads "view error &
  log →".
- Prereq: builds in the list.

**SRC-09 — Coverage-shading campaign picker**
- Steps: in the Source view toolbar, open the coverage-shading dropdown → pick a completed fuzz campaign.
- Functional: arms per-line coverage shading for the next-opened file (the green/amber hit/miss tint of
  FUZZ-12); the control is present even before a file is open.
- Qualitative: the picker makes "shade this file by THAT campaign's coverage" discoverable without leaving
  Source (Discoverable); selecting a campaign is one click (Friction).
- Principle: coverage is a lens you point at the source, chosen explicitly.
- Prereq: S20 — a finished campaign with a coverage map.

---

## SURFACE 8 — Top toolbar (analyze / author / report / export / audit)

**TOOL-01 — Add Node modal**
- Steps: toolbar **Node** → pick a type → (socket: kind/port/name; endpoint: route; etc.) → pick a binary
  when the type is target-bound → **Create**.
- Functional: the node is created and appears in the graph; type help text + recommended attributes show.
- 🔌 Backend: `POST` create-node (or create-socket for sockets); verify the node.
- Qualitative: the per-type help makes the right type discoverable (Discoverable, the sink-vs-symbol guidance);
  Create disabled until valid (Forgiveness).
- Principle: hand-author any node type.
- Prereq: ≥1 target.

**TOOL-02 — Add Edge modal**
- Steps: toolbar **Edge** → pick from/to (grouped option list) → type → optional attributes JSON → **Create**.
- Functional: the edge is created (merging list-attrs); appears in the graph; type help + attribute hints show;
  invalid JSON errors inline.
- 🔌 Backend: `POST` create-edge (merge=true); verify.
- Qualitative: the endpoint list is grouped (targets / functions / other / findings / strings) so it's
  navigable (Discoverable).
- Principle: connect any two entities; list-attrs merge, not clobber.
- Prereq: ≥2 nodes.

**EDGE-DEL — Delete an edge (from the edge inspector)**
- Steps: select an edge (GRAPH-12) → **Delete edge** → confirm.
- Functional: the edge is removed from the graph.
- 🔌 Backend: `DELETE` edge; verify it's gone from `/graph`.
- Qualitative: confirm explains it's permanent and that removing a node's edges reversibly means removing the
  node instead (Forgiveness).
- Prereq: a deletable edge.

**TOOL-03 — Compare runs**
- Steps: toolbar **Compare** → pick two runs over a target → diff.
- Functional: shows added/dropped/changed findings between two analysis runs.
- 🔌 Backend: the compare endpoint.
- Principle: n-day / regression diffing.
- Prereq: a target with ≥2 runs (intended; note if only one).

**TOOL-04 — Link same-code**
- Steps: toolbar **Same-code**.
- Functional: links identical functions across targets; an alert reports the count of pairs linked.
- 🔌 Backend: link-same-code; verify new `similar_to` edges.
- Qualitative: a result count is the feedback (Feedback).
- Principle: n-day clone detection across binaries.
- Prereq: ≥2 targets with shared functions.

**TOOL-05 — Merge duplicates**
- Steps: toolbar **Merge dupes**.
- Functional: folds duplicate nodes/binaries (e.g. `sym.foo` == `foo`); an alert reports counts.
- 🔌 Backend: merge-duplicates; verify the node count drops.
- Principle: dedup by canonical identity.
- Prereq: a graph with duplicates.

**TOOL-06 — Report modal**
- Steps: toolbar **Report**.
- Functional: a markdown report of confirmed/reported findings (viewable/copyable/exportable).
- 🔌 Backend: the report endpoint.
- Prereq: confirmed/reported findings.

**TOOL-07 — Export graph JSON**
- Steps: toolbar **Export**.
- Functional: downloads the project graph as JSON named after the project.
- Qualitative: a real file download (Feedback).
- Prereq: a graph.

**TOOL-08 — Egress audit view**
- Steps: toolbar **Audit**.
- Functional: a table of every outbound action (when · verdict allowed/denied · destination · tool · detail);
  an allowed/denied count summary; an empty log states the default `--network none` posture; a refresh button.
- 🔌 Backend: `GET` egress events; verify the rows match the DB.
- Qualitative: denied rows are red, allowed green (Feedback); empty is reassuring, not alarming (honesty).
- Principle: nothing reaches the network without an audited EgressEvent.
- Prereq: egress events (the seed records allowed + denied).

**SEARCH-01 — Toolbar search → focus / view finding**
- Steps: type in the toolbar search (functions / strings / findings / targets).
- Functional: a results popover grouped by kind; picking a target/node focuses it in the graph; picking a
  finding opens its Inspector; a coverage note shows.
- 🔌 Backend: `GET` search (debounced); verify results match.
- Qualitative: search RANKS nodes/targets first and DRIVES focus (not just a passive ring) — the
  search-drives-the-graph promise; nodes inside a collapsed room auto-expand to land the focus.
- Principle: "find X and show me its world" is one action.
- Prereq: a graph with searchable entities.

---

## SURFACE 9 — Settings

**SET-01 — Settings page open / close (Esc)**
- Steps: open Settings (gear) → close (button or Esc).
- Functional: the page loads current settings; Esc closes back to where you were.
- 🔌 Backend: `GET /api/settings`.
- Prereq: none.

**SET-02 — Model access (backend / model / key presence)**
- Steps: change the default backend / model preference; read the secret-presence rows.
- Functional: backend/model persist; API keys show presence-only (detected/source or not set), never the value.
- 🔌 Backend: `PATCH /api/settings`; verify; the secret is NEVER written/returned (the BYOK invariant).
- Qualitative: the hint is explicit that keys are never stored/transmitted (honesty/trust).
- Principle: BYOK, presence-only, never logged/stored/returned.
- Prereq: none.

**SET-03 — Toggle each optional feature (the gates)**
- Steps: toggle each feature switch: Ghidra, Fuzzing, Source & Build (+ build_fetch, source.edit), PoC
  verification, Network egress, Remote fuzz environments, MCP read/write/run groups, Delegate-to-agent.
- Functional: each toggle persists; the dependent sub-controls show/hide; the workspace reflects it (e.g.
  enabling Fuzzing surfaces the Campaigns tab + Fuzz rows; enabling Build surfaces the Build button).
- 🔌 Backend: each is a `PATCH /api/settings`; verify each in `GET` and that the gate actually changes behavior.
- Qualitative: every policy-relaxing feature carries an explicit ⚠ SECURITY IMPLICATION (executes code /
  executes the target / contacts a live target / supply-chain risk) — the honesty the setup catalog requires;
  the resource note is clear it's not a security relaxation. Enabling a policy gate on a *running* server does
  not take effect until restart — see SET-03b.
- Principle: each gate is opt-in, with its security implication stated.
- Prereq: none.

**SET-03b — Policy gate "restart to apply" (the startup ceiling)**
- Steps: with the server already running, enable a policy gate that was OFF at startup (e.g. Fuzzing, PoC,
  Network egress). Then, separately, *disable* a gate that was ON at startup.
- Functional: enabling shows an amber **restart to apply** chip next to that gate AND a top-of-page amber
  **Restart required to activate** banner naming the pending gate(s); the toggle stays on (the choice is
  saved). The behavior it unlocks does NOT activate until `hexgraph serve` is restarted. Disabling, by
  contrast, takes effect immediately (no chip, no banner) — and re-enabling a gate that was on at startup is
  also immediate (it's within the frozen ceiling).
- 🔌 Backend: `read_settings()` returns a `policy` block — per gate `{configured, effective, pending_restart}`
  plus top-level `restart_required` / `pending`. The PATCH response carries the fresh block, so the chip/banner
  appear in the same render with no extra round trip. `policy.current_policy()` clamps each gate to the set
  captured by `policy.snapshot_ceiling()` at server / MCP-session startup, so a mid-session widen of
  settings.json can never grant execution/egress to the running process. The capability/launch menu also
  honors the ceiling (`engine/capabilities.py` reads `policy.effective_gates()`, not raw settings), so a
  mid-session-enabled gate is not advertised as a launchable task until the restart that would actually
  permit it. (`effective` in the policy block reflects the *resolved* running outcome — it folds in the
  inter-gate dependencies, e.g. build_fetch is effective only when build is too — while `pending_restart`
  tracks only what a restart changes: this gate's own toggle being clamped by the startup ceiling.)
- Qualitative: the operator is never misled into thinking a saved-but-inactive toggle is live (the failure
  this kills), and never confused about why a click "didn't work" — the banner explains *why* (a long-lived
  server freezes its capabilities at startup) and *what to do* (restart). Honesty + Forgiveness.
- Principle: enabling a policy gate is the one direction deferred to a restart; disabling is always live. The
  ceiling is the deterministic guard that an agent/host-local writer can't self-escalate a running session.
- Prereq: a running server (not the CLI, which re-reads live each invocation — it never snapshots a ceiling).

**SET-04 — Ghidra modes + test connection**
- Steps: enable Ghidra → pick headless/bridge → (headless: timeout; bridge: host/port) → **Test connection**.
- Functional: mode-specific fields show; Test reports ok/detail.
- 🔌 Backend: `PATCH` + the Ghidra test endpoint.
- Prereq: none (test may report unavailable offline — that's a legible state, not a failure).

**SET-05 — Container resources (shared default)**
- Steps: in the always-visible **Container resources** card, set memory / cpus / pids / scratch tmpfs / timeout,
  or toggle **unconstrained**.
- Functional: each persists on blur (`resources.default.*`); unconstrained hides the per-field ceilings. The
  shared default is inherited by every container type (sandbox / build / fuzzing) unless a per-type key overrides
  it; per-type sandbox/build overrides are settable via the Settings API / `hexgraph config set` (not on this page).
- 🔌 Backend: `PATCH resources.default.*`; verify a sandbox/build/campaign container picks up the new ceiling.
- Qualitative: the hint is explicit that tuning ceilings / unconstrained is NOT a security relaxation, and that
  raising memory also raises the memory-derived limits (honesty). Always visible (not gated behind a feature).

**SET-05b — Resource ceilings (fuzzing override)**
- Steps: with Fuzzing on, set max time / max len / max crashes / sandbox timeout + the **Default campaign
  resources** override (mem/cpus/pids or unconstrained).
- Functional: each persists on blur; the resources block writes `resources.fuzzing.*` (layered over the shared
  Container-resources default); unconstrained hides the per-field ceilings. The Fuzz modal prefills from the merged
  default ← fuzzing override and can override again per run.
- 🔌 Backend: `PATCH`; verify.
- Qualitative: the note is explicit that ceilings/unconstrained are NOT a security relaxation (honesty).
- Prereq: Fuzzing on.

**SET-06 — Remote fuzz environment register / health / remove**
- Steps: with fuzz_remote on, register an env (name/transport/descriptor) → health-check → remove.
- Functional: the env appears; health reports; the connection is presence-only (a secret set in env, never
  stored here); remove deletes it.
- 🔌 Backend: register / health / delete env endpoints; verify; the secret connection is never persisted in
  settings.
- Principle: remote compute, same sandbox boundary, secret presence-only.
- Prereq: fuzz_remote on.

**SET-07 — Server bind host/port**
- Steps: change bind host / port.
- Functional: persists; the hint notes loopback-only default and the override env for a non-loopback bind.
- 🔌 Backend: `PATCH`; verify.
- Qualitative: the loopback invariant is surfaced as guidance (honesty).
- Prereq: none.

**SET-08 — Paths / availability footer**
- Steps: read the footer.
- Functional: shows config.toml + settings.json paths and Docker availability.
- Prereq: none.

---

## STATE COVERAGE MATRIX

Every interaction's **Prereq** must trace to a row here. This is the contract between the two roles:
the VR-analyst sequence (Role 1 in the skill) produces each state, so when the researcher (Role 2)
opens the UI, every interaction has its prerequisite present — **no empty panels**. The "VR-analyst step"
column names the step in `.claude/skills/ux-assessment/SKILL.md` (Role 1) that produces it.

| # | Prerequisite state | Produced by VR-analyst step | Unlocks (contract IDs) |
|---|---|---|---|
| S1 | ≥1 project exists | A0 create the project | PROJ-01, SHELL-*, all |
| S2 | A disposable project to delete | A0 (a second throwaway project) | PROJ-03 |
| S3 | A standalone byte binary target, deep-recon'd | A1 ingest a standalone binary + run recon | TGT-02, TGT-05, GRAPH-07/10, FIND-*, TASK-04 |
| S4 | A firmware target with an unpacked filesystem + path-named children | A2 ingest a firmware image | TGT-03, TGT-04, TGT-09, TGT-10, GRAPH-01, GRAPH-26 |
| S5 | A `web_app` surface target | A3 register a web_app surface | TGT-06 (surface kinds), VIEW-*, GRAPH-27 |
| S6 | A `service` (raw-TCP socket) surface target | A4 register a socket/service target | TGT-06, GRAPH-27, FUZZ-01 (network surface) |
| S7 | Findings across types (vulnerability/recon/info-leak/auth/fuzz_crash/poc) | A5 run static analysis tasks producing findings | FIND-01/02/03, GRAPH-18/20, TOOL-06 |
| S8 | Findings across the assurance ladder (static, reachable, lab-confirmed, verified) | A5 + A8 (verify a PoC) | FIND-04, FIND-12 |
| S9 | A finding with a PoC spec + repro command + source_ref | A5 (the command-injection finding) | FIND-10/12/13, FUZZ-13 |
| S10 | A finding with a decompiled snippet | A5 (a memory-safety finding) | FIND-14 |
| S11 | A finding with suggested follow-ups | A5 (findings carry followups) | FIND-15 |
| S12 | A hypothesis node + evidence edges | A6 create a hypothesis, link a finding | FIND-16, GRAPH-14 (by-finding), TGT-* |
| S13 | Annotations incl. an agent-proposed one | A6 add notes/tags; (proposed via an analysis task) | FIND-17, TGT-* |
| S14 | Findings in varied states (new / accepted / dismissed) | A7 confirm some, dismiss some, leave some new | FIND-01/02 (status filter), FIND-05/06 |
| S15 | A disposable finding to delete | A5 (one extra low finding) | FIND-07 |
| S16 | Tasks (succeeded + at least one finding-less, + traces) | A5 (each analysis is a task) + A1 recon | TASK-01/02/03 |
| S17 | An instrumented derived target (real build) | A9 build an instrumented target from source | FUZZ-01/02, SRC-05/07, GRAPH-29 |
| S18 | A managed source tree (lib + harness) editable | A9 (the source tree) + SET-03 source.edit | SRC-01/02/03, SRC-04 |
| S19 | A succeeded build with provenance + a failed build (both produced offline — A9b drives a deliberately-failing build) | A9 (succeeded) + A9b (a deliberately-failing build) | SRC-06, SRC-07, SRC-08 |
| S20 | A finished fuzz campaign with crashes + coverage map | A10 run a fuzz campaign to completion | FUZZ-03/05/06/07/08/09/10, FUZZ-12, FIND (fuzz_crash) |
| S21 | A running (live) campaign | A10b start a longer campaign and leave it running | FUZZ-03 (live climb), FUZZ-11 (stop) |
| S22 | A degraded / 0-exec campaign | A10c start a no-op/degraded campaign | FUZZ-04 |
| S23 | Manual nodes + edges hand-authored | A6 add a node + draw/author an edge | TOOL-01/02, EDGE-DEL, GRAPH-12/37 |
| S24 | A graph with duplicate nodes/binaries | A11 ingest a sibling binary sharing code | TOOL-04, TOOL-05 |
| S25 | A target with ≥2 analysis runs | A12 re-run a task over a target | TOOL-03, TASK-02 (re-run) |
| S26 | Egress events (allowed + denied) | A13 enable network + run a web probe (allowed) and attempt a denied dest | TOOL-08, SET-03 (network) |
| S27 | Cross-target edges (links_against / connects_to / shared sockets) | A2+A11 (firmware + sibling) | GRAPH-27/28, VIEW-04/05, TOOL-04 |
| S28 | A LARGE / PATHOLOGICAL / REAL-scale project | A14 seed/ingest a many-target firmware (or use `just graph-tiers`) | GRAPH-01/23/25/26, VIEW-02, SHELL-* at scale |
| S29 | Optional features enabled (fuzzing, poc, build, network, source.edit) | A0b enable the needed gates in Settings | TGT-07, FUZZ-*, SRC-02/04/05, FIND-12, SET-03 |
| S30 | A saved lens | A15 customize a view and save a lens | VIEW-06/07/08 |
| S31 | A target with recorded tool results (observations), some spanning ≥2 tools/kinds, with ≥1 node and/or finding carrying provenance | A5 (analysis tasks / agent tool calls record observations and provenance) | OBS-01/02/03/04/05 |

**Coverage check:** the VR sequence steps A0–A15 (in the skill) produce S1–S30, which between them are the
Prereq of every interaction above. If a new contract entry introduces a Prereq not in this matrix, the same
PR must add the matrix row AND the VR-analyst step that produces it — otherwise the assessment would open
that surface empty.
