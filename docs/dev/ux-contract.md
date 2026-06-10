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
  rather than cramming (Aesthetics). Cards are a **uniform, capped width** (they don't stretch to fill a
  partly-full row), and the grid is **left-aligned**, so a lone trailing card on the last row reads as one
  more card at the left — never a wide stretched box beside an awkward empty column (Aesthetics).
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

**SHELL-04b — Right-pane tab bar wraps on a narrow pane**
- Steps: narrow the right pane (drag the center/right splitter toward its ~280px minimum).
- Functional: the primary tab buttons (Findings / Hypotheses / Journal / Tasks / Campaigns) **wrap onto a
  second line** rather than overflowing or hiding behind a horizontal scroll; every tab stays visible and
  clickable, and the expand/collapse controls stay reachable at the top-right.
- Qualitative: primary navigation is never clipped — a researcher can always see that "Journal" exists, even
  at minimum width (Discoverable, Consistency).
- Principle: primary nav is never hidden behind a scroll.
- Prereq: a project open with the right pane narrowed.

**SHELL-05 — Detail section drag / expand within the right pane**
- Steps: drag the horizontal splitter between the findings list and the Detail section; or click the
  Detail expand toggle.
- Functional: the Detail box grows/shrinks; expand gives Detail the whole right pane.
- Qualitative: consistent with the other splitters (Consistency).
- Prereq: a finding or node selected (so Detail has content).

---

## SURFACE 1 — Targets pane (left)

The Targets pane shows only **visible** targets. A firmware unpacks into hundreds of ELF children,
each registered HIDDEN (recorded, searchable, recon-enriched, but not in the pane or graph) so the
tree isn't a 765-row wall; you **reveal** the binaries worth analyzing from the firmware's
FilesystemBrowser (TGT-13/TGT-14). A lone ingest and a promoted file are visible immediately.

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
  tree → add a NON-registered file (a script/config, or a binary unpack didn't register) as a child target.
- Functional: the file is added as a new (visible) child target and appears in the tree.
- 🔌 Backend: `GET` the firmware filesystem listing (entries carry `added` + `revealed`); the add-file
  (`promote-file`) call creates a visible child `target`. Verify the row.
- Qualitative: the FS browser reads like a file explorer (Discoverable); adding is one action (Friction).
- Principle: any file in the firmware is promotable to a curated target.
- Prereq: a firmware with an unpacked filesystem.

**TGT-13 — Reveal an unpack-registered (hidden) binary**
- Steps: in a firmware's FilesystemBrowser, find an ELF entry showing a **Reveal** button (it's `added` —
  unpack registered it — but not yet `revealed`) → click Reveal.
- Functional: the child target becomes visible — it appears in the Targets tree and the graph, its recon
  symbol/string nodes materialize, and the entry's button flips to the plain `added` badge.
- 🔌 Backend: `POST /api/projects/{id}/targets/{tid}/visible` `{visible:true}` (`target_set_visible`) flips
  `target.visible` and materializes the recon nodes from the already-stored facts (no re-run); verify the
  target now appears in `GET /api/projects/{id}` and `/graph`, with code nodes under it.
- Qualitative: Reveal is distinct from add (Honesty — the binary already exists; you're surfacing it, not
  re-ingesting); one click (Friction); the firmware's hundreds of ELFs stay out of the way until chosen (calm).
- Principle: hidden-by-default keeps the graph lean; reveal is the curation gate for firmware children.
- Prereq: a firmware whose unpacked ELFs are hidden (the default after ingest).

**TGT-14 — Reveal a whole directory of binaries**
- Steps: in the FilesystemBrowser, on a folder that holds hidden ELFs (or the header's **reveal all**),
  click **reveal all**.
- Functional: every hidden child under that directory prefix is revealed at once (appears in tree + graph);
  a directory with nothing hidden shows no reveal-all button.
- 🔌 Backend: `POST /api/projects/{id}/targets/{fwId}/reveal-dir` `{prefix}` (`target_reveal_dir`) reveals
  all matching hidden children + materializes their recon nodes; verify the count and that the revealed
  targets appear in the listing.
- Qualitative: bulk reveal for "I want everything under /usr/sbin" without clicking each (Friction); the
  button only shows where it would do something (Forgiveness — no dead control).
- Principle: reveal scales from one binary to a directory.
- Prereq: a firmware directory with ≥1 hidden ELF child.

**TGT-11 — Ghidra import (bridge mode)**
- Steps: with Ghidra bridge enabled, click the **Ghidra** button in the Targets header → the import modal.
- Functional: lists programs open in the connected Ghidra; importing one creates a target.
- 🔌 Backend: the Ghidra bridge endpoints; verify a target is created on import.
- Qualitative: shown ONLY when bridge mode is configured (Consistency — no dead button otherwise).
- Principle: Ghidra is an optional, gated seam.
- Prereq: `features.ghidra` = bridge, a reachable Ghidra (intended; assessment notes if unverifiable offline).

**TGT-12 — One-click promote a recon import / export to a node**
- Steps: select a byte target → in its NodeInspector, under **Imports** or **Exported functions**, click the
  `+` on an entry (e.g. `strcpy`).
- Functional: that entry becomes a graph node WITHOUT decompiling — an **import → a `symbol` node**, an
  **export → a `function` node** — wired `contains` to the target; the chip flips to a ✓ (added); the graph
  node count goes up and the new node's type appears in the legend. Both the Imports and the Exported-functions
  lists carry the same `· click + to add as a node` affordance (previously only exports did). A **long imports
  list collapses to a preview** (24) with a `+N more` / `show fewer` toggle, so a busy binary doesn't bury the
  Tool Results below it.
- 🔌 Backend: `POST /api/projects/{id}/nodes` (`graph_create_node`) — the same path the agent uses. The node
  **auto-enriches** on creation (`get_or_create_node` → `apply_facts_for_node`): a promoted import that a prior
  tool already flagged dangerous joins its `is_sink` tag; a function joins any waiting prototype/address. Verify
  the node exists in `/graph/{id}` with the right `node_type`.
- Qualitative: promoting is one click, mirroring the export affordance exactly (Consistency); re-clicking an
  already-added entry is a no-op disabled chip (Forgiveness); a bare symbol with no prior analysis comes in
  plain rather than mislabeled (Honesty — auto-enrichment never *judges*).
- Principle: anything recon surfaced is one click from the curated graph; promotion is lightweight and
  forward-enriching.

**TGT-15 — Target "Next steps" (recon-derived follow-ups)**
- Steps: select a byte target whose recon found risky-sink imports (e.g. it imports `strcpy`) → in its
  NodeInspector, look under **Next steps** (between the Run launcher and Recon facts).
- Functional: one or more suggestion buttons (e.g. "Static-analyze … for memory safety"); clicking one opens
  the LaunchModal prefilled for that task type on this target.
- 🔌 Backend: `GET /api/targets/{id}/suggestions` (`suggest_target_followups`) — the home for the risky-sink →
  static-analysis follow-up now that recon enriches the target instead of minting a per-target finding.
- Qualitative: the loop still surfaces ("recon found a binary that imports strcpy → static-analyze it")
  without a noise finding (Honesty); absent when there's nothing to suggest (no empty section).
- Principle: the target → task loop survives recon-as-enrichment; follow-ups live on the target, not a finding.
- Prereq: a byte target whose recon metadata shows a risky sink import.
- Prereq: a target whose recon facts include imports/exports.

---

## SURFACE 2 — Graph canvas (center, default view)

These are the densest set. The governing principle (design-graph-presentation §0): **calm by default,
loud only where you are looking; every node/edge/color kept, mute never deletes.**

**GRAPH-01 — Default frame at each tier**
- Steps: open a project cold at SMALL / MEDIUM / LARGE / PATHOLOGICAL / REAL.
- Functional: SMALL/MEDIUM = the full graph (rooms auto-expanded). LARGE/PATHOLOGICAL = skeleton-collapsed
  to ~10–25 labeled, finding-weighted *rooms*. REAL (skeleton mode) = rooms only, a "skeleton · N rooms" badge
  + a hint to double-click a room to load its interior; the browser never holds ~13k nodes.
  **SMALL/single-binary specifically** fits TIGHTER (smaller letterbox) and enforces a comfortable minimum
  zoom so the curated content *fills* the canvas with readable leaf labels — it must NOT open as a lone room
  card up top with huge dead vertical space below (the issue-5.1 failure). A `target_id`-less node that is
  `about` a target (e.g. a hypothesis) nests INSIDE that target's room rather than floating loose far below it.
  **Hypotheses are OFF-CANVAS by default** (`attrs.pinned_to_graph` false) — they live in the Hypotheses
  worklist tab and draw on the canvas only when explicitly pinned (HYP-04), a deliberate net reduction in
  clutter. A pinned hypothesis nests in its target's room exactly as above; an unpinned one never renders.
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
  node). **On a function node** an extra **Open in source viewer** verb appears (between Reveal and Hide) →
  opens the function source viewer (see FSV-01). The **native browser menu must NOT appear**. The menu is
  anchored at the **cursor**, not the node's center — its top-left corner sits where you clicked
  (`evt.renderedPosition`), nudged inward only if it would spill off the canvas edge.
- Qualitative: the menu is compact, sized to fit, not clipped (Aesthetics); it lands under the pointer so the
  first verb is a tiny travel away (Direct manipulation); native-menu suppression is absolute anywhere on the
  canvas (Consistency, Forgiveness); the source-viewer verb shows ONLY on function nodes, not strings/sockets
  (Consistency — verbs are type-aware).
- Principle: HexGraph owns the right-click everywhere on the canvas; a context menu opens at the cursor.
- Prereq: a graph with content nodes (incl. at least one function node).

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
- Qualitative: the responsiveness feels right to a hand (Overall) — `wheelSensitivity` tuned to ~1.4. The
  tuned value no longer logs cytoscape's "custom wheel sensitivity" **console warning** on every graph mount
  (it's silenced for the construction call only, so no other warning is ever swallowed) — a clean console (Polish).
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

**GRAPH-39 — YARA `matches_rule` edge labeled on canvas**
- Steps: open a project that ran a YARA sweep/scan (it has `pattern` nodes + `matches_rule` edges from the
  scanned target to them).
- Functional: the YARA→target relationship draws as a **violet, labeled `matches_rule` edge** (always-labeled,
  like the other typed semantic edges) — NOT a faint anonymous hairline that only exists in data/Table. It's a
  distinct color from `instance_of_pattern` (orange) so the two pattern relations read apart, and it appears in
  the legend below the canvas and toggles with the semantic edge-class layer.
- Qualitative: the rule-hit relationship is legible at a glance, consistent with every other typed edge (Consistency).
- Principle: a meaningful typed edge is a labeled, colored canvas edge — not a data-only relationship.
- Prereq: a project with `matches_rule` edges (a YARA sweep result).

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

**FIND-02b — Reveal findings on hidden targets (toggle)**
- Steps: with findings recorded on hidden firmware children (unrevealed ELF targets), click the
  **"+N on hidden"** eye toggle in the filter bar.
- Functional: those findings fold into the list (and the severity summary), each badged "hidden target";
  toggling off hides them again. Off by default. The toggle is absent when there are none. The Findings
  **tab** header also shows a dimmed "+M" after the visible count (M = hidden count) with a tooltip, so the
  hidden findings are discoverable before the panel is opened.
- 🔌 Backend: `detail.hidden_findings` / `detail.hidden_targets` from `GET /api/projects/{id}` — SUBSTANTIVE
  findings (recon excluded — it's the per-child flood) on non-archived hidden children, kept OUT of
  `targets`/the graph (no Targets-pane flood). `include_hidden=true` folds the full firehose into `findings`
  instead and empties the hidden buckets.
- Qualitative: discoverable — the count tells the analyst findings exist they aren't seeing (the firmware
  child was analyzed but never revealed); the badge + tooltip point to revealing the target to manage it
  normally (Feedback/Honesty). A merely-hidden child is recoverable here; an *archived* target's findings stay
  gone (distinct from this — see TGT remove).
- Principle: a finding is never silently dropped because its target isn't in the pane; it's one toggle away.
- Prereq: at least one finding on a hidden (unrevealed, non-archived) firmware child.

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
- Functional: a hypothesis is created/linked; it appears on the Hypotheses worklist (HYP-01) as
  `investigating` and OFF the canvas (pin it via HYP-04 to draw it).
- 🔌 Backend: create-hypothesis + link-evidence; verify the hypothesis node + the evidence edge.
- Principle: findings feed hypotheses.
- Prereq: a finding; (for link) an existing hypothesis.

**FIND-17 — Annotations: add note / tag / rename + confirm/reject proposed**
- Steps: in a finding/node/target Detail, add a note/tag (rename for function nodes) → for an
  agent-proposed annotation, Confirm or Reject it.
- Functional: the annotation appears; proposed ones show confirm/reject; rejected ones strike through.
  Note on agent renames: an agent renaming a node that still has a decompiler placeholder name
  (`fcn.00401234`, `FUN_…`, `sub_…`) is auto-confirmed and applied immediately, so it does NOT appear
  as a pending confirm/reject proposal — only an agent rename of an already-real name lands as a
  proposal awaiting a human. (Human renames always apply.)
- 🔌 Backend: create-annotation + set-status; verify. An agent rename of a placeholder-named node
  persists with `origin=agent, status=confirmed` and the new name applied (the old placeholder kept in
  `name_history`); an agent rename of a real-named node persists `status=proposed`, not applied.
- Principle: human curation layered over agent output — but naming the genuinely-unnamed is pure
  value-add and need not wait on a click.
- Prereq: an entity; (for confirm/reject) an agent rename of an already-real name (a placeholder rename
  won't queue).

**FIND-18 — Solved input (angr symbolic execution)**
- Steps: select a `vulnerability` finding produced by the angr solver (its `evidence.reproducer` +
  `evidence.extra.solver` are set) → read the **Solved input** section in the Inspector.
- Functional: a dedicated EVIDENCE block headed "Solved input · {backend} symbolic execution" shows a
  one-line explanation (which sink, which input model). When the solver determined which bytes actually
  matter (`evidence.extra.solver.minimal_input_hex` is set and is shorter than the full reproducer), a
  **"constrained serial" code block is shown FIRST and most prominently** — labelled "first N bytes that
  matter" — with its own copy icon (flips to a check); the full buffer then renders below it relabelled
  **"full reproducer"** with an "incl. unconstrained filler" note. When no minimal prefix is available the
  single block is headed **"reproducer"** as before. Both code blocks are copyable, and the section also
  shows the byte repr and the key solver fields (input model, reached address, sink, path length, angr
  version, steps, elapsed) plus a collapsible full path-to-sink and the backing observation id.
- 🔌 Backend: the fields render straight from the finding's `evidence` (`reproducer` + `extra.solver`); no
  extra call. The full reproducer shown must equal the stored `evidence.reproducer`; the constrained serial
  must equal `evidence.extra.solver.minimal_input_hex` (and is only shown when shorter than the full buffer).
- Qualitative: the flagship symbolic-execution result reads as a first-class, scannable block — the part
  that actually matters (the constrained serial) is the headline and is one click to copy, with the padded
  full buffer kept for completeness but visually demoted, not buried in a JSON dump (Aesthetics, the whole
  reason this surfacing exists).
- Principle: the solver's solved input is visible and copyable, and the bytes that matter are surfaced
  ahead of the unconstrained filler — never invisible.
- Prereq: an angr `vulnerability` finding with a solved reproducer (and, for the constrained-serial block,
  a `minimal_input_hex` shorter than the full buffer).

**FIND-19 — Mitigations as weak/ok badges (not a JSON blob)**
- Steps: on a finding whose `evidence.extra.mitigations` is set (e.g. a hardening finding), read the
  **mitigations** row in the EVIDENCE section.
- Functional: each protection renders as its own color-coded badge — present protections green ("NX",
  "canary", "PIE", "FORTIFY", "RELRO full"); missing ones red ("NX off", "no canary", "no PIE",
  "no FORTIFY", "RELRO off"); partial RELRO amber ("RELRO partial"). No raw `{"nx":false,…}` JSON.
- 🔌 Backend: rendered from `evidence.extra.mitigations`; the weak/ok split must match the binutils
  observation summary's honest wording ("weak: nx, canary, relro=partial").
- Qualitative: "weak, not silently ok" reads at a glance and in the app's chip idiom (Aesthetics/honesty) —
  a hardened-but-actually-weak binary cannot read as fine. Shared with the NodeInspector RECON-FACTS row
  (same component, same colors). If a mitigations map carries ONLY unrecognized keys (no nx/canary/pie/
  fortify/relro), neither the badges NOR the **mitigations** label render — no dangling label beside an empty
  value (`hasKnownMitigations` guards both the Inspector and NodeInspector rows).
- Principle: weak mitigations are conspicuous, never hidden in a blob.
- Prereq: a finding (or target node) carrying mitigations.

---

## SURFACE 4d — Hypotheses worklist (right pane, "Hypotheses" tab)

The research-question worklist (design-working-memory.md §4): the elevated hypothesis surface. A
right-pane tab beside Findings/Tasks/Campaigns, mirroring the Findings list pattern. Two orthogonal
axes per hypothesis: the evidence **status** (open/supported/refuted/contested + the pinned
confirmed/rejected verdicts) and the **work-state** (investigating / parked / done — "am I on this?").

**HYP-01 — Hypotheses tab: render the worklist**
- Steps: open the **Hypotheses** tab in the right pane.
- Functional: a row per hypothesis — statement, evidence-status tag, work-state tag (with icon), and the
  supporting/refuting evidence counts; a check-off control on the left, a pin-to-graph toggle on the right.
  Done hypotheses read struck-through + dimmed. An empty project shows a clear "record an open question"
  hint, not a blank panel.
- 🔌 Backend: `GET /api/projects/{id}/hypotheses` (the worklist rows with counts).
- Qualitative: scannable and calm at tens–hundreds of rows; the eye separates "what I'm chasing" from
  "settled" at a glance; one thought per row (Aesthetics, Overall).
- Prereq: hypotheses exist (create via FIND-16 or graph_create_hypothesis).

**HYP-02 — Filter by work-state / evidence status + sort**
- Steps: use the work-state select, the evidence-status select, the sort select (recent / work-state /
  evidence), and the text filter.
- Functional: the list filters live and composes across all four; the work-state select shows per-state
  counts; sort reorders without refetching.
- Qualitative: filters compose predictably; counts give feedback (Feedback, Consistency).
- Prereq: hypotheses spanning work-states / statuses.

**HYP-03 — Check off (done + verdict) / reopen**
- Steps: click the left checkbox on an open row to mark it **done**; click it again on a done row to reopen
  (→ investigating). (The detail pane offers explicit Mark-done / Park / Resume + Confirm/Reject verdict.)
- Functional: the row's work-state flips; a done row dims + strikes through; the change persists.
- 🔌 Backend: `POST /api/hypotheses/{id}/work-state` (`work_state`, optional `verdict`). Verify the
  hypothesis node's `attrs.work_state`.
- Qualitative: closing a question feels like ticking a box — light, reversible, never a modal (Forgiveness).
- Principle: a checked-off hypothesis is "I stopped looking", separate from the evidence verdict.
- Prereq: an open (investigating/parked) hypothesis.

**HYP-04 — Pin / unpin to the graph canvas**
- Steps: click the hex pin toggle on a row (or in the hypothesis detail).
- Functional: pinning sets `attrs.pinned_to_graph` true and the hypothesis now DRAWS on the canvas (nested
  in its target's room); unpinning removes it from the canvas. The toggle reflects the current state.
- 🔌 Backend: `POST /api/hypotheses/{id}/pin` (`pinned`). After the graph reloads, a pinned hypothesis node
  is visible on the canvas, an unpinned one is not.
- Qualitative: the canvas stays calm by default; pinning is the deliberate "anchor this beside its evidence"
  gesture, not the norm (Aesthetics — net declutter).
- Principle: existence (a node, always) is decoupled from canvas visibility (opt-in).
- Prereq: at least one hypothesis.

**HYP-05 — Select a hypothesis → detail (singular HypothesisPanel)**
- Steps: click a worklist row.
- Functional: the Detail split shows the existing hypothesis detail — status + origin chips, the work-state
  tag, the pin toggle, the rationale, Confirm/Reject/Reopen + Mark-done/Park/Resume actions, and the
  supporting/refuting evidence lists (each finding clickable → its Inspector). This holds **even when the
  hypothesis node isn't currently loaded in the graph** — hypotheses are off-canvas by default (HYP-04) and on
  a large project the graph loads skeleton-first, so the node may not be rendered; the click then **fetches it
  by id** (the same fallback as a journal @-mention, JRN-03) so the inspector opens regardless of graph LOD.
- 🔌 Backend: `GET /api/hypotheses/{id}` for the worklist detail; when the hypothesis node isn't in the loaded
  graph the click also calls `GET /api/projects/{id}/nodes/{node_id}` (which routes a `node_type='hypothesis'`
  node to the HypothesisPanel; 404 if missing).
- Qualitative: the worklist row and the detail agree on both axes; reusing the existing detail view keeps
  the vocabulary consistent (Consistency). A click reliably opens the hypothesis regardless of graph LOD.
- Prereq: a hypothesis with linked evidence; ideally one that isn't pinned to the canvas (large project /
  skeleton mode) to exercise the fetch-by-id fallback.

---

## SURFACE 4e — Journal (right pane, "Journal" tab)

The research notebook (design-working-memory.md §5): the interpreted-narrative half of the working-memory
layer, paired with the Hypotheses worklist under one "notebook" mental model. A right-pane tab beside
Findings/Hypotheses/Tasks/Campaigns. A timeline of freeform markdown entries (newest first), each attributed
to a **human** or an **agent**, plus a lean composer that appears only when writing. Entries can `@`-mention
any graph object as a clickable chip. All entry markdown is rendered **sanitized** (no raw HTML) — agent
entries may quote attacker-derived strings from a hostile target, so this is a security boundary, not just
hygiene.

**JRN-01 — Journal tab: render the timeline**
- Steps: open the **Journal** tab in the right pane.
- Functional: a card per entry, newest first — an author badge (human/agent, distinct colour + icon), a
  relative timestamp, an "edited" marker when the entry was edited, and the entry body rendered as sanitized
  markdown (headings, lists, code, blockquotes, tables, task-lists). A staleness line ("last agent note N ago")
  sits above the list. An empty project shows a "capture an idea / dead end / what you learned" hint, not a
  blank panel.
- 🔌 Backend: `GET /api/projects/{id}/journal` (entries newest-first, each with resolved mentions).
- Qualitative: reads like a notebook — calm, skimmable, one entry per card; human vs agent is legible at a
  glance; markdown is tastefully styled, never a wall of raw source (Aesthetics, Overall).
- Prereq: ≥1 journal entry (human-written via JRN-04, or agent-written via a completed LLM task / `journal_add`).

**JRN-02 — Filter by author / full-text search**
- Steps: type in the search box; use the author select (all / human / agent).
- Functional: search hits `GET …/journal/search?q=` (substring over bodies, newest first); the author select
  filters the list; the two compose. Counts show per author in the select. A no-match search shows a clear
  "no entries match", not an empty void.
- 🔌 Backend: `GET /api/projects/{id}/journal/search?q=` (search) / `GET …/journal?author=` (filter).
- Qualitative: search is the cross-session "what did I try on X" memory verb — fast, debounced, obvious
  (Feedback, Efficiency).
- Prereq: entries spanning both authors / varied bodies.

**JRN-03 — `@`-mention chips: navigate / dangling**
- Steps: in a rendered entry, click an `@`-mention chip.
- Functional: a live chip (a kind glyph + the object's current label, in accent colour) selects the referenced
  object via the SAME plumbing as elsewhere — a finding opens its Inspector; a node/target/hypothesis opens in
  the **Detail/Inspector pane** (and focuses in the graph when loaded). This holds **even when the object isn't
  currently loaded in the graph** — on a large project the graph loads skeleton-first / a node subset, so the
  mentioned node may not be rendered; the click then **fetches it by id** so the inspector still opens (a
  hypothesis node routes to the HypothesisPanel; an unloaded target falls back to the loaded targets list).
  A **dangling** mention (the object was archived, merged away, or deleted) renders greyed + struck-through and
  does **not** navigate (never an error).
- 🔌 Backend: mentions are resolved server-side through the merge keeper; each carries `resolved_id` + a
  `dangling` flag. Clicking selects `resolved_id`. When the node isn't in the loaded graph, the client calls
  `GET /api/projects/{id}/nodes/{node_id}` (the single-node graph-node shape, incl. an `archived` flag; 404 if
  missing) and opens the inspector from that.
- Qualitative: chips read as first-class links, not raw `@[…](…)` syntax; the dangling state is unmistakable
  yet unalarming (Consistency, Forgiveness). Link stability survives a merge/archive, and a click reliably
  opens the object regardless of graph level-of-detail.
- Prereq: an entry mentioning ≥1 live object and (ideally) ≥1 dangling reference; ideally also a mention of a
  node that isn't in the loaded subset (large project / skeleton mode) to exercise the fetch-by-id fallback.

**JRN-04 — Compose a new entry (markdown + live preview)**
- Steps: click **Write**; type markdown in the textarea; toggle **Preview**; **Add entry** (or ⌘/Ctrl+Enter).
- Functional: the composer appears only while writing (not an always-on editor). Write shows the markdown
  source; Preview renders it sanitized (with mention chips). Posting creates a **human** entry — this REST
  surface is the researcher's own workbench. The new entry appears at the top of the timeline; Cancel discards.
- 🔌 Backend: `POST /api/projects/{id}/journal` (`body`, `author:"human"`). Verify a new `journal_entry` row.
- Qualitative: lean and unintimidating — a source box + preview, no WYSIWYG chrome; the editor doesn't eat
  panel space when idle (Aesthetics — anti-bloat).
- Prereq: a project.

**JRN-05 — `@`-typeahead at the caret**
- Steps: while composing, type `@` followed by a query.
- Functional: an inline popover opens **at the caret** and searches targets / graph nodes / findings /
  hypotheses live (reusing the header search resolver, extended to hypotheses); arrow keys move the highlight,
  Enter/Tab/click inserts `@[label](kind:id)` and restores the caret after the token; Escape or a space
  dismisses.
- 🔌 Backend: `GET /api/projects/{id}/search` + `GET …/hypotheses` (the candidate set).
- Qualitative: the popover sits on the `@`, not floating elsewhere; picking a result feels instant; this is
  the most novel surface and should feel delightful (Efficiency, Aesthetics).
- Prereq: a project with objects to mention.

**JRN-06 — Edit / delete an entry**
- Steps: hover an entry → click the pencil (edit) or × (delete) action.
- Functional: edit reopens the composer inline seeded with the body; saving marks the entry **edited** and
  re-parses its mentions. Delete confirms, then removes the entry. From this human workbench, ANY entry
  (human or agent) is editable/deletable (the agent-only-own rule is enforced on the MCP path, not here).
- 🔌 Backend: `PATCH /api/journal/{eid}` (edit, sets `edited`) / `DELETE /api/journal/{eid}` (delete).
- Qualitative: actions reveal on hover (calm by default); editing is in-place, never a modal; the "edited"
  marker is honest without being noisy (Forgiveness, Consistency).
- Prereq: ≥1 entry.

**JRN-07 — Back-references ("the narrative trail") in a detail pane**
- Steps: select a finding (Inspector) or a node / target / hypothesis (NodeInspector) that journal entries
  mention; scroll to the **In the journal** section.
- Functional: a compact list of the entries that `@`-mention this object, each rendered as sanitized markdown
  with its author badge + time; mention chips inside still navigate. The section is **absent** (not an empty
  header) when nothing mentions the object.
- 🔌 Backend: `GET /api/projects/{id}/journal?mentions_kind=…&mentions_id=…` (resolved through the merge
  keeper, so a mention of a now-merged duplicate still matches the keeper).
- Qualitative: closes the loop — read a hypothesis/finding, see the story that worked it without hunting the
  journal (Overall, Discoverable); it sits naturally below the existing detail, not bolted on.
- Prereq: an object mentioned by ≥1 entry.

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

**OBS-06 — A node's full result-set at the node**
- Steps: select a graph node that tool calls have referenced (e.g. a decompiled function) → in its
  NodeInspector read the **Tool Results** section below the attributes/provenance.
- Functional: a count + a filterable list of EVERY tool result referencing this node (its `node_refs`) —
  decompilation, disassembly, xrefs, recover_constant, … — not just the producing/enriching ones in the
  provenance block above. Same rows + tool/kind filters + raw-payload modal as the per-target panel
  (OBS-01..03), but scoped to the node. Empty state explains how results get attached.
- 🔌 Backend: `GET /api/projects/{id}/nodes/{nodeId}/observations` — every Observation whose `node_refs`
  includes the node (a superset of `attrs.provenance`), row metadata only; the single-get carries the
  payload. Verify the rows match the node's `node_refs`.
- Qualitative: the node becomes the place to see everything known about it without hunting the target's
  full Tool Results (Discoverable); the section reuses the per-target panel's idiom (Consistency); a node
  with no results shows a calm explanation, not a void (Feedback).
- Principle: the graph node is the hub — its full analysis history is one selection away, while the bodies
  still live in the Observation store (the graph stays curated).
- Prereq: a node with ≥1 referencing tool result.

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

**FUZZ-01b — Instrumentation knobs (source-fuzz surfaces only)**
- Steps: in the Fuzz modal on a `source_lib`/`file_format` target, find the **Instrumentation** group →
  toggle **Bug-detection oracles**, set **path coverage** (off/1/2/3), toggle **CmpLog**.
- Functional: the group appears ONLY for source-fuzz surfaces (not binary-only/network); each control
  defaults from `features.fuzzing.{bug_oracles,path_coverage,cmplog}` and overrides it for this campaign.
- 🔌 Backend: the values ride `POST …/campaigns` (`bug_oracles`/`path_coverage`/`cmplog`) → recorded on the
  campaign's `config_json`; a source campaign with `bug_oracles` on reports `stats_json.instrument_extras.
  bug_oracles=true` once it runs (the knob really reached the sandbox).
- Qualitative: the group sits with the other per-campaign overrides (Stop conditions / Resources), same card
  styling; helper text names what each does (oracles catch arithmetic/OOB bugs ASan misses) without wall-of-text.
- Principle: per-campaign instrumentation is a first-class, discoverable control — not an env var only an agent can set.
- Prereq: a `source_lib`/`file_format` target; `features.fuzzing` on.

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

## SURFACE 7b — Function source viewer (decompiled / disassembled bodies)

The IDE-style reader for one function's body — the right surface for long decompiled /
disassembled code (the details pane is wrong for it). Built on the same `<CodePane>` as the
Source view, so the two read identically (syntax highlighting, a dimmed line-number gutter).
A center-pane overlay: opening it covers whatever view is active; closing returns to it.
Bodies are fetched on demand (`POST /api/targets/{id}/decompile`, `…/disassemble`) and never
stored.

**FSV-01 — Open the source viewer (from NodeInspector / graph / deep-link)**
- Steps: select a **function** node → in its NodeInspector click **Open in source viewer**; OR right-click a
  function node → **Open in source viewer** (GRAPH-02); OR open a URL with `?fn=<name>&fnt=<targetId>`.
- Functional: the center pane shows the viewer for that function — a header (back · name · address · target ·
  backend) + Decompiled/Disassembly/Split tabs + the highlighted body. The URL gains `?fn=&fnt=` (and
  `&fntab=&fnline=`). A **✕** closes it and clears those params, returning to the underlying view. The
  NodeInspector **Decompile** quick-peek still exists (an inline snippet) — the viewer is the full reader.
- 🔌 Backend: `POST /api/targets/{id}/decompile` (configured backend) for the Decompiled tab; the body matches
  what the decompiler emits. The viewer passes the function node's **address** alongside its name, and the
  endpoint **resolves by address when present** — so a function whose name isn't a discoverable symbol (a
  STRIPPED binary, a renamed function, or one the fast analysis didn't flag) still decompiles, where a
  name-only lookup returned "not found". Empty/absent Docker degrades to a clear "decompiling…/unavailable"
  note, never a blank.
- Qualitative: the viewer feels like an editor pane, not a cramped sidebar (Aesthetics); opening is one click
  from the node (Friction, Discoverable); the header orients you (which function, where, by what backend); a
  node with a recorded address resolves even on a stripped binary (Forgiveness — no cryptic "not found").
- Principle: long bodies get a real reading surface, deep-linkable like every other view; the node's address
  is the reliable resolution key.
- Prereq: a function node (ideally with a recorded address) on a target Docker can decompile.

**FSV-02 — Decompiled ⇄ Disassembly ⇄ Split tabs**
- Steps: toggle the three header tabs.
- Functional: **Decompiled** shows C pseudocode (highlighted as C); **Disassembly** shows the radare2
  instruction listing (highlighted by the target's arch grammar — x86/arm/mips — else escaped-plain, still
  line-numbered); **Split** shows both side-by-side. Each body loads lazily on first view and is cached.
- 🔌 Backend: Disassembly always calls `POST /api/targets/{id}/disassemble` (radare2 even when the configured
  decompiler is Ghidra, which emits no disasm); the `backend` tag reads `radare2` on that tab. Like Decompiled,
  it passes the node's **address** and resolves by it when present (so a stripped/renamed function still
  disassembles instead of "no disassembly").
- Qualitative: switching tabs is instant after first load (Friction); the disasm is real instructions, not an
  empty pane on a Ghidra setup (the reason the dedicated endpoint exists); split is genuinely two readable
  columns, not a squeeze (Aesthetics).
- Principle: decompiled and disassembled are two faithful lenses on the same function.
- Prereq: a decompilable function.

**FSV-03 — Click a callee to navigate**
- Steps: in the Decompiled (or Disassembly) body, click a **callee** token rendered as a link.
- Functional: the viewer loads that function's body in place (same target); a **back** affordance appears in
  the header to return. Linkable tokens are the function's callees ∪ the project's known function names (the
  function's own name never links to itself).
- 🔌 Backend: the clicked name drives a fresh `…/decompile` (or `…/disassemble`) on the same target.
- Qualitative: linked callees are visually distinct (dotted underline) and obviously clickable on hover
  (Affordance); navigation keeps you in the reader rather than bouncing to the graph (Direct manipulation);
  back is forgiving (Forgiveness). Non-call tokens and HTML entities must NOT become links (Correctness).
- Principle: reading code means following calls; the viewer makes the call graph walkable in place.
- Prereq: a function with callees that are themselves known functions.

**FSV-04 — Copy / raw provenance**
- Steps: click the header **copy** icon; if a **Raw** chip is present, click it.
- Functional: copy puts the visible body (both bodies in Split) on the clipboard with a check-flash; **Raw**
  (shown only when the opened function node carries `attrs.provenance`) opens the raw tool-result Observation
  modal (OBS-03) for the first backing observation.
- Qualitative: copy is one click with clear feedback (Feedback); Raw is present exactly when there's a real
  observation to show, absent otherwise — never a dead link (Honesty).
- Principle: the body is always copyable; provenance is one hop away when it exists.
- Prereq: a viewer open on a function (with provenance, for Raw).

**FSV-05 — Deep-link restore on reload**
- Steps: copy a viewer URL (`?fn=&fnt=&fntab=&fnline=`) → reload / open fresh.
- Functional: the viewer reopens on that function, on that tab, at that line.
- Principle: the viewer is addressable and reload-restorable, like Map/Graph/Source.
- Prereq: a viewer opened on a function.

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
- Steps: type in the toolbar search (functions / strings / findings / targets). Either CLICK a result, or
  press **Enter** to take the top result.
- Functional: a results popover grouped by kind; picking a target/node focuses it in the graph; picking a
  finding opens its Inspector; a coverage note shows. **Pressing Enter** lands the TOP result via the SAME
  reveal path (focus a target/node, or open a finding's Inspector), **closes the popover, and clears the
  query** — it must not leave the popover open and the focus un-landed (the issue-5.3 failure). Esc clears
  the search.
- 🔌 Backend: `GET` search (debounced); verify results match. (Enter awaits the in-flight fetch if pressed
  before results land, so the first Enter never no-ops.)
- Qualitative: search RANKS nodes/targets first and DRIVES focus (not just a passive ring) — the
  search-drives-the-graph promise; nodes inside a collapsed room auto-expand to land the focus.
- Principle: "find X and show me its world" is one action — by click OR by Enter.
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
- Steps: toggle each feature switch: Ghidra, angr (the deeper-static gate — see SET-03c; FLOSS + YARA
  are now always-on and carry no toggle), Fuzzing, Source & Build (+ build_fetch, source.edit), PoC
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

**SET-03c — Deeper-static analyses (always-on FLOSS / YARA info + the angr gate)**
- Steps: read the "Always-on static tools" card (FLOSS + YARA — no toggle); read its YARA "Your rules" path;
  toggle angr symbolic execution; with angr on, edit its image tag.
- Functional: the always-on card has NO switch — it states FLOSS + YARA are always available and shows the
  resolved YARA user-rules directory. Only the angr toggle persists (`features.angr.enabled`); the angr image
  field shows/persists only when angr is on (`features.angr.image`).
- 🔌 Backend: the angr toggle/image is a `PATCH /api/settings`; verify in `GET`. There is NO `features.floss`/
  `features.yara` key (they were removed when the tools went always-on). The `paths.yara_rules_dir` field of
  `read_settings()` is the resolved drop-in dir (`config.yara_rules_dir()`) and is still surfaced.
- Qualitative: none of these relaxes a sandbox/exec/egress boundary (no native target execution, no network).
  FLOSS + YARA are presented as always-on static tools, like recon/binutils, with no false ⚠ execution warning
  and no toggle to second-guess — the card is operator info plus where to drop custom `.yar` rules (a manual act,
  the no-network invariant). angr keeps its toggle because symbolic execution is genuinely CPU/memory heavy (the
  one analysis that can exhaust them) and ships in its own dedicated image; its card carries that honest
  heavy-compute note, not a boundary-relaxation warning.
- Principle: a tool that relaxes no boundary and is cheap-enough rides the static surface ungated (FLOSS/YARA);
  only genuinely heavy compute (angr) keeps an opt-in gate. Neither is a policy gate, so no `restart to apply`
  chip applies.
- Prereq: none.

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
