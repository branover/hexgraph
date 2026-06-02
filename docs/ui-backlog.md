# UI improvement backlog

## Campaigns / Artifacts triage + Source coverage — Phase 4 (fuzzing+source design §6/§7, 2026-06-02)

**Shipped in `build/fuzz-phase4`:** the full Source/IDE + fuzz-triage UX (the payoff of Phases 1–3).
- **Campaigns tab** (`CampaignsPanel.tsx`) — a live row per campaign (status pill, execs/s, edges,
  crash count, coverage %, black-box flag), Stop/Resume, a "New campaign" button. Live status streams
  over **SSE** (`/api/campaigns/{id}/events`) with **automatic polling fallback** if the EventSource
  errors. Playwright-verified the list + live stats render and the row selects the triage view.
- **Artifacts / triage view** (`ArtifactsView.tsx`) — crashes grouped by **dedup bucket**
  (representative + `+N dupes`), an **assurance chip** (`AssuranceChip.tsx`, the two-standards ladder,
  green=reachable+dynamic / amber=lab-confirmed / muted=static), the exploitability rating, and a
  **source-mapped stack** (top frame clickable → Source tab at the line). Per-crash **Reproduce /
  Minimize / Promote / Promote→PoC** all wired to the API (LLM-free re-verify). Playwright-verified
  the chips, the stack, and that Promote flips the finding to `confirmed` live.
- **Coverage shading** in the Source viewer — a campaign picker tints covered lines green / uncovered
  amber (from `/api/campaigns/{id}/coverage`). Playwright-verified covered/uncovered lines render with
  the legend, and a frame click lands on the right line with shading visible.
- **Surface-aware Fuzz modal** (`FuzzModal.tsx`) — engines are **server-advertised**
  (`/api/fuzz/engines?target_id=`), with the per-campaign **ResourceSpec** (mem/cpus/pids +
  unconstrained, defaulted from Settings). Playwright-verified the engine options are `afl (default)`
  / `libfuzzer` for a source_lib target and the ResourceSpec controls render.
- **`reveal()` + deep-links** — one navigation primitive; `?view=source&file=…&line=…` and
  `?tab=campaigns&campaign=…` restore the view (verified via the frame-jump URL).
- **Settings** — a Source & Build card + the default ResourceSpec controls in the Fuzzing card.

**Deferred to later phases (per the design):**
- [ ] **P5** — real per-line coverage from afl-cov/llvm-cov (the probe must emit `coverage.json`; the
  serializer + UI already render whatever map a campaign exposes — the mock emits one for the demo).
- [ ] **P5** — a coverage **heat overview** (per-function % across the tree, not just the open file).
- [ ] **P7** — Monaco/CodeMirror syntax highlighting in the viewer (still a line-numbered `<pre>`).
- [ ] **P7** — true afl-tmin re-minimization behind the **Minimize** button (today it shares the
  verify replay; the probe already minimizes inline at ingest).
- [ ] Surface a **fuzz_campaign node in the graph** so "reveal in graph" works for a campaign (today
  campaigns are table rows reached via the Campaigns tab; reveal() handles finding/node/target).
- [ ] A coverage **sparkline** on the campaign row (the live number is shown; a trend line is nicer).

## Build modal — Phase 2 (fuzzing+source design §6.3, 2026-06-01)

**Shipped in `build/fuzz-phase2`:** the capability-gated **Build modal** (`BuildModal.tsx`),
reached from a **Build (instrumented)** button in Source mode's tree pane (shown only when
`features.build` is on, read from `GET /api/capabilities`'s new `features.build` flag). It is
build-as-API: instrumentation toggles (ASan/UBSan/MSan · SanCov · engine) + an artifacts field
regenerate a **read-only recorded-recipe preview** via `POST /api/projects/{id}/build/preview`
(phases + the injected base-image-contract env `CC/CXX/CFLAGS/SANITIZER/FUZZING_ENGINE` + the
`recipe_sha`) — there is **no free-text command box**, and a "vendored/offline only
(`--network none`)" note is shown. Launching posts to `POST /api/projects/{id}/builds`; a
**Builds** status list in the tree pane shows each build's status/artifacts and an
"instrumented" tag when it registered a derived target. (Playwright-verified the modal renders
the recipe preview + injected env + recipe_sha.)

**Deferred to later phases (per the design):**
- [ ] **P3** — live build status streaming (currently the list refreshes on completion);
  pairs with the Phase-4 SSE campaign status.
- [ ] **P4** — surface the instrumented **derived target** prominently (a "fuzz this" CTA) once
  coverage-guided fuzzing lands (Phase 3).
- [ ] **P3** — a build-log viewer in the UI (the `GET /api/builds/{id}/log` endpoint exists; the
  list only tooltips the error today).
- [ ] **P7** — the dependency-posture control ("vendored" default vs the audited "fetch" tier)
  becomes meaningful when `features.build_fetch` ships; today it's vendored-only (shown as a note).

## Source/IDE tab — Phase 1 (fuzzing+source design §6, 2026-06-01)

**Shipped in `build/fuzz-phase1`:** the center-pane **Graph ⇆ Source** segmented control
(`?view=source` persisted, mode not route); a read-only **Source mode** (`SourceBrowser.tsx`)
with a multi-tree dropdown switcher + a `<FileTree>` explorer (mirrors `FilesystemBrowser`) +
a line-numbered code viewer; the **finding→source jump** (Inspector "Open in source (line N)"
reads `evidence.extra.source_ref`, switches to Source mode, opens the file, highlights the line).
Source trees with `origin=extracted` are labelled untrusted; editability is shown read-only.
Harness/source_file nodes render in the graph wired by `harnesses`/`located_in`/`built_from`.

**Deferred to later phases (per the design):**
- [ ] **P2** — a "Sources" section under each target in the left tree (currently the dropdown
  switcher in Source mode is the only tree picker). The design §6.1 wants both.
- [ ] **P3** — finding-count dots / coverage shading / a PoC ▶ on the file tree (Phase 4 triage UX).
- [ ] **P3** — Monaco/CodeMirror syntax highlighting (the viewer is a plain line-numbered `<pre>`).
- [ ] **P7** — editable IDE (`features.source.edit`, revisioned saves, rebuild-from-revision).
- [ ] An "Open source" button beside Decompile on a source-mapped `function` node (§6.3) — the
  node→source flip; deferred until functions carry `attrs.source` (Phase 2+ build mapping).

## From the dynamic-surfaces UX review (2026-05-31)

**Done in the `ux-refresh` PR:** network-egress Settings card (A1); type-aware NodeInspector tip for
socket/endpoint/input/sink (A4); node icons for the new types (A5); search ranks nodes first + section
headers (A6); always-label semantic edges (A7); legend driven from the shared color maps, present-only,
nodes+edges, red reserved for severity (B1/B2); distinct node shapes per type (B2); modernised selects
(B3); pill toggle switches (B4); endpoint/param hand-authoring (A3).

**Deferred (next UI pass):**
- [ ] **A2** — surface the EgressEvent audit log in the UI (needs a `GET /api/projects/{id}/egress`
  endpoint + `api.egress` + a small list, e.g. in the web_app NodeInspector or a Tasks-tab sibling).
- [ ] **B5** — schema-driven edge-attribute form in the Add-edge modal (use `edgeSchemas()` to render
  known fields per type instead of a raw JSON input).
- [ ] **A4+** — richer typed-node inspector sections (socket → its listens_on/connects_to peers;
  endpoint → its params + routes_to handler) — needs the node's edges passed in or fetched.
- [ ] **B6** — accessibility: keyboard-operable menu/search items (role/tabindex on the `.mi`/`.res`
  divs), larger icon-button hit targets, focus rings tuned for dark theme, nudge `--muted` contrast.
- [ ] **B7** — collapse low-frequency workspace toolbar actions into an overflow menu; give the right
  "Detail" box more height.

## From the VR UX evaluation (2026-05-30)

**Done (this session):**
- [x] Stale finding status in the detail panel after Accept/Dismiss — `load()` now refreshes the
  selected finding. *(the eval's one outright bug; top priority)*
- [x] Surface the failure reason inline on failed tasks + make trace files openable (error.txt /
  prompt.txt / fuzz.json / agent_trace.json viewer).
- [x] Merge the duplicate "Follow-ups" vs "Suggested next steps" blocks into one deduped "Next steps".
- [x] Vocabulary: button "Accept" → "Confirm" (matches the `confirmed` status); bulk action too.
- [x] Label the confidence chip ("conf X") so it isn't mistaken for severity.
- [x] Persistent (faint) Run affordance on target rows — targets read as runnable.
- [x] Tooltips on Compare / Same-code / Node / Edge; "Mock scenario" already gated to the mock backend.
- [x] Graph export button in the UI (downloads graph JSON).
- [x] Docs: unify `sbin/httpd` vs `vuln_httpd` naming; reword "one-click follow-up" → pre-filled launch;
  README reflects opt-in fuzzing/Ghidra/agent features; note `ingest`/`serve` auto-init the DB.

**Remaining ideas (not yet done):**
- [ ] **P1 — In-app decompilation viewer.** Findings show a DECOMPILED snippet and tasks expose trace
  files now, but a researcher can't open the *full* decompiled function on demand (e.g. a "decompile"
  action on a function node that shows pseudocode inline). Highest-value "show me, don't tell me".
- [ ] **P1 — Auto-derive `links_against`** from the dynamic section (DT_NEEDED) so firmware
  dependency edges (which binary loads which library) appear without manual authoring. Recon reports
  0 today; investigate whether recon populates `metadata.libraries` for the fixtures.
- [ ] **P1 — Graph scaling for real firmware.** ~84 nodes already crowds labels. Have double-tap
  collapse + the filter popover; still want cluster-by-target / focus-subtree / hide-resolved at
  hundreds of functions.
- [ ] **P2 — Firmware/version diffing** (v1.0 vs v1.1) — the biggest real-world VR workflow not served;
  `Compare` is target-vs-target, not version-vs-version.
- [ ] **P2 — CWE tagging** on findings (e.g. CWE-121). The Finding schema is frozen, so carry it in
  `evidence.extra` or as an annotation tag, and use it in dedup + report.
- [ ] **P2 — Upload/ingest progress state** ("ingesting… unpacking…") during the sandbox unpack.
- [ ] **P3 — Bulk triage discoverability** (checkboxes + bulk Confirm/Dismiss exist; make the
  multi-select action bar more obvious).

---

Captured from a visual review of the running workspace (firmware project with recon + mock
`static_analysis`/`pattern_sweep`/`reverse_engineering` findings), driven via headless Chromium.

**Current state is solid for an MVP:** three-pane dark workspace (target tree · Cytoscape graph ·
findings + detail), severity chips, a node/finding graph with `contains`/`links_against`/`related_to`/
`about` edges, a per-target task launcher, and a finding detail panel that shows summary, reasoning,
evidence (function/sink/decompiled snippet) and follow-up buttons. The items below are refinements,
not blockers. Priorities: **P1** = high impact / do first when polishing; **P2** = meaningful;
**P3** = nice-to-have.

> Tackle alongside M5 (polish); a few overlap with M4 (spawn/activity) and M3-T6 (cost display).

## Graph (center pane) — highest-impact area
- [ ] **P1 — Finding-node labels overlap and are unreadable.** Long titles crowd the top row. Fix by
  truncating node labels (e.g. ~24 chars + ellipsis), showing the full title on hover (tooltip), and
  positioning findings as small satellites of their target rather than a flat top row.
- [ ] **P1 — `about` edges clutter the graph.** Six identical "about" labels add noise. Drop the edge
  label for finding→target links (keep it only for `contains`/`links_against`/`related_to`), and style
  finding edges thinner/dashed.
- [ ] **P1 — Graph nodes aren't interactive.** Clicking a graph node should select the corresponding
  finding/target (open its detail, scroll the list, highlight it). Today clicks do nothing.
- [ ] **P2 — Misleading legend.** Legend shows "finding" as one red dot, but findings are colored by
  severity. Replace with a severity scale (info→critical) + shape key (circle=target, diamond=finding).
- [ ] **P2 — Fit/zoom/controls.** Auto fit-to-viewport on load, visible zoom/reset controls, and a
  better layout (e.g. `cose`/`dagre`) so nodes don't overlap on denser graphs.
- [ ] **P3 — Node text is small (9px) and low-contrast.** Bump size/contrast; consider labels only on
  hover/selection for findings.

## Findings list + detail (right pane)
- [ ] **P1 — Detail panel is cramped.** It shares a narrow pane with the findings list (max-height
  45%). Decompiled snippets need width. Move detail to a modal/overlay or an expandable full-height
  view; consider a dedicated finding route.
- [ ] **P1 — No sort/filter/grouping.** Sort by severity (critical first), filter by status
  (new/accepted/dismissed) and by target; show a count + a per-severity summary. A flat list won't
  scale past a handful of findings.
- [ ] **P2 — Findings don't show their target.** Each card should name the target it's on and link to
  it; selecting a finding should highlight its target/graph node.
- [ ] **P2 — Triage actions (accept/dismiss) absent** (M5). Surface them on the card and in detail.
- [ ] **P3 — Severity color convention.** Verify the scale reads intuitively (critical = strongest,
  then high/medium/low/info); current high/critical hues are close.

## Left pane (targets + task launcher)
- [ ] **P1 — Target detail view is missing.** Clicking a target should show its recon facts
  (format/arch, mitigations, imports, hashes) and its task history — the spec's "Target detail" view.
  Recon metadata is currently invisible in the UI.
- [ ] **P2 — Task launcher is noisy/utilitarian.** Two raw `<select>`s + Run repeated per target.
  Collapse into a single "Run task ▾" action (small dialog/menu); **hide the mock-scenario select
  unless the backend is `mock`**.
- [ ] **P2 — Tree isn't really a tree.** Children are only slightly indented; add expand/collapse and
  parent/child connectors for deep firmware trees.

## Activity, cost, and live feedback (cross-cutting)
- [ ] **P1 — No live task feedback.** Launching a task silently polls then hard-reloads the whole
  graph (jarring). Add a running indicator/spinner + an activity log; ideally SSE/websocket task
  status instead of polling. (Pairs with M4 spawn.)
- [ ] **P1 — No cost display** (M3-T6). Show per-task tokens/cost and a running per-project total
  (mock tagged `$0`, `cost_source: mock`) — the spec's right-pane "activity + cost".
- [ ] **P2 — Styled empty/loading/error states.** The tree currently dumps raw error text; add proper
  loading skeletons and friendly empty states.

## Header / navigation / global
- [ ] **P2 — Workspace header is sparse.** Show the project name, the active backend, and project cost;
  add a back link / project switcher (only the brand link exists now).
- [ ] **P3 — Projects page is minimal.** Add target/finding counts per project; consider an ingest
  affordance (currently CLI-only) and a create-project flow.
- [ ] **P3 — Responsiveness.** The fixed 3-column grid breaks on narrow windows; make panes
  collapsible/responsive.
- [ ] **P3 — Affordances/a11y.** The ⟳ refresh button is tiny/unlabeled; add tooltips, focus states,
  and keyboard navigation.
