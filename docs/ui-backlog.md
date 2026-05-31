# UI improvement backlog

## From the VR UX evaluation (`docs/ux-eval-vr.md`, 2026-05-30)

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
