# UI improvement backlog

## README + docs overhaul — single-folder screenshots (2026-06-02)

**Shipped in `docs/readme-overhaul`.** Docs/tooling only (no behavior change beyond the two
showcase scripts). Slimmed `README.md` to a lean overview (hero shots + install + a feature
matrix linking out + the core loop) and moved the reference detail into focused per-feature docs
under `docs/` (`setup.md`, `graph-ui.md`, `verification-assurance.md`, `fuzzing.md`,
`build-from-source.md`, `dynamic-surfaces-rehosting-remote.md`, `mcp.md`), each embedding its
screenshot from `docs/images/` by stable name.

- **`docs/ui-shots/` retired.** Its one still-useful shot (the **network** fuzz modal) was folded
  into `scripts/capture_screenshots.py` and now regenerates as `docs/images/fuzz-modal-network.png`;
  the rest (superseded by `source-coverage.png` / `graph-selected.png` / a generic toolbar strip)
  were deleted with the folder. **Single canonical screenshot folder is now `docs/images/`.**
- **Hero-3 (`artifacts-triage.png`) fix.** The triage shot composed sparsely (one campaign + one
  crash → a big empty void). The showcase seed now writes a populated, multi-bucket crash inbox
  (4 distinct dedup buckets, varied kind/function/exploitability + dupe counts, ASan reports that
  symbolize to source frames) onto the SAME single campaign before reaping — so the crash-triage
  detail pane reads dense + inviting, and the campaign stats (1.89M execs / 318 edges / 4 crashes)
  look real. Guard test (`test_showcase_seed.py`) updated to require ≥3 crash buckets + dupe counts.

## Screenshot showcase + capture mechanism (2026-06-02)

**Shipped in `build/showcase`.** A reproducible way to (re)generate the README hero shots and
per-feature doc images as the UI evolves — so they never bit-rot against the live SPA:

- `just showcase [--reset]` → `scripts/seed_showcase.py` seeds ONE rich, deterministic project on
  the mock backend (offline, $0, no Docker): a firmware tree + a standalone binary + a `web_app` +
  a `service` socket surface + a source tree; findings spanning every finding_type + all four
  assurance rungs (incl. a verified PoC); a wide curated edge variety; typed function/string/sink/
  socket/endpoint/param nodes; a finished mock fuzz campaign (crash artifacts + coverage map); and
  egress-audit events.
- `just capture` → `scripts/capture_screenshots.py` serves it on a spare port and drives headless
  Chromium (Playwright, dev-only) to shoot **13 PNGs into `docs/images/`** at 1440×900, dark theme,
  1.5× scale. Manifest + per-image captions/slots in `docs/images/README.md`.
- Guard test `tests/test_showcase_seed.py` (offline) keeps the seed rich (asserts the target kinds,
  edge-type variety, node types, the assurance-ladder rungs, the verified PoC, and the finished
  campaign + coverage) so a UI/data refactor that hollows out the showcase fails CI.

**When the UI changes materially**, re-run `just capture` and re-commit `docs/images/*.png`. The
capture script tolerates UI churn (it clicks by visible text / titles and degrades gracefully per
shot), but the *quality* judgement is manual — VIEW the PNGs and tweak the seed/capture for
composition before committing.


## Build-from-source modal — modernized to match the Fuzz modal (2026-06-02)

**Shipped in `build/ui-buildmodal`** (Playwright-verified, before/after PNGs judged). Pure
VISUAL/LAYOUT pass — zero backend/behavior change. Brings `BuildModal.tsx` up to the Fuzz
modal's standard (PR #62) so the two launch dialogs read as siblings.

- **Before:** a flat, all-caps dump — scattered `ADDRESS/UNDEFINED/MEMORY` + `SANCOV` checkboxes,
  `ENGINE/ARCH/DEPENDENCIES` selects on loose inline rows, a plain artifacts/custom-phases field,
  and a monochrome recipe-preview block; Cancel/Build footer with a small primary button.
- **After:** reuses the `.modal.fuzz` system (`h3` header + boxed `.lede` + grouped `.grp` cards +
  scrollable `.modal-b` + pinned `.modal-f` footer). New `.build`-scoped CSS in `theme.css`:
  - **Instrumentation** card — the sanitizers + SanCov are now a tidy **toggle-pill row** (`.toggles/.tgl`)
    showing a friendly name (ASan/UBSan/MSan/SanCov) + the raw flag as a sub-label; the pill lights
    up (accent border + tint) when on.
  - **Engine & arch** — aligned 2-col grid; **Dependencies** — the vendored/fetch posture select
    (disabled with an explanatory note when `features.build_fetch` is off); **Artifacts to capture**
    — output paths + the optional custom-phases textarea.
  - **Recorded recipe preview** — now a proper read-only **code panel** (`.recipe`, dark `#0c0f17`
    bg, mono) reusing the source-viewer code-styling language: tinted env keys/values (cyan key,
    green value), `$`-prefixed commands, the fetch phase in amber, and `recipe_sha` as a clean
    caption under a dashed rule.
  - Prominent **Build (sandboxed)** primary button (chip icon), Cancel ghost.
- **Verified (Playwright):** every input intact and the recipe-preview reactivity unchanged —
  toggling UBSan adds `,undefined` to CFLAGS, deps→fetch switches the meta line + surfaces the
  fetch phase, a custom phase flows in as `$ sh -c …`, the artifacts field accepts text, and
  `recipe_sha` recomputes on each change. No console errors (only the pre-existing Cytoscape
  wheel-sensitivity warning). Screenshots judged at 1440px; readable 1280–1600.

## UI "sexiness" pass — source viewer + toolbar + fuzz modal (2026-06-02)

**Shipped in `build/ui-sexiness`** (Playwright-verified, before/after screenshots judged;
final PNGs under `docs/ui-shots/`). A pure VISUAL/LAYOUT pass — zero backend/behavior change.

- **Source viewer** (`SourceBrowser.tsx`, `highlight.ts`, `theme.css .codeview`) — was a
  line-numbered `<pre>` where every line rendered as a separate bordered ROW with a thick
  colored gutter rule, huge line spacing, NO syntax coloring, and weird left/right alignment.
  Now a clean **continuous code block**: syntax highlighting via **highlight.js core** (only
  c/cpp/python/js/ts/bash/json/xml registered → ~30 KB raw added to the bundle, vs the full
  ~190-language auto-bundle), themed to the dark palette; a dimmed, right-aligned, tabular
  line-number gutter with a gap before the code; faithful indentation (`white-space: pre` +
  `tab-size`) with **horizontal scroll** for long lines (no more wrap-mangling). The
  highlighter is line-split (carries open `<span>`s across newlines so block comments/strings
  stay colored) and only colors the TEXT — **coverage shading** (covered=green tint + left
  rail / uncovered=amber) and the **finding→source jump** highlight ride as per-row classes
  UNDER it, so all three coexist. Verified: covered/uncovered shading still lights up; the
  Inspector "Open in source" jump still lands on + highlights the right line (1 `.cl.hot`);
  file picker / source-tree dropdown / read-only vs Edit affordance / Build modal launch all
  unchanged. No console errors.
- **Center-pane toolbar** (`Workspace.tsx`, `theme.css .toolbar .tgroup/.tsep`) — was an
  undifferentiated scattered row. Now grouped with vertical dividers: **view-toggle**
  (segmented Graph/Source) · **search** (grows to fill) · **create** (Node, Edge) ·
  **analyze** (Compare, Same-code, Merge-dupes) · **report/export** (Report, Export, Audit),
  with tidier icons (Same-code/Merge-dupes → `copy`, Export → `arrowin`). Wraps cleanly at
  1280/1440/1600 px, staying grouped.
- **Fuzz campaign modal** (`FuzzModal.tsx`, `theme.css .modal.fuzz`) — was plain + busy
  (all-caps labels, cramped surface/engine row, run-together resources block). Redesigned into
  a clean header + a lede panel + grouped cards (**Target & engine** · **Network target** ·
  **Inputs** · **Stop conditions** · **Resources**) with aligned grids, consistent labels, a
  scrollable body (`max-height: 90vh`) and pinned footer with a prominent primary button. ALL
  inputs kept functional: the target picker, the network host/port/protocol/proto_spec block
  (verified rendering on a `web_app` surface), seeds/dictionary, the numeric params, and the
  Resources unconstrained-toggle (collapses mem/cpu/pids when on). No console errors.
- **Highlighter choice + bundle:** highlight.js core (registering 8 grammars). Raw JS bundle
  935.6 KB → ~967 KB (gzip ~294 KB → ~304 KB); the dominant weight is still Cytoscape.
- **Deferred (still true):** no inline-diff/coverage-diff view in the editor; the source viewer
  is read-only-highlighted (the Edit textarea is still plain — editing UX unchanged on purpose).

## First-class raw-TCP / socket targets — `register_socket` (2026-06-02)

**Shipped in `build/register-socket`** (Playwright-verified). A bare non-HTTP service is now a
first-class **`service`** target (raw TCP/UDP Channel, no bytes/creds). UI touches were minimal —
the Fuzz modal already filtered only `firmware_image` and shows the inferred `network` surface
inputs, so a `service` target was selectable + fuzzable with no modal change:
- **Graph + target pane** — added `service` to the target-kind color map (`GraphView.tsx` `KIND`,
  teal-green `#34d399`; also added the previously-missing `remote`) and the kind→icon map
  (`Icon.tsx` `NODE_ICON`, `service: "plug"`), and `service` to the `bestFuzzTarget` preference
  (`Workspace.tsx`) so a registered socket target is auto-picked for the Fuzz button.
- **Verified:** registering two `service` targets (a tcp bindshell + a udp coap-daemon) renders
  both in the Targets pane (plug icon, `service` label) and in the graph as green `service` nodes
  each `listens_on`→ its shared pink `socket` node (`tcp:1337`, `udp:5683`) — the
  target-as-surface vs socket-node-as-annotation distinction is crisp and legible. The Fuzz modal
  shows the inferred `network` surface with host/port/protocol inputs pre-applicable to it.

## Battle-test remediation PR-3 — build→fuzz handoff + coverage/symbolization (2026-06-02)

**Shipped in `fix/battletest-buildfuzz`** (Playwright-verified, screenshots judged). These are
BACKEND fixes that make two existing-but-empty UI affordances finally render real data — no new
components were needed (`SourceBrowser.tsx` coverage shading + `ArtifactsView.tsx` source-mapped
stack already existed; they were starved of data):
- **Coverage shading now lights up** — `coverage_for` previously returned `available:false` for a
  libFuzzer campaign (no per-line map was ever produced), so the Source IDE's "Coverage shading"
  picker shaded nothing. The fuzz probe now collects a per-line llvm-cov map (`coverage.json`)
  on a coverage-guided run, and `coverage_for` serves it. **Verified:** opening `target.c` in the
  Source/IDE view with the campaign selected shades covered lines GREEN (left-border + tint) and
  uncovered lines AMBER, with the covered/uncovered legend — the prominent-but-empty affordance
  the libFuzzer agent flagged now works.
- **Source-mapped stack + frame→source jump now render** — ASan crash frames were unsymbolized
  (module+offset only; no `llvm-symbolizer` wired at runtime) so `frames:[]` and the triage
  stack was empty. The probe now forces ASan symbolization (`ASAN_SYMBOLIZER_PATH` →
  llvm-symbolizer, present in `hexgraph-fuzz`) + carries the symbolized `_report`, and the reaper
  parses `func file:line` frames. **Verified:** the artifact DETAIL shows a "Stack" section with
  `#0 line_1 target.c:1`; clicking the frame JUMPS to the Source view at that file/line. Binary-only
  (AFL qemu) "abort in ?" is now addr2line'd/gdb-symbolized to the real sink function too.
- **No new components / no UI rebuild gotcha:** `just ui` rebuilt the SPA; the data now populates
  the existing components. The fixes are entirely in the probes/engine serializer.

## Battle-test remediation PR-1 — fuzz UX + campaign status + egress audit (2026-06-02)

**Shipped in `fix/battletest-fuzzux`** (Playwright-verified, screenshots judged):
- **Campaign degraded/warning state** (`CampaignsPanel.tsx`, `ArtifactsView.tsx`) — a campaign
  that did 0 work (unreachable / 0 executions) or hit engine instability now finalizes as a
  distinct **`degraded`** status (amber pill) with a **warning banner** stating WHY (the
  `warning` / `engine_note` the serializer now exposes). Verified: a `clean` campaign stays green
  `completed`; `unreachable` shows "service … not reachable at start"; `unstable` shows "AFL
  persistent mode unstable …" — visually unmistakable from a real run (was the no-op confusion).
- **Surface-aware Fuzz modal** (`FuzzModal.tsx`) — adds a **target picker** (switch the surface to
  fuzz, not pinned to the wrong root), **network** inputs (host / port / protocol / proto_spec)
  shown only for a `network` surface, always-available **seeds** + **dictionary** textareas, and
  the focus-function field hidden for network. Verified both source_lib + network states render.
- **Custom build phases** (`BuildModal.tsx`) — a "custom build phases" textarea (one shell step
  per line) so a `custom` source tree's recipe can be authored in the UI (was "author via the API").
- **Egress audit-log view** (`EgressPanel.tsx`, **Audit** toolbar button) — a read-only table of
  every outbound action (allowed/denied · destination · tool · reason) + allowed/denied counts,
  backed by the new `GET /api/projects/{id}/egress`. Verified rendering with allowed + denied rows.
- **Smarter launch default** (`Workspace.tsx`) — the Campaigns-tab "New campaign" button defaults
  to the best fuzz target (instrumented → live web_app/remote → fuzz_target_sources → non-firmware
  root) instead of `roots[0]` (the raw ingested source).
- **Deferred:** seeds in the modal are host *paths* (no in-browser file upload); the proto_spec is a
  raw JSON textarea (no guided binary-protocol builder).

## Editable IDE + build supply-chain badges — Phase 7 (fuzzing+source design §6.2, 2026-06-02)

**Shipped in `build/fuzz-phase7`** (Playwright-verified, screenshots judged):
- **Editable Source tab** (`SourceBrowser.tsx`) — with `features.source.edit` on, a HexGraph-authored
  file (harness/PoC/script + scratch in an editable tree) shows an **Edit** button → a textarea →
  **Save revision** (never an in-place mutation); below the viewer, a **Revisions** list (newest first,
  per-revision **revert**, append-only). Imported/extracted/vendor files show **read-only** and have no
  Edit affordance (the backend also refuses the write). Verified: a harness file opens with Edit; build
  badges render.
- **Reproducibility / supply-chain badges** in the Builds list — **reproducible** (green; the full
  provenance recorded), **cached** (reused a prior identical artifact), **locked** (hash-pinned deps from
  the fetch tier), **instrumented** (a derived target). Verified on a MockBuilder build.
- **Build modal** (`BuildModal.tsx`) — added an **arch** selector (cross-compile) and a **dependency
  posture** selector (vendored / fetch — the audited/allowlisted option enabled only under
  `features.build_fetch`); the recorded-recipe preview shows the cross/sysroot + the fetch phase + the
  deps posture. The compile-is-always-`--network none` note was corrected.
- **Settings → Source & Build card** — ccache + cache-reuse toggles, a **Bounded dependency fetch** sub-
  toggle (with the supply-chain warning), and an **Editable IDE** sub-toggle. Verified rendering.
- **Deferred:** the code viewer is still a plain textarea/`<pre>` (no Monaco / syntax highlighting /
  inline diff view); a dedicated coverage-diff visualization (the data is available via
  `/api/campaigns/{id}/coverage-diff` + the `coverage_diff` MCP tool, but the UI exposes only
  single-campaign shading today).

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

## Phase 6 — remote fuzz environments (shipped)
- **DONE** — a **Remote fuzz environments** Settings card (toggle `features.fuzz_remote`; register /
  list / health-check / remove environments; presence-only connection + health badges; trust-model
  hint) and an **environment selector in the Fuzz modal** (shown only when the gate is on; defaults to
  `local`). Playwright-verified the Settings card renders with an env row, status badges, health-check/
  remove buttons, the slug id, and the register form.
- [ ] **P3 — env health auto-refresh.** Health is shown from the cached `last_health_json`; the
  Health-check button refreshes on demand. A periodic/auto refresh + a per-env "last checked" relative
  time would be nicer than the raw ISO timestamp tooltip.
- [ ] **P3 — Campaigns tab: show the environment a campaign ran on.** The campaign row doesn't yet
  surface its `environment_id`/descriptor (it's in `config_json`); add a small "ran on: <env>" chip.

## Graph presentation — Phase 1: visual legibility (2026-06-02)

**Shipped in `build/graph-phase1`** (`docs/design-graph-presentation.md` §8 Phase 1). Pure
style/`mapData` over today's flat dagre graph — **zero new deps, color-coding untouched (D8)**.
Changes: structural edges recede (opacity ~0.18, arrowheads dropped at rest) while semantic edges
sit a touch stronger (~0.32); importance-driven node sizing (anchors 40px + glyph + always-label,
hubs degree-ramp 30→40px, detail 22px, findings sized up for critical/high); extended `NODE_SHAPE`
so every conceptual type is shape-distinct (a redundant channel); node/edge labels fade in with zoom
via `text-opacity: mapData(zoom/degree)` + `min-zoomed-font-size` (kills the label-collision soup);
legend gains shape swatches + hover-preview / click-isolate-by-type (lightweight dim, hue preserved).

**Tier fixture (reusable A/B for every phase):** `scripts/seed_graph_tiers.py` (`just graph-tiers
[--reset|--tier T]`) seeds four deterministic mock/offline projects — SMALL (~13n/26e), MEDIUM (the
showcase, ~27/58), LARGE (~173/649), PATHOLOGICAL (~494/2144). Guard test
`tests/test_graph_tiers_seed.py` keeps them sized + deterministic.

**Before/after human-eyes verdict (Playwright, §9 criteria):**
- **SMALL** — Before: fine, uniform 26px dots. **After: better.** The executable anchor is clearly
  the biggest node (+glyph, labeled), the critical finding is a prominent red diamond, sink=vee /
  socket=hexagon read by shape. Eye lands on the anchor + red diamond. *Unregressed → improved.*
- **MEDIUM** — Before: already the good bar (the showcase). **After: better.** Clear hierarchy now —
  target anchors are the big circles, hubs sized up, critical findings pop; structural edges recede
  so `taints`/`routes_to`/`listens_on` colors separate out; labels legible on approach. *Improved.*
- **LARGE** — Before: an undifferentiated upper-center clump, gray/teal cobweb the dominant ink,
  letterboxed. **After: markedly calmer.** The gray cobweb is pushed back so semantic structure +
  sized hubs/anchors read; zoomed in it's navigable (colored semantic edges legible against the
  receded gray, hub labels appear). Still letterboxed/small at default fit (layout-by-context is
  Phase 4) — but the eye now has size hierarchy + an entry point where before it slid off. *Clear win.*
- **PATHOLOGICAL** — Before: a dark illegible smudge. **After: visibly less of a smudge** — distinct
  sized dots, gray cobweb receded; zoomed regions are now navigable. Not fully fixed at default
  (the calm-countable-rooms promise needs the compound-islands phase) but a real legibility gain.
- **Legend isolate-by-type** — verified: clicking `taints` (MEDIUM) / `socket` (LARGE) dims all but
  that type + incident edges/endpoints, hue preserved at low alpha (mute, not de-color). Surfaces the
  firmware network map as a readable subset. Hover = transient preview, click = pin (click to clear).
- [ ] **Phase 3+ (later):** compound target islands + skeleton-collapsed default +
  size-by-finding-weight (Phase 3); layout-by-context (fcose-spread / scoped dagre / concentric) +
  semantic-zoom LOD to kill the letterbox at LARGE/PATHOLOGICAL (Phase 4); layer panel + filter rail
  + Table/Matrix (Phase 5).

## Graph presentation — Phase 3: compound islands + grouping + expand/collapse (2026-06-02)

**Shipped in `build/graph-phase3`** (`docs/design/design-graph-presentation.md` §8 Phase 3, §1/§2.1/
§3/D1/D6/D7/D8). The **headline structural fix** — turns the flat node plane into collapsible
per-target "rooms" so even the *default resting view* of a huge target is parseable. Composes on
Phase 1 (sizing/edge-recede/labels) + Phase 2 (focus/hide/breadcrumb). **Two new deps** (see bundle
note); **color-coding untouched (D8)** — rooms use the target-kind/severity color, the only mute is
the existing `.context` opacity/desaturate.

Changes:
- **New deps:** `cytoscape-fcose` (compound-aware force layout that spreads islands + fills the pane
  where dagre letterboxed) + `cytoscape-expand-collapse` (registered for collapse mechanics; the
  visual model is driven by React `expandedRooms` state + a rebuild for determinism). **Bundle
  impact: gzip 315.9 kB → 361.7 kB (+45.8 kB); raw 1000.5 kB → 1166.5 kB.** `cytoscape-cxtmenu`
  skipped — the hand-rolled Phase-2 verb menu already covers the verbs cleanly (now extended with
  room expand/collapse).
- **Compound rooms by target (default).** Each byte target → a Cytoscape compound parent; a
  `firmware_image` is the GRANDPARENT room containing its child-target rooms ("12 boxes in one box").
  Sub-file nodes nest under their target's room; findings nest under the target they're `about`.
- **Skeleton-collapsed default at LARGE/PATHOLOGICAL (D1).** The skeleton = rooms visible, interiors
  hidden: the firmware grandparent is expanded so its child rooms show as **finding-weighted cards**
  (size ∝ node + Σfinding-severity), each carrying a **severity rollup ring** (worst finding inside
  tints the border red/orange) + a chip (`sbin/svc_00  27 · 1⚠`). SMALL/MEDIUM **auto-expand all
  rooms** below the node ceiling (look like today's full graph).
- **"Group by" control** (in the graph Filter menu): **target** (default) / **type** (a box per node
  type) / **finding** (each finding parents the nodes it's about) / **none**. **"None" = the flat
  Phase-1/2 dagre graph — the REGRESSION FALLBACK**, verified to reproduce Phase 2 exactly.
- **Collapse-all / expand-all** controls (toolbar buttons + Filter menu); expand-all warns above 200
  nodes. Double-tap a room or right-click → Expand/Collapse toggles a single room (auto-frames the
  opened room's interior, scoped `fcose` re-layout — never on a plain rebuild, per §3.4).
- **Aggregated cross-room meta-edges:** edges between two collapsed rooms fold into ONE weighted
  ribbon with a `×N` count (width ∝ count). Semantic meta-edges (links_against/taints/listens_on…)
  stay visible + labelled; purely-structural ones (references/contains) recede to faint hairlines —
  the same edge-ink discipline at the room scale (kills the room-level cobweb).
- **Socket bus lane:** shared `socket` nodes (`target_id = null`, cross-binary) belong to no room and
  render as loose pink hexagons around the islands, linked to the rooms that listen/connect — the
  firmware's network map stays a first-class, separately-readable region.
- **Auto-expand-path on focus/search (Phase-2 reviewer note):** focusing or searching a node inside a
  collapsed room now auto-expands the path to it so the focus actually lands.

**Before/after human-eyes verdict (Playwright, §9 — judged as a human):**
- **PATHOLOGICAL default (THE headline pass/fail, ~494n/2144e)** — Before: an undifferentiated
  smudge of equal dots / near-invisible static; the eye slides off. **After: PASS, decisively.** The
  default frame opens as a firmware grandparent box containing ~18 countable, labeled, colored room
  cards (blue executables, teal libraries), each ringed by its worst-finding severity (red/orange
  cards jump out), with a pink socket bus-lane around them and the structural cobweb pushed to faint
  hairlines. I can count the binaries and point to the critical-finding rooms at a glance.
  **[Eye lands ✓][Countable rooms ✓][Calm default ✓][Color kept ✓][Squint test ✓]**
- **LARGE default (~173n/649e)** — Before: flat clump in the upper-center. **After: PASS.** ~12 room
  cards inside the firmware box, severity rings legible, breathing room, semantic meta-edges + bus
  lane readable.
- **Drill-in (double-tap a room)** — PASS: the room opens to its interior (functions + call graph +
  the finding diamond + sink), auto-framed, siblings collapse to cards. Clean, scoped, reversible.
- **Group by: none** — PASS: reproduces the Phase-2 flat dagre graph verbatim (the fallback is solid).
- **Group by: type / finding** — both render without error (7 type-rooms / 9 finding-rooms on LARGE).
- **SMALL/MEDIUM** — PASS, unregressed/better: SMALL auto-expands to a single labeled `sbin/httpd`
  room with its functions/sink/finding + the http socket on the bus lane; MEDIUM auto-expands all
  rooms (the showcase's good frame).

*Limitations / deferred:* MEDIUM with many open compound boxes + cross-target meta-edges reads a
touch busy (acceptable — it's the auto-expanded "today's good frame"). The socket bus is loose
fcose-placed nodes, not a literal reserved lane (visually grouped, not geometrically banded —
deferrable polish). Layout-by-context fine-tuning + semantic-zoom LOD are Phase 4.

## Graph presentation — Phase 2: focus / hide / navigation (2026-06-02)

**Shipped in `build/graph-phase2`** (`docs/design-graph-presentation.md` §8 Phase 2, §4/§5/§9).
Live-instance only — class toggles + camera on the existing flat dagre graph; **zero new deps, no
rebuild, color-coding untouched (D8 — `.context` only mutes opacity + desaturates, hue preserved).**
The fix for the "drowned highlight" the council found at LARGE/PATHOLOGICAL.

Changes:
- **Focus model replaces `.lit`-only.** Selecting/focusing a node applies `.focus` to it + its
  N-hop neighborhood (default 1, expandable to 3) and `.context` to everything else (mute to ~16%
  opacity + `background-blacken` + labels dropped + `events:no`, **hue preserved at low alpha**). The
  focus anchor gets an amber ring; focus edges brighten + label.
- **Scoped auto-frame + live concentric re-arrange.** On an explicit focus (double-tap / search /
  verb menu / URL restore — never hover, never plain select, per D5) the focus set is re-arranged
  into a concentric ring around the anchor *on the live cy instance* (positions saved + restored on
  clear — the resting layout is untouched, no layout-engine swap) and `animate({fit})` frames it.
  This is what makes a hub's scattered neighbors land as a readable local diagram instead of a
  full-graph fit. (Reliable framing required running dagre explicitly after wiring `layoutstop` —
  dagre is synchronous and fires `layoutstop` from the constructor before a listener can attach.)
- **Hover preview** (transient `.hl`/`.hl-dim`): lifts the hovered node + 1-hop ring, dims the rest,
  no commit/reframe — suspended while a focus is committed.
- **Focus stack + breadcrumb (URL-serialized).** `Overview › crumb › crumb` pinned top-left; each
  focus/hop pushes a frame, a crumb pops to it, `↺`/clear returns to the resting full graph. The top
  frame's `?focus=<id>&hop=N` is in the URL → shareable + reload-restorable.
- **Search drives the graph (§4.3):** picking a node/target result now `focusOn`s it (push + frame),
  not just select.
- **Right-click verb menu (dependency-free):** Focus neighborhood · Expand one hop · Reveal in panel
  · Hide this node. **Reversible hide chip** ("N hidden · restore ↺", bottom-left) — non-destructive,
  one-click reverse.

**Before/after human-eyes verdict (Playwright, §9 criteria — judged as a human):**
- **PATHOLOGICAL focus (the headline pass/fail)** — Before: focusing a node in the ~494n/2144e
  smudge did nothing legible (selection brightened a few edges lost in the static). **After: PASS,
  decisively.** The amber-ringed anchor sits in a clean concentric ring of its ~24 labeled function
  neighbors with call edges radiating; the entire rest of the firmware is a faint, present, muted
  backdrop. The eye lands on the anchor instantly and reads the local neighborhood — exactly the
  "neighborhood pops out of a quiet background" goal. **[Eye lands ✓][Focus pops ✓][Color kept ✓]**
- **LARGE focus** — Before: same drowned highlight in ~173n/649e. **After: PASS.** Identical clean
  concentric local diagram; 1-hop ≈ a dozen+ labeled neighbors, 2-hop a richer inner+outer ring,
  both legible against the mute.
- **Breadcrumb** — verified present + reversible: `Overview › <fn>` top-left, clear/`↺` returns to
  the full resting view (foc→0, URL cleared), navigation feels safe/undoable. **[Reversible ✓]**
- **Auto-frame** — fires only on explicit focus (double-tap/search/verb/URL), zoom lands ~1.4 on the
  scoped set; never on hover/plain-select; consistent across repeated PATH trials (no flake). **[Auto-frame ✓]**
- **Hover preview** — a subtle transient lift of the hovered node + ring against a light dim; reads as
  "what's this connected to?" without committing focus. Modest at full-graph zoom but distinct from focus.
- **Hide + restore** — right-click → Hide removes a node from the focus ring; the "1 hidden · restore
  ↺" chip restores it in one click. Non-destructive. **[No-loss ✓]**
- **SMALL/MEDIUM + LARGE/PATH default (resting) frames** — unchanged from Phase 1 (no breadcrumb, no
  mute until a focus is committed). **[SMALL/MEDIUM unregressed ✓]**

*Limitation (by design — deferred):* the concentric re-arrange is a Phase-2 live nicety so focus
frames readably on the flat layout; the resting LARGE/PATH default frame is still letterboxed/small
(layout-by-context + the skeleton default are Phase 3/4). Hover preview is faint at far zoom.
