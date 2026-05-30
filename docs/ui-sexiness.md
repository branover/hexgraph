# UI sexiness pass — punch list

Goal: make the workspace feel like a modern, expressive analyst notebook — value obvious
in one screenshot. Grounded in the current SPA (`frontend/`). Checked items are done in
this pass.

## Design system (biggest bang)
- [x] **S1** Refreshed design tokens: layered surfaces, refined dark palette, severity scale,
  accent gradient, elevation shadows, focus rings, custom scrollbars.
- [x] **S2** Typography hierarchy (sizes/weights/letter-spacing); a real button system
  (primary/ghost/danger/icon, sizes); pill/chip system; smooth transitions everywhere.
- [x] **S3** Inline SVG icon set (offline; no icon font) — node-type, severity, action, tab icons.

## Graph (the centerpiece)
- [x] **G1** Bigger, cleaner nodes with a **severity/confidence halo** and type icons.
- [x] **G2** Color-coded edges by type; **hide edge labels by default**, reveal on hover/selection.
- [x] **G3** Floating graph controls: fit-to-view, zoom +/−, re-layout; node count chip.
- [x] **G4** Polished selection (glow ring) + hover; smoother layout spacing.
- [x] **G5** Cleaner legend (chips with icons).

## Launcher & actions (less utilitarian)
- [x] **L1** Replace the per-row dual `<select>` with a compact **"Run ▾" popover** menu,
  capability-filtered; mock-scenario only shown for the mock backend.
- [x] **L2** Workspace **toolbar** surfacing P7: global **search**, **Report**, **Link same-code**.

## Findings & inspector
- [x] **F1** Findings cards: severity left-rail + icon, cleaner meta, hover/selected polish;
  nicer group headers + per-severity count summary bar.
- [x] **F2** Inspector: sectioned layout, chips (severity/confidence/category/status), evidence
  key–value grid, monospace code block with copy, refined follow-up/suggestion buttons.

## Shell & states
- [x] **H1** Header: brand mark, project breadcrumb, backend + cost badges, global search box.
- [x] **H2** Loading skeletons + empty states + subtle entrance transitions.
- [x] **P1** Projects page: richer cards (counts), polished hero/empty state.

## Deferred (noted, not in this pass)
- Minimap; saved views; virtualized findings list (>1k); run-compare visual diff UI; report HTML render;
  keyboard command palette.
