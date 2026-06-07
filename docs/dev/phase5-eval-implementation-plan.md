# Phase 5 — Post-Evaluation Implementation Plan

**Date:** 2026-06-06 · **Source:** the Phase 5 tool evaluation against merged `origin/main` (`b4d77e6`).
**Inputs:** `tests/fixtures/phase5_tool_eval/reports/vr-agent-report.md` (Role A), `…/reports/ui-assessment-report.md` (Role B), and the pre-eval UX design discussion (the "graph-curation" cluster).

## Status (updated 2026-06-07)

**Shipped — Phases 1, 2, 3, 4** across PRs #177–#185 (prior) and #187–#192 (this run):
1.1 angr-reproducer render · 1.2 YARA honesty · 1.3 mitigation badges · 1.4 `graph_create_edge` param wording ·
2.1 Settings UI · 2.2 `meta_check_features` · 3.1 truncation marker + `max_chars` · 3.2 solver
`minimal_input`/`constrained_len` · 3.3 finding category · **3.5 graph-API batch** (`graph_stats`,
`graph_set_node_attr`, first-class CWE envelope + migration, `finding_reachability` precondition — #191) ·
**4.1 one-click promote (#189) · 4.2 node result-set (#190) · 4.3 auto-confirm naming · 4.4 source viewer
(#187 `<CodePane>` + #188)**. (Plus follow-up fix #192 — decompile/disassemble by the node's *address*, so a
stripped/renamed function still resolves.)

**Outstanding:**
- **3.4 — byte-faithful dynamic-verify for a *solver argv* reproducer** `[L]`. `finding_verify_poc` is
  byte-faithful on stdin (`stdin_b64`) but argv is still text-passed (`poc_probe.py` `str(a)`), so a raw-byte
  argv reproducer can't be confirmed end-to-end. The one true capability gap remaining.
- **2.3 — proactive sandbox-image staleness rebuild/warn** `[M]`. Largely met reactively by
  `meta_check_features` (2.2, which flags a broken feature before a wasted run); the proactive
  rebuild/warn-on-toolchain-change in setup is not built.
- **Phase 5 — graph aesthetics / friction polish** `[P2]` (5.1–5.4): single-binary fit/frame + leaf-label
  legibility · `matches_rule` canvas-edge clarity · Search Enter-to-focus · the two nits.

## Evaluation verdict (what we're building on)

**Part 1 — the tools work.** All four Phase-5 capabilities passed end-to-end against the merged build, each from a blind brief + the binary only, with the no-guilty-knowledge guarantee structurally enforced (the VR agent had the hexgraph MCP tools + `Write` and nothing else — no way to read the challenge source). `binutils_facts`, `floss_strings`, `yara_sweep`, and `solve_reaching_input` each surfaced the planted insight that the baseline pass could not, auto-populated the graph deterministically, and re-ran idempotently (cached, empty graph-delta).

**Part 2 — the UI is trustworthy, with surfacing gaps.** A cold researcher would trust the results and want to keep using it: analyses correct, finding write-ups excellent, graph/table/observations/findings all cross-check **exactly** to the backend, zero console errors. The gaps are the UI not *showing* what the backend already has correctly.

**Bonus finding (process):** the eval caught that an "up-to-date build" had a **stale sandbox image** — `hexgraph-sandbox:latest` predated the FLOSS/YARA toolchain, so both tools were dead at runtime and `yara_sweep` returned `match_count: 0` (indistinguishable from a clean scan). The agent met the objectives manually anyway; rebuilding the image and re-running validated both tools. This drives the robustness items below.

---

## The plan (5 phases, prioritized by value ÷ effort)

Effort: **S** ≈ hours, **M** ≈ a day, **L** ≈ multi-day. Each item names the eval finding and the likely seam/files.

### Phase 1 — Credibility + correctness quick wins (do first: small, high-value, low-risk)

| # | Item | Why (finding) | Where | Effort |
|---|---|---|---|---|
| 1.1 | **Render the angr solved input in the Inspector** | P0 — the flagship's evidence is invisible: `evidence.reproducer` (`3b25065c…`), input model, and the `evidence.extra.solver` path exist in the API but `Inspector.tsx` has no branch for them. Add a reproducer/solver block with a copy button (mirror the repro-command block). | `frontend/src/components/Inspector.tsx` | S |
| 1.2 | **YARA silent-failure → honest result** | The robustness headline: `yara_sweep` returned `{match_count:0, hits:[]}` when *every* file errored — a false all-clear. Surface `scanned_ok` vs `errored` counts; never report `match_count:0` when all files errored; bubble the per-file error reason into the summary, not just `errors[]`. | `engine/` yara result assembly + `sandbox/probes/yara_probe.py` | S |
| 1.3 | **Mitigations as badges, not a JSON blob** | P1 — both the NodeInspector RECON FACTS and the finding EVIDENCE print `JSON.stringify({"nx":false,…})`; a human must know false-is-bad. Render per-flag weak/ok color-coded badges (NX off / no canary / no PIE / partial RELRO). The honest "weak: …" wording already exists in the binutils observation summary — reuse it. | `frontend/src/components/NodeInspector.tsx`, `Inspector.tsx` | S |
| 1.4 | **`graph_create_edge` param naming** | The schema advertises the vocab under `edge_types` but the param is `type`; passing `edge_type` errors. Align the description (or accept `edge_type` as an alias). | `engine/mcp_catalog.py` | XS |

### Phase 2 — Feature management + health (close the "can't see or manage the features" gap)

| # | Item | Why | Where | Effort |
|---|---|---|---|---|
| 2.1 | **Settings UI for `features.floss/yara/angr`** | P0 — enabled in `settings.json` but **absent from the Settings page and all of `frontend/src`**. Add the three feature cards with their heavy-compute/security notes, and **surface the YARA user-rules directory**. (Contract SET-03 expects every optional toggle with its implication.) | `frontend/src` Settings + `PATCH /api/settings` plumbing | M |
| 2.2 | **`meta_check_features` health preflight** | There's `meta_check_decompiler` but nothing that distinguishes *gated-off* from *configured-but-broken* for floss/yara/angr/emulation. Would have caught the stale image before a wasted run. A read tool that probes each feature's runtime availability. | `engine/mcp_tools.py` + catalog + SKILL | M |
| 2.3 | **Sandbox-image staleness: rebuild on toolchain change / warn** | "Up-to-date build" must include the sandbox image, not just venv/SPA. Setup/wizard should rebuild (or warn) when a feature's toolchain dep postdates the image. At minimum, a startup/`meta` check comparing image build date vs the toolchain manifest. | `setup_catalog.py` / `sandbox/runner.py` | M |

### Phase 3 — Agent tool ergonomics (from the VR runs)

| # | Item | Why | Where | Effort |
|---|---|---|---|---|
| 3.1 | **Actionable truncation marker + agent `max_chars`** | A — `_clip` head-truncation (`_MAX=6000`) hid the `system()` sink. Marker should embed the obs id + sizes + recovery knobs; add optional `max_chars` (default 6000, clamped, generous ceiling) to the body-returning `re_*` tools so the agent owns the context spend. *Do NOT remove the cap.* | `engine/agent_tools.py`, `mcp_catalog.py`, SKILL, `docs/mcp.md` | M |
| 3.2 | **Solver reproducer ergonomics** | D — `concrete_input` is the full argv buffer (8 real + filler) with no "which bytes matter" hint. Add `constrained_len`/`minimal_input` to the solver result. | `sandbox/probes/angr_probe.py`, `engine/solver.py` | S |
| 3.3 | **`weak-gate`/`logic` finding type** | D — `vulnerability/other` fits a crackable license check poorly. Add a finding-type/category that reads right for "the gate is satisfiable." (DB-envelope, classifier in `engine.findings`.) | `engine/findings.py` (+ the FINDING_TYPES source of truth) | S |
| 3.4 | **Byte-faithful dynamic-verify for a solver argv reproducer** | D — `finding_verify_poc` text-mangles argv (unsafe for non-printable bytes), so a solver's raw-byte reproducer can't be confirmed end-to-end. A byte-faithful "verify this solved argv input" handoff. | `engine/poc.py` / `sandbox/probes/poc_probe.py` | L |
| 3.5 | **Small graph-API ergonomics batch** | A — `graph_stats`/counts verb (listing 100+ nodes to count is unworkable + truncates); `graph_set_node_attr` (re-create-merge to set `is_sink` is awkward); first-class **CWE field** on Finding; explicit `precondition` on `finding_reachability` (couldn't express "unauthenticated"). | `engine/mcp_*`, models/finding, `engine/reachability.py` | M |

### Phase 4 — Graph-curation UX cluster (the bigger UX investment; mostly frontend over existing plumbing)

These four were designed pre-eval and **independently corroborated** by it (noted per item). They share a through-line: read/curate over the Observations + enrichment + `node_refs` machinery that already exists — little new backend.

| # | Item | Why / corroboration | Where | Effort |
|---|---|---|---|---|
| 4.1 | **One-click promote of tool-discovered symbols** | Today only `target.metadata.exports` is one-click-promotable; functions/symbols/imports in tool results aren't. The VR agent independently asked for a lightweight "promote this callee" verb. Newly-created nodes auto-enrich via `get_or_create_node → apply_facts_for_node`. | `frontend` (clickable result rows) + reuse `graph_create_node`; a `re_promote_*` agent verb | M |
| 4.2 | **Surface a node's full result set at the node** | The body stays in Observations (correct), but the node view shows only decompilation on demand; the VR agent's "Tool Results buried under the imports grid" (P2 #6) is the same gap. Surface all `node_refs`-linked Observations at the node; reorder/collapse the imports grid. | `frontend/src/components/NodeInspector.tsx` via `Observation.node_refs` | M |
| 4.3 | **Auto-confirm naming of an *unnamed* object; only renaming a *named* one needs approval** | Today `create_annotation` gates purely on origin, so every agent label needs a human click (a real bottleneck). Corroborated by the VR note "annotation lands `proposed`, no way to see it applied." The `fcn.<addr>`/`sub_`/`FUN_` placeholder signal already exists in `engine.nodes`. Logic-only, no migration. | `engine/annotations.py` | S–M |
| 4.4 | **"Open in source viewer" (full v1)** | A's truncated-decompile pain has a human counterpart: the details pane is wrong for reading 200-line bodies. Build it to match `SourceBrowser.tsx` by extracting a shared `<CodePane>` (reuses `highlight.ts`); Decompiled⇄Disassembly tabs, line numbers, click-a-callee-to-navigate, deep-linkable. Bodies stay in Observations; add one thin `POST /disassemble`. Register asm grammars in `highlight.ts`. | `frontend` (`SourceBrowser.tsx` refactor + new viewer), `api/routers/targets.py` | L |

### Phase 5 — Graph aesthetics / friction polish (P2)

| # | Item | Why | Effort |
|---|---|---|---|
| 5.1 | **Single-binary graphs read empty** — tighten default fit/frame so curated content fills the canvas; bump leaf-label legibility at default zoom. | P2 #5 | S |
| 5.2 | **`matches_rule` edge rendering clarity** — pattern nodes show `instance_of_pattern` on canvas; the YARA→target `matches_rule` (×8) lives in data/Table. Confirm the intended canvas edge for the YARA→target relationship and label it. | P1 #4 | S |
| 5.3 | **Search Enter-to-focus** doesn't land the focus/expand the skeleton room (popover-click works). | P2 #7 | S |
| 5.4 | Nits: projects grid empty right column on a lone second-row card; the intentional Cytoscape wheel-sensitivity console warning fires on every mount. | Nits | XS |

---

## Suggested sequencing

1. **Phase 1** as one small PR (or two) — the angr-reproducer render + the YARA honesty fix are the two that most affect *credibility* and are both small.
2. **Phase 2** next — the Settings UI + `meta_check_features` together remove the "enabled but invisible/unmanageable" class of problem the eval hit twice.
3. **Phase 3** as a tool-ergonomics batch (3.4 byte-faithful verify is its own larger task).
4. **Phase 4** is the flagship UX investment — sequence 4.4 (source viewer) as its own effort; 4.1–4.3 can land incrementally.
5. **Phase 5** folds into whatever graph PR is open.

## What we are explicitly NOT changing
- The **truncation cap** (the agent context-budget protection) — we make it actionable + agent-tunable, not removed.
- The **curated-graph / Observation split** — bodies stay in Observations; we surface them better, we don't stamp blobs onto node attrs.
- The Finding **schema** is frozen — the CWE field and `weak-gate` type ride the DB envelope, not the JSON schema.
