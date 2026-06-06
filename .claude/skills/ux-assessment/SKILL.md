---
name: ux-assessment
description: >-
  Run the two-role, agent-driven UX walkthrough of the HexGraph web UI against the living
  contract in docs/dev/ux-contract.md. Use this on every major UI change, fix evaluation, or
  release: one agent (the VR analyst) drives HexGraph the way a researcher's agent would and
  populates every surface; a second, separate agent (the simulated researcher) opens the UI
  cold and walks the contract entry by entry, scoring each interaction on functional + the
  qualitative dimensions, verifying backend effects, narrating the experience like a newcomer,
  and flagging contract drift. Produces a deviation + experience report. This is repeatable and
  re-run, never one-and-done.
---

# UX assessment — the two-role walkthrough

## What this is and why

HexGraph keeps shipping UI interactions that don't behave the way the design intends, caught
only when the maintainer manually clicks around. This skill replaces that with a repeatable,
agent-driven, role-separated walkthrough:

- **Role 1 — the VR analyst** drives HexGraph the way an agent is *meant* to (the MCP server in
  driver mode, and/or `hexgraph run` / the CLI), following a deliberate ordered sequence that
  **populates every surface** the researcher will touch. The goal: when Role 2 opens the UI,
  **nothing is empty** — every panel, tab, modal, and badge has the state it needs.
- **Role 2 — the simulated researcher** is a *separate* agent that opens the UI cold (Playwright)
  on the analyst's project and uses it as a first-time human researcher would, walking
  `docs/dev/ux-contract.md` **entry by entry**, performing each step, **scoring every dimension**
  (functional + the qualitative axes), **verifying the backend effect** (the screenshot is
  evidence, not the check), and **narrating the experience** like a newcomer.

The contract (`docs/dev/ux-contract.md`) is the spec; this skill is how it's exercised. The
contract documents *intended* behavior — so when the implementation diverges, Role 2 *catches*
it as a deviation. That is the point.

**This is a living loop.** Re-run it on every major UI change, every fix evaluation, and before
a release. The self-audit step (Role 2 flags entries that no longer match the code, and surfaces
it found that aren't in the contract) keeps the contract current between the per-PR updates that
the CLAUDE.md merge-gate rule enforces.

---

## Prerequisites & isolation (do this once, per run)

Run in an isolated worktree/home so nothing collides with other work (CLAUDE.md isolation rules):

```bash
# from a worktree (or the primary checkout if you own it)
export HEXGRAPH_HOME="$PWD/.hghome-uxassess"     # OWN data/DB/settings
export HEXGRAPH_PORT=8779                          # spare port (not the default 8765)
export HEXGRAPH_HOST=127.0.0.1                     # loopback invariant — never 0.0.0.0
export HEXGRAPH_LLM_BACKEND=mock                   # zero token spend, deterministic
export HEXGRAPH_FUZZER=mock HEXGRAPH_BUILDER=mock  # offline build/fuzz

just install                                       # own venv (if not already)
just ui                                            # build the SPA into this worktree's dist
.venv/bin/pip install playwright && .venv/bin/playwright install chromium   # dev-only, not in pyproject
```

Docker is **optional**: with it, recon/build/fuzz run for real in the sandbox; without it, the
offline mock builder/fuzzer + the seed scripts still populate every surface (the assessment
notes any interaction that genuinely needs Docker and couldn't be exercised offline). Either way
the run is `$0` and offline.

---

## The orchestrator launches the two roles as SEPARATE agents

The whole value comes from separation: Role 1 finishes and **leaves state**; Role 2 assesses
**cold**, having never seen Role 1's reasoning — exactly like a researcher opening a project an
agent prepared. The orchestrator (you, or a parent agent):

1. Launches **Role 1** (the VR analyst) with the §"Role 1" brief below. It runs to completion,
   leaving a fully-populated project (and the optional extra states), and reports the project
   ids + which State-Coverage-Matrix rows (S1–S30) it satisfied.
2. Serves the UI: `HEXGRAPH_HOME=… HEXGRAPH_PORT=8779 HEXGRAPH_HOST=127.0.0.1 .venv/bin/python -m hexgraph.cli mcp`
   is the analyst's tool channel; for the UI, `.venv/bin/python -m hexgraph.cli serve` in the
   background (capture the PID; kill it when done).
3. Launches **Role 2** (the simulated researcher) with the §"Role 2" brief, handing it ONLY the
   base URL + the project ids + the contract path — never Role 1's transcript.
4. Collects Role 2's deviation + experience report and the proposed contract edits.

If you cannot spawn separate sub-agents, run the two roles as two clearly-separated *phases* in
one session, but treat Phase 2 as cold: do not let Role-1 knowledge answer a "does this behave as
intended?" question — drive the UI and read the actual result every time.

---

## ROLE 1 — the VR analyst (agentic session that populates everything)

**Brief:** You are a vulnerability researcher's agent. Using HexGraph's MCP driver tools and/or
`hexgraph run` / the CLI (NOT by editing the DB directly), build out ONE primary project so that
every surface a researcher touches has real state. Then leave it. Below is the deliberate, ordered
sequence; each step is annotated with the State-Coverage-Matrix rows (S#) it produces and the
contract IDs it thereby unlocks. **Order matters** — later steps depend on earlier state.

A fast path exists for the bulk of it: the deterministic seed scripts. Use them to lay the rich
baseline, then exercise the *live* actions (run a task, start a campaign, verify a PoC) so the
"actually launches / actually verifies" interactions are real, not just seeded rows.

### A0 — Create the project(s) and enable the gates  → S1, S2, S29
- `just showcase --reset` seeds the primary project (the Acme R7000 router engagement): firmware
  + unpacked-FS children (httpd, libupnp.so) + a standalone daemon + a web_app surface + a service
  (socket) surface; a managed source tree + harness; typed nodes; a wide edge variety; findings
  across types and the assurance ladder INCLUDING a verified PoC; a finished mock fuzz campaign with
  crashes + coverage; egress events (allowed + denied). This single command satisfies the bulk of
  S3–S13, S16, S17, S20, S23, S26, S27.  (Run it; note the printed project id.)
- `just graph-tiers` seeds SMALL / MEDIUM / LARGE / PATHOLOGICAL / REAL (≈250-target / ≈13k-node)
  projects → **S28** (skeleton-first, LOD, scale).
- Create a second throwaway project (`POST /api/projects` or the Projects UI) so PROJ-03 has a
  disposable delete target → **S2**.
- In Settings (or `hexgraph config set` / a `PATCH /api/settings`), enable the gates the assessment
  needs: `features.fuzzing`, `features.poc`, `features.build`, `features.source.edit`,
  `features.network`, and the `features.mcp.{read,write,run}` groups → **S29** (the seed already
  enables fuzzing/poc/network/build; confirm and add source.edit).
  Unlocks: PROJ-*, all gated surfaces.

### A1 — Ingest a standalone binary + run recon  → S3, S16
- The showcase already ingests a standalone daemon with real bytes. To exercise a *live* recon
  (the "Run → recon executes for real" interaction), run a recon task on it:
  MCP `run_task(target_id=<daemon>, type="recon")` or `hexgraph run <daemon> --type recon`.
  (Needs Docker; if absent, the seeded recon facts already populate the inspector — note the gap.)
  Unlocks: TGT-02/05, GRAPH-07/10, TASK-01/02.

### A2 — Confirm the firmware + its unpacked filesystem  → S4, S27
- The showcase firmware has a browsable unpacked FS + path-named children (httpd, libupnp.so),
  giving the folder tree, the rollup badges, and cross-target edges. Verify it loaded
  (MCP `list_filesystem` / the Targets pane). For the curatable-targets folder grouping at depth,
  the REAL tier (A0) has the ~250-child firmware.
  Unlocks: TGT-03/04/09/10, GRAPH-01/26, GRAPH-27/28.

### A3 — Register a web_app surface  → S5
- The showcase registers the router admin UI web_app. To add one explicitly:
  MCP `target_register_web_surface(kind="web_app", base_url=…, routes=…)`, then `run_task(surface_recon)`.
  Unlocks: TGT-06 (surface kinds), GRAPH-27, VIEW-* with a surface.

### A4 — Register a service (raw-TCP socket) surface  → S6
- The showcase registers a UPnP/telnet-ish service. Explicitly: MCP `target_register_service(kind="tcp",
  host=…, port=…)` (or `POST /api/projects/{id}/targets/socket`).
  Unlocks: TGT-06, GRAPH-27, FUZZ-01 (network surface fields).

### A5 — Static analysis producing findings across types & severities  → S7, S8, S9, S10, S11, S15
- The showcase persists findings spanning vulnerability / recon / info-leak / auth-bypass /
  fuzz_crash / poc and the full assurance ladder (static code_present, argued input_reachable,
  lab-confirmed, and a verified PoC). To produce a *live* finding too, run a static-analysis task:
  MCP `run_task(target_id=<httpd>, type="static_analysis", objective=…)` or
  `hexgraph run <httpd> --type static_analysis` (mock backend → deterministic findings).
  Ensure at least one extra LOW finding exists as a disposable delete target (S15).
  Unlocks: FIND-01/02/03/04/10/12/13/14/15, GRAPH-18/20, TOOL-06.

### A6 — Author nodes, edges, a hypothesis, annotations  → S12, S13, S23
- MCP write tools (or the UI Node/Edge modals): `create_node` (a function + a sink + a socket),
  `create_edge` (e.g. a `taints` source→sink), `create_hypothesis` + `link_evidence` from a
  finding, and `create_annotation` (a note + a tag; a function rename). Leave at least one
  annotation in the `proposed` state (an analysis task proposes renames) so FIND-17's confirm/reject
  is testable.
  Unlocks: TOOL-01/02, EDGE-DEL, GRAPH-12/14/37, FIND-16/17.

### A7 — Leave findings in varied states  → S14
- Confirm a couple of findings (`update_finding(status="confirmed")` / the Confirm button),
  dismiss one (`status="dismissed"`), and leave several `new`. So the status filter, the lifecycle
  pills, and the dismissed-vs-deleted distinction all have real examples.
  Unlocks: FIND-01/02/05/06.

### A8 — Verify a PoC  → S8 (the verified rung)
- The showcase ships a verified command-injection PoC. To exercise the live verify path, with
  `features.poc` on call MCP `verify_poc(finding_id=<the cmd-injection finding>)` (or the Inspector
  **Verify PoC** button). This proves the green "✓ verified" + assurance line are real.
  Unlocks: FIND-04, FIND-12.

### A9 — Build an instrumented target from source  → S17, S18, S19 (succeeded), S29
- The showcase builds the instrumented httpd for real via the offline MockBuilder, registering a
  derived instrumented target with a recorded recipe + reproducibility triple + a promoted harness +
  on-disk fuzz target sources. Confirm the build row exists (Source view → Builds). The source tree
  is editable when `features.source.edit` is on (S18).
  Unlocks: SRC-01/02/03/04/05/07/08, FUZZ-01/02, GRAPH-29.

### A9b — Produce a FAILED build  → S19 (failed)
- Trigger a build that fails (e.g. a custom build phase that won't compile, or an artifact path that
  won't exist) so the failed-build detail modal (error + log) has a subject. If the offline mock
  builder can't be made to fail, note S19-failed as unsatisfiable offline so Role 2 records SRC-06 as
  not-exercised rather than a deviation.
  Unlocks: SRC-06.

### A10 — Run a fuzz campaign to completion (crashes + coverage)  → S20
- The showcase runs a finished mock fuzz campaign → crash artifacts (dedup group + exploitability +
  minimized reproducer) + a per-line coverage map + a fuzz_crash finding. To run one live: open the
  Fuzz modal on the instrumented target and **Start campaign** (or MCP `start_fuzz_campaign`), let it
  finish. This makes FUZZ-05–10 + FUZZ-12/13 real.
  Unlocks: FUZZ-03/05/06/07/08/09/10/12/13.

### A10b — Leave a campaign RUNNING  → S21
- Start a second, longer campaign and leave it running (a long `max_total_time`) so Role 2 can watch
  the live exec/edge climb and exercise Stop. (Needs Docker for a genuinely live one; the mock fuzzer
  finishes fast — if so, note S21 as a finished-stats-only check and FUZZ-03's live-climb as
  not-exercised offline.)
  Unlocks: FUZZ-03 (live), FUZZ-11.

### A10c — Produce a degraded / 0-exec campaign  → S22
- Start a campaign that does no useful work (e.g. an uninstrumented/black-box target, or a network
  surface with nothing listening) so the amber degraded state + engine_note render. If unseedable
  offline, note S22 unsatisfiable so Role 2 records FUZZ-04 as not-exercised.
  Unlocks: FUZZ-04.

### A11 — Ingest a sibling binary that shares code  → S24, S27
- Add a second binary that shares functions with httpd (the firmware's siblings already do), so
  same-code linking + merge-dupes have pairs to find.
  Unlocks: TOOL-04, TOOL-05, GRAPH-27/28, VIEW-04/05.

### A12 — Re-run a task over a target  → S25
- Re-run an analysis over httpd (TaskDetail **Re-run**, or `run_task` again) so a target has ≥2 runs
  for Compare and the re-run path.
  Unlocks: TOOL-03, TASK-02 (re-run).

### A13 — Generate egress events (allowed + denied)  → S26
- The showcase records a few EgressEvents (allowed + one denied). To make them live, with
  `features.network` on run a `web_recon` / `http_request` against the loopback web_app (allowed) and
  attempt a public-host destination (denied → audited). So the Egress audit table has both verdicts.
  Unlocks: TOOL-08.

### A14 — Have the scale tiers ready  → S28
- `just graph-tiers` (A0) already seeded SMALL/MEDIUM/LARGE/PATHOLOGICAL/REAL. Hand all their ids to
  Role 2 so it can assess the default frame, LOD, skeleton-first, Map, and panels-at-scale across
  tiers.
  Unlocks: GRAPH-01/23/25/26, VIEW-02, SHELL-* at scale.

### A15 — Save a lens  → S30
- Customize a view (e.g. group-by finding + a severity filter + a focus) and save it as a named lens
  (`PATCH /api/settings` `ui.lenses`, or the Lenses → Save current view UI). So Role 2 can apply,
  delete, and deep-link it.
  Unlocks: VIEW-06/07/08.

**Role 1 done.** Report: the primary project id, the tier project ids, the throwaway-delete project
id, and a checklist of which S-rows (S1–S30) are satisfied vs noted-unsatisfiable-offline. Leave the
state in place. Do not assess — that's Role 2.

---

## ROLE 2 — the simulated researcher (cold, at the UI)

**Brief:** You are a vulnerability researcher opening this HexGraph project for the first time. You
have NOT seen how it was set up. Open the UI with Playwright and use it like a curious human. Walk
`docs/dev/ux-contract.md` **entry by entry**. For each entry:

1. **Find it like a newcomer first.** Before performing the documented steps, look for the affordance
   where you'd expect it. Narrate: "I wanted to X, so I looked HERE first." If it wasn't where you
   looked, that's an intuitive/discoverable finding even if the action ultimately works.
2. **Perform the steps** and observe the actual result (drive the real interaction — click, type,
   drag; don't infer).
3. **Verify the backend effect** for any 🔌 entry. Hit the API / re-read the graph / re-fetch the
   finding / read settings to confirm the state actually changed, the task actually launched, the
   file actually wrote. A UI that looks like it worked but didn't persist is a **functional FAIL**.
   Screenshots are evidence, never the check.
4. **Score every applicable dimension** (Functional, Intuitive, Feedback, Aesthetics, Consistency,
   Forgiveness, Friction, Overall) — pass / minor / major / blocker, each with a one-line reason. Do
   NOT collapse to a single pass/fail; the qualitative axes are the whole point ("it works but it's
   cramped/confusing/silent" must be recorded).
5. **Narrate the experience** in a newcomer's voice: where the eye landed, whether a panel felt
   crowded or calm, whether feedback was clear, whether a destructive action scared you appropriately,
   whether you'd want to keep exploring or bounce.

Judge **as a human, not a parser** (CLAUDE.md): completeness is necessary but not sufficient — a
screen that is technically complete but cramped, ugly, silent, or overwhelming has failed. View every
PNG with the Read tool and ask: does the eye flow naturally? Is there breathing room and hierarchy?
Does it look modern, or scotch-taped? Would this delight or intimidate?

**Drive Playwright like the CLAUDE.md guidance:** `p.chromium.launch(args=["--no-sandbox"])`,
`goto(f"{BASE}/projects/{id}", wait_until="networkidle")` + a short `wait_for_timeout(1500–3000)` so
Cytoscape/fcose/fetches settle, then `page.screenshot(...)`. For interactions, use real Playwright
actions (`click`, `dblclick`, `hover`, `fill`, `drag_to`, `mouse.wheel`) and re-screenshot after.
Right-click suppression (GRAPH-02/03/04) is checkable by listening for the `contextmenu` event being
prevented. For backend checks, call the API with `page.request` or a parallel `httpx` client against
the same base URL.

### The self-audit / living-doc step (do this as you go)

While walking the contract, also flag **contract drift** — this is how the doc stays current beyond
the per-PR merge-gate rule:

- **STALE** — a contract entry whose interaction no longer exists or behaves materially differently
  from what's written (and it's an intended *change*, not a bug). Propose the edit.
- **GAP** — a UI surface / interaction you found that is NOT in the contract (a new button, menu,
  modal, state). Propose the new entry (with a stable ID and a Prereq that traces to the matrix; if
  it needs new state, propose the matrix row + the Role-1 step too).

Collect these as proposed contract edits at the end of the report.

### Output — the deviation + experience report

Write the report to `docs/dev/ux-assessment-<YYYY-MM-DD>.md` (and summarize back to the
orchestrator). Structure:

**1. Run header** — date, commit/branch, which project ids were assessed, which S-rows Role 1
satisfied vs noted unsatisfiable-offline (so a not-exercised entry isn't mistaken for a pass).

**2. Per-contract-ID rows** — for every interaction walked:

```
[GRAPH-08] Double-click a node → focus neighborhood        VERDICT: PASS | DEVIATION | NOT-EXERCISED
  Functional: PASS — focus applied, ?focus=<id> in URL, backend n/a
  Intuitive: MINOR — I expected single-click to focus; double-click wasn't discoverable without trying
  Feedback: PASS — camera glided, breadcrumb crumb appeared
  Aesthetics: PASS — clean local diagram, rest a faint ghost
  Forgiveness: PASS — ↺ returned me to Overview
  Expected vs actual: <if deviation, the one-line diff>
  Severity: <blocker | major | minor> (deviations only)
  Repro: <exact steps + the screenshot path>
  Newcomer notes: "I clicked the hub and nothing dramatic happened; only when I double-clicked did
                   the smudge resolve — lovely once I found it."
```

**3. Per-surface overall impression** — one short paragraph per surface (Projects, Targets, Graph,
Views, Findings/Inspector, Tasks, Fuzz/Campaigns, Source/Build, Toolbar, Settings): the gut-check —
calm or busy, inviting or intimidating, polished or dated — judged as a human.

**4. Deviation summary** — every DEVIATION sorted by severity (blockers first), each with its
contract ID, the expected-vs-actual, and repro. This is the actionable list a fix PR works from.

**5. Contract drift** — the STALE and GAP findings with proposed contract edits.

---

## After the run

- Kill the backgrounded `serve` PID.
- The report lands in `docs/dev/`; deviations feed fix PRs; the contract-drift edits are applied to
  `docs/dev/ux-contract.md` (in a docs PR or folded into the fix PR that changes the behavior).
- **Re-run on every major UI change, every fix evaluation, and before a release.** This is a
  standing loop, not a one-time audit — that's what keeps "doesn't behave as expected" from shipping.
