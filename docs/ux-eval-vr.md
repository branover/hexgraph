# HexGraph UX Evaluation — from a vulnerability researcher's chair

**Evaluator persona:** a working VR/RE engineer deciding whether HexGraph earns a place in the
day-to-day toolbox. I followed the README as a new user would, used the **mock** backend, and tried
to reverse-engineer the bundled `synthetic_fw.bin` firmware image **entirely through the web UI**
(driven headlessly with Playwright). Everything ran in an isolated `HEXGRAPH_HOME=/tmp/hexgraph-eval`
so the main install was never touched.

Date: 2026-05-30 · Backend: `mock` · Commit/branch: `build/hexgraph-mvp`

> Format: each section records what I did, then **👍 / 👎 / 💡** notes (works well / rough / idea).
> This doc is meant to feed UX improvements, so I err toward over-reporting friction.

---

## 0. First impressions from the README

The README is genuinely good — the three non-negotiables (local-only, BYOK-or-mock, hostile-target
isolation) are stated up front and made me trust the tool before running anything. The mock-backend
table that maps task type / scenario → expected outcome is exactly what a new user needs.

- 👍 Clear threat model stated immediately ("targets are hostile", LLM never sees raw bytes). For a
  VR audience this is the single most important trust signal and it's front-and-center.
- 👍 "Zero token spend by default" + a `make demo` that exits 0 means I can evaluate the whole loop
  for free before committing a key. Excellent for adoption.
- 👎 The README never tells you the firmware *unpacks into two ELFs* until the very bottom ("Bundled
  test targets"). The quickstart would be stronger if it said "after ingest you'll see `vuln_httpd`
  and `libupnp.so` as children" so a new user knows what success looks like.
- 👎 The mock-scenario table is keyed to "the `sbin/httpd` target", but the bundled firmware unpacks
  to `vuln_httpd` / `libupnp.so` (per the data-model section). The naming mismatch made me unsure
  which child target to launch tasks against. (Confirmed below — see §3.)
- 💡 A single "expected end state" screenshot in the README would orient a first-time user faster
  than any prose.

---

## 1. Setup & ingest (CLI, isolated home)

I isolated everything with `HEXGRAPH_HOME=/tmp/hexgraph-eval` and an explicit `HEXGRAPH_DB_PATH`.

```
$ hexgraph init
Initialized HexGraph at /tmp/hexgraph-eval (schema upgraded, rev 0007_target_archived)   # ~1.0s

$ hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo
project 6d611523-…
target  e8ac3261-…  demo
  child 70e00856-…  sbin/httpd
  child e3851c27-…  usr/lib/libupnp.so
recon complete: 3 target(s), 0 links_against edge(s)                                     # ~2.4s
```

- 👍 Ingest is fast (~2.4s including firmware unpack in the sandbox) and the tree output is clear:
  project id, root target, two children with ids. A VR will immediately recognize this as
  "firmware → extracted rootfs binaries."
- 👍 Isolation via `HEXGRAPH_HOME` works perfectly — nothing touched the real `~/.hexgraph`.
- 👎 **README naming inconsistency, confirmed.** The quickstart and mock-scenario table call the
  target `sbin/httpd`; the "Bundled test targets" section calls it `vuln_httpd`. Reality is a third
  spelling: children are `sbin/httpd` and `usr/lib/libupnp.so` (full rootfs paths). Pick one and use
  it everywhere — a new user matching the scenario table to the tree will hesitate here.
- 👎 `recon complete: … 0 links_against edge(s)`. The README implies a `links_against` relationship
  between httpd and libupnp. Recon found none, so the dependency edge a researcher would *want*
  (which binary loads which library) isn't auto-derived. Not a bug, but a missed expectation for
  firmware work — see §5.
- 💡 The README quickstart omits `hexgraph init`; ingest appears to auto-init the DB. Good, but the
  quickstart should say so explicitly, or drop `init` from the docs entirely to avoid implying it's
  required.

---

## 2. The workspace — three-pane layout

Opening the project lands you in a three-pane analyst notebook: **target tree** (left), **graph**
(center, Cytoscape), **findings/tasks** (right) with a **detail** dock at the bottom-right.

- 👍 The layout maps cleanly onto how a VR actually works: pick a target → run analysis → triage the
  finding → pivot via the graph. Nothing feels out of place.
- 👍 Left tree shows type + arch per target (`executable · x64`, `shared_library · x64`,
  `firmware_image`) with a per-target finding-count badge. Immediately legible.
- 👍 Header chips: backend (`mock`), a **live cost meter** (`$0 · mock`), and `local · 127.0.0.1`.
  The cost meter is a great BYOK reassurance — you always see spend before it surprises you.
- 👍 The right pane has Findings/Tasks tabs, full-text filter, severity + status dropdowns, and a
  group/ungroup toggle (grouped by target by default). This is real triage tooling, not a toy list.
- 👎 **Recon auto-creates a finding per target** ("Attack-surface summary for X", INFO severity but
  *high* confidence). Showing INFO severity and "high" right next to each other reads oddly — a new
  user can't tell at a glance that one is severity and the other confidence. Consider labeling the
  confidence chip ("conf: high") or moving it.
- 👎 **The launcher is hover-gated.** The `Run ▾` button only appears when you hover a target row.
  A first-time user staring at the static tree has no visual cue that targets are runnable. At least
  one persistent affordance (a faint Run icon, or a hint on the selected row) would fix the
  "where do I start a task?" moment. I only found it by enumerating buttons programmatically.

---

## 3. Launching a task — the Launch modal is the standout screen

`Run ▾` → pick a task type (`recon`, `static analysis`, `reverse engineering`, `harness
generation`) → a **Launch** modal opens. The modal has: **Objective/prompt**, **Focus function**,
**Model** (project default / opus-4-8 / sonnet-4-6 / haiku-4-5), **Effort** (low/med/high),
**Budget cap ($)**, **Mock scenario** dropdown, and — crucially — a live **Context preview** pane
showing exactly what the agent will receive (`~179 tok · 6 items`: objective, recon_facts,
prior_findings, imports, strings, sibling) with a `$0 (mock) · decompilation is added at run time`
footnote.

- 👍 **This screen alone would sell me on the tool.** The context preview makes the "LLM never sees
  raw bytes" promise *tangible* — I can see the exact decompiler/strings/imports payload and the
  token count before spending anything. As the objective text changes, the preview and token count
  update live. For a careful VR who cares about prompt hygiene and cost, this is exactly right.
- 👍 Per-task model + effort + hard budget cap. This is the control surface a real engagement needs
  (cheap model for sweeps, opus for the hard function, a $ ceiling so a loop can't run away).
- 👍 The mock scenario picker lives *here* (not in the hover dropdown), so the README's
  "pick a task type and a scenario" is technically accurate — but the two steps are split across two
  UI surfaces, which wasn't obvious. The scenario list matches the docs: `critical_overflow`,
  `no_findings`, `malformed_then_valid`, `error_rate_limit`, `error_timeout`.
- 👎 In a real (non-mock) engagement the "Mock scenario" row is dead UI. It should hide when the
  backend isn't `mock`, or be visually demoted to a "dev/testing" affordance.
- 💡 The context preview shows token count but not which decompiler produced it (radare2 vs Ghidra)
  or the decompilation itself (it's "added at run time"). A VR would want to preview the actual
  decompiled function that's going into the prompt — that's the highest-value/highest-risk context.

### Running `static_analysis / critical_overflow`

Filled objective ("Audit the CGI request handler for memory-safety bugs…"), focus `cgi_handler`,
scenario `critical_overflow`, **Launch agent**. Within ~2–3s:

- A **CRITICAL** finding "Stack buffer overflow in cgi_handler()" appeared, grouped under SBIN/HTTPD.
- The center graph grew **function nodes** (`cgi_handler`, `strcpy`, `printf`) wired to `sbin/httpd`,
  a red finding diamond linked to `cgi_handler`, and an **orange `related_to` edge to libupnp.so**.
- The bottom dock showed the **task** with full **provenance**: bundle id, params
  (`{"effort":"medium","budget_usd":10,…}`), and trace artifacts (`bundle.json`, `prompt.txt`,
  `response.json`, `system.txt`) plus "findings produced (1)".

- 👍 Sub-3s round trip on mock; graph + findings + task all update together with no manual refresh.
- 👍 The finding detail is genuinely useful: **CRITICAL · memory-safety · high confidence**, a clear
  description, structured **EVIDENCE** (function `cgi_handler`, sink `strcpy`, address `0x4a21c`,
  file `sbin/httpd`), a **REASONING** paragraph (no canary → controllable return addr → ROP), a
  **DECOMPILED** section, a status workflow (new→triaging→confirmed→reported), and Accept/Dismiss/
  +Task/Components actions. This is exactly the shape of a triage record I'd keep in an engagement.
- 👍 Task **provenance with on-disk trace files** (prompt/response/system) is the reproducibility
  story RE teams need — you can audit exactly what the agent saw and said.
- 👎 **Two near-duplicate suggestion blocks.** The detail shows **FOLLOW-UPS** (▷, "Generate a fuzz
  harness for cgi_handler" / "Sweep sibling targets for the same strcpy sink") *and* **SUGGESTED
  NEXT STEPS** (✧, "Generate a fuzz harness for cgi_handler" / "Sweep siblings for the same strcpy
  sink") — essentially the same two actions twice, with different icons. It's unclear which to click
  or how they differ (schema followups vs the suggester seam?). Merge them, or clearly label the
  provenance of each ("from finding" vs "suggested").

---

## 4. Closing the loop — follow-up spawn, cross-target sweep, triage

**One-click follow-up → pattern sweep.** From the critical finding I clicked the follow-up
"Sweep sibling targets for the same strcpy sink." It opened a **pre-filled "Launch pattern sweep"
modal** (badged *Follow-up*) whose context preview carried the parent context forward: `prior_findings`
(`[crit] Stack buffer overflow…`), `related_findings`, and `graph_relations` (`relates to:
usr/lib/libupnp.so`), `~225 tok · 8 items`. Launching it produced a new **HIGH** finding
"Same strcpy sink pattern in usr/lib/libupnp.so" on the sibling, with a new `ssdp_recv → strcpy`
subgraph joined to the original finding by the orange `related_to` edge.

- 👍 **This is the product's thesis working in front of me.** target → task → finding → graph →
  spawn next task, and the graph ends up showing the *same* `strcpy` sink in two binaries linked by
  a `related_to` edge. For firmware work (shared libs reused across services) this cross-target
  pivot is genuinely valuable and is the feature I'd actually adopt this tool for.
- 👍 Context carry-over is real: the follow-up's prompt preview includes the parent finding and the
  graph relationship, so the agent isn't starting cold.
- 👎 **README oversells "one click."** The follow-up opens a pre-filled launch modal that still needs
  a "Launch agent" confirmation. The pre-fill is good UX (you can tweak budget/model first), but the
  docs should say "opens a pre-filled launch" rather than "spawn the next task in one click."
- 👎 The pattern-sweep modal header reads "on sbin/httpd" even though the sweep's *result* lands on
  the sibling `libupnp.so`. The target-of-record vs target-swept distinction is muddy in the header.

**Triage.** Accept/Dismiss on a finding, plus a clickable status workflow
(new → triaging → confirmed → reported). Accepting bumped a severity summary row at the top of the
findings list (●1 critical / ●1 high / ●3 info, color-coded) and recolored the finding's left border.

- 👍 The severity summary counts + color-coded left borders give instant triage-state-at-a-glance.
- 👎 **"Accept" maps to status "confirmed."** Two different vocabularies for one action
  (button says Accept, resulting status says confirmed). Pick one verb.
- 🐞 **BUG — stale status in the detail panel after triage.** Clicking **Accept** (or the status
  pills) updates the backend and the findings *list* correctly, but the **open detail panel's status
  control does not re-render** — it keeps showing `new` highlighted until you click away and
  reselect the finding. Verified end-to-end: after accepting two findings the API
  (`GET /api/projects/{id}`) reports them as `confirmed`, yet the detail panel still showed `new`.
  Repro: select a `new` finding → click Accept → detail panel status stays `new` (list flips to
  confirmed). This is the one outright defect I hit; it undermines trust in the triage state.

---

## 5. The graph, the toolbar, and search

The center pane is a Cytoscape graph with a color legend (firmware / executable / library / function /
finding) and a node counter (`78 nodes` → grew to `84` after tasks). A toolbar offers **Node**,
**Edge** (manual graph authoring), **Report**, **Compare**, **Same-code**, plus zoom/fit controls.

- 👍 After the two analysis tasks the graph genuinely *tells the story*: `sbin/httpd → cgi_handler →
  strcpy` (critical) and `libupnp.so → ssdp_recv → strcpy` (high), joined by a `related_to` edge.
  This is the picture I'd want to paste into a report — the shared sink across two binaries is
  immediately obvious.
- 👍 **Report** produces a clean, **confirmed-findings-only** report ("Confirmed findings: 1 critical,
  1 high") with category/target/confidence/status, description, reasoning, **decompiled snippet**,
  and provenance per finding, plus **Copy** and **.md export**. Triage drives the report — exactly
  right. This is a real deliverable, not a debug dump.
- 👍 **Global search** is a categorized autocomplete spanning findings, symbols, strings, and
  functions, with an honest caveat: *"body search covers only decompiled functions; undecompiled
  code is not yet searchable (run static_analysis/decompile to widen)."* Setting that expectation
  in-line is the right call.
- 👍 Manual **Node/Edge** authoring means a researcher can record their own hypotheses/entities, not
  just agent output. Good for a notebook that mixes human + AI work.
- 👎 With ~84 nodes the auto-layout already crowds labels ("Attack-surface summ…" truncated, finding
  diamonds overlapping). On real firmware (hundreds of functions) this will need clustering,
  collapse-by-target, or a "focus this subtree" mode, or it won't scale past the demo.
- 💡 `Compare` / `Same-code` aren't self-explanatory from their labels — a tooltip or one-line
  caption ("Same-code: highlight clone relationships across targets") would help discovery.

---

## 6. Tasks, failure handling, and provenance

The **Tasks** tab lists every run with timestamp, finding count, backend, **per-task cost**
(`$0.0000`), and status, with sort + type filters. I ran `error_timeout` to test failure.

- 👍 The failed task is recorded as **failed** (red), produced **0 findings** (no spurious finding),
  and exposes a **Re-run** button. Graceful, honest failure — important for trusting an agent loop.
- 👍 Every task carries **provenance**: bundle id, params, and on-disk trace artifacts
  (`bundle.json`, `prompt.txt`, `response.json`, `system.txt`, `error.txt`). For an auditable RE
  workflow this is exactly what you want — you can reconstruct what the agent saw and said.
- 👎 **Trace artifacts are named but not viewable.** `error.txt` (and `prompt.txt`, etc.) render as
  plain `<span>`s, not links. When a task fails, the UI gives me a filename but not the *reason* —
  I'd have to leave the app and open `~/.hexgraph/.../error.txt` by hand. Surfacing the failure
  message inline (and making trace files openable) would close a real gap.

---

## 7. Settings & the security story

`/settings` is well-organized: **Model access** (default backend, model preference, and
`ANTHROPIC_API_KEY` / `HEXGRAPH_API_KEY` shown **presence-only** as "not set"), **Ghidra integration
· optional**, **Fuzzing · optional · executes code**, and **Server** (bind host/port).

- 👍 The product's security posture is surfaced *in the UI*, not buried in docs: "API keys are never
  stored or transmitted… BYOK only," loopback-bind enforcement explained, and the **Fuzzing toggle
  is explicitly labeled "executes code"** with a warning that it relaxes the static-only policy
  (still `--network none`, capped, disposable). That explicit, opt-in consent is exactly what a
  careful researcher wants to see before anything runs the target's code.
- 👍 It respected my isolated `HEXGRAPH_HOME` — the footer shows `/tmp/hexgraph-eval/config.toml`,
  `/tmp/hexgraph-eval/settings.json`, and `docker ✓ available`. Transparent about where state lives.
- 👎 **Docs/feature drift:** the README roadmap lists "live fuzzing" as *out of scope (by design)*,
  but Settings now ships an opt-in **Fuzzing** feature (libFuzzer harness execution). Either the
  feature is intended (update the README) or the toggle shouldn't be there. A VR comparing the
  README's stated scope to the actual UI will be confused.

---

## 8. Can you live in the UI? (project/target creation)

- 👍 **New project** is an inline form (name + backend + Create) right on the landing page.
- 👍 **+ Add** in the target tree opens a native file picker (hidden `input[type=file]`), so you can
  ingest/upload a binary from the UI — the whole loop (create project → upload target → run → triage
  → report) is doable without ever touching the CLI. That's the right answer for adoption.
- 💡 I couldn't tell from the UI whether upload-ingest runs recon automatically (as the CLI does) or
  what happens with large firmware. A progress indicator / "ingesting… unpacking…" state would
  reassure during the (potentially slow) sandbox unpack.

---

## 9. Feature expectations I had that weren't there

As a VR, a few things I reached for and didn't find:

- **View the actual decompilation / trace files in-app.** The context preview shows a token count and
  says "decompilation added at run time," and findings have a DECOMPILED section, but I can't open
  the full decompiled function or the raw prompt/response the agent used. That's the highest-value
  context to inspect when judging a finding's validity.
- **A `links_against` dependency edge** between `httpd` and `libupnp.so`. Recon reported 0; for
  firmware triage, "which binary loads which library" is a first-class question and a natural
  auto-derived edge (NEEDED/DT_NEEDED from the dynamic section).
- **Diffing / versioning** across firmware versions (a huge real-world VR use case: "what changed
  between v1.0 and v1.1?"). `Compare` hints at this but it's target-vs-target, not version-vs-version.
- **Export of the graph itself** from the UI (CLI has `graph --export`; I didn't find a UI button).
- **Bulk triage** from the list (the API has `findings/bulk-status` and the list has checkboxes, so
  this may exist — but it wasn't obvious how to act on a multi-select).
- **CWE / CVE tagging** on findings — `memory-safety` is a category, but a CWE id (CWE-121 here)
  would slot straight into a report and into dedup across targets.

---

## 10. Summary — would I adopt it?

**Yes, with caveats — and the core idea is genuinely compelling.** HexGraph nails the thing that
matters: it turns "run an AI over a binary" into a *structured, auditable, navigable* workflow.
The finding schema, the typed graph, the context-preview-before-spend, per-task cost/budget, the
triage-driven report, and the honest security posture are all things I'd actually want in an
engagement. The cross-target pattern-sweep loop (same `strcpy` sink found in two binaries, linked in
the graph) is the demo that would make me say "yes, this saves me time on firmware."

### What works well
- The **Launch modal's live context preview + token/cost** — best-in-class trust feature.
- The **finding → graph → follow-up → cross-target sweep** loop actually delivers the thesis.
- **Triage-driven, exportable Report** scoped to confirmed findings.
- **Provenance everywhere** (bundle, params, trace files) and **graceful failure** with Re-run.
- **Security surfaced in the UI**: presence-only keys, loopback enforcement, "executes code" consent.
- **Honest in-product caveats** (search coverage), **per-task cost meter**, isolated-home respect.

### What's rough / unintuitive
- **Hover-gated `Run` launcher** — no cue that targets are runnable (discoverability).
- **Duplicate "Follow-ups" vs "Suggested next steps"** blocks — confusing, looks redundant.
- **Vocabulary split**: button "Accept" → status "confirmed"; "Mock scenario" shown for all backends.
- **INFO severity + "high" confidence** sit adjacent with no labels — easy to misread.
- **Graph crowds** even at ~84 nodes; needs clustering/collapse to scale to real firmware.

### What broke
- 🐞 **Stale finding status in the detail panel after Accept/Dismiss** (backend + list update;
  detail panel keeps showing `new` until reselect). Verified against the API. Top fix priority.

### Highest-value additions
1. **In-app trace/decompilation viewer** (open `prompt.txt`/`response.json`/`error.txt`, view the
   decompiled function). Turns "trust me" into "show me."
2. **Surface the failure reason inline** on failed tasks (don't just name `error.txt`).
3. **Auto-derive `links_against`** from the dynamic section for firmware dependency edges.
4. **Firmware/version diffing** — the single biggest real-world VR workflow not yet served.
5. **Graph scaling** (collapse-by-target, focus-subtree) before this meets real firmware.

### Docs to fix
- Unify target naming (`sbin/httpd` vs `vuln_httpd`) across README sections.
- "one-click follow-up" actually opens a pre-filled launch modal — reword.
- README roadmap says "live fuzzing — out of scope," but a Fuzzing feature now ships in Settings.
- Quickstart: state that `ingest` auto-inits the DB (or drop the separate `init` step).

