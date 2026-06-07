# Design: the working-memory layer — journal + elevated hypotheses

**Status:** proposed / design (not yet implemented)
**Scope:** a freeform markdown **journal** and an elevated **hypothesis task list**, plus the agent tooling, guidance, and discipline loop that make both reliable.
**Why this doc exists:** to capture the full design discussion in one place so the work can be picked up cold if the session is lost. Read it top to bottom before building; the sequencing plan and open questions are at the end.

---

## 1. Summary

HexGraph proves one loop today: `target → task → structured finding → graph → next task`. That loop captures **results**. What it doesn't capture is **intent and reasoning** — what we believe, what we're chasing, what we already tried and ruled out, and why.

This adds that missing layer in two surfaces that are really one thing — **a shared working memory between the human and the agent**:

- **Journal** — a freeform, timestamped, markdown notebook. Each entry is attributed to a human or an agent and answers four prompts: what idea I had, what I tried, what worked/didn't, what I learned. Entries can `@`-mention any graph object (node, finding, target, hypothesis) as a clickable link that selects it in the graph.
- **Hypotheses as a task list** — the existing `hypothesis` node, promoted from a side concept into the live worklist of "things the human and agent are currently working on," with a real panel to see/sort/filter/close them, and decoupled from the graph canvas so they don't clutter it.

The visible deliverable is two panels and an editor. The **actual** deliverable — the thing that decides whether this is useful or dead weight — is the **discipline loop** (Section 6) that guarantees the agent keeps these stores current under a long, tool-heavy session, plus the **taxonomy** (Section 3) that keeps the five stores from blurring into each other.

Frame both features to the user as one mental model: **your research notebook.** Two halves (open questions + narrative), one idea.

---

## 2. Motivation

The graph, findings, and Observation store are excellent at *facts*. They're poor at *story*. A researcher returning to a project after a week — or an agent resuming in a fresh session — has no place that answers "where were we, what did we believe, what dead ends are already burned." Today that context lives only in the human's head and evaporates between sessions.

Two concrete payoffs justify the build:

- **Cross-session memory for the agent.** `journal_search("what did I try on the CGI handler")` lets a later session re-orient in one call instead of re-deriving everything. This is arguably the single highest-value agent-facing use.
- **Trust and oversight for the human.** Reading the journal + the open hypotheses tells you exactly what the agent has been doing and which leads are worth chasing, without spelunking the tool-call trace.

A third payoff lands later: the journal is the natural narrative source for the engagement report (`engine/report.py`), turning the writeup from a findings dump into a story.

---

## 3. The taxonomy — the single most important decision

After this ships, a fact can land in **five** stores. If the lines between them are fuzzy, both the human and the agent suffer "where does this go?" paralysis and every store rots. Nailing this taxonomy is **Phase 0** — cheaper than any code and the thing that prevents the expensive mistake.

| Store | What it holds | Who writes it | Shape |
|---|---|---|---|
| **Findings** | Substantiated, structured results (a vuln, a verified PoC, a recon summary) | human + agent | frozen Finding schema |
| **Graph nodes/edges** | The curated map — functions, strings, sockets, the relations between them | human + agent | typed nodes + attributed edges |
| **Hypotheses** | Falsifiable open questions you're actively chasing | human + agent | `hypothesis` node + evidence edges |
| **Observation store** | Raw, deterministic tool output (decompiler text, strings, binutils facts), auto-cached | machine (every read tool) | append-only, searchable |
| **Journal** *(new)* | Interpreted narrative — ideas, attempts, dead ends, lessons | human + agent | freeform markdown |

**The two dangerous overlaps, and the lines that resolve them:**

- **Journal vs. Observations.** Both are "stuff recorded over time," so they blur. The line: Observations are *raw machine output*, append-only, never interpreted — the cache of what a tool returned. The journal is *what it means and what I did about it*. An agent that pastes decompiler output into the journal, or writes reasoning into an Observation, has failed.
- **Hypotheses vs. Findings.** A hypothesis is a *claim you're chasing and could be wrong about*; a finding is a *result you've substantiated*. The agent must not mint a hypothesis for every fact, nor a finding for every hunch. A hypothesis that pans out is *promoted to* a finding (and linked as supporting evidence), it doesn't *become* one in place.

This taxonomy is authored **once** as the single source of truth (Section 7) and rendered into the human docs, the agent skill, and the in-process prompt. It must not be written four times and allowed to drift.

---

## 4. Hypotheses: from node to task list

### 4.1 What exists today

Already a first-class concept in [`engine/hypotheses.py`](../../src/hexgraph/engine/hypotheses.py):

- A `hypothesis` **node** with `attrs_json` carrying `statement`, `rationale`, `status`, `status_origin`.
- Evidence attaches as `supports` / `refutes` **edges** (`finding → hypothesis`). `confirms`/`contradicts` are accepted aliases.
- `status` ∈ `{open, supported, refuted, contested}` is **derived** from the evidence, unless a human pins one of the two sticky **verdicts** `{confirmed, rejected}` (`status_origin = "human"`).
- `open_for_target()` feeds open/supported/contested hypotheses into a target's **task context** ([`engine/context.py`](../../src/hexgraph/engine/context.py)), so the agent already reasons against the live question set.
- MCP tools: `graph_create_hypothesis`, `graph_link_evidence`, `graph_set_hypothesis_status`.
- UI: [`HypothesisPanel.tsx`](../../frontend/src/components/HypothesisPanel.tsx) is a **detail view only** (rendered in the inspector when a hypothesis node is selected). There is no list/board surface. Hypothesis nodes render on the canvas as amber pentagons whether or not you want them there.

The backend model is most of the work. What's missing is a panel and two small model additions — which is why **hypotheses go first**.

### 4.2 The missing axis: work-state ≠ evidence-state

The current `status` describes what the **evidence** says. A task list also needs to know whether you're still **working** it — and those are orthogonal. A hypothesis can be `supported` but parked, or `open` (no evidence yet) but the thing you're actively chasing versus sitting in the backlog.

Add a **work-state** dimension, distinct from the evidence verdict:

- `work_state` ∈ `{active, parked, done}` — *am I on this?*
- `status` (existing) ∈ `{open, supported, refuted, contested, confirmed, rejected}` — *what does the evidence say?*

The user's "check it off as proven/unsubstantiated" maps cleanly: **checking off = `work_state → done`**, and the *reason* it closed is the evidence `status` (proven ≈ `confirmed`/`supported`-and-done; unsubstantiated ≈ `rejected`/`refuted`-and-done; abandoned ≈ done with no verdict). The panel's checkbox sets `done` and offers to record the verdict. Don't overload `confirmed`/`rejected` to also mean "closed" — "I proved it" and "I stopped looking" are different facts.

**Storage is cheap:** `status` already lives in `attrs_json` (a JSON column), so `work_state` and the graph-visibility flag below go there too — **no migration needed** for the hypothesis changes. At the expected scale (tens to low hundreds of hypotheses per project) the panel loads all and filters in Python; promoting these to real, queryable columns is a later optimization, not a v1 need.

> Final vocabulary (`active/parked/done`) is an open question — see Section 11. The user floated "unsubstantiated/proven"; reconcile that as evidence-verdict language layered on the close action.

### 4.3 Decouple existence from graph visibility

The user's instinct ("maybe not every hypothesis is a node, hidden/shown as the user sees fit") resolves cleanly: **keep every hypothesis as a node in the model** (the evidence-edge algebra is the entire point) but **decouple whether it renders on the canvas.**

- Add `attrs.pinned_to_graph` (default **off**).
- The canvas hides hypothesis nodes unless pinned; they live in the new panel instead.
- A per-hypothesis "pin to graph" toggle in the panel/detail surfaces the ones a researcher wants visually anchored next to their evidence.

This is a **net reduction** in current clutter — today every hypothesis is an unavoidable amber pentagon.

### 4.4 The panel

A new right-pane tab, **mirroring `FindingsPanel`** (proven sort/filter/checkbox pattern — no new UI vocabulary):

- List of hypotheses with statement, evidence `status` badge, `work_state`, count of linked evidence.
- Sort by recency / work-state / strength of evidence; filter by `work_state` and `status`.
- A checkbox to close (`work_state → done` + optional verdict), and bulk close.
- Click a row → the **existing** `HypothesisPanel.tsx` renders in the detail split (already wired), showing supporting/refuting evidence and the linked objects.
- The detail pane gains a back-reference list: **journal entries that mention this hypothesis** (Section 5.5).

> Naming note: the new list component is `HypothesesPanel.tsx` (plural); the existing `HypothesisPanel.tsx` (singular) stays as the detail view. Keep them distinct.

### 4.5 New MCP tools (stay under the `graph` domain)

Keep hypotheses under `graph_*` to avoid churning every mock fixture and doc. Add the task-list verbs:

- `graph_list_hypotheses` (read) — list with `work_state`/`status` filters. Backs the panel and the agent's "what am I working on" orient.
- Extend `graph_set_hypothesis_status` to also accept `work_state`, **or** add `graph_close_hypothesis` (set `work_state=done` + record verdict). Lean toward extending the existing tool plus a thin `close` convenience.

`work_state` values must be an **importable constant** (e.g. `hypotheses.WORK_STATES`) imported into both `meta_get_schemas` and the catalog enum — never hand-typed (the strict MCP convention; the guard test enforces it).

---

## 5. Journal

This is the real lift — new table, new MCP domain, and the frontend's first markdown/editor dependency.

### 5.1 Data model (new tables → migration mandatory)

Journal entries are **not** graph nodes. They're freeform narrative, don't participate in the edge algebra, and making them nodes would pollute dedup, the canvas, task context, and the typed-node vocab for zero benefit.

`journal_entry`:
- `id` (uuid), `project_id` (scoped per project, like hypotheses)
- `author` ∈ `{human, agent}`
- `body` (markdown text)
- `created_at`, `updated_at`
- `origin_task_id` (nullable) — which agent task/session produced it; powers the staleness counter and the "what has the agent been doing" story
- `edited` flag / lightweight history (see Section 11 on how deep to go in v1)

`journal_mention` (join, populated by parsing `body` on save):
- `entry_id`, `ref_kind` ∈ `{node, finding, target, hypothesis}`, `ref_id`

The mention join exists so back-references are queryable ("entries mentioning hypothesis H") without scanning every entry's markdown. Both tables ship in one Alembic `--autogenerate` migration committed with the models (non-negotiable repo rule).

### 5.2 Authorship rule (the permission invariant)

- The **agent** may add new entries and edit/delete **its own** (`author = "agent"`) entries. It may **never** touch a human entry.
- The **human** may edit/delete **anything** — it's their workbench.

Enforce in the MCP write path: `journal_add` forces `author = "agent"`; `journal_update`/`journal_delete` refuse when the target entry's `author != "agent"`. The asymmetry is deliberate and should be stated in the tool descriptions.

Because the journal is a **trust artifact**, lean toward append-friendly: at minimum mark edited entries; full versioning is deferrable (Section 11).

### 5.3 `@`-mentions

**Syntax stored in the markdown:** `@[label](kind:id)`, e.g. `@[parse_cgi](node:abc-123)` or `@[stack overflow in handle_post](finding:def-456)`. The `kind:id` pair is what the mention join extracts and what the renderer resolves.

**Typeahead:** typing `@` opens an inline popover at the caret that searches as you type. **Reuse the existing resolver** — the header search popover already does debounced typeahead over targets/nodes/findings via the search endpoint; extend it to include hypotheses and render it positioned at the text caret (caret positioning is the only genuinely new bit; the search and result-click logic already exist). Completing a name or clicking a result inserts the `@[label](kind:id)` link.

**Click behavior:** a rendered mention calls the existing `focusOn(id)` / `viewFinding(id)` selection plumbing in [`Workspace.tsx`](../../frontend/src/pages/Workspace.tsx) — selecting the object in the graph and opening its detail.

**Link stability (a real correctness trap, not hygiene):** graph objects get **merged** (`nodemerge` folds duplicates and moves edges to the keeper) and **archived** (hidden but restorable). A mention storing a raw id will dangle. The renderer must:
- resolve `(kind, id)` through the merge keeper at render time, and
- degrade a dead/archived target to a greyed-out, non-crashing "dangling reference," not an error.

### 5.4 Markdown rendering & editor

The frontend has **no** markdown or editor dependency today, so this is the heaviest single addition.

**Security is a real boundary here, not just XSS hygiene.** Agent-authored journal content derives from analyzing **hostile targets** — an agent may quote an attacker-controlled string pulled from firmware into an entry. The renderer must treat **all** journal markdown (human and agent) as untrusted: `react-markdown` + `rehype-sanitize`, **no raw HTML**, mentions rendered via a custom component (not arbitrary anchors).

**Editor choice (v1 recommendation: stay lean).** Two paths:
- *Lean:* a plain textarea / contenteditable for the markdown source + a custom `@`-typeahead overlay + a live `react-markdown` preview. Minimal new deps, reuses the search resolver.
- *Rich:* a WYSIWYG editor (TipTap/ProseMirror or Lexical, both have mention plugins). Nicer, but the largest dependency the frontend would carry.

Recommend **lean for v1** (source + preview + typeahead), defer WYSIWYG. Confirm with the user — Section 11.

### 5.5 The panel

A new right-pane tab (the third notebook surface alongside the hypotheses tab):

- A **timeline** of entries, newest first: author badge (human/agent), timestamp, rendered (sanitized) markdown, mention chips.
- A **compose** box (the editor appears only when composing — not an always-on rich editor eating panel space).
- Filter by author / date / mentioned object.
- Back-references: an object's detail pane (node/finding/hypothesis) lists the journal entries that mention it, closing the loop — read a hypothesis, see the narrative trail that worked it.

---

## 6. The discipline loop — the make-or-break

The hardest requirement the user named: **the agent must not forget to update the journal/hypotheses across a long tool-calling session.** You cannot solve this with a "remember to journal" tool the model volunteers to call — across a long session a non-blocking reminder gets deprioritized and buried; the omission is the *default* outcome. The fix is structural, in three composing layers:

**Layer 1 — enforce at the task-completion seam.** LLM/agent tasks already produce *required* structured findings via the agent loop (`llm/runner.run_findings_agentic`). Make a session-log journal entry a **required closing output** the same way: the runner auto-drafts an entry from the tool-call trace (which tools ran, which targets, what changed in the graph) and the model fills the narrative (tried / worked / learned / next leads). Journaling becomes a structural step of *finishing a task*, like emitting findings — not an optional courtesy call. For the MCP driver/delegate path, the task wrapper checks the session produced/updated a journal entry and closes hypotheses it resolved.

**Layer 2 — nudge in context, mid-loop.** The same context seam that already injects open hypotheses (`engine/context.py` / `open_for_target`) injects a running reminder: *"N tool calls since your last journal entry; open hypotheses with no linked evidence: [...]."* This makes the omission visible **while** the agent works, so it records as it goes rather than only at the end. The nudge names the skill: "invoke the record-keeping guidance."

**Layer 3 — surface staleness to the human.** The notebook panels show "last agent entry: N tasks / M minutes ago" and flag hypotheses untouched for a while. A dark agent becomes visible to the human — itself a useful trust signal.

**How they compose:** the seam guarantees the floor (a task can't close without a log), the nudge raises in-session quality (record continuously, not just at the end), staleness gives the human oversight. The skill (Section 7) is what the agent *reads* to do all three well. **The skill is the "how"; the seam + nudge are the "you must, now."** A skill alone — invoked at the model's discretion — reproduces the exact forgetting failure, so it can never be the enforcement mechanism.

---

## 7. Agent guidance & the skill

The user's idea — formalize the hypothesis/journal instructions as a `SKILL.md` invoked when needed — is right, with three refinements grounded in how guidance actually reaches agents in this repo.

### 7.1 It already half-exists

The VR skill is a **generated** `SKILL.md`: [`agent_setup.py`](../../src/hexgraph/agent_setup.py) defines `SKILL = """..."""` and `write_skill()` emits it to `hexgraph-vr/SKILL.md`. It already has a **`## 3. Record AS YOU GO`** section teaching the hypothesis tools. So the question isn't "should this be a skill" — it's "factor record-keeping into its own progressively-disclosed unit, and make it reach *every* agent path."

### 7.2 Two audiences, one source of truth — the gap that bites

Guidance reaches agents through two completely different paths:

- **Driver / delegate mode** (external Claude Code / Codex with the installed `hexgraph-vr` skill) — *can* invoke `SKILL.md` files. This is who the "invoke when needed" idea naturally serves.
- **The in-process BYOK agent loop** (the **default** path, the one `just demo` runs) — uses a separate, slim system prompt: [`llm/prompting.py`](../../src/hexgraph/llm/prompting.py) `system_prompt(task_type)`, ~45 lines. It has **no skill mechanism** and never sees `SKILL.md`.

So a skill-only design **silently skips the default backend.** Resolve with one-source-of-truth, two delivery paths: author the rubric **once** as an importable constant (the repo's "define once, import into both surfaces" discipline — same as the MCP enum/`meta_get_schemas` rule), then render it into:
1. the generated skill (for skill-capable agents), and
2. a compact form in `prompting.system_prompt` + the full reminder injected by the Layer-2 context nudge when staleness is detected (so every prompt isn't bloated with the whole rubric).

### 7.3 Structure & placement

- **Keep ONE skill.** A separate `hexgraph-record-keeping` skill would compete with `hexgraph-vr` on triggering and force disambiguation between two VR-ish skills. Factor record-keeping into a referenced unit *within* the VR skill — either a tightened in-body section or, for true on-demand "invoke when needed" disclosure, a sub-file `hexgraph-vr/record-keeping.md` that `SKILL.md` points to (requires `write_skill()` to emit more than one file — a small change it doesn't do today).
- **It does NOT go in `.claude/skills/`.** That directory is for the agent *operating on the HexGraph repo* (e.g. `ux-assessment`, which drives the UI via Playwright). The record-keeping guidance is for the *target-analysis* agent and belongs with the generated VR skill in `agent_setup.py`, installed into the user's agent config.
- **Define the rubric as an importable constant** (e.g. `RECORD_KEEPING` in one module) consumed by `agent_setup.SKILL`, `prompting.py`, and the context nudge. Ideally the human-facing taxonomy in this doc and the agent-facing rubric trace to the same source (or a test asserts they match) so they can't drift.

### 7.4 What the rubric contains

- The **five-store taxonomy** and the decision rules from Section 3 (what goes where; the two overlaps).
- The **hypothesis rubric**: what makes a good falsifiable hypothesis (not a fact — facts are nodes/findings); the lifecycle `active → link evidence → done with verdict`; when to create vs. when something is really a finding/node; when to pin to the graph.
- The **journal rubric**: the four prompts (idea / tried / worked / learned); *when* to write (at task close **and** at each meaningful pivot or dead end, not just the end); the authorship rule; keep entries skimmable.
- **2–3 worked examples**: a good hypothesis vs. a bad one, a good journal entry, an anti-example (raw tool output dumped into the journal). Skills are far more effective with concrete examples than with rules alone.

### 7.5 Sync discipline

The repo already requires tool changes to propagate to "the VR SKILL (`agent_setup.py`) and `docs/mcp.md` in the same PR." This work slots into that existing discipline: the rubric source-of-truth lives where the sync already points, and the human docs + this design doc quote/import the same text.

---

## 8. MCP surface

Per the strict conventions in `CLAUDE.md` (enforced by `tests/test_tool_contract.py`):

**New `journal` domain** — must be added to the allowed-prefix set in the guard test.
- `journal_add` (write) — new entry; forces `author = "agent"`.
- `journal_list` (read) — entries newest-first; filter by author/date/mention.
- `journal_get` (read) — one entry in full.
- `journal_search` (read) — search over entry bodies. Description **leads with the corpus** and disambiguates the siblings: *"Search the freeform research JOURNAL (interpreted narrative notes) — not Observations (raw tool output, obs_search) or findings (finding_list)."*
- `journal_update` (write) — refuses when `entry.author != "agent"` (authorship rule at the tool layer).

**Hypotheses** (stay under `graph_*`): `graph_list_hypotheses`, plus `work_state` on the existing status tool / a `graph_close_hypothesis` convenience (Section 4.5).

**Conventions to honor:**
- Function names drop the domain prefix: advertised `journal_add` ↔ function `add_journal_entry`, `journal_search` ↔ `search_journal`, etc. Watch for collisions with existing engine functions.
- Closed value-sets (`author`, `work_state`) are schema `enum`s imported from one source of truth, never hand-listed.
- Journal/hypotheses are **core** (no policy gate), so **no `Gated:` clause** — they sit behind the `features.mcp.{read,write}` grouping like other tools.
- Descriptions lead with what the tool operates on and reference siblings by current name (the three searches `graph_search`/`obs_search`/`journal_search` must each say which corpus they hit).
- Propagate every rename/addition to the VR skill + `docs/mcp.md` in the same PR.

---

## 9. API & frontend surface

**REST** (new router `api/routers/journal.py`, mirroring `observations.py`):
- `GET/POST /api/projects/{id}/journal` (list / create)
- `GET/PATCH/DELETE /api/journal/{eid}`
- `GET /api/projects/{id}/journal/search?q=`
- Hypotheses: `GET /api/projects/{id}/hypotheses` (list with `work_state`); the detail endpoint already exists (`api.hypothesis`).

**Frontend** (all additive — existing components untouched):
- `JournalPanel.tsx` — new right-pane tab (timeline + compose).
- `HypothesesPanel.tsx` — new right-pane tab (list, mirrors `FindingsPanel`); the existing `HypothesisPanel.tsx` detail view is reused as-is.
- A shared **mention** component: resolves `(kind, id)` → label + `onClick` selection, greys danglers.
- `api.ts`: `journalList/create/get/update/delete/search`, `hypothesesList`.
- `GraphView.tsx`: read `pinned_to_graph`; hide hypothesis nodes unless pinned; per-hypothesis pin toggle.

**Reuse map:** `FindingsPanel` → hypotheses list template · header search popover + `focusOn`/`viewFinding` → mention resolver · right-pane tab + detail split → already exist (just add two tab options). The API client is plain `fetch` (`getJSON`/`postJSON`); no react-query, match that.

---

## 10. UI principles (anti-bloat)

The user's explicit worry. Hold these:

- **Reuse the right-pane tab pattern** (findings / tasks / campaigns → + hypotheses + journal). No new chrome, no new layout primitives.
- **Frame the two as one "notebook"** so the user learns one model, not two features.
- **Hypotheses off-canvas by default** — a net reduction in clutter.
- **Journal = timeline + compose**; the editor only appears when composing.
- **Engagement comes from payoff, not features.** Wire the journal into `report.py` and make `journal_search` real cross-session memory; when the notebook visibly saves work, people write in it.
- Judge every screen as a human would (per the `CLAUDE.md` UI rules + the `ux-assessment` skill): calm, hierarchical, modern — not merely complete.

---

## 11. Sequencing & phased plan

**Phase 0 — lock the taxonomy.** This doc + the `RECORD_KEEPING` source-of-truth constant (Section 3 + 7.4). Cheapest step, prevents the expensive mistake.

**Phase 1 — hypotheses (cheap, mostly migration-free).**
- `work_state` + `pinned_to_graph` in `attrs_json` (no migration).
- `HypothesesPanel.tsx` tab (list / sort / filter / close).
- Graph visibility default-off + pin toggle.
- `graph_list_hypotheses` + `work_state` on the status tool / `graph_close_hypothesis`.
- Layer-2 nudge for stale/unevidenced hypotheses.
- Hypothesis rubric into the skill + in-process prompt.
- No heavy frontend deps. Ships value fast and de-risks the data model.

**Phase 2 — journal (the lift).**
- `journal_entry` + `journal_mention` tables + **migration**.
- REST router; MCP `journal_*` tools + guard-test prefix.
- Sanitized markdown render (`react-markdown` + `rehype-sanitize`).
- Lean composer (`@`-typeahead reusing the search resolver; no WYSIWYG).
- `JournalPanel.tsx` tab; authorship enforcement; mention link-stability.
- **The discipline loop**: task-completion seam (auto-draft + required close) + staleness surfacing.
- `journal_search`; journal rubric into the skill + prompt.

**Phase 3 — payoff & polish (deferred).**
- Journal as `report.py` narrative source.
- Cross-link back-references in all detail panes.
- WYSIWYG editor; edit history / audit depth.
- Optional: materialize mentions as graph edges (default no).

---

## 12. Open questions / decisions for the human

1. **`work_state` vocabulary** — `active / parked / done`? And how the panel's "check off" surfaces the evidence verdict (the user floated "unsubstantiated / proven"). Reconcile the two axes' wording.
2. **Editor library** — lean (textarea + preview + typeahead) for v1 vs. WYSIWYG (TipTap/Lexical) now. Recommendation: lean.
3. **Hypotheses domain** — keep `graph_*` (recommended, avoids fixture/doc churn) vs. a new `hyp_*` domain now that they're top-level.
4. **Mentions as graph edges** — default no (lightweight references). Revisit only if you want mentions to show on the canvas.
5. **Journal edit history depth in v1** — "edited" marker only vs. full versioning. Recommendation: marker now, versioning later.
6. **Skill structure** — tightened in-body section vs. a referenced `record-keeping.md` sub-file (needs `write_skill()` to emit multiple files).
7. **Auto-journaling from non-LLM events?** (e.g. a fuzz crash → an auto note.) Recommendation: no — keep the journal human/agent-authored narrative; the crash is already a finding.

---

## 13. Key files to navigate (for a cold pickup)

- **Hypotheses:** [`src/hexgraph/engine/hypotheses.py`](../../src/hexgraph/engine/hypotheses.py) · [`frontend/src/components/HypothesisPanel.tsx`](../../frontend/src/components/HypothesisPanel.tsx) · `graph_create_hypothesis`/`graph_link_evidence`/`graph_set_hypothesis_status` in [`engine/mcp_catalog.py`](../../src/hexgraph/engine/mcp_catalog.py).
- **The store to differentiate from (Observations):** [`engine/observations.py`](../../src/hexgraph/engine/observations.py) · `api/routers/observations.py` · the `obs_*` tools.
- **Agent guidance:** [`src/hexgraph/agent_setup.py`](../../src/hexgraph/agent_setup.py) (`SKILL`, `## 3. Record AS YOU GO`, `write_skill`) · [`src/hexgraph/llm/prompting.py`](../../src/hexgraph/llm/prompting.py) (in-process system prompt) · [`engine/context.py`](../../src/hexgraph/engine/context.py) (`open_for_target` context injection — where the Layer-2 nudge hooks in).
- **Task loop (Layer-1 seam):** `llm/runner.run_findings_agentic` · `engine/agent_delegate.py`.
- **Frontend shell:** [`frontend/src/pages/Workspace.tsx`](../../frontend/src/pages/Workspace.tsx) (tabs, selection, `onGraphSelect`/`focusOn`/`viewFinding`, search popover) · [`components/FindingsPanel.tsx`](../../frontend/src/components/FindingsPanel.tsx) (the list pattern to mirror) · `api.ts` (plain-fetch client) · `GraphView.tsx` (canvas / node visibility).
- **Data model & migrations:** `db/models.py` · `migrations/` (Alembic, baseline `bbdb1d98bf54`) · `engine/nodemerge.py` (merge keeper, for mention stability) · `node.archived` (migration 0011) / `target.archived` (0007) (archived danglers).
- **MCP conventions & guard:** [`engine/mcp_catalog.py`](../../src/hexgraph/engine/mcp_catalog.py) · `tests/test_tool_contract.py` (enforces prefixes, enums-from-source, gating slot).

---

## 14. When this lands

Design docs here (`docs/design/`) are an ephemeral record of the plan and rationale only — expected to go stale as the code evolves and safe to purge wholesale, so the rest of the repo must stay coherent without them. Don't make a design doc load-bearing: do NOT add this doc to `CLAUDE.md`'s "Read before writing code" list or any required-orientation index, and don't make code behavior depend on one. (Soft `(see docs/design/…)` pointer comments in code and docstrings are an accepted convention in this repo and may dangle harmlessly if the docs are purged — those are fine.) What the feature PRs DO ship: propagate the new tools to the VR skill (`agent_setup.py`) + `docs/mcp.md` in the same PR, and write fresh user-facing feature docs (e.g. `docs/journal.md`, an updated graph-UI doc) in human prose per the `CLAUDE.md` docs rules.
