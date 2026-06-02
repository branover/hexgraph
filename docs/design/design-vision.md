# HexGraph Design Vision

> **⚠ Historical — v2 vision, partially superseded.** This document captures the v2
> target shape and is preserved for its data-model, graph-taxonomy, and workflow
> rulings (most of which shipped). **One foundational premise has since evolved:** the
> "the target is never executed / static-only" invariant below was *not* an absolute
> ban — it grew into the **graduated, opt-in policy seam** (`policy.py`): static-only is
> the enforced default, and `features.poc`/`features.fuzzing` (sandboxed execution),
> `features.network` (bounded local-network egress), `features.rehost` (full-system
> emulation), and `features.remote` (one authorized live device) each raise a higher
> tier behind its own gate. See **`CLAUDE.md`** and **`README.md`** for the authoritative,
> current security model, and `design-dynamic-surfaces.md` for the dynamic-surface
> design as shipped. Read §1's "never executed" / "out of scope: dynamic execution" lines
> as the v2 *starting point*, not today's product.

> **This is a design vision — the "what" and "why" — not an implementation plan.**
> It defines the target shape of the product, resolves the contradictions surfaced by
> the dimension proposals and adversarial critiques, unifies terminology, and makes
> opinionated rulings on the cross-cutting decisions nobody owned. A **separate
> implementation plan** (milestones, sequencing, task breakdown, acceptance criteria)
> will follow and will translate these rulings into work. Nothing here may violate the
> hard constraints restated in §1; where a proposal did, this document overrides it.

---

## 1. Executive summary & design principles

HexGraph is a self-hosted, local-only agentic vulnerability-research workbench. You point
it at a binary or firmware image; it ingests the target, breaks firmware into child
targets, runs AI-driven analysis tasks behind a single model-backend seam, and records
every result as a structured **Finding** in a SQLite-backed **typed graph** that links
targets, sub-file code objects, findings, and hypotheses. A loopback-only web UI browses
the graph, launches tasks from any node or edge, and triages findings.

The MVP (branch `build/hexgraph-mvp`) **proved the loop** — target → task → finding →
graph → spawn — mechanically. This vision evolves it from "proves the loop" into "a
researcher can actually break down a binary and a firmware image end-to-end," without
abandoning a single hard constraint.

### The one organizing principle

**Agents expand the search; humans collapse it.** Agents do breadth, recall, and drudgery
(decompile at scale, draft hypotheses, sweep siblings, generate harness boilerplate,
annotate functions). Humans do depth and judgment (choose attack surface, confirm or kill
a hypothesis, judge reachability, set spend, sign the report). Restated for storage and
workflow: **agents produce candidates** (claims carrying provenance + confidence);
**humans produce ground truth** (confirmed renames, confirmed hypotheses, accepted
findings, severity) — and human ground truth flows *back* into agent context so the system
gets smarter as the researcher works. HexGraph is an **instrument panel, not an autopilot.**

### Hard constraints (non-negotiable; every design below respects them)

- **Local-only / loopback.** API/UI bind `127.0.0.1`; startup assertion refuses non-loopback
  unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`. No HexGraph server, no telemetry, no auto-update.
- **BYOK / Claude Code / mock only**, behind one `LLMBackend` seam (`mock` default, offline).
  Read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never log or store it.**
  **Task code never branches on backend identity.**
- **Targets are hostile.** All target-byte handling runs in a disposable Docker sandbox
  (`--network none`, `--read-only`, resource caps, tmpfs, timeout). **The target is never
  executed** (static/RE only in v1). **The LLM never sees raw bytes — only tool output.**
- **The graph is relational** in SQLite via SQLAlchemy (UUID ids). **Neo4j is out of scope.**
- **The Finding is canonical** (`src/hexgraph/schemas/finding.schema.json`); every task and every
  backend emits exactly that shape. The schema has top-level `additionalProperties: false`,
  a closed `suggested_followups.items.task_type` enum, and `confidence` as a `low|medium|high`
  enum (all verified in code, mirrored by `extra="forbid"` Pydantic models).
- **Zero token spend by default.** `just demo` runs the full loop offline at $0.
- **Out of scope:** auth/multi-user/cloud, live fuzzing, dynamic/emulated execution, exploit
  generation, Kubernetes.

### Cross-cutting design rulings (the contradictions, resolved up front)

These are the bindings every section below obeys. They settle the collisions the consistency
and feasibility critiques flagged.

1. **Migrations are a committed prerequisite.** Adopt a real migration tool (Alembic or a
   hand-rolled runner) **before any schema-extending feature ships.** `create_all` never
   ALTERs existing tables, so "additive-with-defaults" silently fails to upgrade an existing
   project DB. **The project DB is durable researcher knowledge and must never be silently
   reset.** Add a `schema_version` and a backup-on-migrate step.

2. **The canonical Finding payload is frozen.** No section adds fields to
   `finding.schema.json` (no `asserted_edges`, no new `task_type` enum values, no new
   `suggested_followups` keys). All new linkage — `node` attachment, context provenance,
   triage state, run grouping — lives in the **DB envelope** (columns/tables/edges around the
   finding), never in the emitted payload. Agent-proposed edges are **derived deterministically**
   from existing emitted fields (`related_target_refs`, `evidence.function`, `evidence.sink`)
   plus `task.type` — not carried in the schema. If a future need truly forces a payload
   change, it is a deliberate, atomic schema + all-fixtures + contract-test change, never
   described as "free/additive."

3. **One node store.** A single relational table named **`node`** holds sub-file/conceptual
   nodes (`node_type` discriminator + `attrs` JSON). `target` stays the **artifact** table
   (things with bytes). `node` holds `function | symbol | string | struct | hypothesis |
   pattern | task`. We reject generalizing `target` into the node table (conflates bytes vs.
   concept and forces byte-handling loops to filter concept rows everywhere). **Owner: §3.**

4. **One edge model.** A single polymorphic **`edge`** table with `(src_kind, src_id)` /
   `(dst_kind, dst_id)` endpoints, **typed attribution columns** (`origin`, `confidence`
   float 0–1, `weight`, `directed`, `created_by_task_id`), and type-specific data in `attrs`.
   One canonical `EdgeType` enum. Edge confidence is stored as a float; the agent/API enum
   `low|medium|high` maps to `0.3|0.6|0.9`. **Owner: §3.**

5. **One context store.** A content-addressed store at `cas/` keyed by sha256, indexed by
   `context_bundle` + `context_item` tables, referenced by `task.context_bundle_id`. All
   caching (decompilation, bundles, response traces) folds into this one store. **Owner: §7.**

6. **One stable node identity.** Symbol/function identity is **content-addressed**:
   `node.content_hash` over the canonicalized decompiled body (or import-set fingerprint for
   symbols), with `fq_name` (`<artifact>::<symbol>`) and `address` as locators. This single
   scheme is what lets renames/annotations/findings/edges survive re-decompilation and
   tool/version changes (radare2 today, Ghidra later), and is the same key used for the CAS
   and for cross-binary "same code as." **Owner: §3, used by §7, §8.**

7. **Findings attach to nodes via an edge, not a column.** `persist_finding()` resolves the
   finest node (`function`/`symbol`) the evidence concerns and emits a typed, attributed
   `about` edge to it. We drop the proposed scalar `finding.node_id` column (a scalar cannot
   carry role/confidence/provenance and creates two write paths). `finding.target_id` stays
   as the coarse artifact pointer. The finding→target/function edge is named **`about`**
   project-wide (de-facto winner; supersedes the SPEC's `finding_in`).

8. **The task TYPE taxonomy stays the canonical five** (`recon`, `static_analysis`,
   `reverse_engineering`, `pattern_sweep`, `harness_generation`), optionally plus promoting
   the already-deterministic **`unpack`** to a named type. We reject the forked ~18-type
   explosion. The genuinely good idea — that work can interrogate a *relationship* or a *set*
   — is captured by the **task anchor** (§5), not by new dispatch types. Relational
   operations (trace-dataflow, diff, confirm-match, explain-link, boundary-taint) are
   **edge-anchored invocations of `static_analysis`/`reverse_engineering`** with an objective
   + params. Snake_case is the only naming convention.

9. **One triage axis.** A single widened `finding.status`: `new | triaging | confirmed |
   dismissed | reported`. `duplicate_of` is an edge, not a status; dismissal reason is a
   separate column. We reject a second parallel `triage_state` axis (the agent's certainty
   already lives in `confidence`). Provenance fields (`origin`, `supersedes`) are orthogonal
   envelope columns. **Owner: §8.**

10. **One notes/annotation store.** A dedicated `annotation` table keyed by `(node_kind,
    node_id)` for `rename | note | tag | type_decl`, with `origin (agent_proposed|human)` and
    `status (proposed|confirmed|rejected)`. Notes are attachments, not nodes. Tags live here
    and are the canonical findings-list filter facet. A **confirmed** rename is applied to the
    node's `attrs.name` with history. **Hypotheses are nodes** (they are edge endpoints).
    **Owner: §8.**

11. **One hypothesis model.** `hypothesis` is a node in the `node` table with status
    `open | supported | refuted | confirmed`. Not a separate table, not a Finding with
    `category:hypothesis` (reusing Finding pollutes triage stats and the closed schema can't
    carry hypothesis status). Edges into it are `supports` / `refutes`.

12. **One live-feedback transport.** Server-Sent Events at `GET /api/projects/{project_id}/events`.
    No websockets in v1.

13. **One token estimator.** A single deterministic `chars/4 + code multiplier` function used
    by the context packer, the preview endpoint, and any pre-launch display — so the number
    shown equals the number used for budgeting. Approximate by design; reconciled against
    actual `usage.cost_usd` after the run. Offline; no tokenizer download in the default path.

14. **Reproducibility & comparison are first-class, not open questions.** Identical inputs
    reproduce byte-identical bundles (and, via cassette, responses). **Different** runs over
    the same node are grouped by an `analysis_run` entity and diffable — this is what makes
    per-task model selection worth anything (§7, §9, §10).

15. **No false negatives asserted as fact.** Static reachability and search coverage are
    honest about incompleteness. Indirect/unresolved calls are marked; the UI never asserts
    "not reachable" or "not present" as fact, only "not found in the static call graph /
    not yet decompiled (N functions outstanding)." (§2, §10, §11)

---

## 2. How a researcher works: end-to-end workflows

Two personas exercise one loop at different scales. The **Bench RE** has one ELF and wants
*depth* (is there a real, reachable bug, can I demonstrate it). The **Firmware Triager** has
a 16 MB image and wants *prioritization* (which 3 of 40 binaries deserve my week). Firmware
triage **funnels into** single-binary deep-dive via the graph. The canonical loop, named
because every UI affordance maps to one move:

`ingest → triage attack surface → pivot to interesting code → hypothesize → confirm →
sweep siblings → harness → report`

At each step below, **M** = the manual (human) move, **A** = the agentic move.

### Workflow A — single binary deep-dive

| Step | Manual (human) | Agentic |
|---|---|---|
| **A1 Ingest** | one command (`hexgraph ingest ./httpd`) | `recon` auto-runs in sandbox, **$0, no LLM**; emits recon facts |
| **A2 Triage surface** | reads the **recon brief** (first screen, not an empty graph): weak mitigations, risky imports (`strcpy`/`system`/`popen`), notable strings; *orders* the function menu by danger | computes a **deterministic, LLM-free danger score** per function (risky-sink call × untrusted source × large frame/input loops); optionally annotates top functions ("parses Content-Length") |
| **A3 Pivot** | clicks `cgi_handler` node, launches `static_analysis` *scoped to that function* | sandboxed radare2 decompiles; recon facts + pseudocode → prompt; LLM reasons; finding returns |
| **A4 Hypothesize** | reads reasoning + snippet; **rules** (confirm / triaging / dismiss); a finding is a *hypothesis, not a fact* | proposes the candidate finding with `confidence`; offers a standard **`challenge` follow-up** that argues the null hypothesis |
| **A5 Confirm** | owns the go/no-go; judges reachability with caveats | assists with a static **caller-trace** to an entry point, emitting `calls` edges — **marking indirect/unresolved calls** so no negative reachability claim is asserted as fact |
| **A6 Harness** | takes the compiled harness to their own fuzzing rig (HexGraph never fuzzes) | LLM writes the harness; sandbox **compiles** it (gcc) and records the real build result; a build failure is **iterable** ("fix harness given this compiler error") |
| **A7 Report** | curates, sets severity, signs off | drafts prose; export composes confirmed/promoted findings with evidence + provenance |

### Workflow B — whole-firmware triage

| Step | Manual | Agentic |
|---|---|---|
| **B1 Ingest + unpack** | one command | sandboxed `unpack` explodes the image into child targets + `contains` edges; `recon` auto-runs on every child, **$0** |
| **B2 Triage board** | reads a per-binary **triage board** (deterministic priority: risky-import count, mitigation weakness, **known-vs-custom** via local baseline hash); sets a **sweep policy** (subset, model, budget) | the breadth **fan-out** — N sandboxed decompiles + N LLM passes, each emitting the *same Finding shape* so results are directly sortable/comparable |
| **B3 Pivot** | picks the hottest binary → drops into Workflow A | deep static on the chosen binary |
| **B4 Confirm one** | confirm gate (as A4–A5) | argues; caller-trace |
| **B5 Sweep siblings** (the graph payoff) | confirms/refutes each candidate; **audits coverage** ("swept 12, 2 matched, 1 uncertain, 9 clean") | `pattern_sweep` over a selection: signature match + LLM confirm; **creates a new finding homed on each matched sibling** and links it to the origin via an attributed edge (§5, §3) |
| **B6–B7 Harness + cross-target report** | curates the class | "this `strcpy` class affects 3 binaries; one confirmed instance + harness" |

**Always-on guardrails the workflow honors:** a projected-cost confirmation gate before any
real-backend batch; recon and the triage board stay **100% LLM-free** (any enrichment is an
explicit opt-in task through the seam so `just demo` stays $0); the system surfaces low-confidence
findings as `triaging` ("ask the human exactly when uncertain"); HexGraph proves *reachability
and pattern*, never *exploitation* — it does not overclaim.

---

## 3. The typed graph: node & edge taxonomy

The graph is the heart of the product and is modeled **relationally** (no Neo4j). Three SQL
tables carry it: `target` (artifacts), `node` (concepts), and one polymorphic `edge`.

### 3.1 Relational schema approach

- **`target`** — artifacts (things with bytes / unpack boundaries). Keeps all existing FKs.
  `kind ∈ {firmware_image, filesystem, executable, shared_library, kernel_module, data_blob,
  unknown}` (`filesystem` is new, making multi-partition images first-class). Recon facts live
  in `metadata_json`.
- **`node`** — sub-file concepts. **Single table, `node_type` discriminator, `attrs` JSON.**
  New types are zero-migration (a new enum value + handler). This matches the existing
  `params_json`/`evidence_json` pattern.
- **`edge`** — one polymorphic table; endpoints are `(kind, id)` pairs over `{target, node,
  finding, task}`.

### 3.2 Node taxonomy (the canonical vocabulary — issue #2 resolved)

| `node_type` | Represents | Key `attrs` / columns | Created by | Lifecycle |
|---|---|---|---|---|
| `function` | A decompiled routine | `address`, `fq_name`, `name`, `size`, `pseudocode_ref` (CAS sha), `content_hash`, `name_history` | `decompile` (lazy) | mutable name/summary |
| `symbol` | Import/export/PLT entry | `attrs.kind ∈ {import,export,local}`, `binding`, `library`, `is_sink` | `recon` (bulk, filtered) | durable |
| `string` | Notable literal | `value` (truncated; full in CAS), `encoding`, `section`, `xref_count` | `recon` (filtered allowlist) | durable |
| `struct` | Recovered type | `members_ref`, `size`, `inferred` | `reverse_engineering` | mutable |
| `hypothesis` | A human/agent claim | `statement`, `status ∈ {open,supported,refuted,confirmed}`, `confidence` | **human** (agent may propose) | first-class HITL node |
| `pattern` | A reusable vuln signature ("unbounded-strcpy") | `cwe`, `name`, `signature` | seeded catalog + sweeps | reused, not duplicated |
| `task` | A run, rendered as a node for provenance/live status | mirrors `task` row | engine | per task |

**Resolved clashes:** `struct` (not `data_type`). `import`/`export` are `symbol` with an
`attrs.kind` facet, not node types. `note` and `external_ref` are **not** nodes — notes live
in the `annotation` table (§8); external references are an `annotation(kind=external_ref)` or
a `vuln_class`/`pattern` linkage, **pasted/typed, never network-fetched**. `vuln_class` folds
into `pattern`. `region` is dropped (use `function`/`struct`). `pattern` and `task` are nodes
because edges point at them.

**Attributes & lifecycle rules:**
- **Stable identity (issue #6):** `node.content_hash` (canonicalized decompiled body / import-set
  fingerprint) is the durable identity; `fq_name` + `address` are locators. Renames, annotations,
  findings, and edges bind to identity that survives re-decompilation.
- **Large payloads never inline.** Pseudocode, full strings, struct members, harness source go
  to the CAS (`cas/{sha256}`); the node holds a `*_ref` sha. Keeps `attrs` token-budget-friendly
  and gives free dedup.
- **Lazy materialization (feasibility #7 resolved):** function/symbol/string nodes are
  materialized **on reference** — when a finding attaches, a human pins, or a task is launched
  against them. Recon emits a *filtered* notable-string/symbol set, **not** thousands of rows.
  Eager pre-indexing of top-N functions is explicitly opt-in, never the default.
- **`created_by` provenance** (`recon|unpack|decompile|llm|human`) is queryable.

### 3.3 Edge taxonomy (typed, attributed, provenance/confidence — issues #4, #8, #9 resolved)

One polymorphic `edge` table:

```
edge(id, project_id,
     src_kind, src_id, dst_kind, dst_id,            -- polymorphic endpoints
     type,                                          -- canonical EdgeType enum
     directed,                                      -- bool
     confidence (float 0-1, nullable),              -- typed column, queryable
     weight (float, nullable),                      -- similarity/call-freq magnitude
     origin (tool|llm|human|derived),               -- provenance, typed
     created_by_task_id (FK task, nullable),
     created_by_tool, created_at,
     attrs JSON)                                    -- type-specific bits + evidence pointer
```

**Canonical `EdgeType` enum** (owned here; all dimensions use these names):
`contains`, `links_against`, `imports_symbol`, `exports_symbol`, `calls`, `references`,
`reads`, `writes`, `instance_of_pattern`, `similar_to` (undirected, `weight`),
`duplicate_of`, `derived_from`, `produced_by`, `confirms`, `refutes`, `supports`,
`contradicts`, `about`, `annotates`, `dataflow_hint`.

Reconciled aliases: pattern membership = `instance_of_pattern` (drop `matches`); cross-binary
code identity = `similar_to`/`duplicate_of` (drop `same_code_as`); provenance =
`produced_by` (drop `produced`); symbol export = `exports_symbol` (drop `defines`); data
access = `reads`/`writes` with `attrs.scope=global` (drop `*_global`); string reference =
`references` with `attrs` (drop `references_string`). `dataflow_hint` is kept as a distinct,
in-scope heuristic edge.

**Attribution is in typed columns, not `attrs`** — required for server-side filtering
(`min_confidence`, `origin`, `edge_types`). `attrs` carries only an **evidence pointer**
(`{finding_id, address}`) so evidence lives in exactly one place and every non-tool edge is
auditable back to its producing task's trace.

**Provenance/confidence semantics:**
- `origin=tool` → ground truth (sandbox probe), `confidence=1.0`/NULL.
- `origin=llm` → a *claim* the human must triage; `confidence` = the float-mapped agent enum.
- `origin=human` → human-drawn or human-confirmed; `confidence=1.0` (a confirmed LLM edge
  keeps `origin=llm` and stamps `attrs.confirmed_by=human` — we never lose that a model
  proposed it).
- `origin=derived` → engine-computed (`duplicate_of`, `produced_by`).

**Integrity without DB-level FKs (feasibility #8):** because endpoints are polymorphic,
SQLite cannot enforce them. Required: composite indexes `(project_id, src_kind, src_id)` and
`(project_id, dst_kind, dst_id)`, an engine-level integrity check in `engine/edges.py`, and a
**cascade-cleanup rule on node delete** (orphan sweep). Not shippable without the cleanup
sweep.

**Findings attach via `about` edges (issue #7):** `persist_finding()` runs
`resolve_evidence_nodes()` to find/create the finest node (`function` from `evidence.function`,
`symbol` from `evidence.sink`) and emits a typed `about` edge (`attrs.role ∈ {primary,context}`).
`target_id` stays the coarse pointer. The synthetic render-time `about` edge is gone.

---

## 4. The graph as central hub: UI/UX

The graph is promoted from a read-only after-the-fact diagram (v1: nodes aren't clickable,
hard-reload after polling) to the **central organ**: where the researcher reads investigation
state, decides where to look next, and launches work. The tree and findings list become
projections of the same node/edge data.

### Visual encoding (a disciplined grammar)

- **Shape = node kind:** firmware_image hexagon · filesystem folder · executable circle ·
  shared_library ringed circle · function rounded square · symbol dot · string tag · struct
  bracket · hypothesis dashed octagon/?-badge · finding diamond · task pill.
- **Fill = headline status:** targets fill with **worst-descendant severity** (a binary
  visibly inherits a "risk halo") and use kind hue as the *border*; findings use the severity
  scale; hypotheses neutral until `confirmed` (green ring) / `refuted` (struck grey).
- **Confidence = saturation/opacity** — solid, trustworthy findings draw the eye.
- **Status badge (corner overlay):** task `queued/running(pulse)/succeeded/failed/needs-triage`;
  finding `new/confirmed/dismissed(dimmed)`.
- **Edge encoding:** distinct line styles per type (`contains` thick solid, `links_against`
  dashed, `similar_to`/`instance_of_pattern` dotted colored, `about`/`produced_by` thin faint);
  **labels only on hover or single-selection** (kills the "six identical `about` labels"
  clutter); arrowheads only on directed types; faded by `confidence`.
- **Label discipline:** truncate ~24 chars + hover tooltip; finding labels render only on
  hover/selection (kills overlap); higher-contrast font.

### Navigation

- **Layouts mode-switch:** `dagre` containment for firmware (firmware → filesystem → binary;
  findings as **satellites** around their target, not in the global rank); `fcose` call-graph
  **compound nodes** inside an expanded binary; the two coexist (focus + context).
- **Progressive disclosure:** collapse/expand compound nodes with **rollup badges** ("3
  binaries · 1 critical · 2 untriaged"); **semantic zoom** (low → only binaries + crit/high;
  high → symbols/strings); expansion is lazy (triggers materialization, §3).
- **Focus mode** dims everything outside the selected node's 1–2 hop neighborhood; **edge-typed
  pivot chips** ("3 instance_of_pattern", "links_against libc") fly the viewport to neighbors —
  edges become navigation.
- **Facets, search, saved views:** a facet bar (kind, severity, confidence, status, category,
  tag, subtree, origin/cost-source, "untriaged only") that *fades* non-matches; a scoped
  search box (`sev:critical`, `import:strcpy`, `string:/admin`, `cat:command-injection`)
  backed by SQLite FTS5/JSON1 (no graph DB); local-only **saved views** persisting
  `(filters, layout, expanded set, focus, viewport)`, seeded with a "risk surface" starter
  view on ingest.

### How results land and route onward

- On launch, an optimistic **task node** appears immediately, wired by a pending `produced_by`
  edge, pulsing (no silent reload).
- Status streams over **SSE** (`GET /api/projects/{id}/events`); the canvas **patches just the
  changed nodes/edges** (no full re-layout jank).
- On `finding.created`, the finding **animates in** as a satellite of its resolved
  target/function; a `pattern_sweep` match **draws the `instance_of_pattern`/`about` edge
  across to the sibling** — the graph visibly "discovers" the connection.
- A **landing toast / Activity rail** ("static_analysis → 1 high finding on cgi_handler · 2
  follow-ups") with a "follow" button frames the new finding and opens its Launchpad — actively
  routing the researcher onward.
- Selecting any node/edge opens a single **Inspector rail** (full-height, replacing the cramped
  detail pane) with three stacked regions: **Dossier** (kind-specific facts — target recon
  table + task history; finding evidence + snippet with width; edge provenance link to the task
  trace), **Related context** (typed neighbor pivot chips), and **Launchpad** (§6).

This subsumes and supersedes `docs/dev/ui-backlog.md`: interactive nodes, target-detail view,
findings sort/filter/group, label/`about`-edge fixes, fit/zoom/layout, single launcher,
mock-scenario gated on backend, live feedback, cost display — all map into this whole.

---

## 5. Tasks: full taxonomy & what they spawn from

### Task types (the canonical five, plus `unpack`)

`recon` (deterministic, no LLM, auto-on-ingest), `static_analysis`, `reverse_engineering`,
`pattern_sweep`, `harness_generation`, and `unpack` (promote the existing deterministic
unpack probe to a named type). **No other dispatch types.** We reject the forked taxonomy
(trace-dataflow/diff-functions/etc. as new types); those are *anchored invocations* of the
five with an objective + params (issue #5, #4).

### The task ANCHOR (the polymorphic generalization — task-taxonomy's real contribution)

A task is anchored to a graph element, not a bare target: `anchor_kind ∈ {NODE, EDGE,
SELECTION, HYPOTHESIS}`. **Node tasks interrogate a thing; edge tasks interrogate a
relationship; selection tasks fan one operation across a subgraph; hypothesis tasks
accumulate evidence for/against a human claim.** The dispatcher resolves the anchor and
enforces an `allowed_anchor_kinds` set per task type *before* any sandbox/LLM work.

**`primary_target_id` resolution rule (issue #12 resolved)** — every anchor yields a single
focus target so the context builder (§7) and preview (§6) keep working:
- NODE → the node's containing artifact.
- EDGE → the src endpoint's containing artifact.
- SELECTION → **null**; batch semantics, **one bundle per member** (the fan-out).
- HYPOTHESIS → the target the hypothesis is `about`.

### What spawns from what

| Anchor | Tasks | Emits |
|---|---|---|
| **NODE** (`target`/`function`) | `recon`, `unpack`, `static_analysis`, `reverse_engineering`, `harness_generation` (function entry), `secret-scan`/`enumerate-strings` *as params of recon/static* | findings homed on the node; may grow `function`/`symbol`/`string` children |
| **EDGE** (`calls`/`links_against`/`related`) | `static_analysis`/`reverse_engineering` invoked with a relational objective: trace-dataflow (`calls`), diff (two functions), confirm-match (provisional sweep edge), explain-link (`links_against`), boundary-taint | **mutates edge attributes** (confidence/`attrs`, provisional→confirmed/refuted) + a verdict finding; may emit finer edges |
| **SELECTION / subgraph** | `pattern_sweep` (re-anchored), batch-recon, cohort-summarize — sugar over batch | one finding per member + provisional relationship edges; the **full candidate set with per-member verdict** (matched/rejected/uncertain) as an auditable coverage artifact (completeness #9) |
| **HYPOTHESIS** | `static_analysis`/`reverse_engineering` invoked to gather evidence, plus the **`challenge`** adversarial invocation | findings linked via `supports`/`refutes`; recomputes hypothesis confidence |

**The `challenge` follow-up (consistency: one name, one home).** Every non-info finding
auto-suggests a single canonical adversarial follow-up — **`challenge`** — an invocation of
`static_analysis` that argues the null hypothesis (is the buffer bounded upstream? is the
input attacker-controlled?). It is not a new task type and not three differently named things.

---

## 6. The task-spawning interface

One shared **Launch dialog / Launchpad**, reachable three ways, all resolving to
`POST /api/tasks` or `POST /api/tasks/batch` — **no new launch code path, seams untouched,
never branches on backend identity.**

- **Three doors:** graph right-click (node/edge context menu — the primary, graph-native
  path), the Inspector's persistent **Run task ▾** button, and a **Cmd-K command palette**
  (`static router_httpd`, `sweep strcpy across libs`).
- **Filter by selection:** a server-driven capability table (`GET /api/task-catalog?
  selection_type=&kind=`) is the single source of truth so CLI, palette, and menu never
  drift; it offers only valid types (e.g. `firmware_image` → recon/unpack only; `executable` →
  full decompile-backed set; an edge → relational invocations) and flags `recommended` (e.g.
  `static_analysis` when imports intersect risky sinks). The **mock-scenario field renders
  only when the resolved backend is `mock`**.
- **Parameterize (schema-generated):** objective; **focus function** typeahead from real
  symbols (`GET /api/targets/{id}/symbols`); **sink** chips prefilled from `imports ∩
  RISKY_SINKS`; backend segmented control + model picker; mock-scenario from the manifest pool
  (mock only).
- **Presets:** a `task_template` table storing **behavior only, no target ids** (so templates
  batch cleanly), filtered by `applies_to`; "Save as template" footer. Templates are part of
  project export (shareable playbooks; contain no secrets — completeness #8).
- **Batch / sweep:** `POST /api/tasks/batch` over explicit ids or a relational subgraph walk;
  grouped by nullable `task.batch_id` + `batch_label`. A reusable named node-set is a
  **`Selection`** row; a batch *may be created from* a Selection (the two are distinct: a
  Selection is a reusable set, a batch is one launch — issue #13 resolved; column is fine for
  v1, promote to a `batch` table only when cancel-all/retry land). Batch shows projected
  aggregate cost and requires confirmation above a threshold or for any non-mock backend.
- **Pre-flight context preview (the differentiator & HITL checkpoint):** `GET
  /api/tasks/preview` runs the **same refactored, shared `build_context` + `build_prompt`**
  pure function as execution, so the preview is byte-identical to what runs. It shows the exact
  prompt, the tool output (decompilation/recon — **never raw bytes**), the resolved
  scenario/sibling/decompile-availability, and a **token estimate** (the single estimator,
  §1.13). It is a side-effect-free `GET`, runs no LLM call, costs $0. **Decompilation in
  preview is served from the per-`(content_hash, function)` CAS cache** so repeated previews
  don't pay Docker spin-up each time (feasibility: the preview must not synchronously
  re-decompile on every call).
- **In-flight / completion UX:** the Activity rail fed by SSE replaces poll+hard-reload;
  findings animate into the graph incrementally; `failed` chips show `error.txt`'s first line
  (so mock fault-injection is visible end-to-end); `needs-triage`/`triaging` chips link
  straight into triage; a per-task **trace** affordance opens the read-only `log_path`
  artifacts.
- **Follow-ups, evolved:** a finding's `suggested_followups` now **pre-fill the dialog**
  (with a "Run as-is" fast path) instead of firing blind, preserving `parent_finding_id`
  provenance while adding informed review.

**Concurrency honesty (feasibility #3):** the worker is **one serial asyncio loop** today.
SSE is fine, but the UI must **not imply concurrency that doesn't exist**: a batch shows a
real queue with position/ETA. A bounded worker pool (`Semaphore` over N `to_thread` workers)
is a *deliberate, separate* future change whose pool size must be capped against the per-
container 2 GB/2 CPU sandbox budget, preserving the Celery-swap seam.

---

## 7. The context model: the Context Bundle

This is the missing spine. Today the prompt is an ephemeral flat string and the model's
*response* trace is dropped on the floor. We make context a first-class, content-addressed,
reproducible object.

### What context, and how assembled

A **Context Bundle** is the complete, frozen, structured input to one task run — an *ordered
list of typed `ContextItem`s*, not a pre-flattened prompt. Item kinds: `recon_facts`,
`imports`/`exports`, `strings`, `decompilation.focus`, `decompilation.callers`/`callees`,
`graph.neighbors`, `prior_findings.this_node`/`related`, `researcher_note`, `hypothesis`,
`objective`, `sibling_decomp`. (Today's loose `TaskContext` hints — `function`, `sink`,
`sibling_*` — become **derived facets** over bundle items, so the mock's `template_vars()` and
the LLMBackend seam are untouched.)

A **ContextBuilder** walks the typed graph around the focus node (bounded radius, default 1;
`pattern_sweep` pulls the specific sibling sink) and **packs items under a per-task token
budget** by `(priority desc, est_tokens asc)`, **recording what it dropped** so the UI can say
"3 callees omitted to fit budget." Human input outranks machine context. Neighbor
decompilation is **summarized, not dumped** (a one-line descriptor + a CAS reference), keeping
budgets sane on 300-ELF firmware.

### Where stored & how referenced

- **CAS** (`cas/{sha256}`, the *one* store per §1.5): raw tool outputs, serialized bundles,
  and the **now-persisted LLM response trace**. Content-addressing gives free dedup
  (identical decompilation across two functions → one blob) and a provenance anchor.
- **Cache key** folds in gaps' good point: artifact cache keyed by **(artifact sha256 + probe
  + args + tool version)**; bundle cache keyed by `bundle_sha`; response cassette keyed by
  `bundle_sha` (the real implementation of the stubbed seam, stronger than a raw-prompt hash).
- **DB index:** `context_bundle` + `context_item` tables; `task.context_bundle_id` FK. The
  full provenance chain is **node → context → task → finding** via `context_item.src_*`
  pointers and `task.context_bundle_id` — *no* change to `finding.schema.json`. The
  visualization `derived_from` edge (task → source node) is a **render-time projection of
  `context_item` rows**, not a second persisted store (so they can't disagree).
- **Per-task trace** (`tasks/{task_id}/`) becomes complete: `bundle.json`, `prompt.txt`
  (derived from the bundle), **`system.txt`** (new), **`response.json`** (new), `usage.json`,
  `error.txt`. This makes a run **replayable**. **All trace writes must continue to exclude
  `ANTHROPIC_API_KEY`** (the new write paths re-affirm the never-store-the-key rule).

### Reproducibility & comparison

- **Determinism:** canonicalized item hashing (sorted keys, normalized whitespace), timestamps/
  UUIDs excluded from the hash basis, tie-breaks seeded from `task_id`, an explicit
  `assembler_version` that *intentionally* invalidates the bundle cache on logic changes.
  Given a `bundle_sha`, `just demo` (mock) reproduces byte-identical bundles and, via the
  cassette, byte-identical responses — offline, $0.
- **Comparison (issue #14, completeness #1):** an **`analysis_run`** entity groups the `(task,
  context_bundle, backend, model, params)` tuple and the findings it produced. Run-to-run
  finding **diff** keyed on `(node identity, category, signature)` yields added/dropped/
  changed-severity buckets, exposed via `GET /api/nodes/{id}/runs` and a UI run-compare view.
  Per-task model override is **useless without this** and ships with it.
- **Staleness (completeness #6):** a bundle records the graph-state inputs it depended on
  (sibling set, neighbor node shas). When those change (a sibling ingested after a sweep ran),
  dependent tasks/findings are marked **`stale`** in the UI with an explicit re-run affordance.
  **The human decides; never auto-refresh.** Without this the reproducibility guarantee is
  hollow.
- **Retention (completeness #6, feasibility):** CAS retention is **manual** for v1 — a
  `hexgraph prune` CLI plus a size report. No auto-eviction.

---

## 8. Manual vs agentic division of labor & human-in-the-loop

**Agents produce candidates; humans produce ground truth.** The graph is the handshake: agent
output arrives as `new`/`triaging` nodes the human must act on; human decisions become inputs
later agents build on.

### The division (by who is accountable for the judgment)

- **Agents only** (the human never does, and often *cannot*): touch target bytes
  (recon/unpack/decompile/compile in the sandbox), reason over tool output, *propose* findings,
  hypotheses, follow-ups, renames, and `instance_of_pattern`/`similar_to` edges, fan out
  sibling sweeps, draft harness boilerplate, argue the null hypothesis on demand.
- **Humans only** (never delegated): set the objective/scope, declare a hypothesis
  confirmed/refuted, accept a finding into the report, choose final severity, set sweep budget,
  curate the graph (confirm/draw/delete edges, pin nodes), and **correct** an agent (rename,
  re-categorize, override severity/confidence).
- **Neither, in v1:** execute the target; auto-launch deep analysis on everything; auto-accept
  a finding or auto-confirm a hypothesis; branch task logic on backend identity.

### Triage, override, and supersession (issue #9 resolved)

- **One status axis:** `new → triaging → confirmed → reported`, plus `dismissed` (with a
  separate reason column). `duplicate_of` is an edge, not a status. The agent's certainty stays
  in `confidence`; we reject a parallel `triage_state` axis.
- **Provenance/supersession (envelope columns, orthogonal to status):** `finding.origin
  (agent|human|agent_edited)`, `supersedes`/`superseded_by`. A **light** edit patches in place
  (original agent `severity`/`confidence` preserved in `evidence.extra.agent_original`); a
  **heavy** edit (changing evidence) **forks** a human-owned copy that supersedes the agent
  original. `human_notes` lives alongside the agent `reasoning`. `PATCH /api/findings/{id}`
  carries field edits.
- **Annotations (issue #10):** one `annotation` table keyed by `(node_kind, node_id)` for
  `rename | note | tag | type_decl`, with `origin (agent_proposed|human)` and
  `status (proposed|confirmed|rejected)`. `reverse_engineering` emits `proposed` annotations;
  the human Confirm/Edit/Reject. **Tags live here and are the canonical findings-list filter
  facet.** A **confirmed rename** is then applied to the node's `attrs.name` with
  `name_history` (the two models — annotation row + node mutation — are made consistent, not
  competing).

### Approval gates (configurable; backend-agnostic — they read cost/risk, never backend identity)

- **Autonomous** — findings land `new` (today's behavior); good for mock/dev and recon.
- **Review-on-output** (default for real backends) — agent runs to completion but findings/
  renames land in a **`proposed` review state** surfaced in a **Review Queue**; nothing mutates
  the curated graph until accepted. *This is cheap, high-value, and needs no `plan()`.*
- **Plan-gated** — show the plan + cost before spending. **Feasibility ruling:** there is no
  separate `plan()` step — each task type is a single `execute_*` function (dispatched in
  `engine/worker.py`) that runs straight through — so true mid-task suspension is *net-new
  infrastructure*, not "expose the existing seam." For v1, implement the gate on the **launch
  side** (the §6 preview already builds the prompt + cost) requiring human confirm before
  `POST /api/tasks`; defer real mid-task suspension until an `execute_*` can yield mid-run.
- **Always-on spend gate** — a per-project budget ceiling; reads `usage.cost_usd` (which the
  runner already returns); mock estimates $0 so it never trips, preserving offline dev.

### Feedback into future context (the loop that makes the system smarter)

`build_context`/`build_prompt` gain a deterministic **"ANALYST-CONFIRMED FACTS"** prologue,
assembled from confirmed annotations + accepted/dismissed findings + confirmed hypotheses, and
rendered *above* tool output as authoritative. Mechanics: confirmed renames **rewrite the
decompiled tool output** before it's sent (post-processing sandbox output — no constraint
impact, LLM still never sees bytes); dismissals become **"do not re-report"** negative context
(killing duplicate churn at the source); a confirmed hypothesis is a prior, a refuted one tells
the agent to stop. This block is highest-priority context (always included) and token-aware.
**Guard against confirmation bias:** a confirmed-hypothesis prior may *inform* but findings that
*contradict* confirmed ground truth are auto-flagged `triaging`, not silently suppressed.

---

## 9. Gap analysis

### (A) Missing features to add

**P1 (blocks real VR use):**
- **A1 — Sub-binary nodes + xref edges** (`function`/`symbol`/`string` + `calls`/`references`).
  *The keystone:* search, dataflow hints, diffing, cross-target knowledge, the launchpad, and
  richer real-backend context all sit on this. v1 discards ~80% of what the sandbox computes.
- **A2 — Global search** (FTS5 over nodes + findings; `import:strcpy`, `string:/admin`), with
  **coverage honesty** (recon populates the string/symbol corpus eagerly + cheaply at ingest;
  function-body search is best-effort with an explicit "N functions not yet decompiled"
  indicator — an empty result is never mistaken for "not present").
- **A3 — Hypothesis node + widened triage** (`open/supported/refuted/confirmed`; finding
  `new/triaging/confirmed/dismissed/reported`).
- **A4 — Notes & tags on any node** (the `annotation` table; the missing findings filter facet).
- **A5 — Content-addressed caching** of decompilation/probe output (folded into the §7 CAS).
- **A6 — Re-run / `analysis_run` grouping + run-to-run diff** — *elevated from P2 to a committed
  design*; this is what makes per-task model selection meaningful (§7).
- **B1 — Recon worklist** ("12 binaries, 4 import `system`, 7 no canary — start here") instead
  of one buried follow-up.
- **B2 — Findings list shape** (group-by-target, sort-by-severity, filter-by-status/category/
  tag, per-severity counts; currently flat and target-blind).
- **B4 — Target-detail view** (recon facts are currently invisible in the UI).
- **B5 — Interactive graph launchpad** (the §4 keystone).

**P2:**
- **A7 — Human-readable report** (offline `GET /api/projects/{id}/report?format=md|html` over
  confirmed/promoted findings, **embedding provenance**: which task/model/bundle produced each
  finding; optional LLM "polish narrative" behind the seam). *Resolved as export-time
  composition over a `promoted` flag, not a heavy report table (completeness #5).*
- **A8 — Cross-target "same code as"** (by `content_hash`) — *elevated*: n-day hunting via
  firmware-version diffing is the highest-yield real technique. Includes an opt-in local
  `~/.hexgraph/index.db` (binary sha256 → {project_ref, prior-findings flag, known-stock flag})
  and a **locally-built/user-imported baseline hash set** for busybox/openssl (lets a triager
  skip 35 of 40 binaries). Strictly local, read-mostly, never a copy of findings.
- **Enriched real-backend context** (B6) — solve the mock-vs-real quality cliff by giving the
  *real* backend the substrate the fixtures imply (A1 nodes, xrefs, dataflow hints) — **never
  by branching on backend identity.**
- **Browsable, cacheable decompilation** (B7) — decompilation is a consumable artifact, not a
  per-task throwaway buried in `prompt.txt`.
- **Live task feedback** (B8) and **typed/attributed edges** (B9) — per §4, §3.

**P3:**
- **A11 — CVE correlation** — *offline only:* a user-imported NVD snapshot matched against
  extracted version strings. **Never a live lookup** (sandbox `--network none`, no telemetry).
- **A9 — Dataflow hints** — *bounded:* intra-function source-import-arg → sink-arg heuristic
  **only**; no inter-procedural propagation, no path conditions; always `confidence`-tagged as
  a heuristic; surfaced as `dataflow_hint` edges. This is the concrete line that keeps it
  in-scope and away from out-of-scope taint/dynamic analysis.
- **A10 — Firmware/function diffing view** (depends on A1 + A5).
- **B10 — Context preview/edit** (the §6 preview; human edits *tool-output framing* via notes,
  never bytes).
- **B11 — Reviewable dedup** (cluster view + undo; `dedup` materializes `duplicate_of` edges
  rather than silently merging).

### (B) Current behaviors that surprise

- **B3 — `pattern_sweep` silently re-homes the finding onto the sibling, erasing provenance
  (P2 — resolved).** *Single canonical behavior:* `pattern_sweep` **creates a new finding
  homed on the matched sibling** (so the sibling has its own triageable finding — preserving
  the UI "lands on sibling" payoff) **and** links it to the origin via an attributed
  `instance_of_pattern`/`related` edge carrying `matched_from_finding_id`, `match_kind`,
  `confidence`. It does **not** relocate the original finding. (Cheap: `metadata_json` is
  already JSON, no migration for the edge attribution itself.)
- **B1, B2, B4, B5, B8, B9** as above (the v1 surprises that the §4 hub design fixes).
- **`needs_triage` is the only coarse feedback signal (P2)** — replaced by the SSE Activity
  rail + per-task outcome summary.
- **Decompilation is single-function, env-gated, and discarded (P2)** — becomes the browsable
  cached artifact of A1/A5.

---

## 10. Cross-cutting concerns

- **Respecting the seams.** Task code **never branches on backend identity** — it calls
  `get_backend()` and consumes `(findings, usage)`. The mock stays a first-class, default,
  offline backend. The sandbox boundary handles all bytes; the LLM sees only tool output.
  Edge/node creation from probe output happens *inside* the sandbox boundary (derived from
  output, never from executing the target). New task anchors and the capability table do not
  leak across the backend seam.
- **The frozen Finding contract.** No section mutates `finding.schema.json`. New structure is
  envelope-only. Mock fixtures don't grow new payload blocks; the contract test stays
  drift-proof. Agent-proposed edges are derived from existing emitted fields.
- **Relational graph (no Neo4j).** Nodes, edges, search (FTS5/JSON1), neighborhood walks, and
  diffing are all plain SQLAlchemy over SQLite. Polymorphic edges trade DB-level FK enforcement
  for a single uniform graph query, *paid for* by composite indexes + an engine integrity
  check + a node-delete cascade sweep.
- **Caching, cost, reproducibility.** One CAS; three cache tiers (artifact, bundle, response);
  one token estimator; `analysis_run` grouping + run diff; staleness flagging (human decides);
  always-on spend gate reading `usage.cost_usd`. `just demo` reproduces byte-identical bundles
  and responses offline at $0.
- **Migrations & data durability.** Alembic (or equivalent) is sequenced **before** any
  schema-extending feature; `schema_version` + backup-on-migrate; **the project DB is durable
  knowledge and is never silently reset.** This is load-bearing for every knowledge-accumulation
  feature (notes, hypotheses, accepted findings, cross-project index).
- **Honesty principles.** No false negatives asserted as fact: reachability marks
  indirect/unresolved calls and never claims "not reachable"; search shows decompile coverage.
  HexGraph proves reachability and pattern, never exploitation.
- **Self-hosted portability.** Non-secret artifacts (task templates, saved views, the
  `pattern`/vuln_class catalog, CVE/baseline snapshots) are part of project export/import —
  shareable playbooks by file copy, honoring self-hosted/no-server while enabling team reuse.
- **Key handling.** Every new trace write path (`system.txt`, `response.json`) re-affirms:
  `ANTHROPIC_API_KEY` is read at runtime in the Anthropic backend only, never logged or stored.

---

## 11. Open questions for the implementation-planning phase

1. **Migration tooling:** Alembic vs. a hand-rolled runner, and the exact `schema_version` /
   backup-on-migrate mechanism — and which schema deltas land in the first migration.
2. **Bounded worker pool:** if/when to introduce a `Semaphore`-bounded concurrent worker, and
   the pool-size cap given per-container 2 GB/2 CPU sandbox budgets (vs. staying serial with an
   honest queue UI). How this preserves the Celery+Redis swap seam.
3. **Decompilation cache lifetime & latency:** confirm the per-`(content_hash, function)` cache
   makes synchronous preview affordable; eager vs. lazy and whether to opt-in pre-index top-N
   functions on large firmware.
4. **CAS retention beyond manual prune:** is a size cap / LRU eviction ever needed, and what
   triggers the size report?
5. **Cross-project `index.db` concurrency & privacy:** single-writer locking surface, opt-in
   write gating, and confirming it stays a hash→project_ref index (never a finding copy).
6. **Baseline hash set provenance:** how the busybox/openssl baseline is generated locally or
   imported, and its update story under no-telemetry.
7. **Reachability coverage UX:** exactly how "N indirect calls unresolved" caveats are
   surfaced so the human is never misled by an incomplete static call graph.
8. **`analysis_run` diff signature:** the precise `(node identity, category, signature)` key for
   stable run-to-run finding diffing across re-decompilation and model changes.
9. **Selection vs. batch persistence:** when to promote `batch_id` columns to a first-class
   `batch` table (cancel-all / batch-retry), and whether saved reusable `Selection`s are in
   v1 scope.
10. **Report composition detail:** the exact Markdown/HTML structure, what provenance is
    embedded per finding, and the boundary of the optional LLM "polish" task.
11. **Token-estimator fidelity for BYOK:** whether to allow an optional local tokenizer only
    when a real backend is selected (network already accepted), keeping `chars/4` as the
    offline default.
12. **Plan-gate evolution:** when (if ever) to build true mid-task `plan()`-based suspension vs.
    living with launch-side gating.
13. **Annotation/edit granularity:** confirm the light-edit-patch vs. heavy-edit-fork threshold
    and whether `name_history` audit suffices for confirmed renames.
