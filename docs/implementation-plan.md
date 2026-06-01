# HexGraph Implementation Plan (v2)

This turns [`docs/design-vision.md`](design-vision.md) into sequenced, trackable work. The vision
defines the *what/why*; this defines the *order, the seams, and the acceptance bar*. The MVP
(M0–M5, branch `build/hexgraph-mvp`) proved the loop; v2 makes it a tool a researcher *wants* to use.

Execution is tracked in `PROGRESS.md` (per-phase checklist). Every phase keeps the contract test
green, develops mock-first, and **updates `CLAUDE.md`** as part of its definition of done.

---

## Strategic context — design now for what comes later

Today's constraints (local-only, BYOK/mock, static-only, single-user) are **temporary**. The eventual
product is open-source + **free with your own key**, with **paid "credits"** features billed against a
**HexGraph API key** (used in-app like any other provider key), plus future **fuzzing, dynamic/emulated
execution, automated exploit gen+testing, Kubernetes scale, and enterprise services**. We build *none*
of that now — but we install thin **seams** so each lands additively, without rewrites. These seams are
created in Phase 0 with local/no-op defaults and are honored by every later phase.

| Future goal | Enabling seam (built thin now) |
|---|---|
| Paid credits / metered features | **Entitlements** (`allows(feature)`) + **Metering** (`record(usage)`); HexGraph-key slot reserved alongside `ANTHROPIC_API_KEY` |
| Auto-suggest tasks from a finding (likely paid) | **Suggester** seam (`FollowupSuggester`); rule-based default now, `LLMSuggester` behind entitlement later |
| Fuzzing / dynamic / emulated execution / exploit testing | **Executor** seam (`run_probe`) + **analysis policy** flag (`static_only`/`allow_execution`) + the existing task registry (new task types drop in) |
| Kubernetes / horizontal scale | **Executor** seam (remote/k8s executor) + **queue** seam (asyncio→Celery+Redis) + stateless API |
| Enterprise / multi-user / ACLs | **Principal** seam (`current_principal()`, local single-user now) + per-principal entitlements |

**Rule:** no feature code branches on backend identity, license tier, or executor. It asks a seam.

### Frontend decision (frontend judgment was delegated)
We **adopt React + Vite + TypeScript** with a polished dark design system and Cytoscape.js for the
graph, replacing the vanilla-JS UI. Rationale: the bar is "value evident from one screenshot" and
"manage thousands of findings" — that needs virtualized tables, a real component model, command
palette, and live updates. The JSON API stays the contract; the SPA builds to static assets served by
FastAPI (still loopback-only). This is additive to the backend and reversible at the API boundary.

### Sequencing principles
1. **Migrations first** — the project DB is durable researcher knowledge; never silently reset it.
2. **Data foundations before rich UI** — the typed graph + context spine are what make the UI worth
   looking at. But land a **polished vertical slice by end of Phase 4** so there's an early "wow."
3. **Mock-first**; the contract test and `just demo` stay green every phase.
4. **Seam discipline** (the table above) and **CLAUDE.md updates** are acceptance criteria, not afterthoughts.

---

## Phase 0 — Foundations & future-proofing seams *(no user-visible change)*
**Goal:** schema durability + the thin seams above. **Depends on:** MVP.
- **P0-1 Migrations.** Adopt Alembic; add `schema_version`; backup-on-migrate; `hexgraph db upgrade`. First migration is a no-op baseline capturing today's schema. (Resolves open-Q1.)
- **P0-2 Executor seam.** Extract `sandbox/runner.py` behind an `Executor` protocol (`run_probe`/`run_json_probe`); `LocalDockerExecutor` is the default. Leaves room for `RemoteExecutor` (k8s) and a future `DynamicExecutor`.
- **P0-3 Entitlements + metering.** `engine/entitlements.py` (`Entitlements.allows(feature, principal)` → all-true for local BYOK; config-driven) and `engine/metering.py` (`MeteringSink.record(task, usage)` → local log/no-op). Wire a check+record around task execution. Reserve a `HEXGRAPH_API_KEY` config slot (read, not used).
- **P0-4 Analysis policy.** `engine/policy.py` with `static_only=True`, `allow_execution=False`; the executor asserts policy before running a probe. Future dynamic/fuzz tasks flip a policy + executor profile.
- **P0-5 Principal seam.** `current_principal()` → a local single-user principal threaded through the API (no auth yet) so multi-user/ACLs attach later.
- **CLAUDE.md:** document the five seams + the migration workflow + the "ask a seam, never branch" rule.
- **Acceptance:** `alembic upgrade head` works on a fresh and an existing DB; all tests + `just demo` unchanged; seams present with local defaults.

## Phase 1 — Typed graph core *(the keystone — A1/B9)*
**Goal:** sub-file nodes + typed attributed edges; stop discarding ~80% of what the sandbox computes.
- **P1-1 `node` table** (`NodeType` = function|symbol|string|struct|hypothesis|pattern|task; `attrs` JSON; `content_hash` identity; `fq_name`/`address` locators) + `engine/nodes.py` with lazy materialization.
- **P1-2 Polymorphic `edge` rewrite** (`engine/edges.py`): `(src_kind,src_id)/(dst_kind,dst_id)`, one `EdgeType` enum, typed attribution columns (`origin`, `confidence` float, `weight`, `directed`, `created_by_task_id`), composite indexes, engine integrity check, **node-delete cascade sweep**. Migration from the old edge table.
- **P1-3 Findings attach via `about` edge.** `resolve_evidence_nodes()` in `persist_finding()` finds/creates the finest node (function/symbol) and emits an attributed `about` edge; drop the synthetic render-time edge; keep `finding.target_id` as the coarse pointer. **Finding schema unchanged.**
- **P1-4 Populate the graph.** Recon emits a *filtered* symbol/string node set; `decompile_probe` is extended to emit a call graph + xrefs → `calls`/`references`/`imports_symbol` edges; function nodes materialize on reference.
- **P1-5 Typed graph endpoint** returns nodes/edges with kinds/attrs/confidence/origin (still relational).
- **CLAUDE.md:** node/edge model, `engine/nodes.py`/`engine/edges.py`, identity scheme.
- **Acceptance:** ingest firmware → function/symbol/string nodes + `calls` edges exist; a finding attaches to a function node; migration upgrades an existing project DB without data loss.

## Phase 2 — Context Bundle, CAS, caching, reproducibility *(the spine)*
**Goal:** make context a first-class, content-addressed, reproducible object; enable cheap real-key testing.
- **P2-1 CAS + index.** `engine/cas.py` (`cas/{sha256}`), `context_bundle`/`context_item` tables, `task.context_bundle_id`.
- **P2-2 ContextBuilder.** Graph-walk (bounded radius) + budget packer `(priority desc, est_tokens asc)` with **drop tracking**; one deterministic token estimator used by builder, preview, and display (ruling #13).
- **P2-3 Full trace.** Persist `bundle.json/prompt.txt/system.txt/response.json/usage.json` under `tasks/{id}/`; re-affirm key never written.
- **P2-4 Caching + cassettes.** Three tiers — artifact (`sha+probe+args+toolver`), bundle (`bundle_sha`), **response cassette (`bundle_sha`)**. This is the real implementation of the stubbed M0-T9 hook and the foundation for $0 CI replays of real-model runs.
- **P2-5 `analysis_run`** entity + run-to-run finding diff keyed on `(node identity, category, signature)`; `GET /api/nodes/{id}/runs`. (Makes per-task model selection meaningful.)
- **P2-6 Staleness.** Bundles record graph-state deps; dependent findings flagged `stale` with a re-run affordance. Human decides; never auto-refresh. CAS retention = manual `hexgraph prune` for now.
- **CLAUDE.md:** context model, CAS layout, cache keys, runs, prune.
- **Acceptance:** re-running a task hits cache; `bundle_sha` reproduces byte-identical bundles offline; a recorded cassette replays a real-model run at $0; run-diff returns added/dropped/changed.

## Phase 3 — Task anchors, relational tasks, suggester seam
**Goal:** tasks that interrogate relationships/sets; intuitive finding→follow-on.
- **P3-1 Task anchor** (`anchor_kind` ∈ NODE|EDGE|SELECTION|HYPOTHESIS, `anchor_id`) + `primary_target_id` resolution. Task *types* stay the canonical five (+ promote deterministic `unpack`).
- **P3-2 Capability table** — server-driven map of which task types are offered for which anchor/node type; `GET /api/capabilities`. The UI filters launch options from this.
- **P3-3 Edge-anchored invocations** (trace-dataflow, diff, confirm-match, explain-link, boundary-taint) as `static_analysis`/`reverse_engineering` with objective+params; the ContextBuilder pulls both endpoints.
- **P3-4 `pattern_sweep` provenance fix (B3).** Create a *new* finding homed on the matched sibling **and** an attributed `instance_of_pattern` edge carrying `matched_from_finding_id`/`match_kind`/`confidence`; never relocate the original finding.
- **P3-5 Suggester seam.** `FollowupSuggester` protocol + `RuleBasedSuggester` default that derives follow-ups from a finding's category/evidence/graph neighborhood. Findings consume *suggestions* uniformly. **Future:** an `LLMSuggester` (entitlement-gated, metered) drops in here — do **not** build it now, just the seam + rule-based default.
- **CLAUDE.md:** anchors, capabilities, suggester seam.
- **Acceptance:** launch a task anchored on an edge; launch options are capability-filtered; `pattern_sweep` preserves provenance; rule-based follow-up suggestions appear on findings and launch in one click.

## Phase 4 — The analyst notebook UI *(value in one screenshot)*
**Goal:** a workbench a researcher wants to use on sight — graph-as-hub + agent launchpad.
- **P4-0 SPA foundation.** React + Vite + TS served by FastAPI (static build + dev proxy); dark design system; retire `web/static` vanilla JS. JSON API unchanged.
- **P4-1 Graph hub.** Cytoscape with dagre/fcose layouts; **visual grammar** (shape = node kind, fill/halo = severity, opacity = confidence, badge = task status); progressive disclosure (expand firmware→binaries→functions); focus+context; in-graph search.
- **P4-2 Inspector** (3 regions: identity/attributes · related context · available tasks). Selecting a node/edge shows its detail and a **capability-filtered task launcher**.
- **P4-3 Live activity.** SSE rail (`GET /api/projects/{id}/events`); task results land incrementally on the graph and lists.
- **P4-4 Launch dialog** (three doors: node, edge, command-palette), schema-generated parameter form, task **templates**, batch/sweep over a selection, and a **pre-flight context preview** that shows the exact bundle, estimated tokens, and cost before spending.
- **CLAUDE.md:** frontend layout, build/dev commands, design-system + visual-grammar reference, SSE endpoint.
- **Acceptance:** one screenshot conveys the value; you can expand a firmware into binaries→functions, select a function, preview its context, and launch a task; live updates land without a manual refresh.

## Phase 5 — Finding & task management at scale *(first-class citizens)*
**Goal:** organize/sort/filter/process hundreds–thousands of findings; make provenance obvious.
- **P5-1 Findings workspace.** Virtualized table; sort + filter + group by target/category/severity/status/tag; per-severity counts; **saved filters**; **bulk actions** (triage, tag, dismiss-with-reason).
- **P5-2 Provenance navigation (≤2 clicks each way).** finding → producing **task** (task detail: context bundle + trace + model + cost) ; finding → **components** it's about (highlight nodes on graph) ; finding → **follow-on tasks** (from the suggester) ; task → findings it produced.
- **P5-3 Task workspace.** Task list/queue with status/cost/model/anchor; re-run; cancel; view bundle + trace.
- **P5-4 Tags/notes.** `annotation`-backed tags + notes on any node/finding; the canonical findings filter facet.
- **CLAUDE.md:** management views + provenance routes + saved-filter model.
- **Acceptance:** a project with hundreds of findings is navigable (sort/filter/group/bulk in a virtualized list); from any finding you reach its task, its components, and its follow-ons in ≤2 clicks; it is always clear which task produced a finding and which components it concerns.

## Phase 6 — HITL, triage, annotation, feedback loop
**Goal:** humans produce ground truth; ground truth flows back into agent context.
- **P6-1 Triage axis.** Widen `finding.status` (new|triaging|confirmed|dismissed|reported) + dismissal-reason column + `origin`/`supersedes`; `PATCH /api/findings/{id}` with light-patch vs heavy-fork semantics.
- **P6-2 Annotations.** `annotation` table (rename|note|tag|type_decl; proposed|confirmed|rejected); `reverse_engineering` emits proposals; Confirm/Edit/Reject; confirmed rename → node `attrs.name` + `name_history`.
- **P6-3 Hypotheses.** Hypothesis nodes + `supports`/`refutes` edges; create/confirm/refute UI.
- **P6-4 Approval gates.** Review-on-output (default for real backends) + launch-side plan/cost gate + always-on spend gate (reads `usage.cost_usd`, entitlement-aware).
- **P6-5 Feedback into context.** "ANALYST-CONFIRMED FACTS" prologue; confirmed renames rewrite tool output (post-sandbox); dismissals become negative context; confirmation-bias guard (contradicting findings flagged, not suppressed).
- **CLAUDE.md:** triage/annotation/hypothesis model, gates, feedback prologue.
- **Acceptance:** human edits/overrides persist and demonstrably change later task context; gates behave per config; hypotheses lifecycle works end-to-end.

## Phase 7 — Search, run-compare, report, cross-target
**Goal:** the high-yield researcher features that ride on the typed graph.
- **P7-1 Search.** FTS5 over nodes + findings (`import:strcpy`, `string:/admin`) with **coverage honesty** ("N functions not yet decompiled").
- **P7-2 Run-compare UI** over `analysis_run` diffs.
- **P7-3 Report export.** `GET /api/projects/{id}/report?format=md|html` over promoted findings, embedding provenance (task/model/bundle); optional LLM "polish" task **entitlement-gated**.
- **P7-4 Cross-target "same code as"** by `content_hash`; opt-in local `~/.hexgraph/index.db` + importable baseline hash set (busybox/openssl) to skip stock binaries; firmware-version diffing view.
- **P7-5 (P3 / may defer)** offline CVE correlation, bounded intra-function dataflow hints, reviewable dedup (materialize `duplicate_of`).
- **CLAUDE.md:** search, runs, report, cross-target index.
- **Acceptance:** search finds nodes/findings with honest coverage; runs are comparable; a Markdown/HTML report exports with provenance; an identical function across two firmware images links via `similar_to`/`duplicate_of`.

## Phase 8 — Real-key validation harness & the cheap vuln target
**Goal:** prove HexGraph finds *real* vulns with a *real* model, cheaply and repeatably. (Cassette infra lands in P2; this phase builds the target + scored test.)
- **P8-1 Multi-vuln test firmware** (`tests/fixtures/vuln_fw/`): a few tiny ELFs each planting one distinct, statically-findable bug mapped to a finding category — stack overflow (`strcpy`), command injection (`system`), format string, hardcoded secret, weak crypto. Small enough that context + `max_tokens` stay tiny.
- **P8-2 Scored real-backend test.** Run `static_analysis`/`reverse_engineering` with `--backend anthropic`, bounded (focused functions, tight context budget, `max_tokens` cap), assert a **detection rate** over the planted set. **Record a cassette once** → CI replays at **$0**; `just test-live` runs live (opt-in, key-gated, behind the spend gate, target cost ≈ a few cents).
- **P8-3 Cost guardrails** verified (spend gate trips, context budget respected) so live runs can't surprise-bill.
- **CLAUDE.md:** how to run `just test-live`, expected cost, how to re-record cassettes.
- **Acceptance:** cassette replay is green in CI at $0; `just test-live` detects ≥ the agreed fraction of planted vulns within a bounded dollar budget.

---

## Test & validation strategy
- **Mock-first, always green:** contract test + `just demo` stay passing every phase; mock remains the default, offline, $0 backend.
- **Cassettes (P2):** real-model behavior is recorded once and replayed in CI at $0; re-record deliberately.
- **Real-key (P8):** a tiny, scored, multi-vuln target with hard token/cost ceilings; opt-in `just test-live`.
- **Migrations (P0):** every schema-touching phase ships an Alembic migration tested on an existing DB.

## Disposition of the design doc's 13 open questions
1 Migration tooling → **P0-1** (Alembic + `schema_version` + backup). 2 Worker pool/k8s → **Executor+queue seams P0-2** (stay serial+honest queue until needed). 3 Decompile cache → **P2-4** (per-`content_hash` cache; lazy; opt-in top-N). 4 CAS retention → **P2-6** (manual prune now). 5 Cross-project index → **P7-4** (opt-in, single-writer, hash→ref only). 6 Baseline hash set → **P7-4** (locally built/imported, no telemetry). 7 Reachability honesty → **P1-4/P7-1** (ruling #15). 8 Run-diff signature → **P2-5**. 9 Selection/batch persistence → **P3-1/P5** (batch_id col; `batch` table only if needed). 10 Report structure → **P7-3**. 11 BYOK tokenizer fidelity → **P2-2** (`chars/4` default; optional local tokenizer when a real backend is selected). 12 Plan-gate → **P6-4** (launch-side now; true `plan()` suspension deferred). 13 Annotation edit granularity → **P6-1/P6-2** (light-patch vs heavy-fork + `name_history`).

## Risks & notes
- **Biggest risk: Phase 1 migration of existing graph data.** Mitigate with the backup-on-migrate step and a reversible migration; the MVP's data is small.
- **Frontend rewrite (P4) is the largest single effort.** Keep the JSON API stable so backend phases (5–8) proceed independently; the SPA can lag a phase behind if needed.
- **Scope control:** P7-5 and parts of P7 are explicitly deferrable; the product is compelling after P5.
- **Seam honesty:** entitlements/metering/executor/policy/principal must stay *thin* — local defaults that grant/allow everything — until the corresponding feature is actually built. They exist to avoid rewrites, not to gate today's free tool.
