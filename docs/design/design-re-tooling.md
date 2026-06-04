# Design — Reverse-Engineering Tooling

**Status:** proposed (design)
**Scope:** the static-analysis / reverse-engineering surface — decompilation, the deterministic analysis tools, how their results are stored and become graph truth, and the external RE tools we want to add.
**Companion evaluations:** `hexgraph-static-analysis-evaluation.md` (radare2 + Ghidra eval) and the fuzzing eval rounds that surfaced the `static_analysis` hallucination.

---

## 1. Why this exists

HexGraph's RE surface is strong in patches and weak in three structural ways, and this design fixes all three:

1. **Broken and opaque at the base.** Ghidra shipped non-functional twice (absent from the image, then a JDK/version mismatch), every probe error is swallowed to a bare `exit N`, the decompiler re-analyzes the whole binary on *every* call, and the agent has no way to see that the configured decompiler is broken.
2. **Shallow in the middle.** Verbs are name-only (no address access), function/struct nodes carry no recovered prototype or attributes, the call graph Ghidra already computes isn't queryable, and there's no way to raise analysis depth or analyze an arbitrary region.
3. **Ungrounded at the top.** The only synthesizing verb, `static_analysis`, is LLM-backed and under the mock backend emits a canned finding (`Stack buffer overflow in cgi_handler()`) for *any* binary — pure fiction on a target it never describes.

The richest capability we already pay for — P-Code data flow, jump-table recovery, C++ vtables, demangling — is computed and thrown away. The plan fixes the base, makes the decompiler fast enough to lean on, **persists and surfaces every tool result**, turns curated results into graph truth, then replaces hallucination with grounded data-flow and adds the high-value external tools behind seams.

## 2. Goals / non-goals

**Goals**
- A decompiler that works out of the box, reports its own health, and never silently fails.
- Analyze-once performance so heavy passes (batch decompile, P-Code taint, similarity) are viable on real firmware.
- A persisted, discoverable, graph-linked **Observation** layer so tool results are never lost and a later agent/user can mine them.
- A graph that stays a **curated result set**, not a dump of the program model, with automatic-where-unambiguous enrichment.
- Grounded, non-LLM static analysis that feeds the existing taint/reachability machinery.
- New RE tools (angr, FLOSS, YARA, BSim, …) added behind seams, sandboxed, feature-gated.

**Non-goals**
- Turning the graph into a complete program database (the substrate holds that; the graph holds results).
- Changing the frozen Finding schema (new structure rides the DB envelope).
- Replacing the LLM's judgment role — the LLM interprets a *grounded* graph; it does not invent structure.

## 3. Design principles

- **Seam, never branch.** Add an Analyzer seam family alongside `get_decompiler()` / `get_executor()`: `get_taint_analyzer()`, `get_similarity_index()`, `get_solver()`. angr / BSim / FLOSS drop in behind these — never `if tool == …`.
- **The sandbox is absolute.** Every tool runs in the disposable container on target bytes; the LLM only ever sees tool output carried in `TaskContext`. New heavy/dynamic tools (angr, P-Code emulation) are opt-in feature gates routed through `policy.py`, like fuzzing/poc.
- **Graph holds results, not the program model.** See §5.1. This is the load-bearing principle.
- **Zero-migration vocab.** `NodeType`/`EdgeType` are String columns; new kinds (`class`, `vtable`, `gadget`, `overrides`) need no migration. Attributes go in `attrs_json` with a `node_schemas.py` / `edge_schemas.py` registry entry (guidance, not schema). The **one** new table in this whole program is the Observation/enrichment store (§5.2, §5.5).
- **Frozen Finding schema holds.** Grounded results emit the same Finding shape.
- **A CI gate so it can't ship broken again.** The Ghidra breakage shipped twice because nothing tested a `WITH_GHIDRA` build end-to-end. Every phase lands with a test that would have caught its regression.

---

## 4. Where things are today (grounding)

- **Decompiler seam:** `sandbox/decompiler.py:get_decompiler()` → `R2Decompiler` (default) / `GhidraDecompiler` (headless) / `GhidraBridgeDecompiler`; selected live from `settings.json features.ghidra` or `HEXGRAPH_DECOMPILER`.
- **Ghidra headless:** `sandbox/probes/ghidra_probe.py` runs `analyzeHeadless -import … -postScript … -deleteProject` **per call** (no caching). The POST_SCRIPT already emits functions, **call graph**, and structs. Errors: the probe prints JSON `{error}` but the surface shows bare `exit 3/4`, and the exit-4 path reads `proc.stderr` while analyzeHeadless logs to **stdout**.
- **radare2:** `decompile_probe.py` (`pdc` pseudo-C), `xrefs_probe.py` (hardcoded sink → caller map).
- **Image:** `docker/sandbox.Dockerfile` pins `GHIDRA_VERSION=12.1` but installs `openjdk-17`; its own comment says 11.1.2 is the last JDK-17 line. Broken by construction.
- **Graph extraction:** recon (`engine/recon.py`) materializes only imports (symbol nodes, cap 60) + strings (cap 20). Function nodes appear **lazily** on decompile (`engine/agent_tools.py:_materialize` — materializes the focus **and all callees with no cap**) or via the opt-in `enrich_recon` (`engine/ghidra.py` — bulk-dumps ≤200 functions, ≤1000 call edges, ≤100 structs, including built-in ELF/libc structs as noise).
- **static_analysis:** `engine/llm_tasks.py` — in `LLM_TASK_TYPES`, runs `run_findings_agentic`; mock replays fixture findings by scenario, template-filled, **not target-matched**.
- **Storage substrate already exists:** `engine/cas.py` (content-addressed store — "holds tool outputs, context bundles, traces"), `engine/runs.py` (`AnalysisRun`), `engine/context.py` (`ContextBundle`/`ContextItem`, the per-task input bundle — the natural place to surface discoverability).
- **Tasks vs tools:** launching a **task** is a user action that spends LLM/agent effort; the agent calls **tools**, it does not create tasks. The deterministic analysis described here is a shared core used by both the user-initiated task and the agent's tool calls.

---

## 5. Core architecture

### 5.1 The substrate ↔ graph boundary

Two distinct stores; never conflate them.

- **The analysis substrate** — exhaustive, queryable, **not the graph**: the full function inventory + addresses + prototypes, the complete call graph, the struct catalog, string table, xref index. It can be huge. Its home is the **persistent Ghidra project (§7 Phase 1) plus the Observation store** (§5.2). Tools read *from* it.
- **The graph** — the curated subset deliberately promoted because it is an analysis *result*: the functions under investigation, the sinks that matter, the taint path behind a finding, the findings themselves.

The graph must grow with the **reasoning trail and conclusions**, never with the binary's full structure.

### 5.2 The Observation store (persisted, discoverable, linked tool results)

Every deterministic tool call writes a durable **Observation**. This is the home for "results that aren't promoted yet" — what both agent and user mine to decide what belongs in the graph. It is also the answer to "tool results must be accessible *and* discoverable."

**Model — `observation` table** (the program's one substantive new model; ships with an Alembic migration; mirrors `AnalysisRun`/`ContextBundle` style):

| field | meaning |
|-------|---------|
| `id`, `project_id`, `target_id` | always scoped to a target |
| `created_at`, `source` | agent-task id / MCP session / user-UI |
| `tool`, `args_json` | the call, normalized |
| `content_hash` | sha256 of the analyzed bytes — scopes/invalidates facts to the exact binary |
| `result_kind` | `decompilation \| function_list \| call_graph \| xrefs \| taint \| strings \| structs \| gadgets \| …` |
| `result_cas` | **full payload in CAS** (`engine/cas.py`), so large outputs don't bloat the DB and identical re-runs dedup |
| `summary`, `status`, `size` | short summary + ok/error |
| `node_refs` | the function/struct/address the call was *about* (bidirectional navigation) |

**Tied to the graph cleanly, without polluting it.** Observations are **not** graph nodes (that re-creates the explosion). The link is **bidirectional by reference**: a node/edge/finding created or enriched from a call carries `attrs.provenance = [observation_id, …]`; the Observation carries `node_refs` back. From a function node you can pull "what produced/enriched me"; from an Observation you can jump to what it touched — the graph stays curated.

**Reuse / perf falls out for free.** A query tool first checks for a fresh Observation (same `tool` + `args` + `content_hash`) and returns it flagged `cached` instead of re-running — "analyze once, reuse forever," realized against the persistent project.

### 5.3 The query / enrich / promote contract

Every tool is exactly one of three behaviors, and the bright line between them is what prevents graph explosion.

1. **Query (default; zero graph mutation).** `list_functions`, `call_graph`, `xrefs`, `list_structs`, `search_decompiled` return results as tool output **and** record an Observation. They create no nodes/edges. Enumerations are answers, not graph objects.
2. **Enrich-existing (automatic; the "free chicken").** When a call recovers richer info about an object **that is already a node**, attach it in place (§5.4). Bounded by what's already curated; cannot explode.
3. **Promote (explicit; user/agent decision).** A new node enters the graph only by a deliberate act — decompiling *this* function, recording a finding on it, an explicit "add to graph." That is the curation gate.

**The one rule that prevents fan-out:** *an edge is materialized only when both endpoints already exist as nodes (or are promoted in the same explicit action).* Decompiling F enriches F and lists its callees in the result/attrs, but does **not** spawn 50 callee nodes — it draws `calls` edges only to callees already in the graph; new callees surface in the result for optional promotion.

**Per-call budget (backstop).** Any single call may add at most *N* new nodes/edges; if a promotion would exceed it, it returns the overflow as promotable results with an explicit "capped — promote these if you want them" note. Never silent truncation (consistent with the repo's no-silent-caps discipline).

This contract changes two current behaviors: `enrich_recon` is redirected to populate the **substrate / Observation store**, not bulk graph nodes (this also dissolves the struct-noise problem — built-in ELF/libc types live in the queryable catalog, filtered, and never reach the graph); and `agent_tools._materialize` stops auto-creating uncapped callee nodes, switching to edge-only-if-endpoint-exists.

### 5.4 Always-welcome auto-enrichment

Some enrichments are so unambiguous that the user is **always** glad they happened — these run automatically, with no LLM or user in the loop, but **only against objects that already exist** and **only for whitelisted facts**.

**The whitelist (always-welcome):**
- A `function` node gains: **address**, recovered **prototype/signature**, param & local **count/types**, **calling convention**, **demangled name**.
- A known dangerous-import `symbol` node gains the **`is_sink`** tag.
- An existing `calls` edge accumulates **`call_sites`** (the merge infra already unions list-attrs as sets).
- A `struct` node (program-defined only) gains its **recovered layout** (from DWARF/GDT when present).

**Never auto-applied** (these need the LLM or the user): severity, exploitability ratings, "this is a vulnerability," summaries/interpretation, speculative types, or **any new node**. Auto-enrichment deepens curated objects; it never makes judgment calls and never grows the node set.

Each auto-enrichment records its source Observation in the node's `provenance`, so it's auditable and reversible.

### 5.5 The enrichment index — retroactive enrichment without rescanning

A node added *later* must automatically receive the always-welcome facts from tool calls that **already happened** — and we must not rescan/re-parse every Observation on each node insert. Solution: a small, keyed **enrichment index**, populated once at observation-write, joined at node-create.

**`enrichment_fact` table** (part of the Observation migration):

| field | meaning |
|-------|---------|
| `project_id`, `target_id`, `content_hash` | scope to the exact bytes |
| `subject_kind` | `name` \| `address` \| `pair` |
| `subject_key` | canonical key — **the same identity `get_or_create_node` computes** (`engine.nodes.normalize_symbol_name` for name; the address; the ordered endpoint pair for relationships) |
| `node_type` | the kind the fact applies to |
| `fact_kind`, `fact_json` | the distilled always-welcome fact (attribute facts) or relationship (`A calls B`) |
| `source_observation_id` | provenance |

Indexed on `(target_id, node_type, subject_kind, subject_key)`.

**Lifecycle (the two events):**
- **Observation write** → a per-`result_kind` **extractor** (a registry seam) distills only whitelisted facts into `enrichment_fact` rows, keyed by canonical identity. If a matching node/edge already exists, enrich it now (the forward, node-before-observation direction).
- **Node create / promote** (`get_or_create_node`) → a single **indexed lookup** by the node's `(name, address)` keys merges any waiting attribute facts into `attrs` (idempotent union); **relationship facts** where this node is an endpoint materialize their edge *iff the other endpoint now exists* (respecting the both-endpoints-exist rule). On a later **address-fill**, re-lookup by the address key.

**Why this shape:** parse-once (extraction at write, never at create); `O(facts-about-this-object)`, not `O(observations)`; idempotent (re-applying merges to a no-op); bounded and always-welcome-only (the extractor's whitelist); temporally symmetric (push at write, pull at create). **Bonus:** as functions are promoted, the call edges *among promoted functions* self-wire from prior observations — the curated graph's connectivity fills in for free, never exceeding the curated node set.

**Extractor registry** keeps it a clean seam: adding a tool means optionally adding an extractor for its always-welcome facts; conflicts (two decompilations disagree) resolve most-recent / highest-confidence with provenance retained.

### 5.6 Discoverability — "know to look" *and* "know where"

Storage without discoverability fails silently. Four reinforcing mechanisms:

1. **Surfaced in the context bundle.** `engine/context.py:_gather_items` gains an **observation-index item** — "prior analysis on this target: 12 decompilations, call graph computed, xrefs run, taint pass done (ids…)." The agent learns what exists without guessing. This is the strongest "know to look" lever and slots in beside the existing prior-findings/annotations/hypotheses items.
2. **Returned inline.** Every tool result includes its `observation_id` + a one-line reuse hint ("recorded as obs `…`; prior results: `list_observations(target)`").
3. **Queryable verbs.** `list_observations(target_id, tool?, kind?, since?)`, `get_observation(id)` (full payload from CAS), `search_observations(query)`.
4. **Advertised in `get_schemas`.** A dedicated `observations` section states the contract: results persist here, do **not** auto-populate the graph, **check here before re-running**, and promote what matters.

**User-facing:** a **"Tool Results" panel** per target (filter by tool/kind, view the raw CAS payload) and a **provenance link** on every node/finding ("derived from these observations") that opens the raw result, with a one-click **"promote to graph"** affordance. New `docs/dev/ux-contract.md` entries cover it. That's where the user knows to look.

### 5.7 Capturing the mentality in the agent/user instructions

The curation model only works if the agent internalizes it. It must appear on every instruction surface:

- **Tool-call descriptions** (`engine/mcp_catalog.py` + `engine/agent_tools.py`): query verbs — *"returns results and records an Observation; does NOT add graph nodes — review and promote what matters; check `list_observations` first to avoid re-running."* Enrich verbs — *"enriches the existing node in place (free) and links provenance."* Promote/record verbs — *"deliberately adds a curated result to the graph."*
- **`get_schemas`**: the substrate-vs-graph note + the Observation contract (§5.6.4).
- **The VR skill** — `~/.claude/skills/hexgraph-vr/SKILL.md` (user-level) **and** the repo-shipped agent instructions (`engine/agent_setup.py`, delegate-mode prompt): a "How analysis flows into the graph" section — *the graph is a curated result set, not the program model; on a target, first read the existing graph + Observation index; query freely (results persist as Observations); enrich existing objects for free; promote only meaningful results as new nodes/edges/findings.*
- **The agent-loop system prompt** (`engine/llm_tasks.py` / `llm/runner.py`): the same contract in one paragraph, so even a non-skill BYOK run inherits it.

---

## 6. The `static_analysis` task and the mock backend

Split the task into two layers:

- **A deterministic analysis core that always runs, backend-independent** — enriches existing nodes (§5.4), populates the substrate/Observations, and emits only **grounded** findings derived from the real bytes (e.g., "input reaches `system` via taint path X"), promoting only the few nodes/edges on the supporting path (§5.3). Its graph footprint is bounded by its findings, never the program.
- **An LLM synthesis layer on top** that interprets/prioritizes/writes exploit narrative — runs with `anthropic`/`claude_code`, reasoning over the now-**grounded** graph.

**Mock backend:** the fixture-replay machinery stays — it's the offline LLM simulator, and the backend-fidelity tests (`test_mock_backend`, `test_m3_llm_tasks`, `test_tool_use`) set scenarios **explicitly** and remain valid. The defect is only the **unprompted default**: with no scenario, `_resolve_scenario` hash-picks (keyed on `task_id`, not the binary) one of the non-error fixtures — and three of the four (`critical_overflow` the configured default, `agentic_overflow`, `malformed_then_valid`) fabricate a binary-agnostic vuln (`critical_overflow` is the canned `Stack buffer overflow in cgi_handler()`). Fix: under mock with no explicit scenario, the synthesis layer **contributes no fabricated finding** (default `static_analysis` to the `no_findings` path); the user sees only the grounded deterministic results. Explicit scenarios (`--mock-scenario`, the demo, the fidelity tests) still replay.

**Demo impact: none.** `just demo` (`src/hexgraph/demo.py`) is ingest → build → fuzz (≥1 crash) → poc (`command_injection`, verified) → spawn follow-up → check structural edges. It uses explicit scenarios for the asserted steps and **never asserts on `static_analysis` findings** (the task is only spawned). The deterministic core also produces grounded findings on the demo's vulnerable fixture, so the loop is *more* honest, not emptier. `enrich_recon`'s redirect is safe (off by default; demo runs no Ghidra; no test asserts on it). The deterministic core and the mock scoping ship together, so there is no window where mock produces nothing.

---

## 7. Phased implementation plan

Multi-PR per phase; a good fit for the integration-branch batch flow.

### Phase 0 — Make the shipped decompiler work, observable, and tested *(S–M; do first)*
- Fix `docker/sandbox.Dockerfile`: align JDK ↔ Ghidra (recommend **JDK 21 + Ghidra 12.x** for longevity) and add a **build-time assertion** that the JDK major matches Ghidra's requirement.
- Stop swallowing errors (`ghidra_probe.py`, `decompiler.py`): surface the probe's JSON `{error}`; capture **stdout**.
- Expose health: a **`check_decompiler`** read verb (wraps `check_ghidra()` + radare2 availability + a round-trip probe) and a `health`/`working` field on `get_schemas.decompiler`; optional **`set_decompiler`** per-session override.
- **CI gate:** build the sandbox `WITH_GHIDRA=1` and decompile a fixture, asserting real C. The single most important durable fix.

### Phase 1 — Persistent Ghidra project cache *(M–L; the perf unblocker)*
- `engine/ghidra_project.py`: analyze **once** into `<data_dir>/ghidra/<sha256>/`, keyed by `content_hash` + toolchain digest; subsequent calls reuse (`analyzeHeadless -process` or a long-lived session) instead of re-import-and-delete. Bounded eviction. This is the substrate's backbone.

### Phase O — Observation store, enrichment index, instruction surfaces *(M–L; foundational, lands before 2–4)*
- The `observation` + `enrichment_fact` tables (one migration), CAS payloads, provenance pointers (§5.2, §5.5).
- The query/enrich/promote plumbing (§5.3), the always-welcome extractor registry (§5.4), the per-call budget.
- Discoverability: context-bundle observation index, `list_observations`/`get_observation`/`search_observations`, `get_schemas` section (§5.6).
- Instruction surfaces updated (§5.7).
- Redirect `enrich_recon` → substrate; fix `agent_tools._materialize` to edge-only-if-exists.

### Phase 2 — Address-level access + breadth verbs *(M)*
- decompile/disassemble **by address**, analyze-at-addr, raise-depth/re-analyze.
- xrefs to/from a user function (callers *and* callees); data/string xrefs to an address.
- **`call_graph`** query verb (the POST_SCRIPT already emits it).
- search across decompiled bodies; wire `disassemble` under Ghidra. Each is a `read` MCP verb mirrored in `agent_tools.py`, all recording Observations.

### Phase 3 — Decompiler output → graph truth *(L)*
- Rich `function` nodes (address, prototype, params, locals, calling convention, summary) via the always-welcome path.
- Real structs only (filter built-ins; real layouts from DWARF/GDT).
- C++ `class`/`vtable` node kinds + `overrides`/virtual-call edges; switch/jump-table edges.
- rename/retype round-trip: `annotate(rename)` propagates into the persistent project (Phase 1) and re-decompiles.

### Phase 4 — Grounded analysis: P-Code data flow replaces hallucination *(L–XL; flagship)*
- A Ghidra script over `DecompInterface`/`HighFunction` P-Code computing **source→sink** flow → grounded `taints` edges feeding `engine/reachability.py`, behind a `get_taint_analyzer()` seam.
- The `static_analysis` deterministic core + mock scoping (§6).
- **P-Code emulation** for constant/key recovery (emulate a decode routine → recover the key).

### Phase 5 — External tools behind new seams *(tiered; XL)*
- **Tier A (cheap, high ROI):** `binutils` quick-facts probe; **FLARE FLOSS** (string deobfuscation); **YARA** (project-wide sweep); **ROPgadget/ropper** (feeds the exploitability ladder).
- **Tier B (flagship external):** **angr** behind `get_solver()` — input-to-sink solving, constraint solving (`check_password`), seed generation toward a sink; pairs with fuzzing + reachability. Opt-in/heavy, sandboxed.
- **Tier C (specialized):** **BSim** behind `get_similarity_index()` (a far stronger n-day than today's exact-`content_hash` `link_same_code`); **BinDiff/Diaphora** version diffing; **Semgrep** on managed source trees; **Unicorn** snippet emulation; **GDB/pwndbg** dynamic confirmation.

Each Tier item: a sandboxed probe + a seam impl + a feature gate; results flow through the Observation store and the frozen Finding schema.

---

## 8. Data model & migration summary

- **New tables (one migration):** `observation`, `enrichment_fact`.
- **No other migrations:** new node kinds (`class`, `vtable`, `gadget`) and edge kinds (`overrides`, `vtable_entry`) are String-column vocab; new attributes ride `attrs_json` with `node_schemas.py`/`edge_schemas.py` registry entries; provenance is an attribute array.
- **CAS** reused for raw payloads (already stores tool outputs).

## 9. Testing & CI

- **The gate:** a CI job builds the sandbox `WITH_GHIDRA=1` and decompiles a fixture, asserting real C output — so Ghidra cannot ship broken again.
- **Curation invariants** (unit): a query verb creates no nodes; an edge is never drawn to a non-existent endpoint; the per-call budget caps and reports overflow.
- **Enrichment index** (unit): node-before-observation and observation-before-node both converge to the same enriched node; re-apply is a no-op; a relationship edge appears exactly when its second endpoint is promoted.
- **Mock/grounding:** `static_analysis` under mock with no scenario emits no fabricated finding; the deterministic core emits grounded findings on the eval fixtures; backend-fidelity tests (explicit scenarios) unchanged; `just demo` still exits 0.
- **Per-tool:** each new analyzer has a fixture-based extractor test (always-welcome facts only).

## 10. Sequencing, sizing, biggest bets

Order: **0 → 1 → O → 2 → 3 → 4**, with Phase 5 tiers interleaved by ROI (Tier A any time after Phase 0; angr/BSim want Phase 1). The four highest-value bets, in order:

1. **Phase 0 + CI gate** — everything else builds on it (and it broke twice).
2. **Phase 1 persistent project cache** — unlocks every heavy capability.
3. **Phase 4 P-Code taint** — replaces the hallucinating analyzer with grounded, graph-feeding results; the biggest quality jump.
4. **angr (Phase 5 Tier B)** — the most valuable new capability (automatic input→sink), composes with fuzzing/reachability.

Rough sizing: Phase 0 small (days); Phases 1, O, 2, 3 each medium–large; Phase 4 large; Phase 5 open-ended by tier.

## 11. Open questions

- **Naming:** "Observation" (model) vs "Tool Result" (UI label) — pick one user-facing term.
- **JDK/Ghidra:** commit to JDK 21 + Ghidra 12.x (recommended) vs pin Ghidra 11.1.2 to the existing JDK 17.
- **Enrichment index vs subject-indexed observations:** the dedicated `enrichment_fact` table (parse-once, recommended) vs indexing observations by subject and re-extracting the matched few at create (fewer moving parts, slightly more work per create). Start with the fact table.
- **angr scope:** how far to take symbolic execution before it becomes its own program (constraint-solve a single check vs whole-path solving).
