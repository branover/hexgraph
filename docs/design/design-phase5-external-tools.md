# Design — Phase 5: External RE Tools Behind New Seams

**Status:** proposed (design) · **Dated:** 2026-06-05
**Scope:** the "External tools behind new seams" section of `docs/design/design-re-tooling.md` (its Phase 5), made concrete and — more importantly — *curated*. This reconciles a ten-tool design council into one authoritative plan we steer from.
**Supersedes for Phase 5:** §7 Phase 5 and §10 of `design-re-tooling.md`. Read that document for Phases 0–4, which are built; read this one for what we add on top, and which tools we consciously decline.

---

## 1. Status & grounding

HexGraph's reverse-engineering substrate is already deep. Phase 5 is the last layer of the RE-tooling plan, and it is the easiest place to do damage by over-building, so the whole point of this document is to decide **which external tools are actually worth their permanent cost** and to slice only those into shippable work. Before any of that, here is the ground truth a resumed session should trust — every claim below was verified directly against the repository, file by file, so a resumed session can rely on it.

**What is already built (Phases 0, 1, O, 2, 3, 4):**

- **Phase 0 — the decompiler works, is observable, is CI-gated.** `sandbox/decompiler.py` exposes the `get_decompiler()` seam (radare2 default; headless/bridge Ghidra when enabled). Probe failures surface their real reason instead of a bare `exit N` (`sandbox/runner.py:_probe_failure_message`).
- **Phase 1 — the persistent Ghidra project cache.** `engine/ghidra_project.py` analyzes a binary once into `<data_dir>/ghidra/<sha256>__<version>/`, keyed by content hash plus toolchain version, with a cross-process advisory lock and bounded LRU eviction. Heavy passes reuse it instead of re-importing. This is the substrate's backbone and the reason any new heavy Ghidra-based tool is cheap to add.
- **Phase O — the Observation store and the enrichment index.** `engine/observations.py` records every deterministic tool call as a durable `Observation` (the call, a summary, the full payload in CAS, scoped to the analyzed bytes by `content_hash`), gives "analyze once, reuse forever" dedup for free, and creates **zero** graph nodes. `engine/enrichment.py` is the always-welcome auto-enrichment machinery: an extractor registry keyed by `result_kind` distills only whitelisted facts (`_ATTRIBUTE_WHITELIST`, `_RELATIONSHIP_WHITELIST`, `DANGEROUS_IMPORTS`) into `enrichment_fact` rows by canonical identity, enriching existing nodes at write and joining waiting facts at node-create. This is the single load-bearing fact for Phase 5: **a new tool plugs in by writing an Observation and (optionally) registering an extractor — it does not get to mint nodes.**
- **Phase 2 / Phase 3 — address-level access and decompiler-output-as-graph-truth** are in the decompiler seam contract (`decompile(..., address=, reanalyze=, project=)`) and the enrichment whitelist (function address/prototype/params/calling-convention/demangled-name; `is_sink` symbol tags; struct layouts).
- **Phase 4 — grounded analysis that replaces hallucination.** `engine/taint.py` is the `get_taint_analyzer()` seam (Ghidra `HighFunction` P-Code source→sink taint; `NullTaintAnalyzer` when Ghidra is off — nothing is fabricated). `engine/static_core.py` is the deterministic `static_analysis` core that emits a grounded finding per real flow. `engine/emulation.py` runs Ghidra's P-Code emulator to recover a constant/key from a decode routine, gated by `policy.assert_allows_emulation()`. `engine/reachability.py` walks the typed graph for a static source→sink argument feeding the assurance ladder. And `engine/crosstarget.py:link_same_code` is today's n-day primitive: it links **byte-identical** (`content_hash`) functions across targets with a `similar_to` edge.

**The constraints that bound every addition** (`CLAUDE.md`, `policy.py`): loopback-only; BYOK / Claude Code / mock backends only; *targets are hostile*, so all target-byte handling runs in the disposable Docker sandbox (`--network none`, read-only rootfs, dropped caps, non-root, resource-capped, hard timeout); the policy seam (`policy.py`) is **the only place** static-only / no-exec / no-network relaxes; the Finding schema (`schemas/finding.schema.json`) is frozen, so new structure rides the DB envelope; every model change ships an Alembic migration; and the seam rule holds — **ask a seam, never branch on backend/tier/executor identity.** Note the existing `policy.assert_allows_emulation()` precedent: a *heavy* opt-in that relaxes **no** boundary (it interprets P-Code, never executes natively) and deliberately raises no tier. Several Phase 5 tools follow exactly that posture.

**The one-line goal of Phase 5:** add the *few* external RE tools whose marginal vulnerability-research value clearly exceeds their permanent maintenance cost, each as a sandboxed probe whose results flow through the Observation store and (where they make a claim) the frozen Finding schema — and consciously decline the rest.

**How to resume from this doc:** read §3 for the verdicts (the curation *is* the product of this document), §4 for the phased rollout of *only* the adopted tools, and §6 for the live checklist of what is done versus next. Everything is grounded in the files cited above; if a status claim here conflicts with the code, the code wins and this doc is stale.

---

## 2. The integration framework

Every external tool we adopt follows one uniform recipe, and that uniformity is what keeps the marginal cost of each new tool low enough to reason about. The framework below is the contract; §3 then decides which tools are worth paying it for.

### 2.1 The uniform recipe

A new external tool is, at most, these five pieces — and the fewer of them it needs, the cheaper it is:

1. **A sandboxed probe** (`sandbox/probes/<tool>_probe.py`). It runs the tool on the target bytes inside the disposable container, emits JSON on stdout, and an error JSON on failure. Probes are **mounted at runtime** (`sandbox/runner.py` overlays `probes/` read-only over the baked copy), so a probe change needs no image rebuild — **only a new toolchain dependency in `docker/sandbox.Dockerfile` triggers a rebuild.** This is the dominant real cost of a tool: not the Python, the image weight.
2. **An Observation `result_kind`.** The tool's output is recorded by `observations.record_observation(..., result_kind="<kind>", payload=...)`, scoped by `content_hash`. This buys dedup, discoverability, and provenance with zero bespoke storage. New `result_kind` values are free (a string).
3. **An optional extractor** (`enrichment.register_extractor("<kind>", fn)`) *only if* the tool recovers an always-welcome fact about an object that already exists (an address, a prototype, an `is_sink` tag). Most Phase 5 tools recover *results*, not always-welcome facts, so they skip this and let the agent/user promote what matters.
4. **A seam, only when a second implementation is plausible.** A tool gets a `get_<capability>()` seam *iff* a different backend could one day answer the same question (the test angr meets: it answers "does input reach this sink" the way `get_taint_analyzer()` does). A tool that is simply itself — FLOSS deobfuscates strings; nothing else does — does **not** earn a seam; it is a probe plus a thin engine function. Inventing a one-implementation seam is bloat dressed as architecture.
5. **A feature gate** (`features.<tool>` in `settings.json`, registered in `setup_catalog.py`) *only if* it is heavy or relaxes a boundary. A cheap, static, no-execution tool can ride the existing analysis surface ungated, like recon does. A heavy tool gets a settings toggle for opt-in; a tool that touches execution or egress routes its gate through `policy.py`.

### 2.2 The seam-taxonomy decision rule

Three categories, and a tool belongs to exactly one:

- **Static, no-execution, single-purpose** (binutils, FLOSS, YARA, ROPgadget): a probe + an engine function + an Observation `result_kind`. No seam (nothing else implements it). A feature gate only if it is heavy enough to warrant opt-in; otherwise it rides the existing static surface. These are cheap and reversible.
- **Heavy analysis another backend could also answer** (angr): a real seam (`get_solver()`), because it answers the same "reaches a sink / satisfies a constraint" question the taint analyzer does, and a future backend (a different symbolic engine, a cloud solver) must drop in behind it. Feature-gated as opt-in heavy compute, routed through `policy.py` in the manner of `assert_allows_emulation()` — heavy, but relaxing **no** sandbox boundary (no native target execution, no network), so it is a heavy-analysis opt-in, not an execution-tier raise.
- **Folds into something already built** (Unicorn, GDB/pwndbg): not adopted as a new seam at all. Their capability is already covered (P-Code emulation, PoC execution) or would duplicate it; adopting them is negative value.

### 2.3 The discoverability system

A capability the agent never reaches for is dead weight, so every adopted tool must light up the same four surfaces the rest of the system already uses (`design-re-tooling.md` §5.6):

1. **The context bundle** (`engine/context.py`) already surfaces an Observation index ("prior analysis on this target: N decompilations, taint pass done…"). A new tool's Observations appear there automatically by virtue of being Observations — the agent learns the tool ran without us writing anything new.
2. **Inline reuse hints** — every probe-backed engine function returns its `observation_id` plus the standing "check `list_observations` first" hint, so the agent knows the result persists and is reusable.
3. **MCP / agent-tool entries** — a read/run verb in `engine/agent_tools.py` and `engine/mcp_catalog.py`, gated under `features.mcp.{read,run}` so the agent's context stays lean. The verb description states the curation contract (queries record an Observation, do not mint nodes; promote what matters).
4. **`get_schemas` / capabilities** — `engine/capabilities.py` advertises the tool when its gate is effective, read through `policy.effective_gates()` (never a raw settings read), so a ceiling-clamped gate is never falsely advertised.

### 2.4 The anti-bloat rules

These make the curation in §3 non-negotiable rather than aspirational:

- **No tool that duplicates a built capability.** Phase 4 already does P-Code data-flow taint, P-Code emulation, reachability, and PoC execution. A tool whose headline feature overlaps these must show a *distinct* marginal benefit or it is dropped.
- **No one-implementation seam.** A `get_X()` abstraction with a single concrete class and no plausible second one is ceremony. FLOSS/YARA/ROPgadget are functions, not seams.
- **Image weight is the real budget.** Every apt/pip dependency in `docker/sandbox.Dockerfile` is paid by every user on every build and pull. A tool that adds hundreds of MB (a second symbolic-execution stack, a full debugger toolchain) must clear a much higher bar than one that adds a single small binary.
- **Every adopted tool is a permanent tax:** a probe, image deps, possibly a seam, a feature gate, an MCP entry, a CI regression test, and ongoing maintenance. Defer or drop on any reasonable doubt; a leaner set is the better outcome.

### 2.5 Unification — results land in one place

There is no second storage path. Every tool writes an Observation; every node/edge/finding it later justifies carries `attrs.provenance = [observation_id, …]` (`observations.add_provenance`) and the Observation carries `node_refs` back. A tool that makes a vulnerability claim emits a frozen-schema `Finding` via `engine/findings.py` with the right `finding_type` (the vocab is `vulnerability | recon | harness | fuzz_crash | poc | annotation | other`; a gadget chain or a YARA hit is `recon`/`other`, never a new type). New graph vocab (a `gadget` node kind, a `matches_rule` edge kind) is a zero-migration String value with a `node_schemas.py` / `edge_schemas.py` registry entry. The only new table Phase 5 could justify is **none** — everything rides CAS, Observations, and the envelope.

### 2.6 The safety envelope

Nothing here relaxes the sandbox. binutils, FLOSS, YARA, ROPgadget, and angr all *read* target bytes; none *executes* the target. They run with the same `--network none`, read-only rootfs, dropped caps, non-root, resource-capped, timed container as every other probe. angr is the one with real resource appetite (symbolic execution can blow up memory and time), so its gate routes through `policy.py` purely to make it opt-in and to let the existing `ResourceSpec` ceilings bound it — **not** because it raises the execution or egress tier. It does not; like `assert_allows_emulation()`, it is a heavy-analysis gate that leaves the boundary exactly where it was.

### 2.7 The CI and maintenance gate

The Ghidra breakage shipped twice because nothing tested it end to end; Phase 5 inherits that lesson. Every adopted tool lands with:

- a **fixture-based probe test** (the tool runs on a committed fixture and produces the expected Observation shape), skipped when the image is absent like the other Docker-gated tests;
- if it adds an image dependency, a **dependency-present assertion** in the sandbox-build CI job (the tool's binary/module is present in the built image), so an image change can't silently drop it;
- if it registers an extractor, an **extractor unit test** asserting it emits *only* whitelisted facts.

No tool merges without these. A tool nobody is willing to write a regression test for is a tool we should not adopt.

### 2.8 Agent-controlled parameters — a small validated set, never raw argv

A tool's *invocation* belongs to HexGraph, not to the agent. The agent loop advertises each capability with a tight, typed schema in `engine/agent_tools.py`, and the model supplies only a few **validated structured fields** — a function name, an address, a rule id, a bounded budget. HexGraph maps those into the fixed command the probe runs and always injects the target itself as the probe's read-only `/artifact`; the model never sets flags, paths, mounts, network, or resource caps. Every tool already in the tree works this way — `decompile` takes `{function}`, `disassemble` takes `{address}`, even `fuzz` takes only `{max_total_time}`, never a command line. Three forces make this non-negotiable: the target bytes are hostile, so an agent-assembled argv is an injection surface; the Observation store dedups by `(content_hash, result_kind)`, which free-form flags would defeat; and the seam rule advertises a *capability*, not a *binary*, so backends stay swappable. So each adopted tool below declares a **small, closed set of agent knobs**, all typed and validated — everything outside that set is fixed in the probe. "The model directs, HexGraph runs the tool" is meant literally.

---

## 3. Tool catalog & verdicts

The council advocated for ten tools, one specialist each. The cross-cutting judgment they could not make — *is this worth its permanent cost given everything already built* — is the value of this section. Here is the curation at a glance:

| Tool | Verdict | One-line reason |
|------|---------|-----------------|
| **binutils** (nm/objdump/readelf/strings) | **Adopt** | Tiny image cost, broad quick-facts value, already partly present; the cheapest win. |
| **FLOSS** (FLARE string deobfuscation) | **Adopt** | Recovers stack/obfuscated strings recon misses — a real, distinct capability firmware/malware needs, at low cost. |
| **YARA** | **Adopt** | Corpus-wide pattern sweep is the natural complement to exact-hash n-day; small, no execution. |
| **ROPgadget / ropper** | **Defer** | Cheap to add, but gadgets are inert until an exploit-primitive consumer exists; none does yet. |
| **angr** | **Adopt (flagship, last)** | The one genuinely *new* answer — a concrete reaching input — but heavy, so it ships last behind a real seam. |
| **BSim** | **Defer** | A strictly better n-day than exact-hash linking, but needs a populated corpus and a standing similarity datastore. |
| **BinDiff / Diaphora** | **Drop** | Real but niche version-diff; high BinExport/Ghidra plumbing cost and upgrade fragility for a workflow few sessions hit. |
| **Semgrep** | **Drop** | Source-tree SAST is off HexGraph's binary/firmware axis; the rare source case is the agent's own job. |
| **Unicorn** | **Drop** | Snippet emulation duplicates the built P-Code emulator (`engine/emulation.py`); a second stack is pure redundancy. |
| **GDB / pwndbg** | **Drop** | Dynamic confirmation overlaps the PoC oracle (`engine/poc.py`); a full debugger toolchain is heavy weight for redundant value. |

Four adopted, three deferred (with clear unblock conditions), three dropped. The subsections below give each tool its full reasoning in the same shape: capability · seam · probe + image deps · gate + tier · outputs · dependencies · sizing · ROI · risks · verdict.

### 3.1 binutils — nm / objdump / readelf / strings

- **Capability.** Fast, authoritative low-level facts: the symbol table, dynamic imports/exports, relocations, ELF/section headers, the program's security mitigations (NX, RELRO, PIE, stack canary), and a clean `strings` pass. These are the questions a researcher asks in the first minute, and recon today answers them only partially (imports capped at 60, strings at 20).
- **Seam.** None — deterministic facts, not a swappable backend. A `binutils_probe.py` plus a thin `engine` helper.
- **Agent knobs.** None — a parameterless facts pass (like `strings`/`imports`); the agent triggers it and HexGraph fixes the whole invocation.
- **Probe + image deps.** `sandbox/probes/binutils_probe.py`. binutils is almost certainly already present transitively via the existing toolchain; if not, it is a single small apt package. Negligible image growth.
- **Gate + tier.** None. Static, no execution, cheap — it rides the existing recon/analysis surface ungated, exactly as recon does.
- **Outputs.** A `binutils_facts` Observation. It registers an extractor for the *always-welcome* subset: imports feed `symbol` enrichment and the dangerous ones get `is_sink` via the existing `DANGEROUS_IMPORTS` path; mitigation flags ride the target's `metadata_json`. Nothing here is a finding on its own; a missing mitigation becomes `recon`-typed context.
- **Dependencies.** None beyond the sandbox image.
- **Sizing.** S (days).
- **ROI.** High per cost — it sharpens the very first move of every analysis at essentially zero permanent cost.
- **Key risks.** Overlap with recon's existing import/string materialization; the probe must *defer to* recon's caps and feed the substrate, not re-flood the graph with strings (the Phase O curation rule).
- **Verdict: Adopt.** The cheapest, broadest win on the board; it strengthens the opening move of every engagement at essentially no permanent cost.

### 3.2 FLOSS — FLARE Obfuscated String Solver

- **Capability.** Recovers strings a plain `strings` pass misses: stack strings, tightly-packed strings, and strings produced by simple decode routines, by lightly emulating the functions that build them. On firmware and malware-adjacent targets these hidden strings (URLs, command templates, keys, format strings) are often the lead.
- **Seam.** None — FLOSS is singular; nothing else does this. A `floss_probe.py` plus an engine helper.
- **Agent knobs.** At most an optional, validated minimum-string-length or single-function selector; the FLOSS flags themselves stay fixed in the probe.
- **Probe + image deps.** `sandbox/probes/floss_probe.py`. FLOSS is a pip package (it vendors a small emulation stack). Modest pip-layer growth, no large native toolchain.
- **Gate + tier.** A light `features.floss` settings toggle is reasonable because the deobfuscation pass is slower than `strings` and you do not always want it; it raises **no** policy tier (it emulates decode routines in-process, never executing the target natively — the same posture as `assert_allows_emulation`) and needs no `policy.py` entry. Default off.
- **Outputs.** A `floss_strings` Observation carrying recovered strings with source function and decode type. Strings of interest are promotable to `string` nodes; a recovered command template feeding a known sink is real lead material, recorded as `recon` context, never auto-asserted as a vuln.
- **Dependencies.** None beyond the pip install.
- **Sizing.** S–M.
- **ROI.** High on the target classes HexGraph cares about (firmware, embedded). It recovers signal that is otherwise invisible, without a heavy stack.
- **Key risks.** FLOSS can be slow on large binaries — bound it with the existing probe timeout and let the gate make it opt-in. Its internal emulator stays inside the sandbox (it is just Python in the probe).
- **Verdict: Adopt.** A genuinely distinct capability recon cannot replicate, at a cost (one pip package, one optional probe) that is easy to carry.

### 3.3 YARA

- **Capability.** Pattern matching across the whole ingested corpus: a researcher writes (or ships) a rule for a vulnerable code pattern, an embedded credential, a known-bad library version, a packer signature — and sweeps every target and every extracted firmware file for it. This is the *pattern* complement to the *exact-hash* n-day link `crosstarget.link_same_code` already provides: where that finds byte-identical functions, YARA finds the fuzzy/structural matches an analyst can author.
- **Seam.** None — YARA is a matcher, not a swappable analysis backend.
- **Agent knobs.** Which bundled ruleset (or *all*) to sweep, chosen by id/enum — never a `yara` command line; the rule files and match flags are fixed.
- **Probe + image deps.** `sandbox/probes/yara_probe.py`. `yara` + `yara-python` is a small, mature dependency. Small image growth.
- **Gate + tier.** No policy tier. A light `features.yara` toggle is justified only because rule management is a UX surface; the matching itself is cheap, static, no execution. Default off until there is a rule-sourcing story.
- **Outputs.** A `yara_matches` Observation per target. A match promotes to a `pattern` node (the kind already exists in `node_schemas.py`) and a `matches_rule` edge (zero-migration vocab) linking the matched node/target to the pattern. A match asserting a known vulnerability is an `other`/`recon`-typed finding citing the rule — never a fabricated severity.
- **Dependencies.** A meaningful rule corpus (the real gating question — see risks).
- **Sizing.** M (the matcher is easy; the rule-management UX is the work).
- **ROI.** High *if* rules exist — it turns one analyst's finding into a corpus-wide sweep, exactly HexGraph's "spawn the next task" thesis. Medium until the rule story lands.
- **Key risks.** The capability is only as good as its rules; shipping YARA with no rules is shipping an empty box. The phase must include a minimal bundled rule set plus a path to add the user's own, or YARA is theater. Rule files are not target bytes, so they need no sandboxing, but the *match* runs in the sandbox like everything else.
- **Verdict: Adopt.** It directly amplifies the product's core loop (one finding → corpus-wide hunt) and is cheap to run; the only real work is rule management, which the phase owns explicitly.

### 3.4 ROPgadget / ropper

- **Capability.** Enumerates ROP/JOP gadgets and helps assemble chains — the raw material for turning a memory-corruption primitive into control-flow hijack.
- **Seam.** None (a gadget enumerator is singular).
- **Probe + image deps.** A `ropgadget_probe.py`; `ROPgadget`/`ropper` are small pip packages. Cheap.
- **Gate + tier.** No execution, no tier; a light toggle at most.
- **Outputs.** A `gadgets` Observation; gadgets promotable as `gadget` nodes (zero-migration vocab).
- **Dependencies.** **A consumer.** Gadgets matter only to a stage that is *building an exploit* — and HexGraph has none. The PoC path (`engine/poc.py`) verifies a *provided* attacker input against a `{{NONCE}}` oracle; it does not synthesize ROP chains, and nothing in the graph or the agent loop reasons over a gadget set today.
- **Sizing.** S to add, but the value is gated on building the consumer (L+).
- **ROI.** Low *now*. Enumerating gadgets that nothing reads is a list in a drawer; the marginal benefit over what's built is near zero until an exploitability ladder consumes gadgets.
- **Key risks.** Adopting it now is taking on maintenance for a feature with no reader — the textbook "complexity for little benefit" the curation guidance warns against.
- **Verdict: Defer.** Cheap and real, but valueless until an exploit-primitive consumer exists. **Unblock condition:** an exploitability/primitive-chaining stage (a successor to the PoC oracle) that actually reads a gadget set. Add ROPgadget *with* that consumer, in the same phase, so it never ships as a list nobody reads.

### 3.5 angr — symbolic execution behind `get_solver()`

- **Capability.** The one genuinely new analytical power in the council: given a sink, **solve for an input that reaches it**; given a check (`if (strcmp(input, secret))`), **recover the value that satisfies it**; generate a seed that drives execution toward a target block to bootstrap fuzzing. It composes with what's built — reachability argues a *path exists*; angr can argue an *input exists* and even produce it; taint flags the flow; angr concretizes it.
- **Seam.** **Yes — `get_solver()`**, the textbook earned seam. It answers the same family of question as `get_taint_analyzer()` (does untrusted input reach this sink, and under what constraints), and a future symbolic backend or cloud solver must drop in behind it. `AngrSolver` is the first concrete; a `NullSolver` degrades gracefully (no solution, nothing fabricated), mirroring `engine/taint.py` (ABC + concrete + Null) precisely.
- **Agent knobs.** The sink/function to solve toward (a validated node reference) and optionally a coarse budget tier; never a raw angr script or unbounded exploration — the step/state/time caps are HexGraph's, enforced in the probe.
- **Probe + image deps.** `sandbox/probes/angr_probe.py`. angr is the heaviest dependency on the board: it pulls a substantial pip stack (z3, the VEX/pyvex/claripy chain, archinfo). Meaningful image growth — the single biggest weight Phase 5 considers, which is exactly why it ships last and gated.
- **Gate + tier.** `features.angr`, routed through `policy.py` as a heavy-analysis opt-in modeled on `assert_allows_emulation()`: **it raises no execution or egress tier** (angr symbolically executes; it never runs the target natively, opens no socket). The gate exists to make it opt-in and bound it with the existing `ResourceSpec` caps, because symbolic execution is the one tool here that can genuinely exhaust memory/time. Default off.
- **Outputs.** A `solver` Observation carrying the recovered input/constraints/path. When angr solves an input reaching a known sink, that promotes the few grounded nodes/edges on the path and emits a high-confidence `vulnerability` finding *with the concrete input in the envelope* — the strongest static claim HexGraph can make short of a live PoC. A recovered constant feeds the same node-annotation path as `engine/emulation.py`.
- **Dependencies.** Phase 1's persistent project is not required (angr works from the raw artifact), but angr pairs best *after* taint has nominated sinks, so it slots after Phase 4 in practice. Composes with fuzzing (seed generation) and reachability (concretizing an argued path).
- **Sizing.** L–XL. Scope discipline is essential: aim at **single-sink input solving and single-check constraint solving**, explicitly *not* whole-program symbolic exploration (which becomes its own runaway project — §7 flags it).
- **ROI.** Highest *new* capability, but also highest cost. Worth it because nothing else can produce a *concrete reaching input* statically — a qualitative jump in finding strength, not an incremental one.
- **Key risks.** Resource blow-up (bound by `ResourceSpec` + timeout + a step cap in the probe); scope creep into a general symbolic engine (hold the line at targeted solving); image weight (accept it consciously, as the flagship, shipped last).
- **Verdict: Adopt (flagship, last).** The only adoption that adds a *new kind of answer* rather than a sharper version of an existing one; its cost is real, so it ships last, behind a real seam, scoped tightly to targeted solving.

### 3.6 BSim — Ghidra structural similarity

- **Capability.** Ghidra's BSim finds *structurally similar* functions across a corpus via feature-vector signatures — a far stronger n-day primitive than `crosstarget.link_same_code`, which links only **byte-identical** functions. BSim catches the same vulnerable routine after a recompile, a minor patch, or a different optimization level — precisely the case exact-hash linking misses.
- **Seam.** Would earn one — `get_similarity_index()` — since BSim and (later) other similarity backends answer the same "is this the same code as something I've seen" question. A legitimately seam-shaped capability.
- **Probe + image deps.** Reuses the persistent Ghidra project (Phase 1) for signature generation, so *generation* is cheap. But BSim's value comes from **querying a populated signature database**, which means standing up and maintaining a BSim DB (its own Postgres/H2 backing store and schema) — meaningful infrastructure beyond a probe.
- **Gate + tier.** No policy tier (static). But the infra (a similarity DB) is real operational weight.
- **Outputs.** Stronger `similar_to` edges (the kind exists), enriched with a similarity score — a direct upgrade to the n-day map.
- **Dependencies.** **A populated signature corpus.** Like YARA-without-rules, BSim-without-signatures is empty; its payoff scales with how much code is indexed, and a single-target session sees nothing.
- **Sizing.** L (the DB and corpus management dominate).
- **ROI.** High *in the limit* (a real n-day engine), low for a user analyzing one or a few targets — the common case today.
- **Key risks.** Standing infrastructure (a database to run, migrate, back up) is a category of cost the rest of HexGraph deliberately avoids (SQLite-only, no Neo4j). Adopting BSim quietly reintroduces "a second datastore to operate."
- **Verdict: Defer.** The right long-term n-day engine, but its value is gated on a populated corpus and it brings standing infrastructure the current single-target usage doesn't justify. **Unblock condition:** a real multi-firmware corpus in regular use *and* a decision to accept a similarity datastore. Until then, `link_same_code` plus YARA cover the practical n-day need.

### 3.7 BinDiff / Diaphora

- **Capability.** Function-level diff between two binary versions — patch-diffing ("what changed between vulnerable and patched firmware, where's the silently-fixed bug").
- **Seam.** A `get_differ()` could exist, but with one realistic backend it is borderline ceremony.
- **Probe + image deps.** BinDiff needs BinExport (a Ghidra/IDA exporter) plus the BinDiff engine; Diaphora needs IDA or a Ghidra bridge and its own SQLite export. Either way the plumbing (export both sides, align, import the diff) is substantial.
- **Gate + tier.** No tier (static), but heavy integration.
- **Outputs.** A diff Observation; changed functions as enriched nodes / a `differs_from` edge.
- **Dependencies.** Two versions of the same target in hand, plus the export toolchain.
- **Sizing.** L (the export/align/import plumbing is the cost).
- **ROI.** Real but **niche** — most sessions analyze one target, not a version pair, and a determined analyst can patch-diff out-of-band. The integration cost (BinExport wiring into the Ghidra project, two-sided orchestration) is high relative to how often a session hits it.
- **Key risks.** Heavy, version-pair-only, and the export tooling is finicky across Ghidra upgrades — a maintenance liability of the same kind that broke Ghidra twice.
- **Verdict: Drop.** A high-cost integration for a workflow few sessions reach; the marginal benefit over manual patch-diffing does not justify the permanent plumbing or its upgrade fragility.

### 3.8 Semgrep

- **Capability.** Pattern-based static analysis over **source code** — strong SAST when you have a source tree.
- **Seam.** None relevant.
- **Probe + image deps.** A `semgrep_probe.py` over a managed source tree; Semgrep is a sizable install with its own rule ecosystem.
- **Gate + tier.** No tier.
- **Outputs.** `vulnerability`-typed findings from rule matches on source.
- **Dependencies.** **A source tree** — off HexGraph's main axis. Targets are binaries and firmware; source appears only in the niche build-from-source path. On the common binary target, Semgrep has nothing to read.
- **Sizing.** M, but mostly wasted on the dominant use case.
- **ROI.** Low *for HexGraph specifically*. When a managed source tree does exist, the agent's own coding-agent tools (and the operator running Semgrep directly) cover it better than a bolted-in probe; the binary-target majority gets zero value.
- **Key risks.** It pulls the product off-axis toward source SAST, a different category, while adding weight the binary-first majority never uses.
- **Verdict: Drop.** Off the binary/firmware axis HexGraph is built around; the rare source case is better served by the agent's existing tools, so the probe is weight without a constituency.

### 3.9 Unicorn — CPU snippet emulation

- **Capability.** Emulate a slice of machine code (a CPU emulator, no OS) to recover what a routine computes — a decoded value, a derived key, a checksum.
- **Seam.** Would duplicate one.
- **Probe + image deps.** Unicorn is a moderate pip/native dependency.
- **Gate + tier.** No tier.
- **Outputs.** A recovered constant — *the exact output `engine/emulation.py` already produces.*
- **Dependencies.** None special, which is the problem: **its capability is already built.** Phase 4's `engine/emulation.py` runs Ghidra's P-Code emulator to recover precisely these constants/keys, gated by `assert_allows_emulation()`, and annotates the function node with the result. Unicorn would be a *second* emulation stack answering the same question.
- **Sizing.** M to add — for negative net value.
- **ROI.** Negative. It adds a dependency and a maintenance surface to duplicate a working capability. The only conceivable edge — P-Code emulation failing where raw-CPU emulation succeeds — is rare and does not justify a parallel stack; if it ever bites, extend the existing emulation seam rather than bolt on Unicorn.
- **Key risks.** Two emulation paths to maintain and keep consistent; the seam rule violated in spirit (two tools answering one question with no abstraction unifying them).
- **Verdict: Drop.** It duplicates the already-built P-Code emulator; a second emulation stack is pure redundancy, and any gap is better closed inside the existing seam.

### 3.10 GDB / pwndbg — dynamic confirmation

- **Capability.** Run the target under a debugger to confirm a crash, inspect memory at the moment of corruption, and validate an exploit primitive dynamically.
- **Seam.** Would overlap one.
- **Probe + image deps.** GDB plus pwndbg (and its Python stack, plus gdbserver for foreign-arch via the existing qemu-user) is a **heavy** toolchain addition.
- **Gate + tier.** This one *does* execute the target, so it would route through `policy.assert_allows_execution()` (the real execution tier) — the same gated category as PoC/fuzzing.
- **Outputs.** Dynamic confirmation of a crash/primitive.
- **Dependencies.** Execution permission — and HexGraph **already has** an execution-confirmation path: `engine/poc.py` runs the target in the sandbox against an unforgeable `{{NONCE}}` oracle and records "verified," including foreign-arch under qemu-user with the parent firmware's rootfs as sysroot. The fuzzing path already produces crash findings with crashing inputs.
- **Sizing.** L (heavy toolchain) for largely redundant value.
- **ROI.** Low. Interactive debugger inspection is powerful for a *human*, but HexGraph's loop is agent-driven and the agent already gets dynamic confirmation through the PoC oracle. A scripted GDB pass would add a heavy toolchain to produce a weaker, less-structured version of what `verify_poc` already returns.
- **Key risks.** Heavy image weight; an execution path parallel to PoC that must stay inside the same hardening; marginal benefit over the existing oracle.
- **Verdict: Drop.** Dynamic confirmation is already covered by the PoC oracle and fuzzing crashes; a full debugger toolchain is heavy weight for redundant, less-structured value.

---

## 4. Phased rollout

Only the four adopted tools are sliced into phases. Ordering follows ROI-over-cost: the three Tier-A quick wins first (cheap, immediately useful, no new infra), then angr last as the heavyweight flagship behind its seam. Deferred and dropped tools appear **only** in §4.4, never in a numbered phase.

### Phase 5A — Quick-facts and hidden strings *(S–M; ship first)*

The cheapest, broadest wins, each a probe + Observation + (where apt) an extractor, no new seam.

- **PR 5A-1 — binutils quick-facts probe.** `binutils_probe.py` (symbols, imports/exports, relocations, ELF/section headers, mitigation flags), a `binutils_facts` Observation `result_kind`, an extractor feeding the always-welcome import/`is_sink` path and the target's mitigation metadata. MCP/agent read verb + capability entry. Ungated. CI: probe runs on a committed ELF fixture; the binutils binaries are asserted present in the image.
- **PR 5A-2 — FLOSS string deobfuscation.** `floss_probe.py`, a `floss_strings` Observation, a light `features.floss` settings toggle (no policy tier), promotable `string` nodes, MCP/agent verb, capability entry. CI: probe recovers a known stack string from a committed fixture.
- **Done-criteria.** Both probes run in the sandbox over fixtures and record Observations; binutils facts auto-enrich existing symbol/function nodes (whitelist only, asserted by the extractor test); FLOSS is opt-in and bounded by the probe timeout; the agent's context bundle shows the new Observations; `just test` and `just demo` stay green.

### Phase 5B — Corpus-wide pattern sweep *(M)*

- **PR 5B-1 — YARA matcher.** `yara_probe.py`, a `yara_matches` Observation, the `matches_rule` edge kind (registry entry), promotion of matches to `pattern` nodes, `features.yara` toggle (no policy tier), MCP/agent run verb, capability entry. CI: probe matches a committed rule against a committed fixture.
- **PR 5B-2 — rule management.** A minimal bundled rule set (a handful of high-signal rules: common embedded creds, a known-bad library banner, a packer signature) plus a documented path for the user to add their own (a rules dir under `HEXGRAPH_HOME`, surfaced in Settings). UX-contract entry for the rules surface. Without this PR, YARA is an empty box, so 5B is not done until both land.
- **Done-criteria.** YARA sweeps every non-archived target and every extracted firmware file under the project, records matches as Observations, and promotes them to `pattern` nodes + `matches_rule` edges; the bundled rules fire on a fixture; a user-supplied rule is picked up; `just test`/`just demo` green.

### Phase 5C — angr, the symbolic flagship *(L–XL; ship last)*

- **PR 5C-1 — the `get_solver()` seam.** `engine/solver.py` mirroring `engine/taint.py`: a `Solver` ABC, `AngrSolver`, `NullSolver` (graceful-degrade), `get_solver()` selecting on `features.angr`. No probe wiring yet — the seam and its Null path land first, with unit tests proving the Null path fabricates nothing.
- **PR 5C-2 — the angr probe and image dependency.** `angr_probe.py` plus the angr pip stack in `docker/sandbox.Dockerfile` (the one rebuild Phase 5 requires). `features.angr` gated through `policy.py` as a heavy-analysis opt-in (no tier raise, modeled on `assert_allows_emulation`), bounded by `ResourceSpec` + a step/time cap in the probe. CI: a dependency-present assertion in the sandbox-build job and a probe smoke test on a tiny fixture.
- **PR 5C-3 — input→sink solving and the grounded finding.** Wire `AngrSolver` to nominate sinks from the existing taint/sink nodes, solve for a reaching input, record a `solver` Observation, promote the path nodes/edges, and emit a high-confidence `vulnerability` finding carrying the concrete input in the envelope. Compose with `engine/reachability.py` (concretize an argued path) and optionally feed a fuzzing seed.
- **PR 5C-4 — constraint solving for recovered values.** Single-check constraint solving (recover the value that passes a comparison), feeding the same function-node annotation path as `engine/emulation.py`. Explicitly *not* whole-program exploration.
- **Done-criteria.** angr is opt-in, bounded, and degrades to `NullSolver` when off; on a committed fixture it solves a reaching input for a known sink and emits a grounded finding with that input; resource caps demonstrably bound a pathological case (a test asserts it times out cleanly rather than OOMs); image-build CI confirms the angr stack is present; `just test`/`just demo` green.

### 4.4 Deferred / dropped backlog

**Deferred** (worth it eventually; not now, with a concrete unblock condition — *not* in any numbered phase):

- **ROPgadget / ropper.** Cheap to add, but gadgets are inert without a consumer. **Unblock:** an exploit-primitive / chaining stage (successor to the PoC oracle) that reads a gadget set; add ROPgadget in that stage's phase so it never ships as an unread list.
- **BSim.** The right long-term structural-similarity n-day engine, but it needs a populated signature corpus and brings a standing similarity datastore the SQLite-only design avoids. **Unblock:** a real multi-firmware corpus in regular use plus a deliberate decision to operate a similarity DB. Until then `link_same_code` + YARA cover the practical need.

**Dropped** (not worth the cost; excluded from the rollout):

- **BinDiff / Diaphora** — high BinExport/two-sided plumbing cost and Ghidra-upgrade fragility for a niche version-pair workflow few sessions hit.
- **Semgrep** — off HexGraph's binary/firmware axis; the rare managed-source case is better served by the agent's own tools.
- **Unicorn** — duplicates the built P-Code emulator (`engine/emulation.py`); any gap is closed inside that seam, not with a second stack.
- **GDB / pwndbg** — dynamic confirmation is already covered by the PoC oracle (`engine/poc.py`) and fuzzing crashes; a full debugger toolchain is heavy weight for redundant value.

---

## 5. Key decision points

Read cold, these are the load-bearing choices; each gives the decision, the realistic options, and a recommendation.

1. **Which tools are worth adopting at all?** *Options:* the completionist ten, or a curated subset. *Recommendation:* **adopt four (binutils, FLOSS, YARA, angr), defer two (ROPgadget, BSim), drop four (BinDiff, Semgrep, Unicorn, GDB).** Every adoption is a permanent tax; a lean set that strengthens the opening move (binutils), recovers invisible signal (FLOSS), amplifies the corpus loop (YARA), and adds one genuinely new answer (angr) beats cramming in tools that duplicate built capabilities or have no consumer.

2. **Does angr get a real seam?** *Options:* a `get_solver()` seam, or a bare probe. *Recommendation:* **a real seam**, because it answers the same input→sink question as `get_taint_analyzer()` and a second symbolic backend is plausible — the textbook earned seam, and mirroring `engine/taint.py` (ABC + concrete + Null) keeps it consistent with what's built.

3. **How is angr gated — heavy-analysis opt-in or execution tier?** *Options:* route through `assert_allows_execution()` (the exec tier), or a standalone heavy-analysis gate like `assert_allows_emulation()`. *Recommendation:* **a standalone heavy-analysis gate that raises no tier.** angr symbolically executes; it never runs the target natively or opens a socket, so it relaxes no boundary — the gate exists only to make it opt-in and bound it with `ResourceSpec`, exactly the `emulation` precedent.

4. **Do the Tier-A tools (binutils/FLOSS/YARA) get policy gates?** *Options:* gate each, or let them ride the static surface. *Recommendation:* **no policy tier for any of them** (they touch no boundary); binutils ungated like recon, FLOSS and YARA behind plain `features.*` settings toggles only because they are optional/heavier, never because they relax policy.

5. **YARA without rules — ship it anyway?** *Options:* ship the matcher alone, or ship matcher + rule story together. *Recommendation:* **together** — a matcher with no rules is an empty box, so 5B bundles a minimal high-signal rule set and a user-rules path, and isn't "done" until both land.

6. **Unicorn vs the built P-Code emulator.** *Options:* add Unicorn for snippet emulation, or rely on `engine/emulation.py`. *Recommendation:* **rely on the built emulator;** drop Unicorn. They answer the same constant/key-recovery question; any future gap is closed inside the existing emulation path, not with a parallel stack.

7. **The one image rebuild.** *Options:* spread image growth across phases, or concentrate it. *Recommendation:* **concentrate it in 5C (angr).** binutils/FLOSS/YARA add negligible or small deps; angr is the one heavy stack, so the single meaningful `docker/sandbox.Dockerfile` rebuild lands with it, gated, last — guarded by the dependency-present CI assertion.

---

## 6. Resume checklist

Adopted tools only. A dropped session reads this to see what is done versus next.

**Phase 5A — quick-facts and hidden strings**
- [ ] 5A-1 binutils probe + `binutils_facts` Observation + always-welcome extractor + MCP/agent verb + CI (fixture run + image-present assertion)
- [ ] 5A-2 FLOSS probe + `floss_strings` Observation + `features.floss` toggle + promotable strings + MCP/agent verb + CI (stack-string fixture)

**Phase 5B — corpus pattern sweep**
- [ ] 5B-1 YARA probe + `yara_matches` Observation + `matches_rule` edge + `pattern` promotion + `features.yara` toggle + MCP/agent verb + CI (rule-vs-fixture)
- [ ] 5B-2 bundled rule set + user-rules dir + Settings/UX-contract surface

**Phase 5C — angr flagship**
- [x] 5C-1 `get_solver()` seam (`Solver`/`AngrSolver`/`NullSolver`) + Null-path unit tests
- [x] 5C-2 angr probe + a DEDICATED optional `hexgraph-angr` image (D10 — the heavy angr/z3 stack does NOT bloat the base sandbox; `docker/angr.Dockerfile`, `just angr-build`) + `features.angr` heavy-analysis gate (no tier) asserted at the probe boundary + `ResourceSpec`/step/time/state caps + a CI angr lane (dep-present assertion + the licensegate solve)
- [x] 5C-3 input→sink solving (`AngrSolver` + `engine/solving.py`) → `solver` Observation + grounded `vulnerability` finding with the concrete reaching input in the envelope; verified end to end on the `licensegate` fixture
- [x] 5C-4 single-check constraint solving → function-node annotation (no whole-program exploration)

**Deferred (not started; unblock first):** ROPgadget (needs an exploit-primitive consumer) · BSim (needs a corpus + a similarity datastore decision).

---

## 7. Open questions

- **angr's scope boundary.** Where exactly does "targeted solving" end and "a general symbolic engine" begin? The 5C PRs draw it at single-sink input solving and single-check constraint solving, but the precise step/loop/state-explosion budget (and whether to expose it as a tunable) needs a concrete cap, decided against a real firmware fixture rather than in the abstract.
- **YARA rule sourcing and trust.** Where do bundled rules come from, how are they licensed and credited (`THIRD_PARTY_NOTICES.md`), and do we ever auto-update them? The local-only / no-network-by-default invariant says rule updates are a manual, user-driven act — confirm that and document it. Also: a small `severity`/`confidence`/`cve` rule-meta convention so a match's finding strength comes from the rule, not a guess.
- **FLOSS performance ceiling.** On large firmware binaries FLOSS can be slow; is the existing probe timeout the right bound, or does FLOSS need a per-function budget so one pathological function can't eat the whole pass?
- **The deferred-tools trigger.** ROPgadget and BSim both unblock on a future capability (an exploit-primitive stage; a similarity corpus + datastore). Track those as their own design docs now, or revisit only when the unblocking work is scheduled? Lean toward the latter — don't design ahead of need.
- **Image-size budget.** angr is a conscious weight increase. Is there a target ceiling for the sandbox image, and if angr pushes past it, do we split angr into its own optional image (like the fuzz/build/rehost images) rather than growing the base sandbox?
