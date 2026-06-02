# Design — First-Class Fuzzing & Source-Code/Build Management in HexGraph

**Status:** Proposed (canonical synthesis of the five-lens design council: fuzzing-engines, build-from-source, data-model, ux-ide, architecture-security).
**Scope:** Make fuzzing a first-class, multi-surface, coverage-guided capability; make source-tree management and reproducible, instrumented, *build-as-API* building first-class; wire both into the typed graph, the verification/assurance ladder, the policy seam, and the SPA. Companion to `docs/design-verification-oracles.md`, `docs/design-dynamic-surfaces.md`, `docs/design-rehosting.md`.

This document grounds entirely in the shipped architecture: the seam rule (`get_executor`/`get_decompiler`/`get_rehoster`), the policy tiers in `policy.py` (`TIER_STATIC_ONLY=0` … `TIER_LIVE_REMOTE=3`, `current_policy()` deriving the tier from `features.*`, fail-closed at 0), the sandbox boundary in `sandbox/runner.py` (`--network none`, `--read-only`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`, mem/cpu/pids caps, tmpfs, hard timeout, `net_container=` netns join), CAS (`engine/cas.py`), the firmware-filesystem precedent (`engine/filesystem.py`), the in-process `TaskWorker` (`engine/worker.py`), and the frozen Finding schema. It honours every non-negotiable: loopback-only, BYOK/mock, hostile bytes only in the sandbox, the LLM never runs a shell, **no gate relaxed anywhere except `policy.py`**, zero token spend by default, the Finding schema frozen, migrations mandatory.

---

## 1. Overview & the governing principle

Today's fuzzing is a single thin pipeline (`engine/fuzzing.py` + `sandbox/probes/fuzz_probe.py`): an LLM writes a C harness into a finding's `evidence.decompiled_snippet`; `fuzz_probe` compiles it with `clang -fsanitize=fuzzer,address`, optionally `--target-lib`-links a *stripped, uninstrumented* `.so` from disk, runs libFuzzer for a wall-clock budget, dedups crashes by `(asan_kind, frame0_function)`, and persists one `fuzz_crash` finding each (`code_present/dynamic` assurance). This is honest but **structurally weak**:

- **The target is never instrumented.** SanitizerCoverage (`-fsanitize=fuzzer`) instruments only the *harness* `.c`. libFuzzer mutates against **zero coverage feedback from the code under test** — effectively black-box fuzzing of the glue.
- **One engine, one surface.** No AFL++ (the only realistic route to binary-only firmware via qemu-mode), no network/protocol fuzzing, no structure-aware fuzzing.
- **No source, no build, no campaign.** Harnesses are transient strings; there is no managed source tree, no reproducible build recipe, no way to rebuild a VR target with instrumentation, no corpus/dictionary/minimization/coverage, no campaign lifecycle, and a crash is a one-off finding rather than a re-runnable artifact.

The fix is **two symbiotic new subsystems behind two new seams**, plus a graph integration, a UX surface, and a policy mapping:

1. **A `Builder` seam** — turn managed source into an **instrumented artifact** via a *recorded, reproducible recipe* the API/tool layer executes in the sandbox. This is what unlocks coverage-guided fuzzing: instrumentation lives in the *target's own objects*, not just the harness.
2. **A `Fuzzer` seam** — select the right SOTA engine *by attack surface* (AFL++/libFuzzer for source, AFL++ qemu-mode for binary-only firmware, boofuzz/AFLNet for network protocols, structure-aware for file formats), run a **long-lived campaign** that produces real artifacts (crashes/hangs/leaks/coverage/corpus) flowing into the graph as findings and triage items that climb the existing assurance ladder.

> **The governing principle — build-as-API / no-manual-execution.** *Anything that builds or fuzzes has an EXPLICIT, RECORDED, REPRODUCIBLE recipe that the API/tool layer executes inside the sandbox. The user and the LLM never run a build or a fuzzer by hand — they author or approve a recipe (which is itself **source**), and HexGraph runs it, reproducibly, gated at the policy seam.*

This is the exact analogue of two shipped invariants: *the LLM never sees raw target bytes — it directs, HexGraph runs probes* (extended: the LLM never runs `make`/`afl-fuzz`; it writes a recipe and calls a run-tool), and *`verify_poc` re-runs a stored, self-contained spec with one click, no LLM* (extended: a `BuildSpec` and a fuzz reproducer are the same shape of object — stored, self-contained, deterministically re-runnable).

---

## 2. The two seams + the surface×engine matrix

### 2.1 The `Builder` seam (`engine/build.py` → `get_builder()`)

Mirrors `get_rehoster()`/`get_executor()`; selected by `HEXGRAPH_BUILDER` (default `sandbox`). Feature code asks the seam, never names a concrete builder.

```python
@dataclass(frozen=True)
class BuildSpec:
    source_tree_id: str
    system: str                 # make|cmake|autotools|meson|cargo|go|custom
    phases: list[BuildPhase]    # ordered, explicit argv (NOT a shell string unless shell:true) — RECORDED verbatim
    instrumentation: Instrumentation   # {sanitizers:[address,undefined,...], coverage:[sancov|afl_pcguard], engine, extra_cflags}
    artifacts: tuple[str, ...]  # rel paths to capture (the fuzz target/.so/binary)
    env: dict[str, str]         # NON-secret build env (CC/CXX/CFLAGS injected per the contract, §4.1)
    arch: str = "x86_64"        # host or a cross target (foreign-arch firmware, §4.4)
    base_image: str = "hexgraph-build:latest"   # RECORDED — part of reproducibility
    network: str = "none"       # "none" (default) | "fetch" (bounded, audited deps phase — features.build_fetch)
    timeout: int = 1800

class Builder(Protocol):
    def build(self, spec: BuildSpec, *, source_root: str) -> BuildResult: ...  # runs build_probe in the sandbox
```

`BuildResult` records `{ok, artifacts: {rel→cas_sha}, log_sha, recipe_sha, source_content_hash, toolchain_digest, instrumentation, duration, error}`. **Reproducibility is the contract:** same `recipe_sha` (hash of `{phases, env, base_image, instrumentation, arch}`) + same source `content_hash` + same `toolchain_digest` ⇒ same build, recorded. Default impl `SandboxBuilder` runs a new `build_probe.py` in the sandbox boundary (source mounted read-only, output only to `/out`, `--network none` for the build phase). Future `RemoteBuilder`/`oss_fuzz` adapters drop in here.

### 2.2 The `Fuzzer` seam (`engine/fuzzers/` → `get_fuzzer(surface, engine=None)`)

The seam dispatches on **attack surface**, not engine identity (the seam rule). Selected by `HEXGRAPH_FUZZ_IMAGE` for the image and by surface for the engine; an explicit `engine` override is validated against the surface (fail-closed on a nonsensical pairing). The current `execute_fuzzing` becomes `LibFuzzerFuzzer` behind this seam — a strict superset of today's behaviour.

```python
class Fuzzer(Protocol):
    name: str; surfaces: tuple[str, ...]
    def prepare(self, spec: FuzzCampaignSpec, executor: Executor) -> PreparedFuzzer: ...  # instrumented build + seed + dict
    def start(self, prepared, *, on_artifact) -> FuzzHandle: ...   # long-running, detached; streams artifacts
    def status(self, handle) -> FuzzStatus: ...                    # execs/s, edges covered, crash count
    def stop(self, handle) -> FuzzSummary: ...                     # preserves corpus in CAS (resumable)
    def minimize(self, prepared, reproducer: bytes) -> bytes: ...  # afl-tmin / libFuzzer -minimize_crash
    def reproduce(self, prepared, reproducer: bytes) -> CrashReport: ...  # one-input replay → ASan report
```

### 2.3 The surface×engine matrix

| `FuzzSurface` | What it is | Default engine (alt) | Instrumentation / coverage |
|---|---|---|---|
| **`source_lib`** | C/C++ lib or parser we have **source** for | **AFL++** `afl-clang-lto` (alt **libFuzzer**) | SanCov+ASan/UBSan baked into the *target's* objects via a `BuildSpec`; LTO collision-free coverage + CmpLog (`-c`) for magic-byte/`memcmp` gating |
| **`binary_only`** | firmware ELF, **no source** | **AFL++ qemu-mode** (`-Q`) (alt frida-mode) | none in target; coverage via QEMU TCG. **Foreign-arch (MIPS/ARM) under qemu-user**, reusing `poc_probe`'s `qemu-<arch>` detection + the parent firmware rootfs as `-L` sysroot |
| **`network`** | live/rehosted/remote service, or a server binary | **boofuzz** (generational, spec'd protocols) / **AFLNet** (mutational, recorded corpus); desock+AFL++ for coverage-guided local | none in target; oracle = liveness/crash on the *service* |
| **`file_format`** | structured input parser | **AFL++ + dictionary/grammar** (alt structure-aware libFuzzer: `FuzzedDataProvider`/libprotobuf-mutator) | as `source_lib` if source, else `binary_only` |

Surface is derived from the target kind + whether a source tree / instrumented build exists; the operator/LLM may override the engine within the surface's allowed set. **A `web_app`/`remote`/rehosted service is fuzzed over the network with no bytes at rest;** a `shared_library` with source is rebuilt instrumented and fuzzed coverage-guided; a binary without source goes qemu-mode.

---

## 3. Build-from-source with instrumentation + build-as-API

### 3.1 The base-image contract (the OSS-Fuzz lesson)

OSS-Fuzz's durable lesson: **separate "what to build" (the project's recipe) from "how it's instrumented" (toolchain env injected by the orchestrator).** The build image guarantees a contract of environment variables the recipe may rely on, set by `build_probe` (never by the LLM):

```
CC, CXX            -> clang / clang++ (or a cross wrapper, §4.4) or afl-clang-lto
CFLAGS, CXXFLAGS   -> sanitizer + coverage flags per the instrumentation profile
SANITIZER          -> address | undefined | memory | coverage | none
FUZZING_ENGINE     -> libfuzzer | afl | none
LIB_FUZZING_ENGINE -> path to the engine driver to link the harness against
SRC, OUT, WORK     -> staged source snapshot (ro→copied) / writable artifact dir / tmpfs scratch
ARCH, CROSS        -> set only for cross-compiles (§4.4)
```

A recorded build phase is then just `["./configure"]` / `["make","-j","4"]`; **instrumentation is entirely in the injected env**, so the *same* recipe yields an ASan+libFuzzer build, an AFL++ build, or a coverage build by changing only the profile. This is the crux of "rebuild with instrumentation: one recipe, swappable profile," and it lets existing OSS-Fuzz `build.sh` files build unchanged (an `oss_fuzz` Builder adapter can import one).

### 3.2 Build-as-API mechanics

Three authoring paths, **all of which end in a recorded spec the API runs**, never a human at a shell:
1. **Detected** — a `build_detect` probe inspects a source tree (presence of `configure`/`CMakeLists.txt`/`Cargo.toml`/`go.mod`), emits a *proposed* `BuildSpec`. Deterministic, runs no project code.
2. **LLM-authored** — via a `propose_build_spec` MCP write-tool, the model reads the project's build docs *as text* (our trusted cloned source, not hostile target bytes) and proposes phases. **The LLM emits a spec; it does not run anything.**
3. **Recorded build.sh** — the operator pastes/edits an OSS-Fuzz-style `build.sh` (stored as a `role=script` source file), referenced by a single `shell:true` phase.

Execution is only ever `POST /api/builds` / the `build_target` MCP **run**-tool → `get_builder().build()` → `build_probe` in the sandbox. A failed build sets `status=failed`, captures the **full build log to CAS**, and surfaces a `needs_triage` signal so the LLM/operator iterates on the *recipe* (readable in the IDE), never on a shell.

### 3.3 Rebuild a VR target with instrumentation (the headline capability)

A `shared_library`/`executable` target with an associated source tree (linked `built_from`) can be **rebuilt instrumented**:
1. `build_target` builds the artifact with SanCov+ASan/UBSan in the target's own objects (plus a CmpLog binary for AFL++).
2. The artifact is registered as a **derived target** (`instrumented_build_of` edge → the original; `metadata: {instrumented: true, build_id, sanitizers}`), so the graph keeps "the shipped binary" and "our fuzzable rebuild" distinct but linked. Findings on the rebuild map back to the shipped target by symbol.
3. A `source_lib` campaign against the derived target gets **real coverage feedback** — the difference between today's coverage-blind fuzzing and SOTA.

Binary-only firmware (no source) takes the `binary_only` qemu-mode path instead. The seam chooses: source present → instrumented rebuild; no source → qemu-mode.

### 3.4 Cross-compilation for foreign firmware arches

The dominant firmware case: rebuild a firmware's busybox/lighttpd/`<vendor daemon>` from upstream source, **instrumented, for the firmware's arch**, then fuzz it. clang is already a cross-compiler (`--target=mips-linux-gnu --sysroot=<firmware-rootfs>`); **the firmware's own extracted rootfs is the sysroot** (already on disk via `engine/filesystem.py`, already used as the qemu `-L` sysroot for PoCs), so the cross-built instrumented binary is binary-compatible with the device userland and runs under `qemu-<arch>` — the proven `verify_poc` path. The build image bundles cross compiler-rt + fallback sysroots (`WITH_CROSS=1`); a cross-build failure degrades gracefully to `binary_only` qemu-mode fuzzing of the original binary (mirroring the best-effort-decompile / `RehostUnavailable` discipline).

### 3.5 Dependency / supply-chain handling — the two-phase build

Real OSS projects fetch deps at build time, but the build invariant is **the compile phase runs `--network none`**. Resolution: a strict two-phase build.

```
Phase F (FETCH, opt-in, audited, OFF by default): network ON to an ALLOWLIST of package hosts;
        package managers resolve + download into a vendor cache; output = a pinned LOCKFILE
        + content-addressed vendor dir.  ── gated by NEW features.build_fetch (§5.3).
Phase B (BUILD, always): network OFF (--network none); reads ONLY the staged source snapshot
        + the Phase-F vendor dir; produces the instrumented artifact.
```

- **Vendored is the default and the recommendation** — a tree cloned `--recurse-submodules` at a pinned commit, or a deps-bundled tarball, needs no fetch phase; Phase B is fully offline-reproducible (UI labels it "offline-reproducible").
- **Bounded fetch is its own opt-in tier, fully audited** — `features.build_fetch` raises a registry-scoped egress (deny-all-but-allowlisted-registries: `crates.io`, `pypi.org`, `github.com`, distro mirror), every download an `EgressEvent` (`tool="build_fetch"`), reusing the `assert_allows_egress`+`NetworkScope` machinery. After fetch, snapshot + build offline. The fetch and compile are **separate sandbox runs**, so a build script cannot exfiltrate during compile.
- **SBOM-lite provenance** — fetched dep URLs + sha256 recorded on the build, so a rebuild is auditable.

This is never folded into `features.network` (fetching the public internet is categorically different from the loopback/private local-network tier).

---

## 4. The data model

The graph is the spine. Design rule (from the data-model lens, validated against the tree): **graph-navigable conceptual entities are nodes/edges; operational lifecycle records (status-bearing, queryable, long-lived) are SQL tables; bytes are CAS + manifests.** New `NodeType`/`EdgeType` *vocabulary* is String-column zero-migration; new tables and any change to the `EDGE_KINDS` endpoint set need an Alembic `--autogenerate` migration. The frozen Finding schema is never touched.

### 4.1 Source trees as a new entity + a thin target façade (KEY DECISION D1)

**Decision: SourceTree is a new SQL entity (`source_tree`/`source_file`), NOT a `TargetKind` proper — but it surfaces through a thin `TargetKind.source_tree` façade so it appears in the Targets tree and can anchor tasks/findings uniformly.**

*Rationale.* A `Target` is "a reachable *surface* — hostile bytes the adversary's input can reach." Source is the opposite: trusted material we possess and build, with no runtime surface of its own, content-addressed by a *tree hash* (not a byte sha256), and a project holds **multiple** independent source trees. Forcing it into `TargetKind` proper pollutes recon/ingest/decompile (which fingerprint and treat bytes as hostile) and forces `if kind == source` branching — the anti-pattern the seam rule forbids. The *instrumented build output* IS a derived `Target` (it has fuzzable bytes). The façade keeps the graph uniform (one Targets pane, one task/finding anchor, reuse of `archived` soft-removal) while the heavy data (files, revisions, history) lives in dedicated storage, not bloating `target` — exactly how a firmware target carries its extracted FS on-disk + in `metadata_json` rather than in extra tables.

*Trade-off considered.* A pure new entity duplicates the Targets UI; a pure subtype conflates "bytes to sandbox" with "editable source." The hybrid pays modest façade plumbing to get both uniformity and a correct trust model.

### 4.2 Storage: filesystem + manifest + lazy nodes (KEY DECISION D2)

**Decision: source trees live on disk under the project data dir, indexed by a manifest, with `source_file` *nodes* materialized lazily on reference** — exactly the `engine/filesystem.py` (firmware FS) + `engine/nodes.py` (lazy function/string) precedent.

```
<project.data_dir>/source/<source_tree_id>/            # the working tree
<project.data_dir>/source/<source_tree_id>/.revisions/  # content-addressed revisions (editable trees)
<project.data_dir>/builds/<build_id>/                   # build scratch + log + lockfile
engine/cas.py (existing CAS)                            # artifacts, logs, lockfiles, reproducers, tree snapshots
```

Materializing every file as a node would explode the graph (a kernel tree = 70k files) and violate the shipped lazy discipline; lazy keeps the graph small and matches precedent. A build always runs over a **content-addressed snapshot** (`source_content_hash`) staged immutably into the container, so editing the working tree never corrupts a past build's reproducibility.

### 4.3 Harnesses, PoCs, and scripts unify as `source_file` (KEY DECISION D3)

**Decision: harnesses, PoCs, build recipes, and run-scripts are all `source_file` nodes distinguished by a `role` attribute** (`code|harness|poc|script|build_recipe|dictionary|corpus_seed`), not separate kinds of thing. This is the maintainer's explicit framing and it pays off enormously:

- A **harness** = a `source_file(role=harness)` + a `harness` node referencing it (replacing today's transient `evidence.decompiled_snippet`; `resolve_harness` keeps a back-compat read path during migration).
- A **PoC** = a `source_file(role=poc)`; the `engine/poc.py` self-contained spec gets a durable home, so `verify_poc` re-runs a *file in the tree*.
- A **run/build script** = `source_file(role=script)`, referenced by a recipe step; **executed only by a probe in the sandbox, never `bash run.sh`.**

One storage model, one IDE editor, one CAS history, one set of edges. A fuzz crash's minimized reproducer becomes a `poc`-role/`corpus_seed` artifact that feeds `verify_poc` — closing the loop with the verification work.

### 4.4 New node & edge vocabulary (zero-migration — String columns)

**Node types:** `source_file`, `harness`, `build_spec`, `fuzz_campaign`, `fuzz_artifact`. (A `function` node gains an optional `attrs.source = {tree_id, rel, line}` when source-mapped.)

**Edge types:** `built_from` (target→source_tree), `instrumented_build_of` (derived target→original target), `harnesses` (harness→target/function), `builds` (build_spec→artifact/target), `fuzzed_by` (target/harness→fuzz_campaign), `produced_artifact` (fuzz_campaign→fuzz_artifact), `reproduces` (fuzz_artifact→finding), `located_in` (finding/node→source_file, `attrs={line,col}` — **the jump-from-finding-to-source link**), `depends_on` (source_tree→source_tree, supply chain), `covers` (fuzz_campaign→function, coverage). `add_edge(merge=True)` set-merge semantics apply (e.g. a campaign accumulating artifact refs); meaningful attrs registered in `engine/edge_schemas.py` (guidance, not a hard schema).

### 4.5 New tables (migrations 0012–0015, additive)

All FK-light (polymorphic string refs — FK enforcement is OFF by design), UUID ids, `project_id`, an `attrs_json`/`metadata_json` envelope, and `archived` soft-removal where appropriate.

- **0012 — `source_tree`** (`name, root_path` [derived from data_dir, never a trusted abs path], `origin: upload|git|archive|extracted|scratch`, `vcs_rev`, `content_hash`, `editable`, `manifest_json`, `archived`), **`source_file`** is a node (lazy) so only the tree row is a table.
- **0013 — `build_spec`** (recipe, recipe_sha, system, instrumentation_json, artifacts_json, toolchain, network) + **`build`** (one execution: status, source_content_hash, toolchain_digest, log_cas, artifacts_json, recipe_sha, returncode, duration — the durable build ledger).
- **0014 — `fuzz_campaign`** (target_id, surface, engine, harness_node_id, build_spec_id, config_json, corpus_ref/dictionary_ref/coverage_ref [CAS], status `queued|building|running|paused|stopped|completed|failed`, stats_json `{execs, edges_covered, crash_count, peak_rss, last_run_at}`, instances, archived) + **`fuzz_artifact`** (campaign_id, kind `crash|hang|leak|oom|corpus`, content_cas [reproducer sha, not bytes], size, sanitizer, **`dedup_key`** [normalized stack hash], faulting_function, exploitability_json, finding_id nullable, `UNIQUE(campaign_id, dedup_key)`).
- **0015 — widen `EDGE_KINDS`.** Confirmed in the tree: `EDGE_KINDS = ("target","node","finding","task")` is a hardcoded tuple **validated in `engine/authoring.py` and `engine/edges.py`** — so adding `"source_tree"`, `"build_spec"`, `"fuzz_campaign"` as valid polymorphic endpoint kinds is a **code change to the constant + both validators** (the data-model lens's "near-zero migration" claim was slightly optimistic; the `src_kind`/`dst_kind` columns are free String, but the validators gate them). No column-type change; ship it with 0014.

A fuzz campaign is a **separate table, not just a `task`** (KEY DECISION D7): it outlives a single task tick, is start/stop/resume-able, and accumulates corpus/coverage/dedup across runs — the durable identity that makes fuzzing *progressive* rather than a coin-flip. The launching `task` records `campaign_id`; status polling reads `fuzz_campaign`.

### 4.6 Findings, the verification tie-in, and frozen-schema respect

A crash is **already a `fuzz_crash` finding** with `code_present/dynamic` assurance via `derive_fuzz_assurance()` — correct (the harness fed the function directly: lab-confirmed real, production input path not yet established). We keep that and extend, never replace:

- **One finding per dedup *bucket*** (KEY DECISION D8), not per crashing input. Today's `(kind, frame0)` over-merges (distinct bugs sharing a frame) and per-input over-splits. The new `dedup_key = sha256(bug_type + "|".join(top_N_normalized_frames))` (N=4, tunable; addresses/ASLR bases/inlining stripped — the ClusterFuzz/AFL++ norm) folds dupes under a representative; the UI shows "1 representative + 7 dupes."
- **Structured exploitability triage** (deterministic, always-on): an `exploitability: {class, rating: not_exploitable|dos|info_leak|control_flow|probably_exploitable, signals[]}` from the ASan report + a `crashwalk`/`exploitable`-style re-run (write-vs-read, attacker-controlled destination, PC-controlled). The optional LLM `_triage` (real backend only) enriches it with root-cause/fix, seeded by the structured signals + the *minimized* reproducer.
- **The artifact IS a re-runnable PoC** (the verification ladder). The minimized reproducer is content-addressed in CAS; `verify_poc` gains a `reproducer_ref` source so re-running a fuzz crash is identical to re-running a hand-written PoC. `reproduces`/`located_in` edges wire the campaign, the reproducer, the harness line, and the finding. The escalation path: `fuzz_crash (code_present/dynamic)` → operator/LLM builds an entrypoint PoC → `verify_poc(scope=entrypoint)` → **`input_reachable/dynamic`** (the ceiling). A network-fuzz crash that drops a *rehosted* service via its live input boundary is `input_reachable/dynamic` directly.
- **Frozen schema honoured.** All new finding structure lives in `evidence.extra` (`extra.fuzz = {engine, surface, campaign_id, dedup_key, reproducer_ref, coverage_at_crash, controlled_crash, sanitizer}`, `extra.source_ref = {tree_id, rel, line}`, `extra.poc_spec`, `extra.assurance`) and the new tables. `finding_type` `fuzz_crash`/`poc`/`harness` already exist (migration 0008). No schema change anywhere.

---

## 5. Security & policy model

Every new capability maps onto the **existing tiers in `policy.py`**; **the only edits to gate logic are in `policy.py`** (the `current_policy()` derivation + two new asserts). Fail-closed everywhere.

### 5.1 Capability → gate → tier

| Capability | Gate | Tier |
|---|---|---|
| **Compile source (don't run the target)** | **new `assert_allows_build()`** (`features.build`) | sub-capability of `TIER_SANDBOXED_EXEC` |
| **Run / fuzz an instrumented target; binary-only qemu-mode** | `assert_allows_execution()` (existing, `features.fuzzing`/`poc`) | `TIER_SANDBOXED_EXEC` (1) |
| **Network-fuzz a local/rehosted service** | `assert_allows_egress()` + `local_tcp_scope` | `TIER_LOCAL_NETWORK` (2) |
| **Network-fuzz a remote device** | `assert_allows_remote()` + `remote_scope` | `TIER_LIVE_REMOTE` (3) |
| **Bounded dependency fetch during build** | **new `assert_allows_build_fetch()`** (`features.build_fetch`) | constrained registry-allowlist egress |
| **Rehost then fuzz the device** | `assert_allows_rehost()` + the above | composes |

### 5.2 The build gate (KEY DECISION D5)

**Decision: a dedicated `features.build` flag (`allow_build`), peer of sandboxed-exec — NOT folded into `assert_allows_execution()`.**

*Rationale.* Building runs **untrusted third-party code** (`configure`/`make` is arbitrary execution and the highest supply-chain risk in the design) so it must be gated — but it is *not* the same as executing the *target*, and a useful workflow is "build instrumented, inspect, don't run yet." `current_policy()` gains `allow_build = features.build.enabled or exec_on` (enabling fuzzing/poc implies you'll build; `features.build` alone permits building without yet permitting target execution). **Running the produced artifact still hits `assert_allows_execution()`** — two independent fail-closed checks. The only change is in `policy.py`.

*Trade-off considered.* Folding build under the exec gate is simpler (one knob) — the fuzzing-engines lens preferred this — but it conflates "compile untrusted code" with "execute the target," forbids build-and-inspect, and muddies the supply-chain story. The architecture-security lens's separate flag wins on honesty and on isolating the supply-chain seam; the cost is one extra toggle.

### 5.3 The bounded-fetch gate (KEY DECISION D6)

**Decision: vendored/offline by default; `features.build_fetch` is a separate opt-in gate raising a registry-allowlist egress, never folded into `features.network`.** `assert_allows_build_fetch(dest, scope)` enforces a recorded, operator-confirmed allowlist of `host:port` package registries (like `remote_scope`'s "operator named this host," but never falling back to "any host"), every connection audited to `EgressEvent`. Fetch and compile are separate sandbox runs; compile has no network. This is the unanimous council position and the only network the build can touch.

### 5.4 Sandbox / build / fuzz image isolation (KEY DECISION D4 image; D-binary engine)

**Decision: two new dedicated images, never touch the shared `hexgraph-sandbox:latest`.**
- **`hexgraph-build:latest`** (`make build-image`, `WITH_CROSS=1` adds cross sysroots) — clang/llvm + sanitizer/SanCov runtimes, autotools/cmake/meson/ninja, AFL++ instrumented compilers, cross toolchains. It *is* the recorded `base_image` in a BuildSpec (immutably date-tagged for reproducibility).
- **`hexgraph-fuzz:latest`** (`make fuzz-build`) — AFL++ (LTO/qemu-mode/frida-mode/CmpLog), libFuzzer runtimes, boofuzz/AFLNet, preeny/desock, `afl-cov`/`llvm-cov`, gdb + an `exploitable`-style classifier, qemu-user (reusing the foreign-arch path).

*Rationale.* The lean `hexgraph-sandbox` is the always-required baseline (every recon/decompile/unpack run); AFL++/boofuzz/cross-toolchains are hundreds of MB–GB and would tax every static run and bloat the build attack surface. This mirrors the shipped rehost-image pattern (`hexgraph-firmae`/`hexgraph-qemu`, separate `make` targets, seam-selected) and Ghidra-as-build-arg. Selected by `HEXGRAPH_BUILD_IMAGE`/`HEXGRAPH_FUZZ_IMAGE`; the `Executor` threads an `image=` arg per probe family (additive, no boundary change). **Worktree discipline holds:** a toolchain change builds a private tag (`hexgraph-fuzz:wt-<topic>`) and points the env override at it — never clobber the shared tag. **Probes still mount from the install** at run time — editing `build_probe.py`/the fuzz probes needs no rebuild; only a toolchain change does.

*Trade-off considered.* Extending the one sandbox image is less to maintain, but bloats the common path — the same reasoning that already made Ghidra and rehosting opt-in separate images. Two images is the right call.

**Binary-only engine: AFL++ qemu-mode default, frida-mode the opt-in alternative.** qemu-mode is the most mature, gives full edge coverage via TCG, and **reuses HexGraph's proven qemu-user foreign-arch path** (the sysroot mount verified end-to-end on real MIPS firmware) — minimal new surface, the strongest fit for a firmware-focused tool. frida-mode is faster on some native x86 targets but weaker cross-arch and adds a runtime-injection dependency; offered as an engine override.

Same hardening for build and fuzz containers as today: `--read-only`, tmpfs `/scratch` (`rw,exec`, needed to compile+run), `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`, mem/cpu/pids caps, hard timeout, `--network none` (except the audited fetch/net-fuzz tiers); source mounted RO, output only to `/out`. A bigger image is not a weaker box. **Hostile bytes stay in the sandbox; the LLM never sees them** — only bounded tool output in `TaskContext` (a coverage summary, an ASan excerpt, a reproducer hash). Source *text* is read host-side only for the IDE viewer (bounded, path-traversal-safe per `read_file`); **all compiling/parsing/fuzzing runs in the sandbox.** Firmware-*extracted* files added as "source" are marked `origin=extracted` (untrusted-for-reading, build-only).

### 5.5 Long-running campaigns: detached executor + durable row (KEY DECISION D-campaign)

**Decision: a fuzz campaign launches a detached, long-lived sandbox container (a `start_detached(...)` capability on the Executor seam), owned by a durable `fuzz_campaign` row, polled/reaped by the worker — NOT run inline on the in-process `TaskWorker`.**

*Rationale.* Confirmed against the tree: the worker is an in-process asyncio `TaskWorker` using `asyncio.to_thread` for the blocking sandbox call — fine for a 60s fuzz tick, **wrong for a multi-hour campaign** (it would pin a thread, block the queue, and die on a `serve` restart). A detached container (`docker run -d`, same hardening) runs the fuzz probe in continuous mode, streaming artifacts/stats to its bound `/out`; the launching task returns immediately (status `running`, `campaign_id` recorded). A lightweight **reaper** (periodic worker job) polls container status, ingests new artifacts into `fuzz_artifact`/findings, updates `stats_json`, and finalizes on completion/stop. **Stop/resume:** stop kills the container preserving the corpus in CAS; resume restarts seeded from it (AFL++ resumes natively). **Crash-safe:** because the container is detached and the row durable, a `serve` restart re-attaches the reaper to running containers by handle — campaigns survive process restarts. Future remote/k8s campaign executors drop in behind the same seam.

**Resource governance** (the real systems risk): per-container mem/cpu/pids/wall caps; AFL++ `instances` (master + N secondaries) capped by a per-host concurrency limit; corpus **minimized** (`afl-cmin`) + CAS-dedup'd; crash artifacts dedup'd by `dedup_key` (only the minimized reproducer kept); a per-campaign disk quota + corpus ceiling triggering cmin prevents a coverage explosion filling the disk; old corpora GC-able by CAS refcount. Crashes stream as they happen, so a 6-hour campaign surfaces the first crash in minutes.

This keeps build-as-API intact: the operator clicks "Fuzz" or the LLM calls `start_fuzz_campaign`; HexGraph spawns and reaps; nobody runs `afl-fuzz` by hand, and the LLM gets only `start/status/stop/list_artifacts/minimize` tools.

### 5.6 Composition with rehost / remote

- **Rehosted device:** boofuzz/AFLNet runs as a channel probe joining the emulator's netns (`net_container=`, exactly like `http_probe`/the callback listener), egress bounded to the device's private IP via `local_tcp_scope` (`features.network`), audited. A service-down crash flips the liveness oracle → `input_reachable/dynamic` (the strongest assurance).
- **Foreign-arch firmware binary:** `binary_only` qemu-mode picks `qemu-<arch>` from the ELF and mounts the parent firmware rootfs as `-L` sysroot — `code_present/dynamic`.
- **Remote device:** network-fuzzing a physical bench device is destructive — gated `features.remote` + single-host `remote_scope`, **defaulted off with a loud warning**; recommended first use is *replay/PoC* (re-feed a known crash), not blind mutation. Fuzzing a local instrumented *rebuild* of the remote device's binary is the safe, valuable path.

### 5.7 The no-manual-execution principle, enforced structurally

There is **no shell tool**. MCP tools (grouped read/write/run, gated by `features.mcp.{read,write,run}` + the policy gates): read — `list_source_trees`, `read_source_file`, `list_fuzz_artifacts`, `fuzz_status`; write — `import_source_tree`, `write_source_file` (scratch/role-tagged trees only), `propose_build_spec`, `create_harness`, `link_finding_to_source`; run — `build_target`, `start_fuzz_campaign`, `stop_fuzz_campaign`, `minimize_artifact`, `triage_artifact`. The LLM authors recipes/harnesses and *requests* builds/fuzzes; HexGraph executes the recorded spec in the sandbox. Identical to the shipped agent-loop contract.

### 5.8 Resource governance knobs & remote fuzz environments (KEY DECISION D-resource / D-remote)

Fuzzing is the one genuinely resource-hungry workload in HexGraph; the user must be able to (a) lift the per-container caps on their own box and (b) push a whole campaign onto beefier/remote hardware. Both fit the existing seams **additively** — no fuzzer/builder code change.

**(a) User-configurable resource limits — small, near-term.** Today `sandbox/runner.py` hardcodes `--memory 2g --cpus 2 --pids-limit 256` (+ tmpfs sizes). Promote these to a `ResourceSpec {mem, cpus, pids, tmpfs, timeout, unconstrained:bool}` carried on the `FuzzCampaignSpec`/`BuildSpec`, defaulted from Settings (a global default + a per-campaign override in the Fuzz modal), threaded into the `Executor.run_probe`/`start_detached` docker flags. `unconstrained` drops the `--memory`/`--cpus`/`--pids-limit` flags and raises the wall-clock/disk ceilings, so a campaign can use the whole machine — AFL++ `instances` (master + N secondaries) then scale to host cores.

**Crucial distinction — this is NOT a policy-gate relaxation.** The policy seam governs *what the sandbox may do* (execute / reach the network / rehost / remote); resource ceilings are orthogonal. "Unconstrained" relaxes **only** mem/cpu/pids — the **security** hardening is untouched: `--network none` (except the already-gated net-fuzz tier), `--cap-drop ALL`, `--no-new-privileges`, `--read-only`, `--user 1000`, and hostile-bytes-stay-in-the-sandbox all still hold. A bigger or busier box is not a weaker box. So `ResourceSpec` lives in Settings/the spec, **never** in `policy.py`.

**(b) Remote fuzz environment — the seam already anticipates it; design now, implement as a later phase.** The Executor seam's own docstring calls out "a future `RemoteExecutor` (Kubernetes / horizontal scale) … drops in **without touching task code**." The **intuitive, lowest-lift route is a `RemoteDockerExecutor` targeting a Docker host the user owns** via `DOCKER_HOST` (`ssh://user@beefybox` over an SSH control socket, or `tcp://…` + TLS client certs). Because Builder/Fuzzer call `Executor.run_probe`/`start_detached`, **building and fuzzing run on the remote with zero fuzzer/builder change** — the seam is the entire point. A **fuzz environment** becomes a first-class, selectable concept: Settings registers environments (`local` + N remote Docker endpoints, each with its own `ResourceSpec` ceiling); a campaign picks one (defaulting `local`).

*The real (bounded) work* beyond pointing `DOCKER_HOST`: (1) **ship the inputs to the remote** — the build context + seed corpus; **CAS (`engine/cas.py`) is the natural transfer unit** (content-addressed ⇒ dedups, cache-friendly), staged to a remote volume instead of a local bind-mount. (2) **stream artifacts/coverage/stats back** — the reaper polls over the same Docker connection and ingests `fuzz_artifact`s into the local graph exactly as for a local detached container. (3) the remote needs `hexgraph-fuzz:latest` present (one-time remote build/pull, surfaced as an environment **health-check**).

**Trust model — the loopback invariant is untouched.** The **control plane (API/UI) stays bound to `127.0.0.1`** on the user's machine; the remote is a **compute backend the user owns and explicitly authorizes** — the exact posture HexGraph already established for `features.remote` (the live-remote tier pins to one operator-authorized host, "operator's responsibility"). So a remote fuzz host is an opt-in `features.fuzz_remote` pinned to a single user-specified Docker endpoint; its connection details are a **secret** (read from env/`config.toml`, never stored in the DB or logged — same rule as SSH/telnet creds), and the SSH/TLS connection is audited. Hostile target bytes still only ever materialize inside the sandbox container — **same boundary, now on a host the user chose.**

*Heavier alternative considered (punted):* a dedicated HexGraph fuzz-worker daemon or a real k8s job executor — more power (autoscaling, multi-user pools) but far more lift and ops surface. The `DOCKER_HOST` route delivers ~90% of the value (a beefy remote box, unconstrained, intuitive) at ~10% of the cost behind the identical seam, so it is the recommended first remote step; k8s remains a later drop-in if multi-user/scale demands it.

---

## 6. UX — the Source/IDE tab + fuzz/triage experience

The SPA has a strong, consistent grammar (three-pane Workspace, capability-gated affordances via `GET /api/capabilities`, the trace-file viewer, the PoC "Re-verify" / task "Re-run" buttons, `FilesystemBrowser`). The new surfaces **extend** it.

### 6.1 IA: a center-pane mode switch, not a new route (KEY DECISION D-ia)

**Decision: a Graph⇆Source segmented control in the existing Workspace toolbar (persisted as `?view=source`), plus two new right-pane tabs (Campaigns, Artifacts), plus a Sources section under each target in the left tree — NOT a fourth top-level route.**

*Rationale.* Source trees, harnesses, builds, and campaigns are *about a project's graph*. A separate route would sever the shared selection/highlight state (`selFinding`/`selNode`/`selGraphId`) that makes jump-from-finding-to-source-and-back instantaneous. The mode switch keeps one data load, one selection model; the inactive heavy view is lazy-mounted. Selection state gains `selCampaign`/`selArtifact`/`openSource:{treeId,path,line}` and a single `reveal(target)` router; deep-links (`?view=source&file=…&line=…`, `?artifact=…`) hydrate it.

### 6.2 The IDE (Source mode)

Two-column center pane: a **multi-tree file explorer** (a dropdown switcher — a project has many `source_tree`s — over a shared `<FileTree>` extracted from `FilesystemBrowser`'s `buildTree`/`Row`, decorated with finding-count dots, harness badges, a recipe wrench, a PoC ▶), and a **tabbed code viewer** (Monaco/CodeMirror, syntax-highlighted, clickable line anchors `file#Lnn`, gutter markers for finding/crash lines, coverage-shading tint for fuzzer-reached lines).

**Read-only by default; editable per-tree and explicit (KEY DECISION D-edit).** Firmware/extracted/imported third-party source is **read-only** (hostile or reproducibility-critical — editing imported source would break the `content_hash` build contract). The files HexGraph itself produces/runs — `harness`/`poc`/`script`/`build_recipe` roles — are **editable** behind `features.source.edit`. **Save creates a new revision** (`POST /api/source-trees/{id}/files/{path}/revisions`, origin=`analyst-edit`, with a diff) and offers an explicit **"Rebuild from this revision"** — never an in-place mutation or auto-run. To patch upstream source you add a patch step to the recipe (keeping the build recorded + reproducible). Even an edit *does nothing* until a recipe-driven build is launched — build-as-API intact.

*Trade-off considered.* A fully editable IDE is flashier but breaks reproducibility/provenance and risks clobbering vendored source; a fully read-only IDE defeats the core "author harnesses/PoCs in-browser" goal. Per-tree explicit editability + revisioned saves + visible dirty/pinned badges is the honest middle.

### 6.3 The load-bearing interactions

- **Finding → source:** the Inspector's Evidence section gains "Open in source" when `evidence.extra.source_ref` is present → switches to Source mode, opens file, scrolls to line, drops a gutter marker (falls back to `decompiled_snippet`).
- **Source → finding/graph:** a gutter marker is clickable (`reveal(finding)`); a source-mapped `function` node gets "Open source" beside the existing **Decompile** button — flipping between decompiled-from-bytes and original source for the same node (the fusion the product is built on, applied to source).
- **Build launch (build-as-API in the UI):** a capability-gated **Build** modal (cloned from `LaunchModal`'s form+preview grammar) shows a **recorded recipe preview** (read-only — *no free-text command box*), instrumentation toggles (ASan/UBSan/SanCov/AFL++) that regenerate the preview via `POST .../build/preview`, the toolchain, and an explicit **dependency posture** ("vendored — no network" default; "fetch — audited" only under `features.build_fetch`, with its allowlist shown). Build runs in the sandbox; status + log stream via the existing trace viewer + the Campaigns tab.
- **Fuzz launch (surface- & engine-aware):** the anchor usually decides the surface (harness → `source_lib`; instrumented binary → `binary_only`; `socket`/`endpoint` node → `network`; `input` node → `file_format`). The modal offers **server-advertised engines** (`GET /api/fuzz/engines?surface=` — the UI never hardcodes engine names, mirroring the LLM-backend registry), corpus/dictionary controls, budget, and a "Build instrumented first" checkbox chaining build→fuzz.
- **Live campaign status (Campaigns tab):** a live row per campaign (coverage sparkline, execs/s, elapsed/remaining, crashes/unique, status pill) over an **SSE stream** `GET /api/campaigns/{id}/events` with graceful fallback to polling (replacing today's jarring whole-graph `pollThenReload` — a campaign runs for minutes-to-hours and must feel alive). Pause/Resume/Stop controls.
- **Artifacts & triage (Artifacts tab):** the crash/hang/leak/coverage inbox, **grouped by dedup bucket** (representative + dupe count, severity from the ASan-kind map, the minimized input first). Per-group **[Reproduce]** (generalizes Re-verify; records `code_present/dynamic`, shown honestly as an assurance chip — never "input-reachable"), **[Minimize]**, **[Open harness line]** (source-mapped ASan stack frames → IDE line), **[Promote to finding]** / **[Promote to PoC]** (feeds the verification pipeline). A coverage sub-view shades the IDE so a researcher sees where the fuzzer is stuck — the single most useful harness-improvement signal.

### 6.4 Settings

Two feature cards (same toggle grammar as the Ghidra/fuzzing cards): **Source & Build** (`features.build`, `features.source.edit`, dependency posture, plus toolchain-availability badges like the Docker/Ghidra ones) and an extended **Fuzzing** card (per-surface engine availability, default budgets, corpus/dictionary defaults, LLM-triage default). Because affordances read the capability table, flipping a toggle makes Build/Fuzz/Edit buttons appear or vanish project-wide with no other UI change.

---

## 7. Phased implementation plan

Each phase is independently shippable through the worktree→PR-review-subagent→merge gate, ships green `just test` (mock `MockFuzzer`/`MockBuilder` fixtures keep it offline/$0; Docker-gated tests skip without the image), updates `PROGRESS.md`, and ships its Alembic migration with any model change.

**Phase 0 — Instrument the target + better triage (immediate, biggest bang-for-buck, no new subsystem). — ✅ DONE.** When a `.so`/source is present, build the *target* with `-fsanitize=fuzzer-no-link,address` so SanCov+ASan are in the target's own objects. Replace `(kind, frame0)` dedup with the normalized stack-hash + bucketing; add `afl-tmin` reproducer minimization; add the deterministic exploitability classifier. All in `engine/fuzzing.py` + `fuzz_probe.py` on the existing image (clang already present). *No schema change.* Makes today's fuzzing immediately less coverage-blind and far less noisy. *Risk:* low.

> **Shipped (`build/fuzz-phase0`).** `fuzz_probe.py` now compiles target SOURCE (`--target-source=`)
> under `-fsanitize=fuzzer-no-link,address` and links it into the libFuzzer harness → real
> coverage-guided fuzzing; with only an uninstrumented `.so` it stays coverage-blind and reports
> `coverage_instrumented=false` (honest — instrumenting a prebuilt binary is the later AFL++
> qemu-mode phase). Crash dedup is a **normalized stack-hash** (`dedup_key`): top-N ASan frames with
> addresses / module offsets / build paths / line:col / anon-namespace+template noise / sanitizer
> interceptor frames stripped, stopped at the program-entry frame — deterministic and
> path-independent; one finding per bucket with a `dupe_count`. Reproducers are minimized with
> libFuzzer's own `-minimize_crash=1 -runs=R` (no AFL++ / afl-tmin needed — they aren't in the
> existing image; the design's afl-tmin mention is satisfied by libFuzzer here per the Phase-0 brief).
> A deterministic, documented **exploitability classifier** reads the sanitizer report (READ vs WRITE,
> UAF/double-free, SEGV near-PC, stack-overflow recursion, OOM/leak/timeout) → `{rating, access,
> signals}`, which refines severity. Engine `resolve_target_sources` mounts source from the task param
> `target_sources` or `target.metadata_json.fuzz_target_sources`. Everything new rides
> `evidence.extra.fuzz` (frozen schema untouched, no migration). `derive_fuzz_assurance()` semantics
> unchanged (`code_present/dynamic`). Tests: `test_fuzz_triage.py` (pure dedup + classifier +
> severity), extended `test_fuzzing.py` (the `evidence.extra.fuzz` envelope, source-mount vs lib-link,
> `resolve_target_sources`), and Docker-gated `test_fuzz_e2e.py` (an instrumented build finds +
> classifies a planted heap-write bug). **Known limit:** the base sandbox image ships no
> `llvm-symbolizer`, so ASan frames are module+offset at runtime — within-run dedup is still
> deterministic, but symbolized cross-build dedup / function attribution awaits the dedicated
> `hexgraph-fuzz` image (Phase 3+).

**Phase 1 — Source-tree foundation + IDE browse (no exec, no new gate).** `source_tree` table (0012) + `source_file` node vocab + lazy materialization (`engine/source.py`, mirroring `filesystem.py`); `built_from`/`located_in`/`harnesses` edges; the `EDGE_KINDS` widening lands here if `source_tree` becomes an endpoint, else with 0014; the read-only Source tab (extract `<FileTree>`, the Graph⇆Source switch, finding→source jump); promote existing transient harnesses to `source_file`s (backfill, back-compat read path). *Risk:* the `EDGE_KINDS` validator change touches `authoring.py`+`edges.py` — keep it minimal and well-tested.

> **Shipped (`build/fuzz-phase1`). — ✅ DONE.** `source_tree` is a new SQL entity (migration
> **0012**, `down_revision=0011`, applies clean on 0011 and round-trips) — a project holds
> multiple trees, each optionally linked to a target via a `built_from` edge (**D1**: source
> trees are SQL entities, surfaced through their own Source pane, NOT a `TargetKind` proper, so
> recon/ingest never branch on them). Storage is **filesystem + manifest + lazy nodes** (**D2**,
> `engine/source.py` mirrors `engine/filesystem.py`): files on disk under
> `<data_dir>/source/<tree_id>/`, a flat `manifest_json` (rel/size/role) on the row, and
> `source_file` *nodes* materialized only on reference (`materialize_source_file`, identity
> `fq_name=<tree_id>:<rel>`, `target_id=None`) — never a row per file. Reads are bounded +
> path-traversal-safe (the `filesystem.read_file` containment guard, reused); `origin=extracted`
> marks firmware bytes as untrusted-for-reading (display only — no exec/parse, that stays in the
> sandbox in later phases). Harnesses/PoCs/scripts unify as **role-tagged `source_file`** (**D3**):
> `promote_harness`/`backfill_harnesses` (`engine/harness_promote.py`) move a `harness_generation`
> finding's transient `evidence.decompiled_snippet` into a managed `source_file(role=harness)` +
> a `harness` node `harnesses`→ the target, and `fuzzing.resolve_harness` now prefers the managed
> file but **falls back to the legacy snippet** (old findings still render/fuzz with no backfill).
> New vocab is String-column zero-migration: node types `source_file`/`harness`; edge types
> `built_from`/`located_in`/`harnesses`. The riskiest touch — admitting `source_tree` as a
> polymorphic edge endpoint — is a **surgical** widening of the `EDGE_KINDS` tuple + the
> `authoring._entity_exists` existence map (the `edges.add_edge` validator already reads the
> tuple), tested both ways. **Read-only Source tab**: a Graph⇆Source segmented control in the
> Workspace toolbar (`?view=source`, mode not route), a `SourceBrowser` with a multi-tree dropdown
> + `<FileTree>` (mirroring `FilesystemBrowser`) + a line-numbered code viewer, and the
> **finding→source jump** (`link_finding_to_source` stamps a `located_in` edge + a frozen-schema-
> respecting `evidence.extra.source_ref`; the Inspector's "Open in source (line N)" opens the file
> at the line). REST: `GET/POST .../source-trees`, `GET .../source-trees/{id}/files|file`,
> `POST .../findings/link-source`, `POST .../backfill-harnesses`. MCP: **read** `list_source_trees`/
> `read_source_file`, **write** `import_source_tree`/`link_finding_to_source` (grouped + gated by
> `features.mcp.{read,write}`). `merge_duplicates` copes with `source_file` nodes via its default
> key (`(type, target_id=None, fq_name)`). The frozen Finding schema is untouched (everything rides
> `evidence.extra` / the new table); no `policy.py` edit; no execution. Tests:
> `tests/test_source.py` (model + lazy materialization + dedup, the three edges incl. the
> endpoint-validator widening, the harness backfill + back-compat resolve, the API/MCP read tools,
> path-traversal safety). **Known limit:** no "Sources" section in the left target tree yet (the
> Source-mode dropdown is the only tree picker) and the viewer is a plain `<pre>` (no Monaco /
> syntax highlighting) — both deferred per `docs/ui-backlog.md`.

**Phase 2 — Builder seam + build-as-API (gated `features.build`).** `engine/build.py` + `SandboxBuilder` + `build_detect_probe.py`/`build_probe.py` + `Dockerfile.build`/`hexgraph-build`; `assert_allows_build()` (the only `policy.py` edit); `build_spec`/`build` tables (0013); `BuildSpec` model + CAS storage + the base-image contract; rebuild-VR-target-with-instrumentation → derived target; `/api/builds` + `build_target` MCP run-tool; the IDE Build modal (recorded-recipe preview, instrumentation toggles, vendored-only). **Vendored/offline only.** *Risk:* supply-chain — contained by sandbox `--network none` compile, non-root RO source, ephemeral container.

> **Shipped (`build/fuzz-phase2`). — ✅ DONE.** The **`Builder` seam** (`engine/build.py` →
> `get_builder()`, `HEXGRAPH_BUILDER`, default `sandbox`; `MockBuilder` keeps `just test`
> offline/$0) turns a source tree into an instrumented artifact via a recorded `BuildSpec`
> {source_tree_id, system, phases (ordered explicit argv, recorded verbatim), instrumentation
> {sanitizers, coverage(sancov|afl_pcguard), engine, extra_cflags}, artifacts, env (NON-secret —
> credential-looking keys rejected), arch, base_image, network("none"), timeout}. **Reproducibility
> is the contract:** `recipe_sha = sha256(canonical-JSON{phases, env, base_image, instrumentation,
> arch})`; the `BuildResult` records {ok, artifacts(rel→cas_sha), log_sha, recipe_sha,
> source_content_hash, toolchain_digest, instrumentation, duration} so same recipe_sha + source
> content_hash + toolchain_digest ⇒ the same build (the MockBuilder proves byte-identical artifacts
> → identical CAS sha). **`SandboxBuilder`** runs `build_probe.py` in the dedicated **`hexgraph-build`**
> image (`Dockerfile.build` / `just build-image` [D4] — clang/LLVM + sanitizer/SanCov runtimes +
> autotools/cmake/meson/ninja + AFL++ `afl-clang-fast/lto` + a `WITH_CROSS` stub for Phase 7; it
> carries **`llvm-symbolizer`**, resolving the Phase-0 symbolization limit for builds here):
> source mounted **READ-ONLY** (the probe copies it to a writable `/scratch` so the snapshot is
> never mutated), output only to `/out`, the build phase **`--network none`** (a net-dep recipe
> fails honestly — proven by a Docker-gated test), same hardening as every probe (RO rootfs,
> `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`, mem/cpu/pids caps, hard timeout). The
> orchestrator INJECTS CC/CXX/CFLAGS/SANITIZER/FUZZING_ENGINE per the **base-image contract (§3.1)**
> — the recipe says *what* to build, the env says *how* it's instrumented, so the same phases yield
> ASan/SanCov vs AFL++ by swapping only the profile. **Policy gate [D5]:** `assert_allows_build()`
> gated by **`features.build`** is the only `policy.py` edit; `allow_build = features.build or
> exec_on` — a peer of, not folded into, the exec gate, so build-and-inspect works without
> permitting the target to run; **fail-closed** (default off raises, proven across the engine/API/
> MCP paths). **Tables (migration 0013, applies clean on 0012 + fresh init_db, autogenerate
> no-drift):** `build_spec` (the recorded recipe + recipe_sha, `archived`) + `build` (the durable
> ledger: status, the reproducibility triple, artifacts as CAS shas, log in CAS, returncode,
> duration, error, derived_target_id). **Rebuild-with-instrumentation → derived target (§3.3, the
> headline):** a build of a source tree linked (`built_from`) to a target registers the instrumented
> rebuild as a DERIVED target (`metadata.instrumented=true`, build_id, sanitizers, real bytes on
> disk for Phase-3 fuzzing) wired **`instrumented_build_of`**→ the original, with the `build_spec`
> **`builds`**→ the derived target. New edge vocab (`instrumented_build_of`/`builds`) is
> String-column zero-migration; the `build_spec` polymorphic edge endpoint is a surgical widening
> of `EDGE_KINDS` + the authoring validator. **API:** `POST /api/builds` (record+run), `/build/preview`
> (recipe preview — no free-text command), `GET /builds[/{id}][/log]`, `/build-specs`. **MCP:**
> run-tool **`build_target`** (gated `features.mcp.run` + `assert_allows_build`) + read-tool
> `list_builds`; the LLM authors/approves a recipe and *requests* a build — **no shell tool**.
> **UI:** the capability-gated **Build modal** (instrumentation toggles regenerate a read-only
> recorded-recipe + injected-env + recipe_sha preview; vendored-only note; a Builds status list with
> an "instrumented" tag), reached from a Build button in Source mode (shown via the new
> `capabilities.features.build` flag). The frozen Finding schema is untouched. Tests:
> `tests/test_build.py` (seam + MockBuilder, recipe_sha determinism/component-sensitivity, secret-env
> rejection, the fail-closed gate, persistence + reproducible CAS, derived-target registration + the
> two edges, the API/MCP surface, the capability flag), `tests/test_migrations.py` (0013 on 0012
> round-trip + fresh init_db), Docker-gated `tests/test_build_e2e.py` (the REAL build_probe builds a
> SanCov+ASan object proven by symbol inspection; a net-dep build fails honestly). **Known limits:**
> cross-compile is a `WITH_CROSS` stub (Phase 7); builds are synchronous (the detached campaign
> lifecycle is Phase 3); `ResourceSpec` is groundwork only (Phase 3); vendored/offline only (the
> audited `features.build_fetch` tier is Phase 7).

**Phase 3 — Coverage-guided source fuzzing, first-class (existing exec gate).** `engine/fuzzers/` seam; refactor `execute_fuzzing` → `LibFuzzerFuzzer` (zero behaviour change) + `AflPlusPlusFuzzer` against the Phase-2 instrumented build (real coverage at last); persistent-mode harness template; seed corpus + auto-dictionary from `list_strings`; CmpLog; coverage reporting; the **detached campaign lifecycle** (`fuzz_campaign`/`fuzz_artifact` tables 0014 + `EDGE_KINDS` widening 0015, reaper, stop/resume, crash-safe re-attach); streaming crashes → `fuzz_crash` findings → triage follow-ups; reproducer → `verify_poc(reproducer_ref)` tie-in. The user-tunable **`ResourceSpec`** lands here (Settings default + per-campaign override, incl. the `unconstrained` opt-in that relaxes only mem/cpu/pids, never the security flags — §5.8a). *Risk:* resource governance + restart-safety — addressed by §5.5.

> **Shipped (`build/fuzz-phase3`). — ✅ DONE.** The **`Fuzzer` seam** (`engine/fuzzers/` →
> `get_fuzzer(surface, engine=None)`, dispatch on attack SURFACE not engine identity, an explicit
> engine override validated against the surface — **fail-closed on a nonsensical pair**;
> `HEXGRAPH_FUZZER=mock` forces the offline `MockFuzzer`). `execute_fuzzing` was refactored to
> resolve its inputs through **`LibFuzzerFuzzer`** as a STRICT SUPERSET — the single-pass
> `fuzz_probe.py` invocation is byte-identical (regression-tested). **`AflPlusPlusFuzzer`**
> (`afl_probe.py`) fuzzes the **Phase-2 instrumented derived target**: the harness + the target's
> own sources compile under `afl-clang-fast` (SanCov+ASan in the target's objects) with the
> libFuzzer-compat driver supplying `main` for the persistent loop, run under `afl-fuzz` (`-m none`
> for ASan) — **real coverage at last**, with `llvm-symbolizer` resolving frames to function:line
> (the Phase-0 symbolization limit, now lifted in this image). Crashes reuse the Phase-0 helpers
> (`dedup_key`/`classify_exploitability`/`parse_asan`) + `afl-tmin` minimization. (CmpLog builds but
> is opt-in `AFL_HG_CMPLOG=1` — its auxiliary forkserver is unstable under the libFuzzer-driver+ASan
> harness; the coverage-guided run is already strong.) **Dedicated `hexgraph-fuzz` image [D4]**
> (`Dockerfile.fuzz`/`just fuzz-build`; worktree builds a PRIVATE tag, `HEXGRAPH_FUZZ_IMAGE`).
> **Detached campaign lifecycle [§5.5]:** `Executor.start_detached`/`poll_detached`/`stop_detached`
> (a `docker run -d` long-lived container, SAME hardening) owned by a durable **`fuzz_campaign`** row
> (**migration 0014**, applies clean on 0013 + fresh init_db, autogenerate no-drift; + **`fuzz_artifact`**,
> `UNIQUE(campaign_id,dedup_key)`); the launching task returns immediately. A periodic **reaper**
> (`engine/campaigns.py reap_all`, a `TaskWorker` job — NOT inline, no worker-thread starvation)
> polls, ingests new crashes → `fuzz_crash` findings, updates `stats_json`, finalizes. **Stop/resume**
> preserves the corpus in CAS (AFL++ resumes natively); **crash-safe re-attach** — the reaper re-binds
> to running containers by `container_name` on a `serve` restart. **Crash → verify tie-in:** the
> minimized reproducer AND the instrumented harness binary are CAS-preserved; `campaigns.verify_artifact`
> (+ `poc.verify_reproducer`) replays the reproducer against THAT binary via the unforgeable `crash`
> oracle — LLM-free, `code_present/dynamic`. **User-tunable `ResourceSpec`** (`sandbox/resources.py`,
> Settings `features.fuzzing.resources` default + per-campaign override): `unconstrained` drops
> `--memory`/`--cpus`/`--pids-limit` ONLY — the security flags (`--network none`, `--cap-drop ALL`,
> `--no-new-privileges`, `--read-only`, `--user 1000`) hold regardless, and `ResourceSpec` NEVER
> touches `policy.py`. Resource governance: a per-host instance cap + a per-campaign corpus disk quota.
> New edge vocab (`fuzzed_by`/`produced_artifact`/`reproduces`/`covers`) + the `fuzz_campaign`
> endpoint kind are String-column zero-migration (+ the `EDGE_ATTRIBUTE_SCHEMAS`/authoring-validator
> widening — so the §7 "EDGE_KINDS widening 0015" is a code change, no separate migration). API
> `/api/campaigns` (start/list/get/stop/resume + artifacts); MCP run-tools `start_fuzz_campaign`/
> `stop_fuzz_campaign`/`minimize_artifact` + read-tools `fuzz_status`/`list_fuzz_artifacts` (gated
> `features.mcp.run/read` + the EXISTING exec gate — **no new policy gate**). Frozen Finding schema
> untouched (all on `evidence.extra.fuzz` + the new tables). Tests: `test_campaigns.py` (the seam +
> fail-closed, `unconstrained`-keeps-every-security-flag, the lifecycle start→reap→finalize, crash-safe
> re-attach, stop/resume, the LibFuzzer-superset regression, the verify tie-in, the API),
> `test_migrations.py` (0014 round-trip + fresh init_db), Docker-gated `test_campaign_e2e.py` (a REAL
> AFL++ campaign finds a planted bug in an instrumented build WITH coverage, dedups/classifies/
> minimizes it, and the reproducer re-verifies — proven against `hexgraph-fuzz:wt-fuzz-phase3`).
> **Known limits:** the rich Campaigns/Artifacts triage UX + SSE live status are **Phase 4** (a
> minimal status API surface ships here); CmpLog + binary-only qemu-mode + network fuzzing are Phase
> 5; afl-cov coverage % reporting is wired through `stats_json` but a per-function coverage map awaits
> Phase 4's UI.

**Phase 4 — The Source/IDE tab full UX + Artifacts/triage.** Campaigns + Artifacts tabs (dedup groups, Reproduce/Minimize/Promote, source-mapped stacks, assurance chips), SSE live status, coverage shading, the surface-aware Fuzz modal (server-advertised engines), the `reveal()` router + deep-links. *Risk:* SSE plumbing — fallback to polling keeps it robust.

**Phase 5 — Binary-only + network fuzzing.** AFL++ qemu-mode/frida-mode (`binary_only`, foreign-arch via qemu-user sysroot); desock+AFL++ (tier 1) and boofuzz/AFLNet against rehosted/local services (tier 2, `local_tcp_scope`, audited, `net_container` netns join); structure/grammar-aware for parsers. Composes with rehost. *Risk:* network-fuzz egress — bounded + audited at the policy seam.

**Phase 6 — Remote fuzz environments (gated `features.fuzz_remote`).** `RemoteDockerExecutor` behind the Executor seam (`DOCKER_HOST` over SSH/TLS); a registered "fuzz environment" concept in Settings (local + remote endpoints, each with a `ResourceSpec` ceiling) + per-campaign selection; CAS-staged build-context/corpus transfer + artifact stream-back over the same connection; an environment health-check (remote `hexgraph-fuzz:latest` present, reachable, authorized). Endpoint connection details are secrets (env/`config.toml`, never DB/logged); the connection audited. Control plane stays loopback (§5.8b). *Risk:* a new remote trust edge — contained by single-authorized-endpoint pinning, the loopback control-plane invariant, secrets-never-stored, and the unchanged sandbox boundary on the remote. Lands after local coverage-guided fuzzing is proven; it's purely additive behind the seam.

**Phase 7 — Supply-chain, cross-compile, editable IDE, polish (was Phase 6).** `features.build_fetch` bounded audited fetch tier + lockfile + SBOM-lite + reproducibility badges; `WITH_CROSS=1` cross-compile (firmware-rootfs-as-sysroot, degrade to qemu-mode on failure); ccache incrementality + `SOURCE_DATE_EPOCH` determinism + cache-key artifact reuse; OSS-Fuzz `build.sh` import; editable IDE behind `features.source.edit` (revisioned saves, rebuild-from-revision — last because riskiest and least-needed for the core loop); run-to-run coverage diff (reuse `AnalysisRun`). *Risk:* fetch tier is the highest residual supply-chain risk — fail-closed, allowlisted, audited, fetch-then-offline.

---

## 8. Risks & invariant audit

- **Supply-chain (highest):** building untrusted source. *Mitigated:* sandbox `--network none` compile, non-root RO source, vendored-by-default, separate audited allowlisted fetch phase that drops network before compile, ephemeral containers, lockfile + hash pinning. A malicious `configure` can burn CPU and exit; it cannot persist or exfiltrate.
- **Resource exhaustion (long campaigns):** *Mitigated:* per-container mem/cpu/pids/wall caps, host concurrency limit, corpus minimization + CAS dedup + disk quota, detached + reaped (no thread starvation), crash-safe re-attach.
- **Gate creep:** every capability maps to an existing tier; the **only** gate edits are `allow_build`/`allow_build_fetch` (+ `fuzz_remote` for the remote-environment opt-in) and their asserts in `policy.py`. No feature code branches on tier, backend, engine, or executor identity.
- **Resource ceilings vs. security (the `unconstrained` knob):** lifting mem/cpu/pids is orthogonal to the policy seam — `ResourceSpec` never touches `policy.py`, and the sandbox's security flags (`--network none` except the gated net-fuzz tier, `--cap-drop ALL`, `--no-new-privileges`, `--read-only`, `--user`) hold regardless of the resource ceiling. A bigger/busier box is not a weaker box (§5.8a).
- **Remote compute trust edge (`features.fuzz_remote`):** the control plane stays loopback; the remote is a single user-owned, user-authorized Docker endpoint (same posture as `features.remote`), its connection details a secret (env/`config.toml`, never DB/logged), the connection audited, and the unchanged sandbox boundary applies on the remote — hostile bytes only ever live inside the container, now on a host the user chose (§5.8b).
- **Hostile bytes / LLM-no-shell:** builds, fuzzers, and reproducers run only in the sandbox via probes; the LLM authors source and *requests* runs via gated MCP tools — it never executes anything and sees no raw target bytes (only bounded tool output in `TaskContext`).
- **Reproducibility:** `recipe_sha` + `source_content_hash` + `toolchain_digest` + RO imported source + CAS-pinned artifacts make every build replayable; editable source is confined to HexGraph-authored roles + revisioned.
- **Migration discipline:** tables ship `alembic revision --autogenerate` (0012–0014) + the `EDGE_KINDS` validator change (0015); node/edge *vocabulary* is String-column zero-migration. The frozen Finding schema is untouched — everything new lives in `evidence.extra` / new tables.

This makes fuzzing genuinely state-of-the-art (coverage-guided, multi-surface, instrumented, campaign-driven, with deduped artifacts feeding the verification ladder) and makes source/build first-class — while every new power lands additively behind a seam, fails closed under the existing policy tiers, and is driven entirely by recorded recipes the API executes, never a human or the LLM at a shell.
