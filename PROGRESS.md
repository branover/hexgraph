# HexGraph Build Progress

The durable, resumable record of this build. **A new session should read this file first**,
then run the resume verifier, then continue at the next unchecked task.

## ▶ RESUME HERE
- **Current milestone:** v2 build — see [`docs/design/implementation-plan.md`](docs/design/implementation-plan.md)
  (built from [`docs/design/design-vision.md`](docs/design/design-vision.md)). MVP (M0–M5) is the foundation.
- **Dynamic surfaces (new track, see [`docs/design/design-dynamic-surfaces.md`](docs/design/design-dynamic-surfaces.md)):**
  extending HexGraph beyond static binaries to web/service, live-device, and rehosted-firmware surfaces.
  **Phase 1 (backbone) DONE:** a Target can now be a `web_app` *surface* (reached via a Channel in
  `metadata_json`, no bytes); `engine/surfaces.py` `register_web_surface` + the offline `surface_recon`
  task materialise `endpoint`/`param` nodes and the **`routes_to`** cross-link from a route to its handler
  `function` in the firmware (the static↔dynamic fuse). Additive `policy.py` tier scaffolding (`tier`,
  `NetworkScope`, `assert_allows_egress` — always denies; Tiers 0/1 byte-identical to before). Drive via
  MCP `register_surface` + `run_task(surface_recon)`. **Offline, zero egress, zero new risk.**
  **Phase 2 (bounded egress) DONE:** opt-in `features.network` → the **local-network tier** (`policy.py`
  `TIER_LOCAL_NETWORK`); a per-target `NetworkScope` from `local_network_scope(base_url)` that **refuses
  any non-loopback/private destination** (external hosts need the deferred live-remote tier); the runner
  gains a policy-checked `allow_network`/`run_channel_probe` (the one place `--network none` is relaxed →
  bridge); `assert_allows_egress(dest, scope)` enforces two independent gates (network-on AND
  dest-in-allowlist); every outbound decision is audited to `EgressEvent` (migration 0010,
  `engine/audit.py`, MCP `list_egress`). `web_recon` task does a bounded, read-only HTTP liveness probe
  (`surface_probe.py`, no redirects) — **denies + audits by default** (network off). Live probe is
  Docker+`features.network`-gated; the policy/scope/audit/denial machinery is fully offline-tested.
  Next: dynamic web PoC (the `{{NONCE}}` oracle over HTTP), then rehosting + live-device collection.
  **UX refresh DONE** (from a full UI review): graph legend driven from the shared color maps
  (present-only, nodes+edges, red reserved for severity) + distinct shapes per node type; semantic edges
  labelled at rest; a **Network-egress Settings card** (the `features.network` tier was previously
  unreachable from the UI); type-aware NodeInspector hints for socket/endpoint/input/sink; node icons for
  the new types; modernised selects + pill toggle switches; endpoint/param hand-authoring; search ranks
  nodes first. Deferred items (egress-audit view, schema-driven edge-attr form, a11y) tracked in
  `docs/ui-backlog.md`. A committed vulnerable web target (`tests/fixtures/vulnrouter/`) backs live testing.
  **Firmware rehosting (Phase 4) — boot a REAL firmware's web UI, DONE + live-validated:** `engine/rehost.py`
  Rehoster seam (`get_rehoster()`) with **two implementations auto-selected by image type** (`select_rehoster`):
  **`QemuDiskRehoster`** (qemu-system-x86_64 + KVM; `docker/qemu/`) boots a **full-OS disk image** as-is (its own
  kernel + init) — the right tool for IoTGoat-style OpenWrt images; **`FirmAERehoster`** (FirmAE in a privileged
  container; `docker/firmae/`) extracts a **vendor blob's** rootfs + supplies a kernel. Both behind a stable
  `HEXGRAPH_REHOST` marker contract, gated by **`features.rehost`** (`policy.assert_allows_rehost`). `rehost_firmware()`
  registers the live web server as a `web_app` surface CHILD of the firmware; the probe joins the emulator container's
  netns (`run_probe(net_container=…)`) to reach the device's private IP, then surface_recon/web_recon/http_request/
  web-`verify_poc` assess it (needs `features.network`). MCP `rehost`, `hexgraph rehost` CLI, `just firmae-build`/
  `qemu-build`/`iotgoat`, `docs/engagement-rehosted.md`, SKILL §2b. **Validated end-to-end on IoTGoat x86: auto-selected
  qemu, booted OpenWrt (uhttpd up), registered the surface, http_request reached it.** FirmAE-image fixes shipped
  (binwalk 2.3.4 from source, in-container postgres, loop-device self-heal + graceful teardown); FirmAE doesn't run
  OpenWrt (procd/ubus) — that's why disk images route to qemu. Heavy image builds + live boot are operator/env-gated
  (offline tests use a fake rehoster; `test_rehost.py` covers the gate, surface wiring, netns plumbing, selection).
  cookie-jar `session` handle on http_request for cross-call auth flows. New MCP tools: `list_filesystem`/`read_file`
  (browse/read a firmware's unpacked FS), `archive_target`/`restore_target` (reversible subtree removal).
  **Phase 3 (dynamic web assessment) DONE — live targets are solvable end-to-end:** `http_probe.py` sends
  crafted request(s) from the sandbox (single-request for the `http_request` MCP tool; multi-step+oracle
  with a CookieJar for web PoCs, so auth flows work). `surfaces.run_http_request`/`run_web_poc` share an
  `_egress_gate` (policy + per-target local-only NetworkScope + EgressEvent audit). `poc.verify_poc`
  branches web_app→HTTP oracle (`body_contains`/`status_is`/`status_differs`, gated by features.network)
  vs binary→exec (features.poc); `{{NONCE}}` shared so a web RCE is unforgeable. SKILL §2b +
  `docs/engagement-vulnrouter.md` + `just vulnrouter`. **Validated**: an agent (MCP only, no source) solved
  vulnrouter — auth bypass + RCE verified → 6 findings/11 nodes/29 edges.
  **First-class raw-TCP/socket targets DONE** (branch `build/register-socket`): a bare non-HTTP service
  (bind shell / vendor binary protocol / custom daemon) is now its own **`TargetKind.service`** —
  reached via a raw TCP/UDP Channel `{kind,host,port}` in `metadata_json`, **no bytes, no credentials**
  (zero-migration: `Target.kind` is a constraint-free `VARCHAR` on SQLite, like `web_app`/`remote` before
  it). `surfaces.register_socket_target` mirrors `register_web_surface`/`register_remote_target` and links
  the surface to the shared `socket` graph node via a `listens_on` edge (surface vs annotation stays
  distinct). `infer_surface` returns `network` for it, so `start_fuzz_campaign` points **boofuzz** straight
  at the target's `host:port` (`_launch_network` reads them from the Channel) on the EXISTING bounded
  local-network tier — `local_tcp_scope` (loopback/private only, refuses public), `features.network`,
  every send audited to `EgressEvent`; **no policy relaxation, no new gate**. MCP `register_socket` (under
  `run`, like its siblings) + REST `POST /api/projects/{id}/targets/socket`; SKILL §2d + README updated to
  use it INSTEAD of misusing `register_remote(transport=telnet)` for a bare protocol. UI: `service` added
  to the graph kind-color + icon maps + `bestFuzzTarget`; the existing Fuzz modal already makes it
  selectable + network-fuzzable (Playwright-verified — two service targets `listens_on` their socket
  nodes). Tests: `tests/test_sockets.py` (register/channel/node-link/validation, infer_surface→network, a
  mock network campaign launches egress-gated+audited + refuses a public host, REST+MCP paths). Plus **graph-quality + tool
  contracts**: every target-bound node gets a `contains` edge (no orphans); `engine/node_schemas.py`
  advertised via `get_schemas` with per-type `use_when`/recommended attrs + the sink-vs-symbol rule;
  `run_task` folds dupes; `test_tool_contract.py` locks it. `just sandbox-build` now forwards
  `--build-arg WITH_GHIDRA`. UI: PoC verification panel + re-verify, edit-any-field (finding+node),
  firmware file viewer, search-includes-targets, edge inspector, Author modals (`name·type·target` +
  type help + draw-to-connect), tighter Settings inputs.
- **Fix: "Promote PoC" on a fuzz crash now actually proves it (`fix/promote-poc`).** Previously
  `promote_artifact(to_poc=True)` only SEEDED a reproducer-backed PoC spec into `evidence.extra.poc`
  (no verification) and the UI hardcoded "promoted → PoC (confirmed)" regardless — and it never checked
  the policy seam, so with PoC disabled it silently seeded a PoC that could never verify (verify_artifact
  refuses static-only): a misleading dead end. Now Promote→PoC is gated at the policy seam
  (`assert_allows_execution()` BEFORE seeding — under static-only it raises `PolicyViolation`, mapped to a
  403 with guidance to enable PoC verification in Settings; nothing is seeded/executed, fail-closed) and,
  when execution IS allowed, it seeds the spec AND inline-runs the SAME LLM-free crash re-run
  `verify_artifact` uses (stored minimized reproducer vs the instrumented harness, unforgeable `crash`
  oracle, in the locked-down sandbox), persisting the result to `evidence.extra.verification` and returning
  `{verified, verify_detail, assurance}`. `ArtifactsView.tsx` now shows the honest outcome — a distinct
  green "Verified PoC" banner (with the assurance standard/method), a muted "couldn't re-confirm" note, or
  the policy-guidance error. Plain Promote (to_poc=false) is unchanged and needs no gate. NO policy
  relaxation outside policy.py, no schema/migration change (PoC + verification live in evidence.extra).
  Tests in `tests/test_campaigns_phase4.py`: disabled→refuses+seeds-nothing (engine + API 403 guidance),
  enabled→seeds+verifies+persists assurance, plain promote still just confirms. `just test` green.
- **Graph-presentation redesign — ALL 5 PHASES DONE** (`docs/design/design-graph-presentation.md`;
  detail + human-eyes verdicts per phase in `docs/ui-backlog.md`): P1 visual legibility (edge-ink
  recede, importance sizing, shape/glyph redundancy, label discipline, interactive legend); P2
  focus/context + breadcrumb + hover preview + search-drives-focus + verb menu; P3 compound target
  islands + group-by + expand/collapse + skeleton-collapsed default + meta-edges + socket bus; P4
  layout-by-context (fcose-spread / scoped dagre / concentric) + semantic-zoom LOD; **P5 (this work):
  the layer panel (node-type/edge-class toggles), the fade-first filter chip rail, the center-pane
  view switcher (Map/Graph/Table/Matrix/Source), Table + Matrix views, Map-as-named-view,
  Saved Lenses (managed `ui.lenses` in `settings.json`, no migration), and panels-drive-scope.**
  All client-side over `/graph` except the one validated `ui.lenses` settings field (+tests).
  **Graph-canvas interaction/layout fixes (`build/graph-canvas-fixes`, this work):** a batch of
  hands-on bugs on top of the redesign, re-verified LIVE then fixed — room-hover no longer draws a
  filled blob (room compounds emphasize via border, never an underlay-fill); hover now emphasizes
  the hovered node + neighborhood instead of inverting; scroll-zoom `wheelSensitivity` 0.25→0.6;
  semantic-zoom `LOD_NEAR` 1.35→0.85 + leaf-label opacity floor so labels show once nodes are
  individuated (was findings-only); the left control rail deduped to ONE +/- (zoom, a segmented
  cluster) on an aligned fixed-width column; **Map** is now a genuinely distinct collapsed-skeleton
  territory view (force-collapsed cards, semantic ribbons only, double-tap → drill into scoped
  Graph) not the by-target Graph in disguise; right-click verb menu sized compact; native
  contextmenu suppressed on the whole canvas (not just nodes); target tree-row run/fuzz/trash
  de-cramped (standalone fuzz button removed — Run menu owns the fuzz path). `#88`/`#86` had already
  resolved the loose-target-dot disconnect and the inspector-card Run overlap. Color untouched (D8).
  Client-side only (`GraphView.tsx`/`Workspace.tsx`/`theme.css`); recurring hover/zoom/right-click/
  view-switch assessment checks added to `docs/dev/ui-backlog.md`. `just test` green (717 passed).
- **Current state:** **P0–P8 all delivered** (core) + **researcher depth (P6/P7) complete**: annotations
  (rename/note/tag, agent-proposed→confirm, confirmed facts feed context), hypothesis lifecycle
  (evidence-derived status, sticky human verdict, open hypotheses feed context), in-app report viewer +
  run-compare diff UI. Remaining documented sub-items (not whole phases): richer approval gates (review-on-
  output / plan / spend), P7-5 (offline CVE / bounded dataflow / reviewable dedup), FTS5 search,
  SSE live activity, real-key cassette recording (`just test-live`). (Ghidra decompiler is DONE —
  see Optional features below.)
- **Optional features (settings-driven, `settings.py` + `/api/settings` + `hexgraph config`; secrets status-only):**
  **Ghidra** (headless `WITH_GHIDRA=1` / bridge / enrich_recon), and **Fuzzing** (`fuzzing` task, off by
  default — the one thing that relaxes static-only, via the policy seam: libFuzzer+ASan on a generated
  harness, finding-per-crash, optional LLM triage). **Fuzzing Phase 0 DONE** (`docs/design-fuzzing-and-source.md`
  §7): now **coverage-guided** — the target's own source (task param `target_sources` /
  `metadata.fuzz_target_sources`) is compiled WITH the harness under SanCov+ASan for real coverage
  feedback (uninstrumented `.so` → coverage-blind, flagged honestly); crashes deduped by a normalized
  stack-hash (one finding/root cause + dupe_count), reproducer minimized (libFuzzer `-minimize_crash`),
  deterministic exploitability rating — all on `evidence.extra.fuzz` (no schema change).
  **Fuzzing+source Phase 1 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 1, branch
  `build/fuzz-phase1`): the **source-tree foundation + a read-only in-browser Source/IDE tab**, no
  exec / no new gate. `source_tree` is a new SQL entity (**migration 0012**) — a project holds
  multiple trees, each optionally `built_from`-linked to a target; files live on disk + a manifest,
  with `source_file` graph nodes materialized **lazily** (`engine/source.py`, mirrors
  `engine/filesystem.py`). Harnesses/PoCs/scripts unify as role-tagged `source_file`s
  (`engine/harness_promote.py` — promotes the transient `evidence.decompiled_snippet`; back-compat
  read path kept). New zero-migration vocab: node types `source_file`/`harness`, edge types
  `built_from`/`located_in`/`harnesses` (+ a surgical `EDGE_KINDS`/`authoring` widening to admit
  `source_tree` as a polymorphic endpoint). Read-only **Graph⇆Source** mode switch + finding→source
  jump (`evidence.extra.source_ref`). MCP read `list_source_trees`/`read_source_file`, write
  `import_source_tree`/`link_finding_to_source`. Frozen schema untouched; no `policy.py` edit.
  **Fuzzing+source Phase 2 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 2, branch
  `build/fuzz-phase2`): the **`Builder` seam + build-as-API** — a managed source tree → an
  instrumented artifact via a recorded, reproducible recipe HexGraph runs in the sandbox.
  `engine/build.py` (`get_builder()`, `HEXGRAPH_BUILDER`, default `sandbox`; `MockBuilder` for
  offline `just test`) + `engine/builds.py` (orchestration: persist the recipe, run it, CAS-ingest
  artifacts/log, register the derived target) + `build_probe.py`/`build_detect_probe.py` +
  `docker/build.Dockerfile`/`hexgraph-build` (`just build-image` — clang/LLVM + sanitizers + SanCov +
  AFL++ + `llvm-symbolizer`). **`BuildSpec`** {system, phases (recorded verbatim), instrumentation,
  artifacts, NON-secret env, arch, base_image, network="none"} with **`recipe_sha` = hash{phases,
  env, base_image, instrumentation, arch}** — reproducibility is the contract (same recipe_sha +
  source content_hash + toolchain_digest ⇒ same build). The orchestrator INJECTS CC/CXX/CFLAGS/
  SANITIZER/FUZZING_ENGINE (the base-image contract) so the same phases yield ASan/SanCov vs AFL++
  by swapping the profile. **New gate [D5]:** `assert_allows_build()` / **`features.build`** (the
  ONLY `policy.py` edit) — peer of, not folded into, the exec gate (build-and-inspect without
  running the target), fail-closed. **Tables (migration 0013):** `build_spec` + `build` (the durable
  ledger). **Rebuild-with-instrumentation → derived target [§3.3]:** a build of a `built_from`-linked
  source tree registers an instrumented derived target wired `instrumented_build_of`→ the original
  (zero-migration edge vocab + `build_spec` endpoint widening). API `/api/builds` (+ `/build/preview`,
  `/builds/{id}/log`); MCP run-tool `build_target` + read-tool `list_builds`; the IDE **Build modal**
  (recorded-recipe preview, instrumentation toggles, vendored-only) gated by the new
  `capabilities.features.build`. **Vendored/offline only** (`--network none`; the audited fetch tier
  is Phase 7). Frozen schema untouched.
  **Fuzzing+source Phase 3 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 3, branch
  `build/fuzz-phase3`): **coverage-guided source fuzzing made first-class + the detached campaign
  lifecycle + the user-tunable `ResourceSpec`.** The **`Fuzzer` seam** (`engine/fuzzers/` →
  `get_fuzzer(surface, engine=None)`, dispatch on attack SURFACE not engine identity, fail-closed on
  a nonsensical pair; `HEXGRAPH_FUZZER=mock` for offline tests): `LibFuzzerFuzzer` (a STRICT SUPERSET
  of the Phase-0 single-pass path — `execute_fuzzing` now resolves inputs through the seam, byte-
  identical, regression-tested) + **`AflPlusPlusFuzzer`** (`afl-clang-fast` + persistent libFuzzer-
  driver `main` + llvm-symbolizer, real coverage on the Phase-2 instrumented derived target) +
  `MockFuzzer`. **Dedicated `hexgraph-fuzz` image** (`docker/fuzz.Dockerfile` / `just fuzz-build` [D4] —
  AFL++ LTO/CmpLog + libFuzzer + llvm-symbolizer + afl-cov + gdb + qemu-user; worktree builds a
  PRIVATE tag, `HEXGRAPH_FUZZ_IMAGE`). **Detached campaign lifecycle [§5.5]:** `Executor.start_detached`/
  `poll_detached`/`stop_detached` (a `docker run -d` long-lived container, SAME hardening) owned by a
  durable **`fuzz_campaign`** row (migration **0014**, + **`fuzz_artifact`**); the launching task
  returns immediately (`running`, `campaign_id`). A periodic **reaper** (`engine/campaigns.py` `reap_all`,
  a worker job) polls, ingests new crashes → `fuzz_crash` findings (reusing the Phase-0 stack-hash dedup
  + exploitability + minimization, `UNIQUE(campaign_id,dedup_key)`), updates `stats_json`, finalizes.
  **Stop/resume** preserves the corpus in CAS; **crash-safe re-attach** — the reaper re-binds to
  running containers by `container_name` on a `serve` restart (the worker's startup pass). **Crash →
  verify tie-in:** the minimized reproducer + the instrumented harness binary are CAS-preserved;
  `campaigns.verify_artifact` / `poc.verify_reproducer` replay it against THAT binary via the
  unforgeable `crash` oracle (LLM-free, `code_present/dynamic`). **User-tunable `ResourceSpec`**
  (`sandbox/resources.py` — `{mem,cpus,pids,tmpfs,timeout,unconstrained}`, Settings default +
  per-campaign override): `unconstrained` drops `--memory`/`--cpus`/`--pids-limit` ONLY — **NEVER** a
  security flag (`--network none`, cap-drop, no-new-privileges, read-only, `--user` all still hold;
  `ResourceSpec` never touches `policy.py`). Resource governance: a per-host instance cap + a corpus
  disk quota. API `/api/campaigns` (start/list/get/stop/resume, artifacts); MCP run-tools
  `start_fuzz_campaign`/`stop_fuzz_campaign`/`minimize_artifact` + read-tools `fuzz_status`/
  `list_fuzz_artifacts` (gated `features.mcp.run/read` + the existing exec gate — **no new gate**).
  New edge vocab `fuzzed_by`/`produced_artifact`/`reproduces`/`covers` + `fuzz_campaign` endpoint
  (String-column zero-migration + the `EDGE_ATTRIBUTE_SCHEMAS`/authoring widening). Frozen schema
  untouched (all on `evidence.extra.fuzz` + the new tables). Tests: `test_campaigns.py` (seam +
  fail-closed, ResourceSpec unconstrained-keeps-security-flags, lifecycle start→reap→finalize,
  crash-safe re-attach, stop/resume, LibFuzzer-superset regression, the verify tie-in, the API),
  `test_migrations.py` (0014 on 0013 round-trip + fresh init_db), Docker-gated `test_campaign_e2e.py`
  (a REAL AFL++ campaign finds a planted bug in an instrumented build with coverage, dedups/classifies/
  minimizes it, and the reproducer re-verifies). The rich Campaigns/Artifacts triage UX is Phase 4.
  **Fuzzing+source Phase 4 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 4, branch
  `build/fuzz-phase4`): the **full Source/IDE tab UX + the Campaigns/Artifacts triage experience** —
  the user-facing payoff of Phases 1–3 (mostly frontend + thin API/serializer fills, **no
  migration**, no `policy.py` edit, frozen schema untouched). **Campaigns tab** (`CampaignsPanel.tsx`)
  with a live row per campaign (status/execs/edges/crashes/coverage) over an **SSE** stream
  (`GET /api/campaigns/{id}/events`) with **automatic polling fallback**; Stop/Resume. **Artifacts/
  triage view** (`ArtifactsView.tsx`): crashes grouped by **dedup bucket**, an **assurance chip**
  (`AssuranceChip.tsx`, the two-standards ladder), exploitability rating, and a **source-mapped
  stack** (the reaper parses ASan frames → `evidence.extra.fuzz.frames` and **auto-links the top
  in-project frame** to its source tree; a frame click jumps to the IDE line). Per-crash **Reproduce/
  Minimize** (replay the stored reproducer, LLM-free), **Promote** (confirm the finding), **Promote→
  PoC** (`promote_artifact(to_poc)` seeds a reproducer-backed PoC the one-click re-verify re-proves —
  the verify-finding endpoint branches a fuzz reproducer to `verify_finding_reproducer`). **Coverage
  shading** in the Source viewer (`coverage_for` serializes a per-file line map, snapshotted to CAS at
  finalize; covered=green/uncovered=amber + a campaign picker). **Surface-aware Fuzz modal**
  (`FuzzModal.tsx`): engines **server-advertised** (`GET /api/fuzz/engines?target_id=`, UI never
  hardcodes), per-campaign **`ResourceSpec`** controls defaulted from Settings. A single **`reveal()`**
  navigation primitive + **deep-links** (`?view=source&file=…&line=…`, `?tab=campaigns&campaign=…`).
  **Settings**: a Source & Build card + the default ResourceSpec in the Fuzzing card; the capability
  table advertises `features.{fuzzing,poc,build}` so the SPA shows/hides Campaigns/Fuzz/Build
  project-wide. IA is a center-pane mode switch + right-pane tab (D-ia), not a new route. Tests:
  `tests/test_campaigns_phase4.py` (9 — frame parse + runtime-skip + unsymbolized→empty, ingest
  frames + auto-link source, promote/promote-to-PoC, coverage serialize incl. CAS snapshot, the
  engines endpoint, the verify/minimize/promote/coverage API, the `features.fuzzing` cap flag).
  Full `just test` green (531 passed, 5 Docker-gated skips). Playwright-verified every surface.
  **Target soft-removal** (archive subtree, restore on re-add) and **firmware filesystem browser**
  (persisted unpacked tree, add any file as a child target; library exports → nodes; function nodes
  launch tasks).
  **Fuzzing+source Phase 5 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 5, branch
  `build/fuzz-phase5`): **binary-only + network/protocol fuzzing**, behind the EXISTING `Fuzzer`
  seam (no new gate, **no migration** — all new structure rides `config_json`/`evidence.extra` + the
  String `surface`/`engine` columns). The surface×engine matrix gained **binary_only → `qemu`
  (default) / `frida`** and **network → `boofuzz` (default) / `desock`**. (1) **Binary-only**
  (`engine/fuzzers/binary_only.py`, `sandbox/probes/afl_qemu_probe.py`): AFL++ **qemu-mode** (`-Q`,
  full edge coverage via QEMU TCG, NO source/instrumentation) — a foreign-arch MIPS/ARM firmware
  binary runs under qemu-user with the **parent firmware rootfs as the `-L` sysroot** (REUSING
  `poc._find_sysroot` + `filesystem.host_root`, the proven PoC path); **frida-mode** the opt-in alt
  (`-O`). Crashes flow into the SAME Phase-3 dedup/exploitability/minimize/verify pipeline
  (`code_present/dynamic`). (2) **Network** (`engine/fuzzers/network.py`): **boofuzz** (default,
  `boofuzz_probe.py` — generational; ships a built-in field mutator so it works even without the
  boofuzz pip) drives a **LIVE service** over a real socket with a **liveness oracle** (service died +
  stayed down = a crash); it rides the **EXISTING local-network tier** — `_launch_network` asserts
  `assert_allows_egress(dest, local_tcp_scope(host,port))` (loopback/private ONLY, refuses any public
  host) + **audits every launch to `EgressEvent`**, the detached container joins a rehosted device's
  emulator **netns** (`net_container`); the crash is **`input_reachable/dynamic`** (the strongest rung
  — reached + triggered end-to-end) and its crashing MESSAGE re-verifies over the socket
  (`_verify_network_artifact`). **desock+AFL++** (`desock_probe.py`, the tier-1 alt) LD_PRELOADs
  preeny/desock to turn a LOCAL server's socket into stdin so AFL++ coverage-fuzzes it with
  `--network none`. (3) **file_format** gains the auto-dictionary/structured hook on the AFL/qemu
  paths. **Gating, by surface (the ONLY change is which existing gate applies):** source/binary-only/
  desock EXECUTE a target → the exec gate (`features.fuzzing`/`poc`); a live boofuzz campaign talks to
  a service → `features.network` — `start_campaign`/`verify_artifact`/the API/MCP pick the right gate,
  **no `policy.py` edit, no new gate**. `start_detached` gained a policy-checked `allow_network`/
  `net_container` (the single place a detached campaign relaxes `--network none`; all other security
  flags hold). Image: `docker/fuzz.Dockerfile` now builds AFL++ from source with **qemu-mode (afl-qemu-trace)
  + frida-mode**, **preeny/desock**, and **boofuzz** (a PRIVATE `hexgraph-fuzz:wt-fuzz-phase5` tag for
  the worktree, `HEXGRAPH_FUZZ_IMAGE`). Tests: `tests/test_fuzz_phase5.py` (19 offline — the matrix +
  fail-closed pairs, prepare() launch descriptions, the network bounded-egress gate + audit + the
  non-local-host refusal, network-vs-binary gate selection, the network-crash `input_reachable`
  assurance, surface inference/input resolution, the engines endpoint) + Docker-gated
  `tests/test_fuzz_phase5_e2e.py` (qemu-mode finds a planted crash in a stripped ELF; **boofuzz drops a
  planted-overflow live TCP service via its netns and the reproducer re-verifies** — the blind-network-
  fuzz battle-test path; desock+AFL fuzzes a local server with `--network none`). MCP/API/SKILL updated.
  **Fuzzing+source Phase 6 DONE** (`docs/design-fuzzing-and-source.md` §7 Phase 6, branch
  `build/fuzz-phase6`): **remote fuzz environments** — a campaign can run on a user-owned remote
  Docker host (beefier compute) behind the **Executor seam** with NO fuzzer/builder change.
  **`RemoteDockerExecutor`** (`sandbox/remote_executor.py`, a `SandboxRunner` subclass) targets
  **`DOCKER_HOST`** (ssh:// or tcp://+TLS); it REUSES `_hardening_args` so the SAME sandbox boundary
  (`--network none`/cap-drop/no-new-privileges/read-only/`--user 1000`/caps) holds on the remote —
  bind-mounts (which don't cross a remote daemon) are replaced by **CAS-staging inputs into a per-run
  named VOLUME** (probes/artifact/corpus via `docker cp`) + **streaming `/out` back** (`docker cp`,
  stateless re-attach via container labels so the reaper + a serve restart re-bind by name —
  crash-safe). The **fuzz-environment concept** is a table (**migration 0015**, applies clean on 0014
  + round-trips + no autogen drift): `FuzzEnvironment` holds ONLY non-secret metadata (slug id, label,
  transport, descriptor, a per-env `ResourceSpec` ceiling, cached health); a campaign **selects** one
  (`local` default) via `engine.fuzz_env.get_campaign_executor` (the single seam point). **Secrets:**
  the DOCKER_HOST/SSH-key/TLS-certs are read from env (`HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST`) or
  `config.toml [fuzz_remote.<id>]` keyed by the env id — NEVER stored in the DB, NEVER logged (the
  executor scrubs it from errors), reported presence-only. **Gate:** `features.fuzz_remote` →
  `policy.assert_allows_fuzz_remote` (fail-closed, default off) — an ORTHOGONAL peer flag (governs
  WHERE compute runs, never raises the tier ladder), the ONLY place consulted; no engine/task/executor
  code branches on identity. Every remote launch **audited** to `EgressEvent` (`tool="fuzz_remote"`,
  non-secret descriptor). Control-plane loopback invariant untouched. An environment **health-check**
  (reachable + authorized + `hexgraph-fuzz` image present) is surfaced via Settings/API/MCP. API
  (`/api/fuzz/environments` + `/health`), MCP (`list_fuzz_environments`/`fuzz_environment_health` +
  `start_fuzz_campaign(environment=)`), UI (a Remote-fuzz-environments Settings card + a Fuzz-modal
  selector when the gate is on). Tests `tests/test_fuzz_phase6.py` (27 offline + 2 Docker-gated): the
  gate fail-closed/orthogonal, the **secret never-stored (greps the sqlite file)/never-logged/
  presence-only** across engine+MCP+API, env registration+health, the seam returns
  `RemoteDockerExecutor`, ResourceSpec-ceiling fold, error-scrub, campaign-via-remote
  audited+gated+recorded, local campaigns unchanged, and **the REAL `RemoteDockerExecutor` against the
  LOCAL daemon-as-remote** (health + CAS-stage-in + run + JSON-back + `/out` stream-back; + a
  FUZZ_IMAGE-gated whole campaign via local-as-remote). `just test` green (577 offline); `just demo`
  exits 0.
  **Fuzzing+source Phase 7 DONE — the fuzzing+source EPIC (Phases 0–7) is COMPLETE**
  (`docs/design-fuzzing-and-source.md` §7 Phase 7, branch `build/fuzz-phase7`): supply-chain +
  cross-compile + determinism/cache + OSS-Fuzz import + the editable IDE + coverage diff.
  **(1) Bounded audited fetch (`features.build_fetch`, fail-closed, the ONLY gate edit
  `policy.assert_allows_build_fetch` + a `build_fetch_scope` registry allowlist):** a SEPARATE
  `build_fetch_probe.py` sandbox run with network ON but bounded to the allowlist (egress-guard
  backstop, never "any host"), producing a **hash-pinned lockfile + SBOM-lite**; then HexGraph DROPS
  NETWORK and compiles `--network none` against the snapshot — **fetch-then-offline** (a Docker-gated
  test proves the compile fails if it touches the network even with fetch on); every fetch audited
  (`EgressEvent tool=build_fetch`). A **reproducibility BADGE** (`build.reproducible`) + a **cache-key**
  that reuses a prior CAS artifact on a hit (`build.cache_hit`; keyed on the TRUE byte-content hash via
  `source.tree_content_sha`, so a same-size edit misses). **(2) Cross-compile (`WITH_CROSS=1`):**
  `instrumentation_env` injects clang `--target`/`--sysroot` (the firmware rootfs); a real MIPS object
  is produced (Docker-gated test); failure degrades to native→qemu-mode. **(3) Determinism:**
  `SOURCE_DATE_EPOCH` + ccache. **(4) OSS-Fuzz import** (`engine/oss_fuzz.py`): a `build.sh` → a
  BuildSpec mapped to our `$CC/$CXX/$CFLAGS/$LIB_FUZZING_ENGINE/$SRC/$OUT` contract. **(5) Editable IDE
  (`features.source.edit`):** `engine/revisions.py` — a save writes a NEW `SourceRevision` (CAS + diff,
  **migration 0016** adds `source_revision` + `build` lockfile/SBOM/reproducible/cache_hit/cache_key/
  source_revision_id columns), `rebuild_from_revision`; CONFINED — the write refuses any non-editable
  tree, so extracted/vendor source can NEVER be revised. **(6) Coverage diff** (`campaigns.coverage_diff`).
  New MCP: `import_oss_fuzz`/`save_source_revision` (write), `coverage_diff` (read); `build_target` gained
  `network`/`fetch_phases`/`arch`/`source_revision_id`. UI: the Build modal gained arch + dependency
  posture + a reproducibility/cross preview; the Source tab a per-file Edit/Save + revision history +
  reproducible/cached/locked build badges; a Settings Source-&-Build card with the fetch + editable-IDE
  toggles. Frozen Finding schema untouched. Tests: `tests/test_fuzz_phase7.py` (28 offline) +
  Docker-gated `tests/test_fuzz_phase7_e2e.py`. `just test` green (607 offline); `just demo` exits 0;
  migration 0016 round-trips + fresh init_db + no autogen drift; Playwright-verified the editable IDE +
  badges + Build modal.
- **Entity removal (`engine/removal.py`, migration 0011 `node.archived`):** nodes **soft-archive** —
  `archive_node` hides the node *and* the edges touching it (the graph already skips edges to hidden
  endpoints); re-adding the same node (`get_or_create_node`) or `restore_node` brings it and its edges
  back (nothing deleted). A single edge is a **hard delete** (`delete_edge`); a whole project is a hard
  delete of all its rows + on-disk data dir (`delete_project`). Full surface: API (`DELETE
  /api/projects/{id}`, `DELETE|POST .../nodes/{id}[/restore]`, `DELETE /api/edges/{id}`), MCP write tools
  (`archive_node`/`restore_node`/`delete_edge`; `list_nodes` skips archived), and UI (NodeInspector
  "Remove node", tap-an-edge → "Delete edge", Projects-card delete — all with confirm). Targets keep
  their existing archive flow. Tests: `tests/test_removal.py`.
- **LLM tool-use:** LLM tasks run an agent loop (`llm/runner.run_findings_agentic` + `engine/agent_tools.py`):
  the model calls sandboxed tools (decompile/strings/imports/…, fuzz when enabled), HexGraph executes them
  and feeds results back until findings. Superset of single-pass; mock drives it offline (`tool_calls`
  fixtures, `agentic_overflow` scenario). Works with a plain BYOK key — no external coding agent needed.
- **Coding-agent integration (MCP):** driver mode (`hexgraph mcp` exposes sandboxed read/write/run tools,
  group-gated) + delegate mode (`agent_delegate` task launches the agent CLI restricted to HexGraph tools).
  LLM tasks use a tool-use agent loop over a BYOK key. `hexgraph mcp install` for setup.
- **Executable PoC findings** (`features.poc`, opt-in): `poc` task + `verify_poc` MCP tool execute the
  target in the sandbox and confirm exploitation via an unforgeable nonce oracle → finding marked
  `verified`. **Findings are typed** (`finding_type`: vulnerability/recon/harness/fuzz_crash/poc/…,
  migration 0008) for sort/filter. Engagement test (`docs/engagement-brief.md`) success = a verified PoC.
- **Autonomous-session work (2026-05-31, harder-challenge + sub-agent feedback loop):**
  - **`xrefs` analysis tool** (`engine/agent_tools._xrefs` + `mcp_tools.xrefs`, `read` group; probe
    `sandbox/probes/xrefs_probe.py`, r2 `axtj`): "who calls this sink", or (no symbol) a two-tier sink
    sweep — memory/exec sinks (system/popen/strcpy/…) and a separate **format-string tier** (printf
    family, labeled "bug only if the format arg is attacker-controlled"). SKILL §2 points agents here
    first. No image rebuild (probes mount from the install).
  - **n-day workflow exposed to agents:** `mcp_tools.link_same_code` (write group — the cross-target
    similar_to primitive, now reachable via MCP; each match flags `has_findings` per side) +
    `mcp_tools.propagate_finding(finding_id, target_id)` (clone a confirmed finding onto a matched
    sibling binary as a fresh finding to triage, wired `derived_from`→ source). SKILL §3 adds the
    confirm → link_same_code → propagate → verify rhythm.
  - **`get_finding(finding_id)` read tool** — returns ONE finding in full incl. the complete `evidence`
    (the only way through MCP to read `evidence.extra`, where verify_poc stores its result; the finding
    analog of `get_node`). **`bypasses` edge type** (String col → zero-migration) for auth/logic bugs
    where `taints` overstates the relationship.
  - **Feedback fixes:** `get_or_create_node` now fills a missing `address` on an existing (recon-seeded)
    node — the requested function-address feature was silently dropped before; `create_node` echoes
    back stored address+attrs. `link_evidence` accepts `confirms`/`contradicts` aliases.
    `set_hypothesis_status` takes a `rationale`. `get_schemas` documents all of it.
  - **`recon_probe` classifies wrapped real firmware** (TRX/uImage/UBI/JFFS2/cramfs/FIT signatures, not
    just bare squashfs) so binwalk carving runs on real vendor images.
  - **Challenge fixtures** (`tests/fixtures/challenges/`, obfuscated, CVE-class, x86 so verify_poc is
    end-to-end; `build.sh` rebuilds all, `README.md` is the answer key): `keyserv` (stack overflow via
    wrong bounds check), `netcfgd`/`orbweaver_fw.bin` (command injection behind an INCOMPLETE sanitizer
    — bypass via newline/backtick), `eventlogd`/`halcyon_nvr_fw.bin` (CWE-134 format-string env-secret
    disclosure, unforgeable via env `{{NONCE}}`), `authsvc`+`cfgsvc`/`vantage_gw_fw.bin` (shared
    `unpack_record` stack overflow across two services — the n-day case), `admind`/`sentry_sx3_fw.bin`
    (CWE-287/697 auth bypass — attacker-controlled compare length). Four sub-agent rounds
    (escalating difficulty) each solved end-to-end with verified PoCs; feedback in
    `/tmp/hexgraph-auto/feedback-*.md` drove every fix above.
- **Typed attributed edges + socket nodes** (this session): edges carry type-specific attributes
  (`engine/edge_schemas.py` registry; list attrs like a `calls` edge's `call_sites` merge on repeat
  via `add_edge(merge=)`/`update_edge`). New `socket` node type — a network/IPC endpoint shared across
  binaries (a server `listens_on`, a client `connects_to`, both resolve to one node) → the firmware
  network map. Full surface: MCP (`create_socket`/`update_edge`/`list_sockets`/`get_finding`,
  `get_schemas` advertises edge schemas + socket kinds), API (`POST /sockets`, `PATCH /edges/{id}`,
  `GET /api/edge-schemas`), agent loop (`xrefs` adds a network tier), and UI (socket node + edge-attr
  labels + author forms). `bypasses` edge type for auth/logic bugs.
- **Real vendor-firmware analysis — DELIVERED (was the known limit):** the sandbox image now bundles
  **sasquatch** (vendor/LZMA squashfs, built from squashfs-tools/), **jefferson**/**ubi_reader**
  (JFFS2/UBIFS), p7zip, and **qemu-user** (all arches). `unpack_probe` uses sasquatch + recursive
  binwalk; `poc_probe` runs foreign-arch targets under `qemu-<arch>` (arch from the ELF header,
  `-0 argv0`), and `verify_poc` mounts the parent firmware's rootfs as the qemu sysroot (`-L`).
  **Verified end-to-end:** DVRF `DVRF_v03.bin` (Linksys E1550, MIPS) → 218 ELFs extracted; `verify_poc`
  on its real `/bin/busybox` (MIPS LE, uClibc, dynamically linked) ran under qemu-mipsel and returned
  verified:true. Dockerfile layers ordered after Ghidra so rebuilds keep the cached Ghidra layer.
- **Code-review pass (5 parallel agents: security/bugs/clutter/docs/tests):** sandbox hardening
  (`--cap-drop ALL`, `--security-opt no-new-privileges`, `--user`); fixed an r2 command-injection via
  unvalidated function names (decompile_probe); sha256 at ingest (archive/restore without recon);
  dedupe edge-cascade; misc leaks/idempotency; added `findings.is_verified` helper; new tests
  (secret-never-logged, loopback startup, unpack manifest, regression guards). Merged to `main` (PR #1).
- **Live-device + rehosting-engagement track (2026-05-31/06-01, autonomous) — DELIVERED + VR-vetted:**
  - **Gap #1 — disk-image rootfs extraction:** a full-OS disk image used to ingest with no FS, so the
    agent had zero pre-auth intel. `recon`/`unpack` now detect a partition table (`_looks_like_disk_image`:
    MBR/GPT) and extract the ext rootfs unprivileged via **The Sleuth Kit** (`mmls`+`tsk_recover`, binwalk
    fallback for squashfs-on-partition). (PR #20.) `tests/test_disk_image.py`.
  - **Gap #2 — live route/content discovery:** `surface_recon` only materialised a *supplied* spec, so a
    rehosted surface had no endpoints. Added the **`web_discover`** task/MCP tool — a bounded, same-host
    read-only crawl (`web_discover_probe.py`, `<a>`/`<form>` parse) that materialises `endpoint` nodes.
    (PR #21.) `tests/test_web_discover.py`.
  - **`verify_poc` web oracle hardened:** `body_contains` could match a `{{NONCE}}` *reflected* in a
    403 re-auth page (no command ran → forged `verified:true`). The probe now strips the request's own
    echoed payload (raw + URL/HTML-encoded) before matching and flags a 401/403 match. (PR #22.)
  - **Live-remote target (SSH/telnet), Tier 3:** a `remote` target for a box we don't have firmware for —
    `register_remote_target` + `remote_run`/`remote_list_files`/`remote_read_file` MCP tools run the SAME
    read-only tool kinds (paramiko SSH / telnetlib, fixed `TOOLS` allowlist, `shlex.quote` paths) as on a
    static/rehosted image. New `policy.TIER_LIVE_REMOTE` + `features.remote` gate pins exactly one
    operator-authorised host (`remote_scope`); creds come from env/`config.toml [remote]` only — **never
    stored/logged/returned**; every op audited to `EgressEvent`. Validated against a live sshd container.
    (PR #23.) `engine/remote.py`, `sandbox/probes/remote_probe.py`, `tests/test_remote.py`.
  - **FirmAE branch validated on REAL vendor firmware (DVRF, Linksys E1550 MIPS):** the FirmAE image now
    builds **sasquatch** (vendor/LZMA squashfs — extraction died without it); rehost timeout 600→900s
    (MIPS boot+network-inference ≈525s); FirmAE network inference is **vendor-brand-keyed** so `rehost`
    auto-infers the brand from firmware strings and a no-network error tells you to retry with
    `brand=<vendor>`. A VR agent (MCP only) rehosted DVRF via `rehost(fw, brand="linksys")` → boots
    mipsel → `192.168.1.1` → web up, then read the extracted rootfs and surfaced the planted MIPS
    pwnables. `select_rehoster` correctly routed the squashfs blob to FirmAE (vs qemu for IoTGoat's disk
    image) — both auto-selection branches now proven on real firmware. (PR #24.) `tests/test_rehost.py`.
  - **VR feedback backlog:** captured in [`docs/vr-feedback.md`](docs/vr-feedback.md) — auto-brand limit
    (boot-and-retry loop is ~9 min/boot, left manual), provisioning poc/remote/network together for a
    rehost engagement, starting non-auto-started device services, a computed-output cmdi oracle,
    non-HTTP live services, a credential-cracking seam.
- **Last verified:** `.venv/bin/python -m pytest -q` → **357 passed, 2 skipped** (the realkey test skips
  without a key; the MCP-SDK-absence test skips when the SDK is installed). With Docker + the sandbox
  image present the Docker-gated live tests RUN; SPA builds clean. Sandbox image (`WITH_GHIDRA=1`) includes
  Ghidra + qemu + firmware extractors and works end-to-end.
- **A green OFFLINE run (no Docker) validates NONE of the live egress/exec/rehost/remote paths** — the
  security-critical round-trips (live vulnrouter RCE/auth-bypass, web_discover, SSH remote ops, qemu/FirmAE
  rehost) are Docker-gated and SKIP without the sandbox image. `conftest.py`'s terminal-summary hook prints
  a LOUD count of those skips, and **`just test-ci` FAILS FAST when Docker/the image is absent** (the CI gate
  that refuses to "pass" while skipping the live paths; `allow_no_docker=1` to override).
- **UI quickstart (updated):** `just ui` once → `just sandbox-build` once →
  `hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo` → `hexgraph serve` → http://127.0.0.1:8765.
- **How to re-verify:** `just test`; or run the UI (see UI quickstart below).
- **v2 sequencing:** P0 seams/migrations → P1 typed graph → P2 context bundle/CAS → P3 task anchors →
  P4 React notebook UI → P5 finding/task management → P6 HITL/triage → P7 search/report/cross-target →
  P8 real-key vuln-target test. Thin future-proofing seams (entitlements, metering, executor, policy,
  principal, suggester) land in P0 with local defaults — **ask a seam, never branch on backend/tier/executor.**
- **UI quickstart:** `just sandbox-build` once → `hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo`
  → `hexgraph serve` → open http://127.0.0.1:8765 → click a target, pick task type + scenario, Run.
- **Open notes / gotchas:**
  - **Docker required** for recon/unpack/decompile/harness/demo; `jonsnow` is in the `docker` group.
    Build the sandbox image once with `just sandbox-build` (re-run only after a Dockerfile/toolchain
    change — probes are mounted from the install at runtime, so editing/adding a probe needs no rebuild).
  - Python 3.12.3 (spec asks 3.11+ — fine).
  - Schema changes: `db/models.py` uses `create_all` (no migrations) — delete `~/.hexgraph/hexgraph.db`
    (or use a fresh `HEXGRAPH_HOME`) after changing columns; tests use isolated temp homes.
  - Mock reads fixtures + schema directly from `context/` (single source of truth, no duplication).
  - Backends return raw text; parsing + retry/JSON-repair live in `llm/runner.py` so the path is
    identical for mock and real backends. Tasks call `run_findings`, never `complete`.
  - Pydantic `Finding` (extra='forbid') mirrors the schema; DB `Finding` row adds the envelope
    (id/project_id/target_id/task_id/status/created_at).
  - Ingest does NOT parse target bytes (only copies) — kind/format/arch/mitigations come from the
    sandboxed `recon` task. The LLM never sees raw bytes, only probe output.
  - Decompile/harness-compile are best-effort, env-gated (`HEXGRAPH_DISABLE_DECOMPILE` /
    `HEXGRAPH_DISABLE_SANDBOX_BUILD`, both set in tests) and gated on docker availability — never on backend.
  - UI is vanilla JS + vendored Cytoscape (offline). Anthropic SDK only needed for the real backend (`[byok]`).

## Status legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked

## M0 — Mock backend + contracts  *(schema-valid findings, no key, no network)* ✅
- [x] M0-T1 Scaffold (`pyproject.toml`, package skeleton, `PROGRESS.md`, CLAUDE.md resume rule, Makefile, .gitignore)
- [x] M0-T2 `models/finding.py` Pydantic Finding/Evidence/FollowupSuggestion (matches finding.schema.json)
- [x] M0-T3 `llm/base.py` LLMBackend protocol + LLMRequest/Response/Usage + exception hierarchy; `parsing.py`+`runner.py`
- [x] M0-T4 `llm/mock.py` Layer 1 fixture replay
- [x] M0-T5 Scenario resolution precedence (arg → env → stable hash(task_id)); reads `_manifest.yaml`
- [x] M0-T6 Layer 2 template fill (`{{key|default}}`) from `TaskContext.template_vars()`
- [x] M0-T7 Fault injection (error_* raise real exception types; malformed_then_valid retry path)
- [x] M0-T8 `tests/test_contract.py` every fixture validates vs finding.schema.json; pytest wired (27 pass)
- [x] M0-T9 Layer 3 record/replay cassette hook (`llm/cassette.py`, seam only)

## M1 — Skeleton  *(init/ingest lone ELF → project + one target)* ✅
- [x] M1-T1 `config.py` env + ~/.hexgraph/config.toml; never log/store ANTHROPIC_API_KEY
- [x] M1-T2 `db/models.py` + `session.py` SQLAlchemy project/target/edge/task/finding (UUIDs)
- [x] M1-T3 `engine/ingest.py` single-file ingest → project + root target
- [x] M1-T4 `cli.py` init / ingest / targets (run/findings/graph stubbed to their milestone)
- [x] M1-T5 `api/app.py` FastAPI loopback assertion + `hexgraph serve` (+ `api/loopback.py`)
- [x] M1-T6 `docker-compose.yml` + `Dockerfile` loopback UI service (build not yet smoke-tested)

## M2 — Recon loop  *(core loop demonstrable with ZERO model calls)* ✅
- [x] M2-T1 `docker/sandbox.Dockerfile` (file/binwalk/strings/pyelftools/lief; Ghidra opt-in build arg).
      **radare2 deferred to M3-T1** (not in bookworm-slim apt; install from upstream there).
- [x] M2-T2 `sandbox/runner.py` docker run --network none --read-only + mem/cpu/pids caps + tmpfs +
      timeout (docker kill); HOME/TMP→/scratch; probes baked in (dev-mount via HEXGRAPH_SANDBOX_DEV=1)
- [x] M2-T3 `tasks` recon via `engine/recon.py` + `sandbox/probes/recon_probe.py`; one recon finding/target
- [x] M2-T4 Firmware unpack (`engine/unpack.py` + `unpack_probe.py`): children + contains edges; links_against
- [x] M2-T5 `engine/worker.py` asyncio worker over task table; POST /api/tasks
- [x] M2-T6 `engine/graph.py` + GET /graph/{project}
- [x] M2-T7 UI: target tree / Cytoscape graph / findings + detail panel; dark theme.
      **Deviation:** vanilla JS (fetch) instead of HTMX — one vendored lib (Cytoscape) kept the UI fully
      offline; HTMX added no value over plain fetch here. Cytoscape vendored at web/static/vendor/.
- [x] M2-T8 `tests/fixtures/build.sh` (vuln_httpd, libupnp.so, synthetic_fw.bin built+committed);
      `just demo` runs ingest→recon→finding→graph offline, exit 0

## M3 — LLM tasks via the interface ✅
- [x] M3-T1 `sandbox/decompiler.py` Decompiler seam + R2Decompiler; `decompile_probe.py`; radare2 6.1.4 in image
- [x] M3-T2 static_analysis via `engine/llm_tasks.py` (backend-agnostic; mock critical_overflow/no_findings/malformed)
- [x] M3-T3 reverse_engineering (info annotation findings) via same path
- [x] M3-T4 `cli.py run` + `--type/--objective/--model/--backend/--function/--mock-scenario`; API POST /api/tasks
- [x] M3-T5 `llm/anthropic_api.py` (BYOK, exception mapping, cost) + `llm/claude_code.py` (CLI, graceful fail);
      shared `llm/prompting.py` embeds the schema; registry lazy-loads both
- [x] M3-T6 Cost: per-task `cost_estimate` + usage trace under log_path; project total in API + UI cost readout
- [x] M3-T7 Tests: static_analysis critical, no_findings, malformed-retry, error→failed, RE annotation,
      real-backend mapping (fake client), decompiler (sandboxed), cost
- NOTES: decompilation is best-effort, env-gated (`HEXGRAPH_DISABLE_DECOMPILE=1` in tests; gated on docker
  availability, never on backend identity). hash-fallback scenario pick excludes `error_*`.

## M4 — Spawn the next thing ✅
- [x] M4-T1 `engine/followups.py` spawn_followup + POST /api/findings/{id}/followups/{i}; UI buttons wire
      parent_finding_id + target_ref + params; shared `engine/refs.py` (resolve_target_ref, pick_sibling)
- [x] M4-T2 pattern_sweep: homes the finding ON the matched sibling + seed→sibling related_to edge
- [x] M4-T3 harness_generation: `compile_probe.py` + `engine/harness.py` actually compile the emitted
      source in the sandbox (gcc added to image); real build result replaces the mock's claim
- [x] M4-T4 `just demo` extended: static_analysis → spawn pattern_sweep follow-up → sibling finding +
      related_to + parent_finding_id. 66 tests pass.

## M5 — Polish ✅
- [x] M5-T1 Accept/dismiss finding status: POST /api/findings/{id}/status + UI Accept/Dismiss buttons
- [x] M5-T2 `engine/dedup.py` (signature = target+category+title+function+sink) + POST /api/projects/{id}/dedup
- [x] M5-T3 Export: `hexgraph findings <p> --export f.json`, GET /api/projects/{id}/export (graph+findings),
      graph export (`hexgraph graph --export`, from M2)
- [x] M5-T4 README finalized (markers flipped; CLI/UI/backends/roadmap accurate); `just demo` is the
      documented acceptance run (ends with the spawn chain)

## v2 execution — phases (detail in `docs/implementation-plan.md`)
- [x] P0 Foundations & seams: Alembic migrations (baseline `bbdb1d98bf54`) + `hexgraph db upgrade` (backup + legacy-adopt); seams `sandbox/executor.py` (get_executor), `policy.py`, `entitlements.py`, `metering.py`, `principal.py` with local defaults; reserved `HEXGRAPH_API_KEY`. 78 tests pass.
- [x] P1 Typed graph core: `node` table + content_hash identity (`engine/nodes.py`); polymorphic attributed `edge` (`engine/edges.py`, String type cols, no CHECK); findings attach via `about` edge; recon materializes bounded symbol/string nodes; decompile makes function nodes + `calls` edges; migration `0002_typed_graph`. 83 tests pass.
- [x] P2 Context Bundle + CAS: `engine/cas.py` content-addressed store; `engine/context.py` ContextBuilder (graph-walk + budget pack + drop tracking + deterministic `bundle_sha`); full trace (prompt/system/bundle/response/usage); `llm/cassette.py` response cassette keyed by bundle_sha (record/replay/auto); `engine/runs.py` analysis_run + diff_runs; CLI `prune`; migration `0003_context_runs`. 88 tests pass. (Staleness: deps recorded on bundle; UI surfacing deferred.)
- [x] P3 Task anchors (`anchor_kind`/`anchor_id`, migration `0004`) + edge-anchored context; `engine/capabilities.py` + `/api/capabilities`; `engine/suggester.py` FollowupSuggester+RuleBasedSuggester + `/api/findings/{id}/suggestions` (entitlement-gated); pattern_sweep edge carries `matched_from_finding_id`. 93 tests pass.
- [x] P4 Analyst-notebook UI (React+Vite+TS in `frontend/`, served at `/`): graph hub + visual grammar +
  progressive disclosure, Inspector (detail/triage/followups/suggestions), capability-filtered launchers,
  findings management (sort/filter/group/counts), cost badge. Verified via Playwright. `just ui` builds it.
  **Deferred:** SSE live activity (polls now), pre-flight context preview, non-finding node detail.
- [x] P5 Finding/task management: API (project tasks, task detail+trace, rerun, finding components, bulk-status);
  SPA Findings|Tasks tabs, TasksPanel/TaskDetail (provenance: bundle id + trace + produced findings + re-run),
  bulk triage, Inspector provenance (↗ task, ◉ components). 97 tests pass. (Tags/notes → P6 annotations; virtualization deferred.)
- [~] P6 HITL — **core done**: widened triage (String status; migration `0005`), HITL envelope
  (origin/dismissed_reason/supersedes/human_notes), `PATCH /api/findings/{id}` (agent_original stash),
  feedback-into-context (analyst_confirmed / do_not_report). **Remaining:** annotation table
  (rename/note/tag) + confirmed-rename rewrites tool output; hypothesis lifecycle; richer approval gates.
- [x] P7 (backend) Search (LIKE, coverage-honest) + report export (provenance-embedded MD) + cross-target
  same-code-as (`similar_to` via content_hash); run-compare backend from P2. 106 tests pass.
  Deferred: search/report UI + FTS5; P7-5 (CVE/dataflow/dedup-review).
- [x] P8 Real-key validation: `tests/fixtures/vuln_fw/` (cgi/cmd/creds planted bugs + expectations.json);
  `hexgraph/eval.py` scored harness; `just test-live` (key-gated, cassette-backed, tight budget); no-key CI
  proves bugs statically present + scoring logic. 102 pass / 1 skipped.

## UI backlog
- Visual review done (headless Chromium screenshots). Requirements captured in
  [`docs/ui-backlog.md`](docs/ui-backlog.md) — P1/P2/P3, to tackle with M5 polish (some overlap M4 + M3-T6).
  Top P1s: graph finding-label overlap, non-interactive graph nodes, cramped detail panel,
  missing target-detail view, no live task feedback, no cost display.

## Project-specific skills created (note here as added)
- **`ux-assessment`** (`.claude/skills/ux-assessment/SKILL.md`) — the two-role, agent-driven UX
  walkthrough. Role 1 (VR analyst) drives HexGraph via MCP/CLI through a deliberate ordered
  sequence (A0–A15) that populates every surface; Role 2 (a separate cold researcher agent) opens
  the UI with Playwright and walks `docs/dev/ux-contract.md` (the living behavior contract) entry by
  entry, scoring each interaction on the functional + qualitative dimensions, verifying backend
  effects, and flagging contract drift. Re-run on every major UI change / fix evaluation / release.
  Paired with the CLAUDE.md rule that any UI-behavior PR updates `docs/dev/ux-contract.md`.
- _(candidates: `regen-fixtures`, `run-task`, `add-mock-scenario`)_

## Session log (newest first)
- 2026-06-03: **feat: hard-delete a finding (distinct from dismiss)** (branch `build/delete-findings`).
  Findings could only be *dismissed* (the row persists, reversibly greyed). Added a true, irreversible
  HARD delete alongside it. `engine/removal.delete_finding(session, finding_id)` removes the Finding row
  and cleans up every polymorphic reference (FK enforcement is off): edges where the finding is src OR
  dst (`about`/`located_in`/hypothesis evidence/…), its `node_kind="finding"` annotations, and it nulls
  any task's dangling `parent_finding_id` (the task's own history stands). Idempotent — a missing finding
  is a safe no-op returning `found=False`. Wired up as `DELETE /api/findings/{id}` (distinct from the
  reversible `/status` dismiss path), an MCP **write** tool `delete_finding` (gated under
  `features.mcp.write` like the other write tools; dismiss stays via `update_finding(status='dismissed')`),
  and a frontend **Delete** action in the finding Inspector — set apart on its own row, right-aligned with
  a dashed danger border, behind a two-step inline "delete permanently?" confirm so it can't be a foot-gun
  next to the benign Dismiss. No schema change, no migration (removal logic only). Verified: 5 new tests in
  `tests/test_removal.py` (delete removes finding + an about edge + a located_in source-link + an
  annotation with NO dangling refs; follow-up task detached not deleted; nonexistent is a no-op; dismiss
  still works unchanged; API delete → 404 + idempotent) plus full `just test`; Playwright screenshots
  confirmed the Delete/confirm UX and an end-to-end UI delete dropped the graph finding count 10→9.
  **Review fix (PR #99):** `delete_finding` also missed `FuzzArtifact.finding_id` (a COLUMN ref, not an
  edge, so invisible to the edge/annotation cleanup) — a `fuzz_crash` finding is owned by its crash
  artifact, so after delete the artifact kept a dangling `finding_id` and wedged the triage inbox
  (`promote_artifact`/`verify_artifact` raised "linked finding not found"). Now NULLs `FuzzArtifact.finding_id`
  symmetric with the `Task.parent_finding_id` detach (artifact row + crash bytes survive), reports it as
  `artifacts_detached`, with a new test in `test_removal.py`. Confirmed Task + FuzzArtifact are the ONLY
  two column refs to a finding id (no other dangling type). Also fixed a `docs/mcp.md` nit: the
  removal tools (`delete_edge`/`archive_target`/`restore_target`/`archive_node`/`restore_node`) are
  **write** tools, were wrongly listed under read.
- 2026-06-03: **feat: deeper, staged showcase fuzz target so coverage visibly CLIMBS** (branch
  `build/deeper-fuzz`). The showcase's fuzz entrypoint was `parse_host_header`, which overflows a
  64-byte buffer on basically input #1, so a coverage-guided campaign crashed immediately and the
  coverage story stayed flat at ~0 — the opposite of what we want to demonstrate. Replaced it with
  `parse_request(data, len)` in the embedded `HTTPD_C` (appended AFTER `diagnostics`, so the
  `system()` sink + `strcpy` lines didn't move within the function bodies; only the new
  `#include <stdint.h>` shifted everything down by ONE line). It's a tiny length-prefixed command
  protocol whose single stack-buffer-overflow (`key[16]`, CWE-787) is gated behind FOUR discoverable
  stages: a magic prefix `"CMD"` → opcode `0x02` (SET) → flag byte `0xAA` → a klen that exceeds 16.
  Pure: every READ is bounds-checked (`len >= 6 + klen` before reading klen bytes), so only the WRITE
  on the deep path overflows; no `system()`/IO/side effects. The harness (`HARNESS_C`) now drives
  `parse_request`. `get_param`/`cgi_handler`/`diagnostics`/`target.c` are unchanged library code (still
  referenced by the static/PoC findings, the function graph nodes, and `target.c`'s coverage-map key);
  the #95 Makefile is unchanged (the new fn lives in httpd.c). **Line refs re-counted + fixed for the
  one-line shift:** PoC `link_finding_to_source` 27→28 (the `system()` sink), static finding 33→34 (the
  `strcpy`), and the synthesized triage ASan reports' `diagnostics`/`cgi_handler` frames likewise
  (28/34). **Proof the coverage now climbs in stages then crashes** (real clang-14 libFuzzer+ASan inside
  `hexgraph-fuzz:latest`, `clang -fsanitize=fuzzer,address` on the seeded sources): `cov:` rose
  3→4→5→6→7→8→9→10→11→12→13→14 over the run as libFuzzer satisfied each gate, THEN ASan reported a
  `stack-buffer-overflow` WRITE in `parse_request /src/httpd.c:61` (frame `key[16]`), crashing input
  `CMD\x02\xAA...` (magic+SET+flag+klen 0x2f). **Showcase-seed-only**; no schema/policy/migration.
  **NOTE: maintainer must `just showcase --reset` to pick up the new fuzz target** (existing projects
  keep the old one). Tests: `test_showcase_seed.py` green; full `just test` green except the known
  WSL2 qemu/AFL Docker e2e flake (`test_fuzz_phase5_e2e::…qemu_mode…`, passes in isolation; my diff
  touches no fuzz-probe code).
- 2026-06-03: **fix: from-source build UX** (branch `fix/build-ux`). Two related defects in the
  "build instrumented target from source" experience, fixed as ONE PR. **(1) A REAL build of the
  showcase source tree FAILED (a regression from PR #92).** PR #92 dropped `int main()` from the
  showcase's embedded `httpd.c` so the libFuzzer harness links cleanly, but the showcase Makefile's
  default `all: httpd` still tried to link the now-main-less library into a standalone program →
  `undefined reference to main`. (Only the offline MockBuilder hid this — it fabricates artifacts
  without compiling.) The Makefile also ignored the injected `$(CFLAGS)` (used a hardcoded
  `-O0`, so ASan/SanCov were never applied) and the `fuzz_target` rule linked no fuzzer driver.
  **Rewrote the `MAKEFILE` constant in `scripts/seed_showcase.py`:** default target is now
  `fuzz_target`, which compiles the harness + the library sources (httpd.c/upnp.c) + target.c with
  the injected `$(CC) $(CFLAGS)` plus `-fsanitize=fuzzer` — the driver supplies `main()` for BOTH
  engines (clang/libFuzzer and afl-clang-lto's libFuzzer-compat driver). Dropped the broken `httpd`
  rule. **Root infra fix uncovered while verifying:** `SandboxBuilder` computed the dedicated
  `hexgraph-build` image but `executor.run_probe` had no `image=` param, so EVERY build ran in the
  shared `hexgraph-sandbox` image — which has plain `clang` (so libFuzzer accidentally worked) but
  NO `afl-clang-lto`, so an AFL build could never find its compiler. Added an `image=` override to
  `run_probe` (both the local + remote executors, the Executor protocol) and wired `SandboxBuilder`
  to pass `self.image` for the compile + fetch runs. **Proven via the full `engine.builds.run_build`
  flow with the real SandboxBuilder against `hexgraph-build:latest`: BOTH libfuzzer AND afl now build
  status=succeeded, producing runnable instrumented binaries** (AFL one carries `__afl_area_ptr` /
  `__afl_manual_init`; libFuzzer one responds to `-help=1`). **(2) A FAILED build was a dead end in
  the UI** — only a tiny status badge + a `title` tooltip, no way to read the error/log. New
  `frontend/src/components/BuildDetailModal.tsx`: clicking any build row (now a `.buildrow` button
  with a hover affordance) opens a modal in the Build/Fuzz modal idiom — for a failure it leads with
  the recorded `error` + the full log fetched from `GET /api/builds/{id}/log` (CAS-backed; the
  `api.buildLog` method already existed); a success shows captured artifacts + the reproducibility
  triple + provenance. The failed row reads "view error & log →" in accent so it's clearly
  actionable. Verified live (Playwright, isolated home, mock/offline): both the failed-build and
  succeeded-build detail modals render legibly. **NOTE: the maintainer must `just showcase --reset`
  to pick up the new Makefile (existing projects keep the old one); the build-error UI works without
  re-seeding.** Tests: `test_showcase_seed.py` + the build/executor/sandbox suite green; `just test`
  green (offline, mock).
- 2026-06-03: **feat: setup wizard registers MCP + skill; fix: just --list truncation** (branch
  `build/setup-mcp`). Two setup-experience improvements in one PR. **(1)** The interactive `hexgraph
  setup` wizard now offers a final **coding-agent integration** step: register HexGraph's MCP server
  with Claude Code / Codex / gemini-cli (pick agent + scope — project vs user) and install the VR
  skill (pick destination: `~/.claude/skills`, a project `.claude/skills`, or a custom path). New
  `agent_setup.register_agent()` PERFORMS the registration by editing the agent's own config file
  directly — JSON merge into `mcpServers` (Claude `~/.claude.json` / project `.mcp.json`; gemini
  `~/.gemini/settings.json`) or a `[mcp_servers.hexgraph]` TOML table for Codex — fully idempotent
  (re-running is a no-op; refuses to clobber an unparseable/conflicting config). Both steps are
  local-only filesystem edits, no network and no secret (the MCP command carries no key). The step
  lives only on the interactive path, so the **non-interactive / CI baseline never prompts or installs
  anything** (`hexgraph setup --non-interactive` proven: applies the static-only baseline, exit 0, no
  agent configs touched). **(2)** Fixed `just --list` description truncation: `just` shows only the
  single comment line directly above a recipe, so multi-line blocks were leaking a sentence fragment
  into the menu (`setup`, `install`, `serve`, `up`, `app-build`, `demo`). Reordered each so the
  complete one-liner sits closest to the recipe; every menu description now reads as a full phrase.
  New `tests/test_setup_wizard.py` covers registration per agent/scope, idempotency, JSON/TOML
  preservation, the skill install, the wizard step driven with fakes, and the non-interactive guard.
  Docs updated (README setup, `docs/setup.md`, `docs/mcp.md`). `just test` green.
- 2026-06-03: **fix: fuzz campaign live metrics — edges_covered + mid-run progress** (branch
  `fix/fuzz-live-metrics`). Two related fuzz-campaign bugs, fixed as one PR. **(A) Campaigns
  reported "0 edges" forever despite millions of execs.** ROOT CAUSE: the libFuzzer probe
  (`fuzz_probe.py`) parsed only the exec count from `#NNN: cov: C ft: F` progress lines and
  discarded `cov:`/`ft:`, never writing `edges_covered` into status.json — so the reaper's
  `_update_stats` read None → 0. Added a pure, tested `parse_libfuzzer_progress()` (max `cov:`
  = edges, max `ft:` = features, both monotonic; last `#NNN:` / `DONE` / `number_of_executed_units`
  = execs) and now emit `edges_covered` (+ `features`) in the status. Also fixed the AFL path's
  `_afl_stats` to read `edges_found` (edges *covered*) and NOT fall back to `total_edges` (the
  whole bitmap size) — both engines now populate the same `edges_covered` field. **(B) No live
  progress mid-run — the card looked idle until completion.** ROOT CAUSE 1: libFuzzer ran in one
  blocking `subprocess.run(capture_output=True)` writing status.json only at the end. Switched to
  a non-blocking `Popen` (output → a log file) with a periodic (~2–5s) parse loop that streams a
  partial status.json (execs/edges/crash_count, NO DONE marker) — mirroring what the AFL probe
  already did. ROOT CAUSE 2: `GET /api/projects/{id}/campaigns` (the 4s list poll) never reaped, so
  rows were stale until the per-campaign SSE mounted; `api_list_campaigns` now reaps non-terminal
  campaigns on read (mirroring `api_get_campaign`). No frontend change (it already reads
  `stats.edges_covered`); no schema/policy/migration change (stats live in `stats_json`; sandbox
  hardening untouched). **Verified:** `just test` green (725 passed, 2 Docker-skipped); new unit
  tests for the libFuzzer progress parser (fork + single-process + empty) and the AFL fuzzer_stats
  parser, plus a reaper streaming test (partial status → live `running` + advancing stats, final
  DONE → finalize, crash not double-ingested). REAL libFuzzer run in the fuzz image against a
  coverage-reaching target: `edges_covered: 8`, `features: 8` (was always 0), and mid-run status
  showed execs climbing 1.09M→3.69M with edges>0 while still `running` (no DONE marker).
- 2026-06-03: **feat: curatable targets — Phase 1 (FS-hierarchical targets pane)** (branch
  `build/curatable-targets`). Two deliverables in one PR. **(A)** New design doc
  [`docs/design/design-curatable-targets.md`](docs/design/design-curatable-targets.md) — the
  4-phase plan for "curatable, filesystem-hierarchical targets & active-set graph visibility":
  Phase 1 the pane (this PR), Phase 2 cheap-vs-deep recon split + lazy materialization
  (deferred ONLY for auto-extracted firmware children; a durable migrated `target`
  materialization column; idempotent activate API/MCP/pane action + analyze-directory), Phase 3
  the unifying active-set visibility model (owned-by-active ∪ one-hop edge inheritance for
  shared nodes ∪ stubs-with-counts for cross-edges into inactive targets; consolidates
  archive/scope/layers/active-set into ONE documented model; drops reachability-BFS-as-hiding),
  Phase 4 activate-from-graph/-directory/-search polish. **(B)** Phase 1 itself, **frontend-only**:
  the firmware TARGETS pane now groups path-named children (`usr/sbin/telnetd`) into collapsible
  directory FOLDERS derived client-side by splitting names on "/" — pure UI grouping, no target
  rows, no backend/schema change. Folders show child counts + a rolled-up worst-severity finding
  badge; sort dirs-first-then-files alpha; small firmware (≤12 binaries) opens top-level folders,
  large opens collapsed (heuristic in an effect, idempotent via a ref). Leaf rows preserve ALL
  per-target behavior (select/scope/Run/Fuzz/Remove/badge); leaf shown by FS name, full path on
  hover. SURFACE children (web_app/service/remote) are excluded from folding so a coincidental
  slash like `upnpd control (tcp/5000)` stays a flat leaf. Non-firmware projects render exactly as
  before; #85 (resizable panels) and #88 (skeleton load) untouched. `Workspace.tsx` +
  `theme.css` (`.tree-row.dir`/chevron/count) + a `folder` icon. **Verified** (Playwright, mock,
  isolated `HEXGRAPH_HOME`, port 8772): the `seed_graph_tiers.py` REAL tier (251 targets / ~11.6k
  nodes) collapses from a 250-row scroll to 5 calm folder rows (`bin` 36 · `lib` 36 · `sbin` 36 ·
  `usr` 107 · `www` 35), `usr/` nests `usr/bin`/`usr/lib`/`usr/sbin`; showcase groups
  `sbin/httpd` + `lib/libupnp.so`. `just test` 719 passed / 2 skipped.
- 2026-06-03: **fix: graph-canvas UX round 2** (branch `build/graph-ux-round2`). Five hands-on
  graph-canvas issues the maintainer found after PR #89 — some were RESIDUALS where #89's fix
  didn't fully take, so each was re-verified LIVE (Playwright, isolated `HEXGRAPH_HOME`, mock,
  offline; the `seed_graph_tiers.py` LARGE tier + the showcase). Frontend-only (`GraphView.tsx`,
  `graphLayers.ts`). **(1) Scroll-zoom still sluggish** — `wheelSensitivity` 0.6→**1.4** (set at
  `cytoscape()` construction, the only place cytoscape reads it; confirmed 1.4 on the live `__cy`).
  **(2) Native context menu still leaked** — #89's preventDefault sat on the inner `#cy` div in the
  bubble phase; moved it to the OUTER `.graph-wrap` in the **capture phase** so every right-click
  (canvas layers, DOM overlays, node/edge, empty bg) is intercepted on the way down. Live: 4/4
  right-clicks `defaultPrevented=true`, only the app verb menu shows. **(3) Expand/collapse teleport**
  — the room toggle rebuilds the cy instance, which snapped the camera; now the camera GLIDES
  (`cy.animate fit`, ease-in-out-cubic) and freshly-revealed interior nodes FADE in on a short
  stagger; collapse symmetrically glides the re-fit. Live: 14 interior nodes animating mid-expand.
  **(4) No way to hide source files** — added `source_file` (+ `harness`, also missing) to
  `NODE_TYPE_LAYERS`; `source_file` is OFF by default (trusted high-volume scaffolding, like
  symbol/string) with the layer panel wiring it live; gave both a distinct color/shape (D8). Live:
  toggling reveals/hides the showcase's 3 source_file nodes. **(5) Room title black-on-black** — the
  collapsed-room base label was `#0a0c12` (black) centered on a mid-brightness card → unreadable; now
  light `#e8edf6` in a dark rounded text pill (the legible LOD-far/mid treatment), card keeps its
  per-type color fill + severity ring. `just ui` clean; `just test` 718 passed / 2 skipped / 1 failed
  (`test_desock_afl_fuzzes_local_server_no_network` — a Docker+AFL fuzzing e2e that degraded to
  no-crash in this env; unrelated to the frontend diff). Left for the orchestrator's reviewer + merge.
- 2026-06-02: **fix: Run menu advertises kind-valid tasks for SURFACE targets** (branch
  `fix/surface-run-menu`). Companion to PR #84's backend routing: the Run menu was server-driven via the
  capability table, but `web_app`/`service`/`remote` SURFACE kinds had **no entry in `_TARGET`**, so they
  fell through the frontend `caps.target?.[kind] ?? ["recon"]` fallback and offered **byte 'recon'** —
  wrong for a surface with no bytes (the worker then routed it to `surface_recon` for `web_app` or a clear
  `NotImplementedError` for `service`/`remote`). Fix, two layers: (1) `engine/capabilities.py` gains a
  SEPARATE `_SURFACE_BASE` map (web_app→`surface_recon`; service/remote→`[]` — no offline single-shot task
  is wired, the honest minimal set, never byte recon) + `_surface_caps()` which folds in the live
  `web_recon`/`web_discover` only when `features.network` is on (mirrors the worker's egress gating);
  `capabilities_for("target", …)` and `capability_table()` route surface kinds through it. Byte targets
  unchanged. (2) Frontend: `Workspace.tsx` replaces the two `?? ["recon"]` fallbacks with a `targetCaps()`
  helper that trusts the server set verbatim (incl. an empty list) and falls back to byte `recon` ONLY for
  a kind the table doesn't know AND that isn't a surface; `taskMeta.ts` adds copy for
  `surface_recon`/`web_recon`/`web_discover`. Tests: `tests/test_p3_anchors.py` +2 (a web_app advertises
  `surface_recon` and NOT byte recon / harness-gen / static-analysis; service & remote are empty;
  `web_recon`/`web_discover` appear only under `features.network`). `just test` green (719 passed / 2
  Docker-gated skips); SPA rebuilt clean (`just ui`). Left to the orchestrator's reviewer + merge.
- 2026-06-02: **build: Run/fuzz UX on the target card** (branch `build/run-fuzz-ux`). Three changes,
  frontend + a small backend tweak. (1) **Expressive Run menu** — `frontend/src/taskMeta.ts` (new) gives
  every task type a label + one-line summary + a richer hover explanation; `Launcher.tsx` rewritten to
  render rows with icon/title/summary and a side popover on hover (`.task-menu`/`.task-pop` in
  `theme.css`). Task SET stays server-driven (the capability table), so a target only sees kind-valid
  tasks. (2) **Fuzz entry points reconciled** — the legacy single-shot `fuzzing` task is filtered out of
  the Run menu; a guided **"Fuzz campaign…"** row opens the detached-campaign modal instead (wired via a
  new optional `onFuzz` on `Launcher`, passed from `Workspace.tsx` TreeRow + `NodeInspector.tsx`). The
  single-shot path now lives only on a harness finding's "Fuzz this harness" button. (3) **Human errors**
  — `api.ts` helpers parse the FastAPI `detail` body (was a bare `400 /api/…`); `api/routers/campaigns.py`
  returns a friendly, target-named 400 for the "nothing to fuzz" case before a half-created campaign row.
  Test `tests/test_campaigns_phase4.py::test_api_campaign_nothing_to_fuzz_is_clear_400`. `just ui` + `just
  test` green (708 passed / 3 Docker-skipped); Playwright-verified the menu, hover popover, the reconciled
  Fuzz path, and the clean modal error. No model/DB change → no migration. Reviewed + merged via PR #86.
- 2026-06-02: **build: resizable + collapsible workspace panels** (branch `build/resizable-panels`).
  Frontend-only (plus docs). `Workspace.tsx` 3-pane layout is now user-adjustable so the center graph
  can claim room. (1) **Drag-to-resize** both vertical dividers (left↔center, center↔right) via a
  hand-rolled pointer-drag splitter in a new `frontend/src/hooks/useWorkspaceLayout.ts` — **no new
  deps** — with min/max clamps (left 180–480px, right 280–680px) and a global col-resize cursor +
  selection-lock during drag. (2) **Collapse/restore** each SIDE pane to a thin clickable edge (header
  chevron collapses; double-clicking a divider also collapses that side; the edge restores) so the
  graph goes near full-width. (3) **DETAIL-section drag** — a row-resize handle on the right pane's
  `DETAIL` divider trades space between the findings/tasks/campaigns list and the detail pane (clamped
  18–85%). (4) **Persisted** to `localStorage` (`hexgraph.ws.layout.v1`) — widths + collapsed flags +
  detail fraction survive reload, no DB/settings migration; corrupt/absent storage falls back to the
  prior defaults (268 / 392 / 0.46). `.workspace` became flex (skeleton loader keeps the even
  3-column look via `.skel-grid`). Rebased onto #88 (skeleton-first load) — both preserved: the
  skeleton-first `load()`/`expandRoom` lives inside the now-resizable center pane. **Playwright-verified**
  (`scripts/ws_layout_shot.py`): left drag 268→388, right drag grows center, detail drag works, both
  collapsed grows the graph, and sizes + collapsed state persist across a reload. `just ui` tsc-clean;
  `just test`: 707 passed, 2 skipped, 1 failed (the known Docker qemu-mode fuzz flake `test_fuzz_phase5_e2e`,
  unrelated to this frontend change). UI-backlog entry added. Reviewed + merged via PR #85.
- 2026-06-02: **build: graph at REAL firmware scale — skeleton-first loading** (branch
  `build/graph-scale`; `docs/design/design-graph-presentation.md` §1/§8-Phase-3 + the §8 scoped-graph
  endpoint note, D1). The Phase 1–5 redesign was validated against a ~500-node synthetic tier — ~25× too
  small; a real IoTGoat firmware (~12.9k nodes) still rendered as a smudge because the client fetched +
  rendered EVERY node at once. **Fix (two parts): (1) backend skeleton-first endpoints** (`engine/graph.py`
  `graph_size`/`build_skeleton`/`build_room` + `/graph/{id}/{size,skeleton,room/{tid}}`, no migration —
  read-only serialization): `/skeleton` serves rooms-only (per-room + **subtree** rollups, shared sockets,
  **aggregated cross-room meta-edges**) — a 38k-element graph → 275 nodes + 875 edges; `/room/{tid}` serves
  one room's interior on demand. **(2) client skeleton-first** (`Workspace.tsx` probes `/size`, loads the
  skeleton above a 1500-element threshold, lazily merges a room's interior on expand; `GraphView.tsx`
  skeleton mode). A firmware with >40 children opens as a **single card** (`250 bins · 90⚠`, critical ring)
  + the socket bus — expand to drill in. **SMALL/MEDIUM/LARGE under-threshold paths unchanged.** Fixed a
  latent compound-mode bug (a `target` rendered as both a room box AND a loose anchor dot — fatal at scale).
  New REAL tier in `scripts/seed_graph_tiers.py` (~11.6k nodes) + `tests/test_graph_skeleton.py`. **Real-
  scale Playwright A/B: BEFORE = a smudge of thousands of dots; AFTER = one calm, countable firmware card,
  25 nodes rendered, expand-to-load interiors clean. `just test` green, tsc clean.** Reviewed + merged
  via PR #88 (independent reviewer re-ran the offline suite + the real-scale human A/B + below-threshold
  unchanged check).
- 2026-06-02: **fix: byte recon never runs on a path-less surface target** (branch `fix/recon-surface`,
  PR #84). A generic `recon` task on a `web_app`/`service`/`remote` SURFACE target (no bytes, `path=""`)
  resolved the empty path to the cwd and crashed with a baffling `artifact not found: <repo root>`. Two
  layers: (1) `engine/worker.py` `_dispatch` routes a `recon` task whose target is a `SURFACE_KIND`
  (new `db/models.py` `SURFACE_KINDS` frozenset, a zero-migration Python constant) — or any path-less
  target — to `_dispatch_surface_recon`, which sends a `web_app` to the offline deterministic
  `run_surface_recon` and fails a `service`/`remote` with a clear, actionable `NotImplementedError`
  naming the kind + the right tool. (2) Defense-in-depth: `sandbox/runner.py` (`run_probe` +
  `start_detached`) refuses an empty/whitespace artifact with a clear "no byte artifact — Channel-reached
  surface" `SandboxError` BEFORE `Path("").resolve()` → cwd — backstopping the `pipeline.run_recon` path
  that bypasses `_dispatch`. Byte recon on a real file target is unchanged. Tests: `tests/test_surfaces.py`
  +3 (web_app→surface recon, socket surface→clean error, runner refuses empty artifact). Known separate
  caveat: LLM tasks on a surface still go through the decompiler over `target.path` (Run-menu kind-valid
  offering is PR #86); this PR doesn't worsen that and the runner guard broadly protects the byte-sandbox
  crash class. Reviewed offline (583 passed / 2 skipped on the offline suite; relevant modules 58 passed);
  Docker-gated subset left to the sibling fuzz/graph-scale agents' runs.
- 2026-06-03: **fix: showcase fuzz target links cleanly + finds a real crash** (branch
  `fix/fuzz-showcase-link`). A REAL (Docker) fuzz campaign on the showcase's instrumented
  `sbin/httpd` died at link time — `multiple definition of main`/`cgi_handler`/`diagnostics` —
  and AFL showed "degraded · 0 executions". Two seed-data bugs in `scripts/seed_showcase.py`'s
  embedded C tree: (1) `HTTPD_C` defined its own `int main()`, colliding with libFuzzer/AFL's
  driver `main`; (2) `target.c` was a verbatim COPY of `HTTPD_C`, and `builds.py`
  `_instrumented_target_sources` globs every code-role `.c` into `fuzz_target_sources`, so
  `httpd.c` + `target.c` both compiled → duplicate `cgi_handler`/`diagnostics`/`get_param`.
  Latent third issue: the harness drove `cgi_handler`, which `system("ping … %s")` per input —
  a process spawn per exec, useless for a campaign. **Fix (seed data only):** dropped `main`
  from `HTTPD_C` and added a pure, side-effect-free `parse_host_header()` with a planted
  unbounded copy into `field[64]` (CWE-787) as the libFuzzer/AFL entrypoint; rewrote `HARNESS_C`
  to drive it; replaced the `target.c` write with a NEW distinct `TARGET_C` (unique symbol
  `log_request_line`, no `main`, links cleanly) — `target.c` must still EXIST because the mock
  coverage map + `capture_screenshots.py` key on it. `cgi_handler`/`system()` stay in the binary
  (static/PoC findings + graph nodes reference them) but are simply uncalled by the harness.
  Fixed now-stale `httpd.c:37` source refs (old `main` line) → `:33` (the `diagnostics` strcpy);
  PoC link stays at `:27` (the `system()` sink). **Verified:** `test_showcase_seed.py` green;
  `cc -fsanitize=address fuzz_cgi.c httpd.c upnp.c target.c stubmain.c` links with NO duplicate
  symbols (clang unavailable on host → cc + a stub `main` standing in for FuzzerMain) and running
  it trips an ASan `stack-buffer-overflow` in `parse_host_header` via `LLVMFuzzerTestOneInput` —
  proving the real campaign now both links AND finds a crash fast. Full suite green (717 passed)
  except the desock-AFL real-fuzz e2e, which flakes ONLY under self-induced concurrent-Docker
  contention (passes clean in isolation here and on main; unrelated — it uses its own fixture).
  **Existing showcase projects keep the broken tree until `just showcase --reset` re-seeds.**
- 2026-06-02: **build: make `just showcase` genuinely RUNNABLE** (branch `build/showcase-runnable`).
  The showcase project stays a "show off every feature" swiss-army knife for the UI/screenshots, but
  the common **Run actions now WORK against it** instead of dead-ending on seeded rows:
  • **Fuzz** — the instrumented rebuild is no longer a hand-stamped row with empty `fuzz_target_sources`
    and no harness (which made "Start a fuzz campaign" 400 *"no fuzz harness available"*). It's now built
    by the REAL build flow (`engine.builds.run_build` via the offline **MockBuilder**, $0, no Docker):
    `_register_derived_target` wires `instrumented_build_of`→httpd + `builds` from the build_spec, sets
    real on-disk `fuzz_target_sources`, and **promotes the harness** (`harnesses`→ derived target). A
    live UI "Start campaign" now resolves harness + 3 real sources, infers `source_lib`, and **launches**
    (engine afl). • **Recon/static** — the firmware children + standalone `acmecfgd` are ingested from
    REAL fixture bytes (verified: a real `recon` task on `acmecfgd` runs in the sandbox, status succeeded,
    refines arch x64). Fixed honesty quirks: byte targets are labelled `x86_64` (the fixtures' real arch,
    so recon confirms not contradicts); `acmecfgd` now uses real *executable* bytes (was a `.so` mislabeled
    executable). The rich breadth (wide edge variety, all 4 assurance rungs, socket bus, multi-bucket crash
    inbox, dynamic surfaces) stays curated/seeded. **Degrades gracefully** — no Docker → the visual project
    still seeds (MockBuilder is offline; recon/fuzz just aren't *triggered* by the seed). Guard test
    `tests/test_showcase_seed.py` updated: requires `features.build`, the new `builds`/`harnesses` edges,
    and a RUNNABILITY block (real build_id + a resolvable harness + on-disk sources + `source_lib` surface).
    `just showcase`/`just capture` (13 PNGs regenerated) + `just demo` green; full suite 707 passed
    (the one Docker qemu-mode fuzz e2e flaked only under self-induced concurrent-pytest Docker contention —
    passes clean in isolation here and on main). Only `scripts/seed_showcase.py` + the guard test changed.
- 2026-06-02: **build: graph presentation Phase 4 — layout-by-context + semantic zoom** (branch
  `build/graph-phase4`; `docs/design/design-graph-presentation.md` §8 Phase 4, §3.2/§3.3/§3.4/D7/D8).
  Frontend-only; builds on the Phase-3 rooms and **fixes the Phase-3 caveat — room labels were only
  readable when zoomed in.** `GraphView.tsx`: (1) **★ semantic-zoom LOD** — a debounced `cy.on('zoom')`
  stamps `lod-far|mid|near`; FAR+MID render a **readable below-card room label** (inverse-of-zoom font,
  min-font cutoff dropped) while suppressing interior + edge labels, NEAR returns full detail — so the
  default full-pane LARGE/PATHOLOGICAL frame opens **labeled + legible** with no zoom-in. (2) **letterbox
  fix** — fcose `tile`+`packComponents`+higher separation spreads islands, first-open fits all visible
  elements, a utilization backstop re-runs if <50% (measured util LARGE 0.71 / PATH 0.79, in the 55–80%
  target). (3) **layout by context (D7)** — fcose skeleton, **scoped dagre LR inside an expanded leaf
  room** (call flow), **concentric for hub focus** (the Phase-2 focus now uses cytoscape `concentric`,
  positions saved/restored). (4) **dead-dep cleanup** — **removed** `cytoscape-expand-collapse`
  (registered-but-unused; our collapse is React-state-driven). **Bundle DROPS: gzip 361.7 → 353.65 kB
  (−8 kB).** **Color-coding untouched (D8)** — no color-map edits. `just test`: 703 passed, 1 failed
  (the known Docker qemu-mode fuzz flake — `test_fuzz_phase5_e2e`, unrelated to this frontend change),
  2 skipped. Human-eyes A/B (§9) in `docs/ui-backlog.md`: **PATHOLOGICAL/LARGE default now PASS** — rooms
  fill the canvas with readable labels at the resting frame; zoom sweep reveals/hides detail smoothly;
  interior dagre reads as call flow; hub concentric pops; SMALL/MEDIUM + None unregressed. Phase 5
  (Map/Table/Matrix + layer panel + filter rail) remains.
- 2026-06-02: **build: graph presentation Phase 3 — compound islands + grouping + expand/collapse**
  (branch `build/graph-phase3`; `docs/design/design-graph-presentation.md` §8 Phase 3, §1/§2.1/§3/
  D1/D6/D7/D8). The **headline structural fix** — the flat node plane becomes collapsible per-target
  "rooms" so even the default resting view of a huge target is parseable. **Two new deps**
  (`cytoscape-fcose` + `cytoscape-expand-collapse`; `cxtmenu` skipped — the Phase-2 verb menu suffices,
  now extended with room expand/collapse). **Bundle: gzip 315.9 → 361.7 kB (+45.8 kB).
  Color-coding untouched (D8).** `GraphView.tsx` rewrite (composes on Phase 1 sizing/edge-recede/labels
  + Phase 2 focus/hide/breadcrumb): targets render as **compound parent rooms** (firmware = grandparent
  containing child-target rooms); **skeleton-collapsed default at LARGE/PATHOLOGICAL** (rooms visible
  as finding-weighted cards w/ a severity-rollup ring, interiors hidden) with **SMALL/MEDIUM
  auto-expand** below the node ceiling; a **Group-by control** (target/type/finding/**none** — None =
  the flat Phase-1/2 graph, the regression fallback); **collapse-all/expand-all**; **aggregated
  cross-room meta-edges** (one `×N` ribbon, semantic visible / structural faint); a **socket bus lane**
  (shared sockets loose around the islands); double-tap/right-click room expand auto-frames the
  interior (scoped fcose); **focus/search auto-expands the path** into a collapsed room (Phase-2
  reviewer note). `just test` green (mock/offline; Docker fuzz flakes excepted). Human-eyes A/B (§9) in
  `docs/ui-backlog.md`: **PATHOLOGICAL default is the decisive PASS** — ~494n/2144e opens as a firmware
  box of ~18 countable, labeled, severity-ringed room cards + a socket bus, the structural cobweb
  receded to faint hairlines (vs the baseline smudge); can count binaries + spot the critical-finding
  rooms at a glance; drill-in clean + reversible; None reproduces Phase 2; SMALL/MEDIUM unregressed.
  Deferred to Phase 4: semantic-zoom LOD + layout-by-context fine-tuning; the socket "bus" is grouped
  not geometrically banded.
- 2026-06-02: **build: graph presentation Phase 2 — focus / hide / navigation** (branch
  `build/graph-phase2`; `docs/design-graph-presentation.md` §8 Phase 2, §4/§5/§9). Frontend-only,
  live-instance class toggles + camera over the existing flat dagre graph — **zero new deps, no
  rebuild, color-coding untouched (D8)**. The fix for the "drowned highlight" at LARGE/PATHOLOGICAL.
  `GraphView.tsx` + `Workspace.tsx` + `theme.css`: a real **focus model** replaces `.lit`-only —
  `.focus` on the anchor + N-hop neighborhood (1–3), `.context` on the rest (mute ~16% opacity +
  `background-blacken` + drop labels + `events:no`, **hue preserved at low alpha**); a **live concentric
  re-arrange** of just the focus set around the anchor (positions saved/restored on clear — resting
  layout untouched) so the **scoped `animate({fit})`** lands on a readable local diagram instead of a
  full-graph fit; **hover preview** (transient `.hl`/`.hl-dim`, no commit); a **focus stack + breadcrumb**
  (`Overview › crumb`, URL-serialized `?focus=&hop=` → shareable/restorable, crumb pops + reframes);
  **search drives focus** (`focusOn` not select); a dependency-free **right-click verb menu** (focus /
  expand-hop / reveal / hide) + a **reversible hide chip** ("N hidden · restore ↺"). Auto-frame fires
  only on explicit focus (double-tap/search/verb/URL), never hover/plain-select (D5). NB: dagre is
  synchronous so the layout is now run explicitly *after* wiring `layoutstop` (the constructor fired it
  before a listener could attach). `just test` 702 passed / 2 skipped. Human-eyes A/B (Playwright, §9)
  in `docs/ui-backlog.md`: **PATHOLOGICAL focus is the decisive PASS** — the amber-ringed anchor +
  concentric ring of labeled neighbors pops out of a faint muted backdrop (vs the baseline static);
  LARGE focus, breadcrumb reversibility, auto-frame (no flake), hide+restore all verified; defaults
  unregressed. Resting LARGE/PATH default frame still letterboxed (layout-by-context is Phase 3/4).
- 2026-06-02: **docs: release-readiness legal files** (branch `docs/disclaimer-notices`). Added two new
  standalone files: `DISCLAIMER.md` (boilerplate authorized-use / dual-use disclaimer for an offensive
  security tool — authorized use only, user is responsible for legal compliance, AS-IS / no liability)
  and `THIRD_PARTY_NOTICES.md` (attribution for bundled/invoked third-party tools — radare2, AFL++,
  LLVM/clang+libFuzzer, boofuzz, preeny, Ghidra, FirmAE, QEMU, binwalk, sasquatch, Sleuth Kit,
  jefferson/ubi_reader, paramiko + the key host Python / SPA deps, sourced from the Dockerfiles +
  pyproject.toml + frontend/package.json), with an aggregation note (tools run as separate processes /
  in containers → consistent with HexGraph's own AGPL-3.0). License stays AGPL-3.0; README untouched
  (owned by a concurrent sibling PR). Docs-only — no test impact.
- 2026-06-02: **build: Docker reorg + app image + docker-compose** (branch `build/docker-reorg`).
  Consolidated all Dockerfiles under `docker/`: moved `Dockerfile.{sandbox,build,fuzz}` → `docker/{sandbox,build,fuzz}.Dockerfile`
  (build context stays the repo root, COPY paths unchanged), keeping `docker/firmae/` + `docker/qemu/` as-is.
  Updated **every** reference (`justfile` build recipes, `setup_catalog.py` build commands, `setup_wizard.py`
  repo-root detection → `docker/sandbox.Dockerfile`, `CLAUDE.md` paths/worktree notes/where-things-live,
  `docs/design-fuzzing-and-source.md`, `pyproject.toml` + `fuzz_probe.py` comments, PROGRESS history tokens).
  **New `docker/app.Dockerfile`** — the full app (multi-stage: Node builds the SPA, Python installs the package
  editable so the migration runner's `repo_root()` resolves `/opt/hexgraph/migrations`; includes the docker CLI
  for Docker-out-of-Docker). Entrypoint runs `hexgraph db upgrade --no-backup` then `hexgraph serve`. **New
  `docker-compose.yml`** (one `app` service): publishes **host loopback only** `127.0.0.1:8765:8765`, mounts the
  host Docker socket so the app spawns its sandbox/build/fuzz siblings on the host daemon (DooD; documented as an
  intentional single-user-local trade-off, not hardened/multi-tenant), persists a named `hexgraph-data` volume at
  `/data`, BYOK key passthrough (never baked in), optional `config.toml` RO mount. **Loopback guard:** added a
  recognized container mode to `api/loopback.py` — `HEXGRAPH_IN_CONTAINER=1` lets `assert_loopback` accept the
  `0.0.0.0` bind Docker's published-port forwarding needs, **without** widening the anti-DNS-rebinding Host-header
  allowlist (the host-loopback guarantee is preserved at the publish boundary); an un-flagged non-loopback bind
  still raises. Tests added (`test_loopback.py`). New `just` recipes `app-build`/`up`/`down`; `.dockerignore` added.
  README gained a "Run with Docker" section (compose path + socket-mount security note + DISCLAIMER.md reference).
  **Verified:** `docker compose config` valid; the app image builds; smoke-run migrated the DB to head, bound
  0.0.0.0 in-container, and `/health` + `/` returned 200 over the loopback-published port. `just test` green.
- 2026-06-02: **build: graph presentation Phase 1 — visual legibility** (branch `build/graph-phase1`;
  `docs/design-graph-presentation.md` §8 Phase 1). Frontend-only, **zero new deps, color-coding
  untouched (D8)**. `GraphView.tsx` + `theme.css`: structural edges recede (opacity ~0.18, arrowheads
  dropped at rest) so the gray cobweb stops dominating and semantic edges (~0.32) separate out;
  importance-driven node sizing (anchors 40px + monochrome type glyph + always-label · hubs degree-ramp
  30→40px · detail 22px · findings sized up for critical/high) gives the eye an entry point; extended
  `NODE_SHAPE` so every conceptual type is shape-distinct (redundant channel); label discipline via
  `text-opacity: mapData(zoom/degree)` + `min-zoomed-font-size` (no more label-collision soup); legend
  gains shape swatches + hover-preview / click-isolate-by-type (lightweight dim, hue preserved at low
  alpha — mute not de-color; un-pin clears the hover preview so click-to-clear works while hovering).
  **Tier fixture (reusable A/B for every phase):** `scripts/seed_graph_tiers.py` (`just graph-tiers`)
  seeds 4 deterministic mock/offline projects (SMALL ~13n/26e · MEDIUM showcase ~27/58 · LARGE
  ~173/649 · PATHOLOGICAL ~494/2144); guard `tests/test_graph_tiers_seed.py`. Before/after human-eyes
  verdict per tier in `docs/ui-backlog.md`: every tier improves — LARGE is markedly calmer (cobweb
  pushed back, size hierarchy + entry point), PATHOLOGICAL visibly less of a smudge (full fix awaits
  the compound-islands + layout phases), SMALL/MEDIUM unregressed → better.
- 2026-06-02: **docs: README + per-feature docs overhaul, single-folder screenshots** (branch
  `docs/readme-overhaul`). Docs/tooling only (no behavior change beyond the two showcase scripts).
  Slimmed `README.md` from ~680 lines to a lean overview — one-paragraph what-it-is + the graph hero
  shot, `just setup`→`just serve` install, a feature **matrix** (one line each, linking out), the core
  target→task→finding→graph→spawn loop + the mock/$0 default + the opt-in policy tiers in a sentence,
  and a tight security/how-it-works/dev section. Moved the reference detail into focused **per-feature
  docs** under `docs/` — `setup.md`, `graph-ui.md`, `verification-assurance.md`, `fuzzing.md`,
  `build-from-source.md`, `dynamic-surfaces-rehosting-remote.md`, `mcp.md` — each embedding its
  screenshot from `docs/images/` by stable name and linking (not duplicating) the existing `design-*`
  docs. **Single canonical screenshot folder is now `docs/images/`:** retired `docs/ui-shots/` (folded
  its one still-useful shot — the network fuzz modal — into `scripts/capture_screenshots.py` as
  `fuzz-modal-network.png`; deleted the rest + the folder). **Fixed the sparse hero-3
  (`artifacts-triage.png`):** the showcase seed now writes a populated multi-bucket crash inbox (4
  distinct dedup buckets, varied kind/function/exploitability + dupe counts, ASan reports that
  symbolize to source frames + realistic 1.89M-exec / 318-edge campaign stats) onto the SAME single
  campaign before reaping, so the triage detail pane reads dense + inviting. Guard
  (`test_showcase_seed.py`) updated to require ≥3 crash buckets + dupe counts; re-ran `just showcase`
  + `just capture` (13 PNGs) and judged the heroes by eye. `just test` green (700 passed, 2 Docker
  skips). ui-backlog + this log updated.
- 2026-06-02: **build: modernize `just demo` to the current headline loop** (branch `build/demo-modernize`).
  Replaced the MVP-era `demo.py` (ingest→recon→static_analysis→pattern_sweep, hard 2/2/3 counts, stale
  SPEC §10/M4 docstring) with a narrated, asserting, $0/offline arc that exercises the current product:
  **(1)** ingest firmware → recon → unpack into child targets + `contains` edges (the real-sandbox stage,
  base image only); **(2)** author a source tree (C lib + libFuzzer harness) and **build-from-source WITH
  INSTRUMENTATION** via the offline **MockBuilder** (`builds.run_build`, `HEXGRAPH_BUILDER=mock`) → an
  instrumented derived target wired **`instrumented_build_of`** → the shipped httpd, with a reproducible
  badge (recipe_sha + source content_hash + toolchain_digest); **(3)** a **coverage-guided fuzz campaign**
  on the instrumented target via the offline **MockFuzzer** (`campaigns.start_campaign`/`reap_campaign`,
  `HEXGRAPH_FUZZER=mock`) → a `fuzz_crash` finding with dedup/exploitability/coverage + a minimized
  reproducer (`fuzzed_by`/`produced_artifact` edges); **(4)** a **`poc` task** that executes a standalone
  ELF in the sandbox with an unforgeable `{{NONCE}}` oracle → a **verified PoC + assurance triple**, printing
  the {standard, method, precondition} ladder (lands `code_present/dynamic`); **(5)** **spawn** the PoC's
  suggested follow-up (the target→task→finding→graph→spawn loop); **(6)** build the graph + print the
  node/edge-type variety. Each step asserts its outcome (replacing the brittle hard counts); needs only the
  base sandbox image + mock seams (no fuzz/build Docker images, no key, no network). Distinct from
  `just showcase` (which SEEDS rows; demo RUNS the pipeline). justfile demo doc-comment + `test_demo.py`
  docstring refreshed. No migration (no model change), frozen finding schema untouched. `just demo` exits 0
  with the new narrated arc (5 targets · 117 nodes · 118 edges · 7 findings).
  **PR-review fix:** the demo was leaking `HEXGRAPH_BUILDER/_FUZZER=mock` into the process env (`main()` set
  them unconditionally, restored only `HEXGRAPH_HOME`), which steered 16 later full-suite tests onto the mock
  seam (the "pre-existing failures" were actually this regression). Now `main()` snapshots + restores the
  mutated env keys in a `finally` (body in `_run()`); `test_demo` asserts no leak. Full offline suite: 1
  remaining failure (`test_fuzz_phase6::test_full_campaign_via_local_daemon_as_remote`) is pre-existing —
  passes standalone, flaky only under full-suite Docker contention (the `remote-fuzz-e2e` sibling's domain).
- 2026-06-02: **build: reproducible screenshot showcase + captures** (branch `build/showcase`).
  A deterministic, $0/offline **showcase** project for the README hero shots + per-feature doc
  captures. `scripts/seed_showcase.py` (`just showcase [--reset]`) seeds ONE rich engagement on
  the mock backend (no Docker): a firmware tree (firmware_image + unpacked-FS children sbin/httpd +
  lib/libupnp.so) + a standalone binary + a `web_app` admin surface + a `service` (tcp/5000) socket
  surface + a source tree (C lib + fuzz harness); 7 findings spanning finding_type + ALL FOUR
  assurance rungs (a **verified PoC** input_reachable/dynamic with a repro spec, a code_present/static
  floor, an input_reachable/static argued path, a fuzz_crash code_present/dynamic); a **wide curated
  edge variety** (contains/calls/routes_to/listens_on/connects_to/built_from/located_in/
  instrumented_build_of/links_against/taints/about/fuzzed_by/produced_artifact); typed function/
  string/sink/socket/endpoint/param nodes; a **finished mock fuzz campaign** (run via the offline
  MockFuzzer → crash artifact + minimized reproducer + dedup + a per-line coverage map); + egress-audit
  events (allowed + 1 denied). `scripts/capture_screenshots.py` (`just capture`) serves it on a spare
  port and shoots 12 PNGs into `docs/images/` (1440×900, dark, 1.5× — Playwright, dev-only) — manifest
  in `docs/images/README.md` mapping each → its README/doc slot. Guard test `tests/test_showcase_seed.py`
  (offline) asserts the seed stays rich. Counts at seed: 7 targets · 27 nodes · 58 edges · 7 findings ·
  1 campaign. README.md untouched (owned by the separate README-overhaul effort — this produces the
  images + manifest it consumes).
- 2026-06-02: **build: launch-and-join for LOCAL-service network fuzzing** (branch `build/loopback-fuzz`,
  design §5.6 / new §5.8b — Decision 1 / Option B). A fuzz container runs `--network bridge`, whose
  loopback is the container's OWN — so a boofuzz campaign could not reach a service on the host's bare
  `127.0.0.1` (only the rehost `net_container` netns-join could reach a private service). **Fix:** for a
  service HexGraph can LAUNCH itself (a `service`/binary target carrying a server ELF, no externally-
  reachable host), HexGraph now (a) starts the service in its OWN detached, hardened sandbox container
  (`sandbox/probes/service_launch_probe.py` — same `--read-only`/`--cap-drop ALL`/`--no-new-privileges`/
  `--user`/resource caps; `--network none`; foreign-arch under qemu-user + the parent firmware rootfs
  sysroot) listening on that container's loopback, then (b) launches the fuzzer with
  `net_container=<service-container>` so the SHARED netns makes `127.0.0.1:port` reachable **WITHOUT
  `--network host`** — same isolation, no host networking. Generalizes the rehost netns-join from "an
  emulator container" to "a service container HexGraph launched." **Gating — NO new gate, nothing relaxed
  outside `policy.py`:** the service launch EXECUTES the target → the EXISTING exec tier
  (`features.poc`/`fuzzing`, asserted in `_launch_network`/`_launch_service` + the runner's
  `requires_execution=True`); the fuzz egress stays `features.network` + `local_tcp_scope` + audited to
  `EgressEvent` (refuses any non-loopback/private host). The **reaper / stop / serve-restart tear down BOTH
  containers** (the service container name is recorded on `fuzz_campaign.config_json["service_container"]`).
  Trigger: a campaign/spec `launch` flag (auto-detected for a launchable target with a loopback/unset host;
  a reachable PRIVATE host is honoured directly, no launch). New `FuzzCampaignSpec`/`PreparedFuzz`/API
  (`CampaignNet`)/MCP (`start_fuzz_campaign`) `launch`/`launch_binary`/`launch_command` fields — all carried
  through resume. **Documented the already-running-host-service workaround** (README + agent_setup SKILL +
  design §5.8b): bind it to a reachable private IP (`192.168`/`10.x`); `--network host` is deliberately not
  offered. No migration (rides `config_json` + the String surface/engine columns); frozen schema untouched.
  Tests: `tests/test_fuzz_loopback.py` (11 offline — launchable-local classification, prepare carries the
  launch fields, auto-enable vs. honour-reachable-private, the two-container launch wiring + the exec/egress
  gate mapping, non-local refusal, reaper + stop teardown of BOTH, spec round-trip, + a startup-grace probe
  test). **PR-review fix (#68):** launch-and-join started the service then immediately the fuzzer, and the
  boofuzz probe did a single `_alive()` check — a slow-binding service was spuriously "not reachable at
  start" (0 execs). Added a bounded startup grace (`_wait_alive`; 15s for a just-launched service vs. 2s
  for an already-up host) + a foreground-only caveat in the service probe docstring. `just test` green
  offline (695 passed, 2 skipped; the 1 remaining failure is the pre-existing remote `DOCKER_HOST` phase6
  test — environmental, out of scope, fails identically on pristine main).
- 2026-06-02: **fix+test: make the Phase-6 remote-fuzz e2e self-provisioning** (branch
  `build/remote-fuzz-e2e`). Validated the `RemoteDockerExecutor` plumbing (design §5.8b) end-to-end by
  simulating a remote Docker host locally, and made `tests/test_fuzz_phase6.py::test_full_campaign_via_local_daemon_as_remote`
  actually runnable. **Bug fixed:** the test set `HEXGRAPH_FUZZ_REMOTE_LOCALASREMOTE_DOCKER_HOST` but the
  env id was the SLUG of `"local-as-remote"` = `local-as-remote`, whose secret-connection env key is
  `..._LOCAL_AS_REMOTE_...` (dashes→underscores in `config.fuzz_remote_connection`) — so the connection
  never resolved and the test raised `FuzzEnvError` (never green). **Self-provisioning:** a new
  session-scoped `dind_remote` conftest fixture stands up a **genuinely separate** Docker daemon
  (docker-in-docker on a loopback TCP port — its own image store, so bind-mounts truly can't cross,
  the highest-fidelity proof the CAS named-VOLUME stage-in + `docker cp` stream-back path is exercised),
  loads the fuzz image into it, yields the `tcp://127.0.0.1:<port>` DOCKER_HOST, and tears down; gated on
  Docker + the fuzz image (skips cleanly otherwise). The e2e now runs green locally (~94s) with NO
  hand-configured DOCKER_HOST. **Validated all 7 plumbing points** against the separate dind daemon:
  (1) connection+health-check; (2) CAS stage-in to a REMOTE named volume (present on dind, absent on host);
  (3) detached fuzz container runs ON the remote (verified via remote `docker ps`); (4) `/out` streamed
  back via `docker cp` + crashes ingested into the LOCAL graph as `fuzz_artifact`s, reproducer re-verified;
  (5) reaper re-attach by label from a fresh executor (post-`serve`-restart); (6) secret never in the
  sqlite DB / scrubbed from errors / presence-only + control plane loopback; (7) `features.fuzz_remote`
  fail-closed when off + every remote launch audited to `EgressEvent(tool="fuzz_remote")` (no secret in
  the audit). The `RemoteDockerExecutor`/`fuzz_env`/`policy` code needed **no changes** — only the test's
  env-var name was wrong (a typo, NOT a runtime defect: a real dashed env name like `my-remote-box`
  resolves its secret on both the env-var and config.toml paths — `slug()` and
  `config.fuzz_remote_connection` agree). Offline suite green (645 passed); the lone Docker-gated failure
  (`test_desock_afl_fuzzes_local_server_no_network`) is pre-existing on `main` (desock/preeny env-dependent
  on this WSL2 kernel), unrelated. **PR #70 review fixes:** (a) the `dind_remote` teardown now
  `docker rm -f -v` so the anonymous `/var/lib/docker` volume (the dind daemon's whole image store, GBs)
  is reaped instead of leaking every run; (b) added `test_dashed_env_name_resolves_connection` — the e2e
  uses a single-word env name, so nothing otherwise exercised the slug↔key dash→underscore normalization
  (regression guard, no runtime change).
- 2026-06-02: **build: interactive `hexgraph setup` wizard** (branch `build/setup-wizard`).
  `just setup` now bootstraps (venv + deps + SPA) then launches a polished, sequential TUI wizard
  (**Rich** panels/tables/progress + **questionary** checkboxes/selects/confirms; added to `[server]`
  + `[dev]` extras and a `[setup]` extra). New `src/hexgraph/setup_catalog.py` is the canonical
  feature/gate REGISTRY — one entry per optional `features.*` toggle with label, what-it-unlocks, the
  **security implication** (accurate to `policy.py` — which gate/tier it relaxes, in the user's words),
  `policy_changing`, the `policy.TIER_*` it raises, and the required build step(s). `setup_wizard.py`:
  detects state (settings.json present? which Docker images built?), presents features pre-checked to
  current state, shows a **red security-implication panel + explicit confirm for each newly-enabled
  policy-relaxing feature**, collects non-secret config (loopback-default bind with a hard
  refuse-unless-`HEXGRAPH_I_KNOW_WHAT_IM_DOING` for non-loopback; backend; Ghidra mode), a
  review-and-confirm screen, then applies settings **via the settings layer only** and runs the chosen
  builds with progress. **Secrets are never prompted-or-stored** (presence-only; pointed to
  env/config.toml) — double-guarded by an `_is_secret_path` assertion in `build_plan`/`apply_settings`.
  **CI-safe:** no TTY / `--non-interactive` / `--yes` / `--defaults` (or `just setup yes=1`) applies the
  static-only baseline + sandbox image WITHOUT prompting. The apply layer (`build_plan`/`apply_settings`/
  `default_plan`) is pure/headless so it's fully unit-tested (`tests/test_setup_wizard.py`, 26 tests:
  registry covers every toggle, each policy-changing feature has a non-understated implication,
  apply writes the right settings + NEVER a secret, loopback refusal, build-step mapping, the
  non-interactive path). No migration (settings.json is not the DB); frozen Finding schema untouched.
  Docs: README setup section, CLAUDE.md `just setup` description + module map.
- 2026-06-02: **build: modernize the Build-from-source modal to match the Fuzz modal** (branch
  `build/ui-buildmodal`). Frontend-only visual/layout pass, ZERO backend/behavior change — brings
  `BuildModal.tsx` up to PR #62's Fuzz-modal standard so the two launch dialogs are siblings.
  Reuses the `.modal.fuzz` system (`h3` header + boxed `.lede` + grouped `.grp` cards + scrollable
  `.modal-b` + pinned footer) and adds `.build`-scoped CSS in `theme.css`: the sanitizers/SanCov
  become a tidy **toggle-pill row** (`.toggles/.tgl`, friendly name + raw flag sub-label, lights up
  when on); **Engine & arch** as an aligned grid; **Dependencies** (vendored/fetch posture);
  **Artifacts to capture** (+ optional custom phases); and the **Recorded recipe preview** as a
  proper read-only **code panel** (`.recipe`, dark mono, tinted env keys/values, `$`-prefixed
  commands, fetch phase in amber, `recipe_sha` caption under a dashed rule) — reusing the source-
  viewer code-styling language. Prominent **Build (sandboxed)** primary button. Playwright-verified
  ALL inputs + the recipe-preview reactivity intact (UBSan→`,undefined` in CFLAGS; deps→fetch shows
  the fetch phase; custom phase → `$ sh -c …`; recipe_sha recomputes). `tsc -b` clean; the
  pre-existing fuzz/Docker e2e `just test` failures on `main` are unrelated. Before/after PNGs +
  notes in `docs/ui-backlog.md`.
- 2026-06-02: **build: UI "sexiness" pass — source viewer + toolbar + fuzz modal** (branch
  `build/ui-sexiness`). Frontend-only visual/layout pass, ZERO backend/behavior change. (1) The
  **Source viewer** (`SourceBrowser.tsx` + new `highlight.ts`) replaces the per-line-boxed,
  uncolored `<pre>` with a clean continuous code block: **highlight.js core** (8 grammars
  registered → ~30 KB raw bundle add) line-split so block comments/strings carry across rows,
  themed to the dark palette; a dimmed right-aligned tabular line-number gutter; faithful
  indentation (`white-space: pre` + `tab-size`) with horizontal scroll. Coverage shading
  (covered/uncovered) + the finding→source jump highlight ride as per-row CSS classes UNDER the
  syntax color, so all three coexist — Playwright-verified shading still lights up and the jump
  still lands+highlights. (2) The **center-pane toolbar** (`Workspace.tsx`) is grouped with
  dividers (view-toggle · search · create · analyze · report/export), wraps cleanly 1280–1600px.
  (3) The **Fuzz modal** (`FuzzModal.tsx`) is redesigned into a lede + grouped cards (Target&engine ·
  Network · Inputs · Stop conditions · Resources) with a scrollable body + pinned footer; every
  input kept functional (target picker, network host/port/proto_spec on a web_app surface, seeds/
  dict, unconstrained toggle). All CSS in `theme.css` (`.codeview`/`.toolbar .tgroup`/`.modal.fuzz`).
  `tsc -b` clean; the 3 `just test` failures are PRE-EXISTING fuzz/Docker e2e failures on `main`
  (verified), unrelated to frontend. Before/after PNGs in `docs/ui-shots/`, notes in `docs/ui-backlog.md`.
- 2026-06-02: **fix: battle-test remediation PR-3 — build→fuzz handoff + coverage/symbolization** (branch
  `fix/battletest-buildfuzz`). Four fixes from the libfuzzer/afl engagements (`FEEDBACK.md` PR-3 block).
  **C [BUG-HIGH] the build→fuzz happy path silently no-op'd:** after `build_target`, the derived
  instrumented target's `fuzz_target_sources` was hard-coded `[]` and no harness was promoted, so
  `start_fuzz_campaign` inferred `binary_only/qemu` on a relocatable `.o` and ran 0 execs. Now
  `builds._register_derived_target` populates `metadata_json.fuzz_target_sources` with the
  instrumented TARGET sources (the tree's code-role `.c`/`.cc`, harness/poc/script EXCLUDED — host
  paths `resolve_target_sources` reads) AND promotes any `role=harness` tree file to a
  `source_file(role=harness)` + a `harnesses`→ edge to the derived target (`_promote_build_harness`).
  So a later `start_fuzz_campaign(derived_id)` infers `source_lib` and runs coverage-guided with no
  manual wiring. Exposed on the existing serializer (`fuzz_target_sources` was already in
  `metadata_json`). **L [BUG] coverage compile couldn't handle a self-including header:** sources were
  mounted flat at `/src/target_N.c` with no `-I`. New `fuzzers/shared.target_source_mounts` mounts each
  source's CONTAINING dir (preserving layout, so a sibling header sits next to its `.c`) + offers each
  dir as `-I`; `fuzz_probe.py`/`afl_probe.py` consume `--include-dir`. **H [BUG] coverage shading +
  source-mapped stacks rendered empty:** (a) the libFuzzer probe now collects a per-line llvm-cov map
  (`_collect_coverage` → `coverage.json` {percent, files:{rel:{covered,uncovered,total}}}) so
  `coverage_for` returns `available:true` and the Source viewer shades lines; (b) ASan crash replays
  now force symbolization (`symbolizer_env` → `ASAN_SYMBOLIZER_PATH`/llvm-symbolizer, present in
  `hexgraph-fuzz`) and the probe carries the symbolized `_report`, so the reaper's `parse_source_frames`
  yields `func file:line` frames + auto-links finding→source; the binary-only AFL qemu "abort in ?"
  is gdb/addr2line-symbolized to the real sink (`afl_qemu_probe._gdb_backtrace`). Also fixed the
  fork-mode execs parse (`#NNN: cov:` lines) + an exec floor so a real run isn't mis-finalized
  `degraded`, and made libFuzzer `-minimize_crash` VERIFY the minimized input still crashes (a
  non-reproducing "minimized" reproducer no longer gets stored — fixes one-click re-verify flakiness).
  **verify_fuzz_artifact [GAP]:** added a first-class `verify_fuzz_artifact` MCP tool (+ catalog entry;
  `minimize_artifact` kept as a back-compat alias) that replays a crash reproducer BYTE-FAITHFULLY;
  `poc_probe.py` gained a `stdin_b64` raw-bytes path and `poc.verify_reproducer` now uses it (was
  `stdin` latin-1 → UTF-8-re-encoded by the subprocess, corrupting a binary reproducer). **No DB
  migration** (`fuzz_target_sources` rides existing `metadata_json`; coverage/frames ride
  `coverage.json`/`evidence.extra`; frozen finding schema untouched). Tests:
  `tests/test_buildfuzz_handoff.py` — an OFFLINE mock regression guard (build populates
  fuzz_target_sources + promotes harness → infer source_lib → mock campaign finds the crash), unit
  tests for `target_source_mounts` (include-dir layout) + the `verify_fuzz_artifact` tool + byte-faithful
  replay, and a Docker-gated libFuzzer e2e (build → coverage-guided campaign → real execs + coverage_for
  available + planted crash + byte-faithful re-verify; skips-with-reason on the host's known libFuzzer
  `-fork` forkserver instability). README/SKILL(`agent_setup.py`)/MCP-catalog/ui-backlog updated;
  Playwright-verified the coverage shading (green/amber lines) + the `#0 line_1 target.c:1` frame→source
  jump render. `just test` green (only the pre-existing environmental `test_fuzz_phase6` local-daemon-as-
  remote fails, identical to baseline `main`).
- 2026-06-02: **fix: battle-test remediation PR-2 — assurance correctness + agent visibility** (branch
  `fix/battletest-assurance`). Four fixes from the poc-tier engagement (`FEEDBACK.md` PR-2 block).
  **B [BUG] the verify-WRITE path overwrote assurance UNCONDITIONALLY** (a failed/misrouted re-verify
  DEMOTED a real `code_present/dynamic` → `unconfirmed`): both the MCP `verify_poc(finding_id=…)` write
  and the REST `api_verify_finding` now MERGE via the partial order through a new pure
  `assurance.merge_assurance(current, candidate)` (the canonical core `upgrade_if_stronger` also uses) —
  a weaker/failed re-verify NEVER lowers an already-stronger stored rung; a genuine same/higher
  re-confirmation still updates. **B-cont [BUG] re-verify resolved the WRONG target** (`finding.target_id`,
  so a PoC against a child/live surface mis-ran): the MCP write now records the PoC's own
  `evidence.extra.poc_target_id`, and REST re-verify resolves THAT (falling back to `finding.target_id`
  when absent/stale). **E [BUG] the assurance triple was invisible** without a per-finding `get_finding`:
  `list_findings` rows and the `verify_poc` tool return now carry the compact `{standard, method,
  precondition}` triple (new `assurance.compact_assurance`). **K [BUG] `import_source_tree` silently wrote
  0 files on a wrong key** (`path` vs `rel`): now accepts `path` as an alias AND errors clearly on a
  keyless/non-object entry instead of a silent 0-file "success". **No DB migration** (assurance rides
  `evidence.extra`; the frozen finding schema is untouched). Tests: `tests/test_battletest_assurance.py`
  (no-downgrade on both MCP+REST paths, PoC-target resolution + fallback, list/verify assurance output,
  import validation) + `merge_assurance`/`compact_assurance` units in `test_assurance.py`. VR skill
  (`agent_setup.py`) updated: assurance now in list_findings + verify_poc output; re-verify resolves the
  PoC's own target and never downgrades. `just test` green.
- 2026-06-02: **fix: battle-test remediation PR-1 — fuzz UX + dev-ex + campaign status** (branch
  `fix/battletest-fuzzux`). Six fixes from the four VR battle-test engagements (`FEEDBACK.md` PR-1
  block). **A [BUG-HIGH] stale SPA on `just serve`:** `serve` now depends on a new `ui-check` recipe
  that rebuilds the SPA only if `dist` is missing or stale vs `frontend/` mtimes (no full rebuild
  when current) — the new UI is no longer invisible by default. **F [BUG] silent degraded campaigns:**
  a campaign that did 0 work (unreachable / 0 execs) or hit engine instability (`engine_note`) now
  finalizes in a distinct **`degraded`** status (not a clean `completed`) via `_finalize_status`;
  `campaign_to_dict` exposes `warning` + `engine_note`; the Campaigns/Artifacts UI renders an amber
  degraded badge + warning banner. SSE/poll terminal sets include `degraded`. **G [UX] Fuzz modal:**
  surface-aware network inputs (host/port/protocol/proto_spec), seeds + dictionary textareas, a target
  picker; **D [BUG] MCP `start_fuzz_campaign` schema** now declares host/port/protocol/proto_spec +
  seeds/dictionary/max_len (fn signature + catalog schema); REST `CampaignCreate` gained `dictionary`.
  **N [UX]** Campaigns "New campaign" defaults to the best fuzz target, not `roots[0]`; **M [UX]**
  new `GET /api/projects/{id}/egress` + an `EgressPanel` (Audit toolbar button) audit-log viewer.
  Build modal gained custom-phase authoring for a `custom` source tree. **No DB migration** (status
  is a plain String; engine_note/reason ride stats_json). Tests: degraded-status (engine + API),
  egress endpoint, MCP schema. `just test` green (626 passed; the 2 pre-existing fuzz-remote/AFL e2e
  failures need a configured remote DOCKER_HOST + are identical on baseline `main`). Playwright-verified
  (campaigns degraded badges, network Fuzz modal, egress audit view). README + VR skill + ui-backlog updated.
- 2026-06-02: **fix: AFL++ source-fuzz forkserver in the hardened sandbox** (branch
  `fix/afl-forkserver`). The Phase-3 AFL++ **source** path (`-fsanitize=fuzzer` aflpp_driver under
  `afl-fuzz`, hardened box) aborted with `Fork server crashed with signal 11` while every other
  fuzzer worked. **Root cause:** AFL++ maps its coverage bitmap in `/dev/shm`, but docker gives a
  `--read-only` container only a fixed **64 MiB** `/dev/shm` — too small, so the forkserver child
  segfaults before the handshake. **Fix (minimal, security-preserving):** `runner.py
  _hardening_args` now mounts a sized `--tmpfs /dev/shm:rw,noexec,nosuid,nodev,mode=1777,size=<tmpfs>`
  (ResourceSpec-governed). NOT a relaxation — the container already had a writable `/dev/shm`; we
  resize it and ADD `noexec,nosuid,nodev` (data-only, stricter than default). `--read-only`/
  `--cap-drop ALL`/`--no-new-privileges`/`--user`/`--network none` untouched; libFuzzer/qemu/desock/
  boofuzz unaffected (verified). `afl_probe.py` also got a generous `-t` + `AFL_FORKSRV_INIT_TMOUT`
  (timing budgets, not security flags) so a slow first instrumented exec doesn't trip the 1 s dry-run
  calibration. **Residual host-kernel caveat (honest fallback):** on some kernels (WSL2 6.6.x) AFL++
  PERSISTENT mode is itself unstable independent of the sandbox (reproduces with zero hardening) — the
  probe now reports a loud `afl_note` (→ `campaign.stats_json.engine_note`) instead of a silent
  zero-crash "success", and the Docker-gated source e2e (`tests/test_campaign_e2e.py`) proves the full
  crash→dedup→verify chain on a capable host and **skips with that reason** when the kernel can't
  calibrate (no false green, no hard flake). Docs: `docs/design-fuzzing-and-source.md` §7 + README
  hostile-target-isolation note. `just test` green (609); `just demo` exits 0. No migration (no model
  change), no `docker/fuzz.Dockerfile` change (probes mounted at runtime).
- 2026-06-02: **fix: AFL++ source-fuzz on high-ASLR-entropy kernels** (branch `fix/afl-aslr`).
  After the `/dev/shm` fix, the AFL++ source path STILL failed on WSL2 6.6.x with two intertwined
  symptoms — intermittent `Fork server crashed with signal 11` (0 execs, ~30%) AND a 100% `test case
  results in a timeout → All test cases time out, giving up` dry-run abort — so `test_campaign_e2e`
  came back `degraded`, not a clean pass. **Two root causes, both host-agnostic, neither a WSL/sandbox
  bug:** (1) the harness+target are built with **ASan**, and on `vm.mmap_rnd_bits=32` kernels (WSL2
  6.6.x / Ubuntu 23.10+ / GitHub CI runners) ASan's `mmap(MAP_FIXED)` shadow reservation intermittently
  **collides with a randomized mapping and SIGSEGVs during ASan init**, before AFL's forkserver
  handshake (confirmed: instrumented binary direct-run SIGSEGVs ~4/15 with ASLR on, **0/30 with ASLR
  off**; refs WSL#40168, runner-images#9515, sanitizers#1614, llbit ASLR/ASan post); clang 14 in the
  image lacks the clang-≥17 auto-re-exec mitigation. (2) The path linked AFL++'s **libFuzzer-compat
  PERSISTENT driver** (`-fsanitize=fuzzer` + `__AFL_LOOP` + SHM testcase), whose first dry-run exec
  **wedges** on this kernel even WITHOUT ASan (`afl-showmap` classic-forkserver on the same binary
  works 8/8). **Fix (minimal, hardening-intact):** (a) run the target with ASLR off via **`setarch -R`**
  (`personality(ADDR_NO_RANDOMIZE)`) — Docker's default seccomp filters out exactly that one
  `personality` arg, so the ASan source-fuzz container (and ONLY it) is launched with a **minimal custom
  seccomp = Docker's default + one rule allowing `personality(0x40000)`**
  (`src/hexgraph/sandbox/seccomp/fuzz-aslr.json`, wired `PreparedFuzz.disable_aslr` → `runner.
  _hardening_args`; the narrowest possible relaxation — reduces only the target's own ASLR, not a
  sandbox-escape primitive; `--network none`/`--read-only`/`--cap-drop ALL`/`--no-new-privileges`/
  `--user` all untouched, every other fuzzer keeps the default profile); (b) **switch to a CLASSIC AFL
  forkserver harness** — compile the `LLVMFuzzerTestOneInput` harness with a one-shot `main()` shim +
  `-fsanitize=address -fsanitize-coverage=trace-pc-guard`, feed input via `@@`, no persistent SHM loop
  (CmpLog left opt-in: its `-c` aux forkserver under ASan is flaky here — 0 crashes with it, crashes
  without); (c) `disable_coredump=1` + `RLIMIT_CORE=0` so a crashing child can't wedge on WSL2's piped
  `core_pattern`. The probe's `_AFL_FAIL_SIGNATURES`/`engine_note` are **re-scoped** — they no longer
  blame "host kernel" for the now-fixed cases, and the e2e **no longer skips on an `engine_note`** (a
  0-exec outcome now FAILS as a regression). Proven **10/10 consecutive** green on WSL2 6.6.x
  (~80–120k execs / 45 s, real coverage). Docs: `docs/design-fuzzing-and-source.md` (Phase-5 caveat
  RESOLVED + new section). `just test` green; other fuzzers regression-checked. No migration (no model
  change), no `docker/fuzz.Dockerfile` change (probes mounted at runtime; the seccomp profile is in-package).
- 2026-06-02: **Fuzzing+source Phase 7 — supply-chain + cross-compile + editable IDE (EPIC COMPLETE)**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 7, branch
  `build/fuzz-phase7`). The FINAL feature phase — closes Phases 0–7. **Bounded audited dependency
  fetch** (`features.build_fetch`, fail-closed, its OWN gate `assert_allows_build_fetch`, never
  `features.network`): a SEPARATE `build_fetch_probe.py` run, network ON but bounded to a registry
  ALLOWLIST (`build_fetch_scope`, egress-guard backstop), produces a hash-pinned **lockfile + SBOM-lite**,
  then HexGraph DROPS NETWORK and compiles `--network none` — **fetch-then-offline** (compile is a
  different container; a fetched dep can be recorded but never run during compile/exfiltrate). A
  **reproducibility BADGE** + **cache-key artifact reuse** (true byte-content hash via
  `tree_content_sha`) + `SOURCE_DATE_EPOCH`/ccache. **Cross-compile** (`WITH_CROSS=1`,
  `instrumentation_env` injects clang `--target`/firmware-rootfs `--sysroot`, degrade→native→qemu-mode;
  real MIPS object proven). **OSS-Fuzz `build.sh` import** (`engine/oss_fuzz.py`). **Editable IDE**
  (`features.source.edit`, `engine/revisions.py`, migration **0016** `source_revision` + build columns):
  revisioned saves (CAS + diff, never in-place) + rebuild-from-revision; CONFINED — refuses
  extracted/vendor/imported trees. **Coverage diff** (`campaigns.coverage_diff`). New MCP
  `import_oss_fuzz`/`save_source_revision`/`coverage_diff`; `build_target` gained network/fetch/arch/
  source_revision_id. UI: Build modal arch + dependency posture + reproducible/cross preview, Source-tab
  Edit/Save + revision history + reproducible/cached/locked badges, Settings fetch + editable-IDE
  toggles. Frozen schema untouched; policy edited ONLY for `assert_allows_build_fetch`. Tests:
  `test_fuzz_phase7.py` (28 offline) + Docker-gated `test_fuzz_phase7_e2e.py` (compile-no-network,
  allowlist-block + audit, real MIPS cross-build). `just test` green (607 offline); `just demo` exits 0;
  migration 0016 round-trips + fresh init_db + no drift; Playwright-verified.
- 2026-06-02: **Fuzzing+source Phase 6 — remote fuzz environments**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 6, branch
  `build/fuzz-phase6`). A campaign can run on a **user-owned remote Docker host** behind the Executor
  seam with NO fuzzer/builder change. **`RemoteDockerExecutor`** (`sandbox/remote_executor.py`)
  targets `DOCKER_HOST` (ssh:// or tcp://+TLS), REUSES `_hardening_args` (SAME boundary on the
  remote), and — since bind-mounts can't cross a remote daemon — **CAS-stages inputs into a per-run
  named volume + streams `/out` back** via `docker cp` (stateless re-attach via container labels →
  crash-safe). A **fuzz environment** is a new table (**migration 0015**, applies clean on 0014 +
  round-trips + no drift): NON-SECRET metadata only (slug id/label/transport/descriptor + a
  `ResourceSpec` ceiling + cached health). A campaign selects one (`local` default) via
  `engine.fuzz_env.get_campaign_executor`. **Secret** connection details (DOCKER_HOST/key/certs) come
  from env (`HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST`)/`config.toml [fuzz_remote.<id>]` — never DB/
  logged, presence-only. **Gate** `features.fuzz_remote` → `assert_allows_fuzz_remote` (fail-closed,
  orthogonal peer flag, the only place); remote launches **audited** to `EgressEvent`; control plane
  stays loopback. Health-check (reachable/authorized/image-present) via Settings/API/MCP. API
  `/api/fuzz/environments` (+ `/health`); MCP `list_fuzz_environments`/`fuzz_environment_health` +
  `start_fuzz_campaign(environment=)`; UI Settings card + Fuzz-modal selector. Tests
  `tests/test_fuzz_phase6.py` (27 offline + 2 Docker-gated incl. the REAL executor against the LOCAL
  daemon-as-remote + a secret-leak grep of the sqlite file). `just test` green (577 offline); `just
  demo` exits 0. README/SKILL/MCP/PROGRESS/design-doc/ui-backlog updated.
- 2026-06-02: **Fuzzing+source Phase 4 — the Source/IDE tab full UX + Campaigns/Artifacts triage**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 4, branch
  `build/fuzz-phase4`). The user-facing payoff of Phases 1–3 — mostly frontend + thin API/serializer
  fills, **no migration**, no `policy.py` edit, frozen Finding schema untouched. **Campaigns tab**
  (live status via SSE `/api/campaigns/{id}/events` with **polling fallback**; Stop/Resume) +
  **Artifacts/triage view** (crashes grouped by dedup bucket, **assurance chips** [the two-standards
  ladder], exploitability rating, **source-mapped stacks** → IDE jump; per-crash **Reproduce/
  Minimize/Promote/Promote→PoC**, LLM-free re-verify). The reaper now parses ASan frames →
  `evidence.extra.fuzz.frames` + **auto-links the top in-project frame** to its source tree. **Coverage
  shading** in the Source viewer (`coverage_for` serializer + CAS snapshot via `coverage_ref`).
  **Surface-aware Fuzz modal** (`GET /api/fuzz/engines` — server-advertised engines, UI never
  hardcodes; per-campaign `ResourceSpec`). A single **`reveal()`** router + **deep-links** make every
  entity addressable/restorable. Settings: a Source & Build card + the default ResourceSpec; the
  capability table advertises `features.{fuzzing,poc,build}`. New: `AssuranceChip.tsx`,
  `CampaignsPanel.tsx`, `ArtifactsView.tsx`, `FuzzModal.tsx`; new API endpoints (artifact verify/
  minimize/promote, campaign coverage + SSE events, fuzz engines). Tests:
  `tests/test_campaigns_phase4.py` (9). `just test` green (531 passed, 5 Docker-gated skips); `just ui`
  clean; Playwright-verified every surface (Campaigns, Artifacts triage, frame→source jump landing on
  the right line with coverage shading, Fuzz/Build modals, Settings, deep-links). README + SKILL
  (`agent_setup.py`) + design-doc §7 Phase-4 DONE + `docs/ui-backlog.md` updated. No new MCP tools
  (the existing campaign/artifact MCP tools cover it); the new API serializer fields
  (`artifact.{frames,assurance,source_ref,finding}`, `/api/fuzz/engines`, `/api/campaigns/{id}/
  coverage`) are UI-facing.
- 2026-06-02: **Fuzzing+source Phase 3 — coverage-guided fuzzing first-class + the detached
  campaign lifecycle + the `ResourceSpec`** ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md)
  §7 Phase 3, branch `build/fuzz-phase3`). The `Fuzzer` seam (`engine/fuzzers/`, dispatch by attack
  surface, fail-closed) — `LibFuzzerFuzzer` (strict superset of the Phase-0 single-pass path, byte-
  identical, regression-tested) + `AflPlusPlusFuzzer` (real coverage on the Phase-2 instrumented
  derived target via `afl-clang-fast` + the persistent libFuzzer driver + llvm-symbolizer) +
  `MockFuzzer`. Dedicated `hexgraph-fuzz` image (`docker/fuzz.Dockerfile`/`just fuzz-build`). Detached
  lifecycle: `Executor.start_detached`/`poll_detached`/`stop_detached` (a hardened `docker run -d`),
  a durable `fuzz_campaign`/`fuzz_artifact` (migration 0014), a periodic reaper (worker job) that
  streams crashes → `fuzz_crash` findings, finalizes, and re-attaches by `container_name` on restart
  (crash-safe). Stop/resume preserves the corpus in CAS. Crash→verify tie-in: the minimized
  reproducer + the harness binary are CAS-preserved and replayed via the unforgeable `crash` oracle
  (`campaigns.verify_artifact`). User-tunable `ResourceSpec` (`sandbox/resources.py`); `unconstrained`
  lifts mem/cpu/pids ONLY — never a security flag, never `policy.py`. API `/api/campaigns`; MCP
  `start_fuzz_campaign`/`stop_fuzz_campaign`/`fuzz_status`/`minimize_artifact`/`list_fuzz_artifacts`.
  No new policy gate (the existing exec gate). README + SKILL + design-doc §7 updated. `just test`
  green (522+ offline); the AFL++ e2e proven against a private `hexgraph-fuzz:wt-fuzz-phase3` image.
- 2026-06-01: **Fuzzing+source Phase 2 — the `Builder` seam + build-as-API**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 2, branch
  `build/fuzz-phase2`). First phase to add a new policy gate + a dedicated image. The `Builder`
  seam (`engine/build.py` `get_builder()` — `SandboxBuilder` default, `MockBuilder` for offline
  tests) turns a managed source tree into an instrumented artifact via a recorded `BuildSpec` the
  API/tool runs in the sandbox (`build_probe.py` in the new `hexgraph-build` image — `docker/build.Dockerfile`
  / `just build-image`: clang/LLVM + sanitizers + SanCov + AFL++ + llvm-symbolizer). Reproducibility
  is the contract (`recipe_sha = hash{phases,env,base_image,instrumentation,arch}`; same recipe_sha +
  source content_hash + toolchain_digest ⇒ same build); the orchestrator injects CC/CXX/CFLAGS per
  the base-image contract so one recipe yields ASan/SanCov vs AFL++ by swapping the profile. New gate
  `assert_allows_build()` / `features.build` [D5] — the ONLY `policy.py` edit, a peer of (not folded
  into) the exec gate, fail-closed. Migration **0013** (`build_spec` recipe + `build` ledger; applies
  on 0012, autogenerate no-drift). Rebuild-with-instrumentation registers an instrumented **derived
  target** (`instrumented_build_of`→ the original) [§3.3] — the fuzzable twin for Phase-3 coverage-
  guided fuzzing. API `/api/builds` (+ preview/log), MCP `build_target`/`list_builds`, the IDE Build
  modal. Vendored/offline only (`--network none`). Proven: full offline `just test` green (mock
  builder + recipe_sha determinism + fail-closed gate + derived-target + migration round-trip),
  Docker-gated `test_build_e2e.py` (real SanCov+ASan build proven by symbol inspection; net-dep build
  fails honestly), Playwright check of the Build modal. Frozen schema untouched.
- 2026-06-01: **Fuzzing+source Phase 1 — source-tree foundation + read-only Source/IDE tab**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 1, branch
  `build/fuzz-phase1`). NO exec, NO new policy gate — pure data-model + read-only browse + graph
  wiring. **`source_tree`** is a new SQL entity (**migration 0012**, `down_revision=0011`, applies
  clean on 0011 and round-trips; fresh `init_db()` create_all still works) — a project holds
  multiple trees, each optionally linked to a target via a `built_from` edge (**D1**: a SQL entity,
  surfaced through its own Source pane, NOT a `TargetKind`, so recon/ingest don't branch). Storage
  is **filesystem + manifest + lazy nodes** (**D2**, `engine/source.py` mirrors
  `engine/filesystem.py`): files under `<data_dir>/source/<tree_id>/`, a flat `manifest_json` on
  the row, `source_file` nodes materialized only on reference (`fq_name=<tree_id>:<rel>`,
  `target_id=None`). Reads bounded + path-traversal-safe (the `filesystem` containment guard);
  `origin=extracted` marks untrusted firmware bytes (display only). Harnesses/PoCs/scripts unify as
  **role-tagged `source_file`** (**D3**, `engine/harness_promote.py`): `promote_harness` /
  `backfill_harnesses` move a `harness_generation` finding's transient `evidence.decompiled_snippet`
  into a managed `source_file(role=harness)` + a `harness` node `harnesses`→ the target;
  `fuzzing.resolve_harness` prefers the managed file but **falls back to the legacy snippet** (old
  findings still fuzz). Zero-migration vocab: node types `source_file`/`harness`; edge types
  `built_from`/`located_in`/`harnesses`. The riskiest touch — `source_tree` as a polymorphic edge
  endpoint — is a surgical `EDGE_KINDS`-tuple + `authoring._entity_exists` widening (the `add_edge`
  validator already reads the tuple), tested both ways. **Read-only Source tab**: a Graph⇆Source
  segmented control (`?view=source`, a mode not a route), `SourceBrowser.tsx` (multi-tree dropdown +
  `<FileTree>` + line-numbered viewer), and the finding→source jump (Inspector "Open in source
  (line N)" reads `evidence.extra.source_ref`). REST `…/source-trees(/{id}/files|file)`,
  `…/findings/link-source`, `…/backfill-harnesses`; MCP read `list_source_trees`/`read_source_file`,
  write `import_source_tree`/`link_finding_to_source` (grouped + `features.mcp.*`-gated).
  `merge_duplicates` folds `source_file` dupes via its default key. Frozen Finding schema untouched
  (everything rides `evidence.extra` / the new table); no `policy.py` edit. Verified: migration
  round-trip; `tests/test_source.py` (19 cases — model, lazy materialization + dedup, the three
  edges + endpoint-validator widening, harness backfill + back-compat resolve, API/MCP read tools,
  path-traversal); full `just test` green (468 passed, 2 skipped); `just ui` + a Playwright check
  of the Graph⇆Source switch, a file open, and the finding→source jump (line highlighted). README +
  SKILL (`agent_setup.py` §2f) + design-doc §7 Phase-1 DONE + `docs/ui-backlog.md` updated. Known
  limits: no "Sources" section in the left tree yet (the dropdown is the only picker); plain `<pre>`
  viewer (no Monaco) — deferred per ui-backlog.
- 2026-06-01: **Fuzzing Phase 0 — coverage-guided target instrumentation + real crash triage**
  ([`docs/design-fuzzing-and-source.md`](docs/design-fuzzing-and-source.md) §7 Phase 0, branch
  `build/fuzz-phase0`). The headline fix: today's `-fsanitize=fuzzer` only instrumented the harness,
  so a `--target-lib`-linked `.so` was fuzzed coverage-BLIND. Now when the target's own SOURCE is
  available (`fuzz_probe --target-source=…`, resolved by `engine.fuzzing.resolve_target_sources` from
  the task param `target_sources` or `target.metadata_json.fuzz_target_sources`) the target is compiled
  under `-fsanitize=fuzzer-no-link,address` and linked into the libFuzzer harness → SanCov+ASan in the
  target's OWN objects → real coverage feedback. With only an uninstrumented `.so` it still runs but
  records `coverage_instrumented=false` (no overstatement). Crash dedup replaced `(kind, frame0)` with a
  deterministic **normalized stack-hash** `dedup_key` (top-N ASan frames, addresses/offsets/build-paths/
  line:col/anon-ns+template/interceptor frames stripped, stopped at program entry); one finding per
  bucket + `dupe_count`. Reproducers minimized via libFuzzer `-minimize_crash` (no AFL++ in the existing
  image). A deterministic **exploitability classifier** (READ/WRITE, UAF/double-free, SEGV near-PC,
  recursion DoS, OOM/leak/timeout → `{rating, access, signals}`) refines severity. All new structure on
  `evidence.extra.fuzz` — **frozen schema untouched, no migration**; `derive_fuzz_assurance()` unchanged.
  MCP `list_findings` gained a compact `fuzz` summary; `get_finding` already returns full `evidence.extra`.
  README fuzzing card + SKILL (`agent_setup.py`) updated; the `coverage_instrumented=false` "don't
  overstate a black-box run" caveat is called out for the agent. Tests: new `test_fuzz_triage.py` (pure
  dedup/classifier/severity), extended `test_fuzzing.py`, Docker-gated `test_fuzz_e2e.py` (instrumented
  build finds+classifies a planted heap-write). `just test` green (448 pass, 2 non-fuzz Docker skips
  offline); e2e verified with Docker+the sandbox image. **Known limit:** the base image has no
  `llvm-symbolizer`, so ASan frames are module+offset at runtime (within-run dedup deterministic;
  symbolized cross-build dedup/function attribution awaits the dedicated `hexgraph-fuzz` image, Phase 3+).
- 2026-06-01: **Verification oracles Phase 2 — the DoS `liveness`/`unavailable` oracle**
  ([`docs/design-verification-oracles.md`](docs/design-verification-oracles.md) §4, branch
  `build/dos-liveness`). New `verify_liveness` in `engine/oracles.py` (dispatched from
  `poc.verify_poc` when `spec.oracle.type` ∈ {`liveness`,`unavailable`}). Proves denial-of-service
  by an **unforgeable LIVENESS TRANSITION** HexGraph observes ITSELF: **baseline UP** (a benign
  `GET /` / `oracle.probe`, or a raw-TCP connect, succeeds) → **send the DoS input** through the
  same live web/tcp boundary (response discarded) → **re-probe DOWN with hysteresis** (default 3
  re-probes, `delay`s between; EVERY one must read DOWN — a single recovered/UP re-probe means only
  a transient blip → NOT verified). Already-down-at-baseline ⇒ **INCONCLUSIVE** (honest, not
  verified). The verdict comes solely from HexGraph's own out-of-band re-probe, never the exploit's
  response. **Policy-seam + audit:** every probe is benign egress via `run_http_request` /
  `run_tcp_probe`, so it's `features.network`-gated (fails closed when off) and audited to
  `EgressEvent`. **Binary degradation:** a binary target's liveness oracle is rewritten to the
  sandbox `crash` oracle (process death already covers it) — no network probe, no reimplementation.
  **Assurance:** live surface ⇒ `input_reachable/dynamic`, binary-degraded ⇒ `code_present/dynamic`,
  inconclusive/transient ⇒ `unconfirmed` (via `derive_poc_assurance`, unchanged); re-verify
  (`POST /api/findings/{id}/verify`) preserves it. Envelope-only — no frozen-schema change, no
  migration. Also advertised to agents: `get_schemas['verify_poc_oracles'].liveness`, the
  `verify_poc` docstring + `_CATALOG` entry. Tests: `tests/test_oracles_liveness.py` (10 — verified
  sustained outage web+tcp, **transient blip does NOT verify** [the unforgeability test],
  inconclusive-when-already-down, 5xx-counts-as-down, every-probe-audited, binary→crash degradation,
  network-tier gating, reprobes/delay clamped to a sane range). Full suite: 431 passed, 2 skipped
  (Docker-gated).
- 2026-06-01: **PoC presentation — a verified PoC is now actionable** (branch `build/poc-presentation`,
  PR #46). **Regression fix:** `api_verify_finding` (one-click Re-verify) was DROPPING
  `evidence.extra.assurance` — it now refreshes the engine-computed assurance triple at BOTH the canonical
  `extra.assurance` and inside `verification` (matching `_poc_finding`); the MCP `verify_poc` attach path
  too. **Human reproduction:** new `engine/poc_repro.py` `repro_command(spec, target)` derives a copy-paste
  command per flavour — a chained `curl` per web step (method/path/params/headers/body vs the surface
  base_url, `{{NONCE}}` left verbatim), `printf … | nc host port` for a tcp spec, `env … <target> argv`
  (+ `printf stdin |`) for a binary spec; stored at `evidence.extra.repro_command` with a readable form in
  `reproducer` (was raw JSON). **UI** (`Inspector.tsx` PoC panel): the assurance triple rendered with the
  lab-confirmed (code_present/dynamic, amber) vs reachable (input_reachable, green) distinction legible, the
  PoC steps in plain language (raw JSON kept in the collapsible), and the reproduction command with a copy
  button; Verify/Re-verify preserved. **SKILL** (`agent_setup.py` + `get_schemas['assurance'].presentation`):
  keep the PoC spec self-contained for one-click Re-verify (no agent), record a how-it-works in
  summary/reasoning, note the assurance is shown to the user. Envelope-only — no frozen-schema change, no
  migration. Tests: `tests/test_poc_repro.py` (repro_command per flavour; re-verify preserves/refreshes
  assurance). Full suite: 419 passed, 2 skipped (Docker-gated). Playwright-verified the PoC panel.
- 2026-06-01: **Verification oracles Phase 4 — Standard B, static (source→sink reachability ARGUMENT)**
  ([`docs/design-verification-oracles.md`](docs/design-verification-oracles.md), branch
  `build/static-reachability`). New `engine/reachability.py`: a multi-source, forward, bounded +
  cycle-safe BFS over the typed graph that argues a finding is `input_reachable/static` when the
  service can't be booted to trigger it live (the DIR-823G case — real cmdi sink, FirmAE couldn't
  boot goahead). **Sources** = the untrusted boundary (`input`/`param`/`endpoint`/`socket`, or a
  `function`/`symbol` explicitly `attrs.entry`); **sinks** = a `sink` node or any `attrs.is_sink`
  node (a finding resolves its sink via `about`→node, falling back to a name match on
  `evidence.sink`/`function`). **Traversal**: forward only (never reverse an edge) over
  `taints` (strongest — `via_taint`), `dataflow_hint`, `calls`, `routes_to`, `writes`, `reads`,
  `references`, `bypasses`; `contains` excluded (vacuous). **Precondition** derived from the path:
  an auth boundary (`attrs.auth` set, `auth_check`, or a `bypasses` edge) ⇒ `requires_credentials`;
  an explicitly-unauth start boundary ⇒ `unauthenticated`; else `unspecified`. **Precedence**:
  `assurance.upgrade_if_stronger` encodes the ladder as a PARTIAL order so `input_reachable/static`
  UPGRADES only the `code_present/static` floor and NEVER downgrades a dynamic claim
  (`code_present/dynamic` ‖ `input_reachable/static` are incomparable tier-1; `input_reachable/dynamic`
  wins all). Exposed as the `reachability(finding_id|sink_node_id)` MCP `run` tool (records the path
  to `evidence.extra.reachability` + the upgraded assurance), AUTO-stamped in the static_analysis flow
  (best-effort, advisory, after dupe-merge), and documented in `get_schemas['assurance']
  .static_reachability` + SKILL §3. Envelope-only — no DB model change, no migration. Tests:
  `tests/test_reachability.py` (13: taints/control/auth/bypasses paths + precondition matrix, no-path
  stays at floor, non-source/backwards-edge/`contains` can't FALSELY claim reach, the partial-order
  upgrade rule incl. not-downgrading dynamic, cyclic-graph termination + max_depth bound) + 2 new
  `engine/assurance.py` rank/upgrade tests. Full suite: 412 passed, 2 skipped (Docker-gated).
- 2026-06-01: **Verification oracles Phase 1 — `callback` / `canary_read` / `oob_write` (unforgeable
  oracles beyond reflected cmdi)** ([`docs/design-verification-oracles.md`](docs/design-verification-oracles.md),
  branch `build/oracles-phase1`). New `engine/oracles.py` (dispatched from `poc.verify_poc` when
  `spec.oracle.type` ∈ {`oob_write`,`canary_read`,`callback`}) + `engine/callback_listener.py`. Each
  observes the vuln's side effect on a channel INDEPENDENT of the exploit's request: **oob_write**
  runs the write, then reads the location back out-of-band (`rootfs`/`remote`/`http`, traversal-checked)
  and checks the run nonce landed; **canary_read** PLANTS a fresh random canary out-of-band (or a
  supplied `known_value`) before the exploit and checks the read primitive returned it (`{{CANARY}}`
  substitution); **callback** stands up a bounded LOCAL listener, mints a `{{CALLBACK}}` token
  (host:port + per-run nonce path), runs the exploit, and waits a bounded time for a hit carrying the
  nonce (proves blind cmdi/SSRF/RCE with zero reflected output; a stray hit without the nonce never
  verifies). All DYNAMIC → flow through `derive_poc_assurance` unchanged (live web/tcp/remote ⇒
  `input_reachable/dynamic`, isolated binary/harness ⇒ `code_present/dynamic`). **Listener placement
  decision:** the audited INGRESS MIRROR of the bounded-egress tier — binds loopback/private ONLY
  (fail-closed), gated by `assert_allows_egress` over its own host:port BEFORE binding (denial
  propagates like every other live gate), every event audited to `EgressEvent` (`callback_listener`
  + `callback_hit`). Local case implemented + REAL local-loopback integration-tested; rehost-netns
  case = a sidecar joining the emulator netns on the gateway IP (mechanism shipped via `bind_host`;
  live rehost validation deferred — needs a cooperative firmware). Oracle results live in
  `evidence.extra` (DB envelope) — frozen `finding.schema.json` UNCHANGED, no migration. Updated
  `get_schemas['verify_poc_oracles']`, the `verify_poc` docstring + `_CATALOG` entry (+ MCP verify_poc
  now attaches the engine assurance to the finding), and SKILL §2e. Tests: `tests/test_oracles.py`
  (15: each oracle's verify/fail/forgery-resistance via fake channels+runner, the REAL loopback
  callback round-trip asserting the hit + audit, non-local-bind refusal, network-tier gating). Full
  suite **394 passed, 2 skipped**.
- 2026-06-01: **DIR-823G real-firmware engagement (closing #44's real-firmware half) + FirmAE
  boot-budget fix.** Ingested the real D-Link DIR-823G v1.0.2B05 vendor blob → sasquatch extraction
  (137 children); statically found + recorded the **unauth HNAP cmdi (Standard A)** in `/bin/goahead`:
  SOAP action `SetNetworkTomographySettings` builds `ping <Address> -c <N> -s <Size> > /tmp/ping.txt`
  via `system()`, `<Address>` unsanitized (CVE-2019-7298 family) — finding + endpoint/param/input/sink
  nodes + `taints` chain, assurance `{code_present, static, unauthenticated-argued}`. FirmAE booted the
  image and **brought the network up** (192.168.0.1, ICMP-reachable, service=/bin/goahead) but the web
  daemon **crash-loops** — `libapmib.so` fails the `/dev/mtdblock0` Realtek-flash "hw setting signature"
  check FirmAE can't emulate, so goahead never binds; **no live surface ⇒ `verify_poc` couldn't run**
  (Standard B dynamic NOT achieved — a FirmAE/Realtek-SDK fidelity limit, not a HexGraph/sink flaw).
  **Fix shipped (`fix/firmae-boot-budget`):** the entry script's hardcoded 12-min ip-poll ceiling
  (`BOOT_BUDGET=144`) timed out this slow MIPS image mid-inference (before `ip` was even written),
  giving a misleading "no device network". Made `BOOT_BUDGET` env-configurable (`HEXGRAPH_BOOT_BUDGET`)
  and had the rehoster forward `budget // 5` so the container ceiling tracks `features.rehost.timeout`.
  With timeout=1800 inference completed and the IP/service were assigned — turning a premature timeout
  into the definitive answer. Captured in `docs/vr-feedback.md` (friction note #7: Realtek-SDK web
  servers need real flash to boot under FirmAE). `make test` green; rehost tests pass.
- 2026-06-01: **Verification oracles Phase 0b — lab-confirmed vs reachable + the assurance floor +
  agent guidance.** Refined the model so `code_present` has BOTH a static and a *dynamic* form,
  differentiating "looks vulnerable" (static observation) from **lab-confirmed** (the bug was fired
  by executing the code in ISOLATION — a harness/fuzzer — proving it's real even when the production
  input path isn't established). `derive_poc_assurance` now keys on the dynamic **scope**: a live
  web/tcp surface ⇒ `input_reachable/dynamic` (real deployed input); an isolated binary exec ⇒
  `code_present/dynamic` (lab-confirmed); `spec["scope"]` overrides. `fuzz_crash` now records
  `code_present/dynamic` (was floored to static). `persist_finding` stamps the **floor**
  (`code_present/static`) on any vuln finding lacking assurance, so EVERY flaw documents at least
  its level and a stronger declared/derived claim is never overwritten. `get_schemas['assurance']`
  + the `verify_poc`/`record_finding` docstrings + SKILL §3 now teach the 4-rung ladder: record the
  floor, AIM for the strictest (`input_reachable/dynamic`, `unauthenticated`), state preconditions
  honestly. design-verification-oracles.md updated with the 2×2 + scope. Tests: test_assurance.py
  (lab-confirmed vs reachable, scope override, fuzz, floor stamped/preserved/skipped).
- 2026-06-01: **Verification oracles Phase 0 — the two standards of "verified", built into the
  engine** (`engine/assurance.py`). The engine now COMPUTES a per-PoC **assurance triple**
  `{standard, method, precondition}` and records it on the finding (`evidence.extra.verification.
  assurance` + the reasoning line) — so code-present (A) vs input-reachable (B) is differentiated
  by code, not by prose handed to an agent. `verify_poc` (refactored: the binary path extracted to
  `_verify_binary_poc`, all three flavours fall through to one assurance step) sets method=`dynamic`
  always, standard=`input_reachable` when verified else `unconfirmed`, and a precondition that
  honors a spec-declared value, else makes the WEAKEST honest inference (single unauth web step →
  `unauthenticated`; login step/cookie/multi-step → `requires_credentials`; tcp → `unauthenticated`;
  binary → `unspecified`) — never overstating "reachable for anyone". Tests: `test_assurance.py`
  (the standard/method/precondition matrix, the finding records it, verify_poc attaches it e2e via a
  fake runner). Next: Phase 1 (callback/canary listener + canary_read/oob_write oracle types).
- 2026-06-01: **Verification-oracles design captured** ([`docs/design-verification-oracles.md`]
  (docs/design-verification-oracles.md)) — how to prove vuln classes BEYOND command-injection
  (memory-corruption RCE, DoS, read/write primitives, SSRF, blind variants) with unforgeable
  oracles. Core principle: an oracle is unforgeable when HexGraph observes the vuln's side effect
  on a channel INDEPENDENT of the exploit's own request (the `{{NONCE}}`-in-output check is one
  instance). Taxonomy + per-class design (callback/canary listener, planted-canary read,
  out-of-band side-effect read, liveness/DoS, crash/ASan RCE spectrum), all bounded by the policy
  seam + audited; oracle types live in the PoC spec / `evidence.extra` envelope, not the frozen
  finding schema. Phase 1 (callback/canary + read/write oracles) to implement next. *(proposal)*
- 2026-06-01: **Code-review #44 — full discover→test-live loop for a WEB RCE on rehosted IoTGoat
  (validation; branch `docs/iotgoat-44`).** Drove the engine end-to-end against OWASP IoTGoat
  (x86 OpenWrt disk image): ingest + gap-#1 disk-image extraction (344 rootfs children), qemu
  auto-select + boot in **17 s** (LuCI/uHTTPd live on `https://127.0.0.1:8443`), surface
  registration, and `http_request`(session cookie-jar) reaching the live login — every HexGraph
  mechanism worked. Found the WEB command injection cleanly by static rootfs review:
  `luci.controller.iotgoat.webcmd` pipes `http.formvalue("cmd")` straight into
  `io.popen(cmd.." 2>&1")` as root (CWE-78), reflected to the body, at
  `POST /cgi-bin/luci/admin/iotgoat/webcmd`. Recorded the cmdi `vulnerability` finding +
  endpoint/param/input/sink nodes + taints edges + a credentials finding + hypothesis in the
  engagement project (`HEXGRAPH_HOME=/tmp/hg-iotgoat-44`). **#44 NOT demonstrated as a verified
  live RCE — blocked at credential recovery, not a tooling gap:** the cmdi route inherits LuCI
  `sysauth="root"`, so it needs a `root` web session; `/etc/shadow`'s `iotgoatuser` cracks to
  `7ujMko0vizxv` but the **`root` hash `$1$Jl7H1VOG$…` is not in rockyou (14.3M exhausted)**, and
  the live device rejected both creds (403, no sysauth cookie) with no unauth route to `webcmd`.
  Did NOT force a false positive (`verify_poc` never returned verified:true). Recommendation for a
  clean live-web-RCE demo: **D-Link DIR-823G v1.02B03** (UNAUTH `/HNAP1` cmdi → `system()`;
  CVE-2019-7297/7298, CVE-2018-17787) — `DIR823GA1_FW102B03.bin`, drop at
  `/tmp/DIR-823G_FW102B03.bin`, `rehost(brand="dlink")` (FirmAE). Re-confirms vr-feedback #3 (the
  rehosted image's shadow passwords must be in a common wordlist for the post-auth chain to be
  reachable); added vr-feedback #6. Docs-only; no model/DB change → no migration. Cleaned up the
  qemu container.
- 2026-06-01: **Centralized bounded-egress allowlist enforcement (code-review #7 middle ground;
  branch `build/egress-guard`).** New stdlib-only shared chokepoint `sandbox/probes/_egress.py`
  (`dest()`/`ensure_allowed()`/`install_socket_guard()` + `EgressBlocked`): the socket guard
  monkeypatches `socket.create_connection`/`socket.socket.connect{,_ex}` so EVERY outbound TCP
  (AF_INET/6, SOCK_STREAM) connect is checked against the run's allowlist — the can't-forget
  backstop — while deliberately leaving DNS/UDP/AF_UNIX untouched (no `getaddrinfo` interference).
  All five egress probes (`http`/`tcp`/`surface`/`web_discover`/`remote`) now install the guard at
  startup and route their explicit pre-connect check through the shared helper (behavior unchanged:
  same `destination not in allowlist` shape, no-redirects, oracles, secret handling). Contract test
  statically asserts every egress probe adopts the guard (a new probe that forgets it fails CI) +
  unit tests for allow/deny, off-list block, on-list allow (real localhost listener), DNS/UDP
  pass-through. Kernel-level confinement (Option B: per-container nftables DROP-default) documented
  as deferred future hardening in `docs/design-dynamic-surfaces.md`. No DB change → no migration.
  Verified: `just test` green offline + the Docker-gated live probe tests
  (`test_web_assessment`/`test_remote`/`test_tcp`/`test_web_discover`) pass through the real sandbox.
- 2026-06-01: **Declutter + defense-in-depth hardening (code-review backlog #10/#14/#15/#17/#18/#19 +
  router-split note; branch `build/declutter-hardening`).** Dead code: deleted the unused `TaskHandler`
  Protocol + `ToolStep` dataclass from `tasks/base.py` (nothing implemented them — dispatch is the
  if/elif over `execute_*` in `engine/worker.py`; kept `TaskContext`, rewrote the module docstring to
  describe the real model) and their re-exports; pruned the dead `ls` branch in
  `remote_probe._build_command` (`ls`∉`TOOLS`, so the allowlist already rejected it). Hardening:
  `policy._host_is_local` now rejects IPv4-mapped/6to4/Teredo IPv6 forms outright so a disguised
  `::ffff:169.254.169.254` can't smuggle the cloud-metadata IP past the link-local exclusion (#14);
  `ghidra_bridge._decompile_one` validates the function name against a strict `_SAFE_NAME` regex and
  passes it as a BOUND `fn` eval var instead of `%r`-interpolating it (#17), and dropped a dead
  placeholder remote_eval. Decluttered deps: removed the host-side `analysis` extra (r2pipe/lief/pyelftools
  are sandbox-only) and unused `jinja2` from the `server` extra; dropped `lief` from `docker/sandbox.Dockerfile`
  (no probe imports it; kept python-magic, which recon_probe uses); **deleted the unmaintained M1-era root
  `Dockerfile` + `docker-compose.yml`** (docker-out-of-docker socket-mount footgun, referenced by no
  recipe/doc/test; in git history) and the README section that documented `docker compose up` (#18).
  Refactor: extracted the MCP `_CATALOG`/`GROUPS`/`catalog()` (the agent-facing prompt copy) into a new
  `engine/mcp_catalog.py`; `mcp_tools` keeps the ~50 tool impls and re-exports `GROUPS`/`catalog` lazily
  via PEP 562 `__getattr__` so the dependency is strictly one-way (catalog→tools) with no import cycle
  in either load order (#19). Made `routers/targets.py` call `executor.get_executor()` via the module to
  match the `runner.docker_available()` monkeypatch surface (router-split note). New regression tests in
  `test_review_regressions.py` (host-is-local mapped-IPv6 rejection, run_tool/ls allowlist boundary,
  ghidra name validation/binding). `just test` green: **360 passed, 2 skipped** (357 baseline + 3 new,
  no new skips).
- 2026-06-01: **Structural refactor — split the `api/app.py` god-function into APIRouter modules**
  (code-review structure finding #6). `create_app()` was ~1100 lines defining all ~55 endpoints as
  nested closures in one factory (untestable per-route, a merge-conflict hotspot, forced every helper +
  per-route lazy import into one scope). Extracted ten top-level routers under `src/hexgraph/api/routers/`:
  `projects` (10), `targets` (6), `graph` (10 — nodes/edges/sockets/schemas/`/graph/{id}`), `findings` (9),
  `tasks_runs` (9 — tasks/runs/preview/detail/trace/rerun), `hypotheses` (4), `annotations` (3),
  `settings` (3), `ghidra` (2), `capabilities` (1); shared request models + `*_dict` response shapers moved
  to `routers/_shared.py`. `create_app()` now shrinks to `FastAPI(...)` + lifespan + the **two security
  middlewares unchanged** (`_host_guard` Host-allowlist, `_same_origin_guard` Sec-Fetch-Site CSRF) +
  `include_router(...)` ×10 + `/health` + the SPA static mount (still LAST, after all API routes). Pure
  move/restore: **route count unchanged (64, identical paths/methods verified)**, `make test` green
  (344 passed, 2 skipped — same as main), trust-boundary + SPA-mount intact. One behaviour-preserving care:
  `targets.py` calls `runner.docker_available()` via the module (not a name bound at import) so the existing
  `monkeypatch("hexgraph.sandbox.runner.docker_available")` tests still take effect; `verify_poc` stays a
  lazy in-function import for the same reason. No DB model change → no migration.
- 2026-06-01: **FirmAE boot-reliability hardening + real-firmware live-loop validation (DVRF).**
  Durable fix for the recurring makeImage **silent hang** (~12-min stall → "no device IP"), which has
  TWO distinct causes — both now handled in `docker/firmae/rehost_entry.sh`:
  (1) **stale/leaked loop** backing `/FirmAE/scratch/<iid>/image.raw` shadows the fresh loop — cleanup
  now matches **`(deleted)`-backed** loops, drops any `dmsetup`/kpartx map *before* detaching (so a
  "busy" loop releases), repeats a few passes, and **logs** anything still wedged;
  (2) **missing partition node (the deeper root cause, found live)** — FirmAE's `add_partition` runs
  `losetup -Pf image.raw` then busy-waits forever for `/dev/loopNp1`, but `losetup -P` doesn't reliably
  create that node in a privileged container, so it spins indefinitely (confirmed by hand: loop0 up but
  `/dev/loop0p1` absent; `kpartx -a` + `mknod … group disk` unblocked it). Shipped a **background
  partition-node healer** that creates the missing `p1` node automatically — and (review fix) also
  **`chown`s an existing wrong-group `p1` to `root:disk`**, so `add_partition`'s *second* busy-wait
  (`ls -al … | grep disk`) can't spin forever either;
  (3) a **makeImage-phase fail-fast watchdog**, scoped strictly to extraction. It judges progress
  SOLELY by `makeImage.log` activity (review fix: `image.raw` is fdisk-preallocated full-size, a dead
  signal) and **disarms the instant makeImage completes** (detected via FirmAE's `time_image`/
  `makeNetwork.log` artifacts), so it can NEVER false-abort the legitimate ~360s network-inference
  boot that follows (review fix: the prior size+log watchdog falsely bailed mid-inference). On no
  `makeImage.log` progress for `HEXGRAPH_MAKEIMAGE_STALL`s (default 300) or a dead pipeline it prints a
  clear `ip:null` marker + dumps `makeImage.log`/`makeNetwork.log`/qemu-serial tails + tears down
  (`FirmAERehoster` maps `ip:null` → clean `RehostError`); the overall `BOOT_BUDGET` governs inference.
  Also widened the device **port-probe** sweep to include high vendor/admin ports (8000/8888/49152/
  **52000** etc.) so auto-`remote`/raw-TCP intel reflects high-port management UIs (DVRF's is on :52000);
  each probe keeps a hard timeout. Docs: `docs/design-rehosting.md` "Honest limits". **Real-firmware
  validation:** DVRF (Linksys, MIPS) booted under FirmAE via `rehost_firmware()` (brand=linksys) →
  device **192.168.1.1**, web up on **:80**, `web_app` surface registered, makeImage completing and the
  boot reaching an IP through network inference with NO false watchdog abort. Honest live-loop result:
  DVRF's FirmAE boot exposes **only port 80** (no ssh/telnet, web 302→dead :52000 unconfigured-router
  splash), so a **verified live raw-TCP PoC is BLOCKED at "get initial access"** — no shell to
  `remote_launch` the `socket_cmd`/`socket_bof` pwnable, nothing auto-listening on a raw port. This is a
  real-world firmware limit, not a HexGraph tooling gap (the raw-TCP machinery —
  `tcp_probe`/`verify_poc`-tcp/`remote_launch` — remains proven against a synthetic live netns socket).
  VR feedback in `docs/vr-feedback.md`. No model/DB change → no migration.
- 2026-06-01: **build: migrate the build tooling from `make`/Makefile to `just`/justfile (branch
  `build/justfile-migration`, PR).** The Makefile had accreted heavy/optional targets with no signal
  about which a basic user needs, which are testing/demo-only, or *when* to rebuild. Replaced it with a
  documented `justfile`: a `default` recipe that runs `just --list`, every recipe doc-commented and put
  in a `[group(...)]` — **setup** (install/venv/setup), **run** (serve), **build** (ui, sandbox-build),
  **test** (test/test-live/fixtures), **demo** (demo), **rehosting (optional, heavy)** (firmae-build,
  qemu-build, vulnrouter, iotgoat), **maintenance** (clean). Each rebuild-sensitive recipe states WHEN
  to rebuild (e.g. `ui` after any `frontend/` change; `sandbox-build` only after a Dockerfile/toolchain
  change — **probes are mounted from the install at runtime, no rebuild needed**) and prerequisites
  (Docker; FirmAE=privileged+/dev/net/tun; qemu=/dev/kvm). Parameterised recipes preserved
  (`sandbox-build with_ghidra="0"`, `iotgoat fw=""`, top-of-file port/image vars); `clean` is
  `[confirm]`-gated. No targets dropped — all 1:1 (help → `default`/`--list`). The Makefile is now a
  3-line shim that prints "use `just`". Updated every `make X` reference repo-wide → `just X`
  (CLAUDE.md, README, docs/*, scripts, src comments, frontend Settings hint, Dockerfiles,
  docker-compose, conftest skips); documented installing `just` (the official no-sudo one-liner /
  `snap`) in README + CLAUDE.md as a dev dependency. Verified: `just --list` renders the groups cleanly;
  `just test` green (331 passed, 2 Docker-skipped); heavy Docker/KVM recipes `--dry-run`-checked for
  valid bodies. No DB model change → no migration.
- 2026-06-01: **fix: firmware-unpack basename collision (silent graph corruption).** `ingest_file`
  copied every artifact to a flat `artifacts/<basename>`, so two different files (or two unpacked
  firmware children) sharing a basename — e.g. `bin/foo` and `sbin/foo`, or two firmwares both named
  `image.bin` — OVERWROTE each other on disk, and recon/decompile/poc later read the WRONG bytes for
  one target with no error surfaced. Now copies to `artifacts/<target_id>/<basename>` (the row is
  flushed first to get its UUID, then the bytes land in a per-target subdir), so the basename can never
  collide. All readers go through `target.path` (recon/decompile/poc-sysroot/fuzzing/ghidra/agent_tools)
  and were verified unaffected; archive/restore-by-sha256 (`restore_matching`) keys on
  `metadata_json["sha256"]` not the path, and the firmware filesystem browser already namespaces under
  `unpacked/<firmware_id>/` — both unchanged. **NEW ingests only; no migration** — existing rows keep
  their stored absolute `path` and still resolve (no model/column change). Regression tests:
  `test_ingest_basename_collision_no_overwrite` (two distinct `image.bin` → distinct artifacts, each
  reads back its own bytes, sizes+sha256 differ) and `test_unpack_children_sharing_basename_keep_own_bytes`
  (unpack side, fake executor, two same-basename ELFs). 331 passed, 2 skipped. (PR #30.)
- 2026-06-01: **Retired the MVP `context/` bundle (relocate-and-reconcile, branch
  `build/retire-context-bundle`).** Moved the two LIVE assets *into the package* so they ship in the
  wheel and no longer depend on a repo-root folder: `context/schemas/finding.schema.json` →
  `src/hexgraph/schemas/finding.schema.json`, `context/fixtures/mock_llm/**` →
  `src/hexgraph/llm/fixtures/mock_llm/**`. `paths.py` now resolves `finding_schema_path()` /
  `mock_fixtures_dir()` relative to the package `__file__` (not `repo_root()`); `repo_root()` kept
  for migrations/`tests/fixtures` but re-anchored on the `pyproject.toml`/`.git` sentinel instead of
  `context/SPEC.md`. `pyproject.toml` package-data extended (`schemas/*.json`,
  `llm/fixtures/mock_llm/**/*.json`, `*.yaml`) — verified the 11 data files land in a built wheel.
  Deleted the superseded `context/SPEC.md`, `context/README.md`, `context/fixtures/targets/README.md`;
  moved `mock-llm-provider.md` to `docs/` (durable design value) with a provenance banner. `context/`
  is gone entirely. Repointed all refs (CLAUDE.md "Read before writing code" + tree, README, code
  docstrings). Reconciled docs to the shipped security model: `design-vision.md` got a
  "partially-superseded" banner (static-only → graduated opt-in policy seam); `design-dynamic-surfaces.md`
  flipped to IMPLEMENTED, corrected its tier table to the real flags (`features.network`/Tier 2
  TIER_LOCAL_NETWORK, `features.remote`/Tier 3 TIER_LIVE_REMOTE), and trimmed Phasing to "delivered".
  `just test` green (329 passed, 2 Docker-skipped); no DB model change → no migration.
- 2026-06-01: **Security hardening — operator-machine trust boundary (2 high-sev review findings).**
  (1) The loopback API had no Host/CSRF/auth guard → a page the operator visits could DNS-rebind to
  127.0.0.1 and flip the sandbox-relaxing feature gates (PATCH /api/settings) or hit DELETE/task
  endpoints. Added a custom **Host-header guard** (`loopback.host_allowed`; allowlist = loopback
  names/IPs + `testserver`, widens to `*` only on a deliberate non-loopback bind via
  `HEXGRAPH_I_KNOW_WHAT_IM_DOING`) — the primary anti-rebinding defense. NOT Starlette's
  `TrustedHostMiddleware`, which matches on `host.split(':')[0]` and would mangle a bracketed IPv6
  loopback `[::1]:8765` → `[`, locking out the UI where localhost resolves to ::1; `host_allowed`
  parses IPv6 correctly. Plus a **same-origin guard** that allows a state-changing `/api/*` request
  ONLY when `Sec-Fetch-Site` is `same-origin` (the SPA's own fetches) or ABSENT (non-browser; the
  CLI/MCP/tests call the engine in-process, not HTTP) — **`cross-site` AND `same-site` AND `none` are
  rejected**. Rejecting `same-site` is essential: a page on `evil.localhost` resolves to 127.0.0.1
  and is same-SITE to `localhost`, so it would otherwise slip past both guards. `tests/test_trust_boundary.py`.
  (2) `run_remote()` put SSH/telnet creds into the `--channel` JSON → serialized onto the docker run
  argv (world-readable via `ps`/`/proc/<pid>/cmdline`). Now the secret is delivered out-of-band via
  the `HG_CHANNEL_SECRET` env var (new `secret=` param on `SandboxRunner.run_probe`/`run_channel_probe`,
  passed by NAME on the docker argv with the value only in the child process env); `remote_probe`
  reads + merges it. Only the non-secret descriptor stays on the argv; result-scrub of password/key
  preserved. Test asserts the secret is absent from the constructed argv yet reaches the probe via env.
  No DB model change → no migration. `just test` green.
- 2026-06-01: **Raw-TCP live testing + bounded service-launch (closing the live-exploit half-loop,
  part 2 of 2).** Non-HTTP analogue of the web tools so a rehosted/remote device's *socket* services
  (bind shells, vendor binary protocols, pwnable daemons) can be tested live: `sandbox/probes/
  tcp_probe.py` (connect to host:port in the emulator netns, optionally send a payload, read a
  bounded response; an `oracle` strips the sent bytes — reflection — before matching, so a verified
  result is unforgeable, same {{NONCE}} principle as http_probe). `surfaces.run_tcp_probe` gates it
  with a new `policy.local_tcp_scope(host, port)` (loopback/private only, this port) + EgressEvent
  audit. `poc.verify_poc` gains a **`tcp` flavour** ({transport:"tcp", port, payload, oracle:
  response_contains}), checked before web/binary since a rehosted device is also a web surface;
  reaches the network tier (features.network), not exec. New MCP run-tools: **`tcp_request`** (raw
  socket hands), **`remote_launch`** (the one non-read-only remote op — start a not-auto-started
  daemon by binary path + shell-quoted args, backgrounded, features.remote + audited). SKILL §2c/2d
  document the launch→tcp_request→verify_poc(tcp) loop. Closes vr-feedback #2 (non-HTTP services) and
  most of #0. Tests: test_tcp.py (reflection oracle, scope refuses public, gate deny/allow+audit,
  netns routing, verify_poc tcp + nonce substitution, launch command quoting).
- 2026-06-01: **Rehost auto-registers the live device as a remote target (closing the live-exploit
  half-loop, part 1 of 2).** The FirmAE entry script now probes the booted device's ports (22/23/
  80/443/8080/8443/1337/9999 via `/dev/tcp`) and reports the open set in the `HEXGRAPH_REHOST`
  marker; `RehostResult.ports` carries them. When the device exposes SSH/telnet, `rehost_firmware`
  auto-registers it as a `remote` child target pinned to the emulator netns (`net_container`), so
  the agent enumerates the LIVE device (remote_list_files/remote_run, features.remote) — not just
  the extracted rootfs. The `rehost` MCP tool returns `remote_target_id` + `ports`; SKILL §2b
  documents it. `register_remote_target` gained `parent`/`net_container`. Addresses VR feedback #0.
  Tests: test_rehost.py (ssh-preferred, telnet-fallback, none-open). *(Next: raw-TCP probe +
  non-HTTP verify_poc + bounded service-launch so binary socket services can be tested live.)*
- 2026-06-01: **Test-confidence + CI-visibility hardening (`build/test-confidence`).** Closed the
  test-coverage/CI gaps from the code review (357 passed, 2 skipped). (#5) `conftest.py` gained a
  `pytest_terminal_summary` hook that LOUDLY counts Docker-gated security/live tests that SKIPPED, plus a
  `just test-ci` recipe that FAILS FAST when Docker/the sandbox image is absent (so CI can't go green while
  silently skipping the live egress/exec/rehost/remote paths) — RESUME-HERE updated. (#8) direct tests for
  the new MCP run-tools `tcp_request`/`remote_launch`/`register_remote` (success shape, features-off
  error-string not exception, int(port) coercion) + a run-group catalog-membership assertion. (#9) tightened
  `poc._is_tcp` to require BOTH a tcp marker AND a port (an incidental `tcp` field can't misroute a web spec
  or skip the exec gate), with web-vs-tcp dispatch + binary-gate tests. (#11) offline pins for the
  no-secret-leak scrub (`run_remote` strips password/key) and the dedup edge-cascade (earlier row survives,
  later row's edges gone, distinct finding untouched). (#12) agent-loop recovery tests (two tool calls in one
  turn; RateLimitError-then-retry; invalid-JSON schema-repair re-ask). (#16) aligned `tcp_probe._check_oracle`
  reflection-stripping with `http_probe` (raw + URL- + HTML-encoded forms) so the raw-TCP oracle is as
  unforgeable as the web one, with a transformed-reflection test. (#13) replaced fixed `time.sleep` in the
  live sshd/vulnrouter/web_discover fixtures with a bounded `wait_for_port` readiness poll + a single-non-empty
  container-IP assert (`conftest.container_ip`/`wait_for_port`). No DB model change → no migration.
- 2026-06-01: **Live-device + rehosting-engagement track (autonomous overnight).** Shipped, each
  PR-reviewed + merged + VR-vetted: gap #1 disk-image rootfs extraction (Sleuth Kit, PR #20), gap #2
  `web_discover` bounded crawl (PR #21), `verify_poc` web-oracle reflection-stripping (PR #22), the
  **live-remote SSH/telnet target** (Tier 3 `features.remote`, one authorised host, creds env-only,
  EgressEvent-audited; PR #23), and the **FirmAE branch validated end-to-end on real DVRF** (Linksys
  MIPS): sasquatch built into the FirmAE image, rehost timeout 600→900, vendor-brand auto-inference +
  a no-network error that tells you to pass `brand=` (PR #24). A VR agent rehosted DVRF over MCP only
  (`rehost(fw, brand="linksys")` → 192.168.1.1, web up) and found the planted pwnables; IoTGoat's disk
  image still auto-routes to qemu — both `select_rehoster` branches proven on real firmware. VR feedback
  → `docs/vr-feedback.md`. `cookie jar` `session` handle on `http_request` for cross-call auth. Full
  suite 319 passed, 2 skipped; cleaned up to `main`-only.
- 2026-05-31: **Duplicate-node/target merge + name normalization + MCP usability.** Function/symbol
  identity now normalizes decompiler prefixes (`sym.get_param`==`get_param`) at creation
  (`engine.nodes.normalize_symbol_name`); `engine/nodemerge.py` folds existing duplicates by per-type
  canonical key (target sha256 for binaries) moving all edges/findings/annotations to the keeper —
  auto-run after LLM tasks + `POST /merge-duplicates` + MCP tool + "Merge dupes" button. Added a
  `taints` edge type. SQLite now WAL (web UI + agent MCP server share the DB concurrently). MCP fixes:
  absolute launch command (was bare `python`), stderr "ready" banner, `hexgraph mcp --check`, mcp in the
  dev extra, probes mounted from the install (no rebuild to add a probe). SKILL rewritten: graph is
  shared durable memory, read it first, **record before verifying** (suspect→record→explore→verify→
  update), link hypotheses↔findings, and a confirmed vuln MUST have a linked verified PoC finding.
  Engagement test acted on the agent's run feedback. 215 tests pass.
- 2026-05-31: **Executable/verified PoC findings + finding-type tagging + engagement test.** (1) PoC:
  `features.poc` opt-in flips the policy to allow execution; `poc_probe.py` runs the target in the
  sandbox with an attacker spec and an unforgeable `{{NONCE}}` oracle; `engine/poc.py` (verify_poc +
  `poc` task) records a `verified` poc finding; `verify_poc` MCP tool. Verified live against the eval
  firmware (injected echo ran, nonce in output). (2) **finding_type** column (migration 0008) +
  `classify_finding`; findings panel gains a type filter + type/verified chips. (3) Real vulnerable
  firmware `tests/fixtures/eval_fw/eval_fw.bin` (pre-auth command-injection RCE) + `docs/engagement-
  brief.md` / `engagement-answer-key.md` (success = a verified PoC) + installable Claude skill +
  `ingest` MCP tool. 210 tests pass. NOTE: run `just sandbox-build` to bake the new fuzz/poc probes.
- 2026-05-30: **Coding-agent integration (both directions) + VR-eval UX pass.** (1) **MCP driver mode**:
  `hexgraph mcp` server (`mcp_server.py` + `engine/mcp_tools.py`) exposes sandboxed tools — read (inspect),
  write (record_finding/create_node/create_edge/create_hypothesis/annotate), run (run_task) — grouped and
  gated via `features.mcp.{read,write,run}` (+ `--tools`/Settings) so the agent's context stays lean.
  `agent_setup.py` + `hexgraph mcp install` print per-agent registration; `[mcp]` optional extra. (2) **Delegate
  mode**: `features.agent` + `agent_delegate` task (`engine/agent_delegate.py`) launches the agent CLI
  headless wired to MCP + the VR skill, restricted to HexGraph tools (no shell on the target). (3) Acted on
  `docs/ux-eval-vr.md`: fixed stale-detail-after-triage bug, merged duplicate suggestion blocks,
  Accept→Confirm, labeled confidence, faint Run affordance, toolbar tooltips + graph Export, README/doc
  fixes, and an **in-app decompilation viewer** on function nodes. 200 tests pass.
- 2026-05-30: **LLM tool-use (agent loop).** Tasks advertise sandboxed tools and run a bounded loop —
  model requests a tool → HexGraph runs it in the sandbox → result fed back → repeat until findings.
  `llm/base.py` (ToolSpec/ToolCall + messages/tool_calls), `llm/runner.run_findings_agentic` (superset of
  single-pass, retains retry/JSON-repair, step budget), `engine/agent_tools.py` (decompile/disassemble/
  list_functions/read_imports/list_strings + policy-gated fuzz_function). Mock drives it at $0 via
  `tool_calls` fixtures (`static_analysis/agentic_overflow`); Anthropic backend does real tool_use/
  tool_result. The model directs, HexGraph executes — a plain BYOK key suffices. 179 pass.
- 2026-05-30: **Fuzzing + target removal + firmware filesystem.** (1) `fuzzing` task (opt-in via the
  policy seam — the single relaxation of static-only): `fuzz_probe.py` compiles a harness with
  libFuzzer+ASan, fork-runs under a budget, reproduces each crash for its ASan report; `engine/fuzzing.py`
  makes a deterministic finding per unique crash (+ optional LLM triage). clang/libclang-rt added to the
  image; runner gains `extra_ro_mounts` to link the target .so. (2) **Soft target removal** (migration
  0007 `target.archived`): archive subtree, hide nodes/findings everywhere, restore on re-add by sha256.
  (3) **Firmware filesystem** (`engine/filesystem.py`): unpack persists the tree + manifest; detail-panel
  browser adds any file as a child target; library exports → nodes; function nodes launch tasks. 171 pass.
- 2026-05-30: **Settings system + Ghidra (optional) + UI fixes.** Managed `settings.json` layer
  (`settings.py`, `/api/settings`, `hexgraph config`, Settings page) — env > settings.json > config.toml >
  defaults; secrets status-only (never written/returned). Ghidra behind the Decompiler seam, settings-driven:
  headless (`ghidra_probe.py` analyzeHeadless in sandbox, `WITH_GHIDRA=1`), bridge (`engine/ghidra_bridge.py`,
  connect to a running Ghidra → list/import programs), enrich_recon (functions/calls/structs into the graph);
  all fall back to radare2. UI fixes: Run-menu portal (no clip) + expandable detail box; LaunchModal redesign
  (fixed columns, wrapping preview) + finding follow-ups now route through it with `parent_finding_id`;
  graph collapses duplicate parallel edges (one per src→dst→type, merge at creation + at render). Makefile
  collapsed to one-shot `just setup`. CLAUDE.md condensed to rules+orientation. 154 tests pass.
- 2026-05-30: **Researcher depth — Chunk C: P7 viewer UI** (frontend only; backend endpoints already
  existed). `ReportModal` renders the project report (`/api/projects/{id}/report` markdown) in-app via
  a tiny offline md→HTML renderer (`.markdown` theme styles), with copy + download-.md. `RunCompareModal`
  picks a target, lists its `analysis_run`s, and diffs two (`/api/runs/diff`) into added / dropped /
  severity-changed. Workspace toolbar Report button now opens the modal (was raw new-tab); new Compare
  button. **P6/P7 researcher depth complete.** Build clean; backend suite still 128 pass.
- 2026-05-30: **Researcher depth — Chunk B: hypothesis lifecycle** (P6). `engine/hypotheses.py` +
  API (`/api/projects/{id}/hypotheses`, `/api/hypotheses/{id}/{evidence,status}`). A hypothesis is a
  `hypothesis` node; findings attach as `supports`/`refutes` evidence (finding→node edges). Status is
  *derived* (open→supported/refuted/contested) unless a human pins confirmed/rejected (sticky until
  reopened). Open/supported/contested hypotheses anchored (`about`) to a target feed that target's
  task context (`open_hypotheses` item). UI: `HypothesisPanel` in NodeInspector + "New from
  finding"/link-to-existing controls in the finding Inspector; distinct graph color + bulb icon.
  128 tests pass. (Next: C — report viewer + run-compare UI.)
- 2026-05-30: **Researcher depth — Chunk A: annotations** (P6). `annotation` table (migration `0006`),
  rename/note/tag on target|node|finding; human→confirmed, agent→proposed (confirm/reject); confirmed
  rename updates node display name (keeps fq_name identity + name_history); confirmed renames/notes feed
  the agent-context loop; tags are a findings filter facet. API + `Annotations` SPA panel in both
  inspectors. 123 tests pass. (Next in this direction: hypothesis lifecycle; report/run-compare UI.)
- 2026-05-30: **Web authoring (no CLI needed)** — `engine/authoring.py` + API (create project, upload
  target→recon, create node, create edge) with enforced invariants (targets only from real bytes;
  code nodes require an existing binary; edges can't dangle). SPA: New-project form, +Add upload,
  +Node/+Edge modals. 114 tests pass; e2e verified via Playwright (create→upload→recon→graph).
- 2026-05-30: **UI-sexiness pass** (`docs/ui-sexiness.md`, all items done) — design-system refresh,
  inline SVG icons, graph halos + color-coded edges + fit/zoom controls, "Run ▾" launcher popover,
  polished findings/inspector, global search + Report + Same-code toolbar, richer projects cards.
  Verified via Playwright (no page errors). Also **fixed a serve bug**: legacy/create_all'd DBs are now
  migrated forward (not stamped at head); `serve` lifespan runs `prepare_database`. 107 tests pass.
- 2026-05-30: **Design vision authored** → [`docs/design-vision.md`](docs/design-vision.md). Multi-agent
  workflow (ground → 8 design dimensions → 3 adversarial critiques → synthesis) producing the v2 target
  shape: typed graph (`target` artifacts + `node` concepts + polymorphic `edge`), task anchors
  (node/edge/selection/hypothesis) over the canonical 5 task types, the content-addressed **Context
  Bundle** model (provenance + reproducibility + analysis_run diff), HITL/triage model, graph-as-hub UI,
  and a prioritized gap analysis. Finding schema stays frozen; migrations are a committed prerequisite.
  **Next: turn this into an implementation plan.** 15 cross-cutting rulings + 13 open questions captured.
- 2026-05-30: **M5 complete → MVP done (M0–M5).** Accept/dismiss status (API+UI), dedup engine+endpoint,
  findings/project export (CLI + API), README finalized. 69 tests pass; `just demo` green. Remaining
  work is polish (see UI backlog) + optional hardening (cassettes, Ghidra, Celery, compose smoke test).
- 2026-05-30: **M4 complete** — follow-up spawner (endpoint + UI + parent_finding_id), pattern_sweep
  homes findings on the matched sibling with related_to edges, harness_generation compiles the emitted
  source in the sandbox (gcc in image), demo extended to show the spawn chain. 66 tests pass.
- 2026-05-30: **M3 complete** — radare2 decompiler seam (probe + R2Decompiler, image rebuilt with r2 6.1.4);
  real backends `anthropic` (BYOK, SDK exception mapping, cost estimate) + `claude_code` (CLI, graceful);
  shared schema-embedding system prompt; per-task + per-project cost (API + UI readout). 62 tests pass.
  Anthropic SDK added to dev/byok extras. Real backends tested offline via injected fake client.
- 2026-05-30: **UI review** — no Chrome MCP connector in this env; drove the UI via ad-hoc headless
  Chromium (Playwright, dev-only, not added to deps). UI is solid for an MVP; captured refinements in
  docs/ui-backlog.md. Next: M3-T5 (real backends) + M3-T1 (radare2 decompiler).
- 2026-05-30: **M3 mock path** — `engine/llm_tasks.py` runs static_analysis/reverse_engineering/
  pattern_sweep/harness_generation through the backend seam (mock); related_to edges from
  related_target_refs; CLI `run`; API task launch + UI task launcher (type+scenario). 51 tests pass.
  Live server verified driving the critical_overflow flow. Real backends (T5) + decompiler (T1) left.
- 2026-05-30: **M2 complete** — sandbox runner (locked-down docker), recon + firmware-unpack probes,
  engine (recon/unpack/graph/worker/pipeline), JSON API + offline Cytoscape UI, fixtures built,
  `just demo` exits 0. 44 tests pass (Docker-gated tests skip without the sandbox image).
  Sandbox image: `just sandbox-build` (radare2 deferred to M3). UI uses vanilla JS not HTMX (noted).
- 2026-05-30: **M1 complete** — config (no-key-leak), SQLAlchemy models + session, ingest,
  CLI (init/ingest/targets), FastAPI on loopback + bind guard, docker-compose/Dockerfile.
  39 tests pass. git ownership fixed by user.
- 2026-05-30: ⚠️ **git commits were blocked** — `.git/objects` + `.git/config` are owned by `root`
  (initial commit was made as root), so this user can't write git objects. Fix once with:
  `sudo chown -R jonsnow:jonsnow .git`. Until then work is saved on disk + tracked here in
  PROGRESS.md; commits (the secondary resume trail) will be made retroactively per-task.
- 2026-05-30: **M0 complete** — Finding model, LLM seam, MockLLMBackend (3 layers minus cassette
  recording), fault injection, contract test. 27 tests pass. Docker installed mid-session → M2 unblocked.
- 2026-05-30: planned M0–M5; created branch, scaffolding; started M0.
