# HexGraph Build Progress

The durable, resumable record of this build. **A new session should read this file first**,
then run the resume verifier, then continue at the next unchecked task.

## ▶ RESUME HERE
- **Current milestone:** v2 build — see [`docs/implementation-plan.md`](docs/implementation-plan.md)
  (built from [`docs/design-vision.md`](docs/design-vision.md)). MVP (M0–M5) is the foundation.
- **Dynamic surfaces (new track, see [`docs/design-dynamic-surfaces.md`](docs/design-dynamic-surfaces.md)):**
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
- **Current state:** **P0–P8 all delivered** (core) + **researcher depth (P6/P7) complete**: annotations
  (rename/note/tag, agent-proposed→confirm, confirmed facts feed context), hypothesis lifecycle
  (evidence-derived status, sticky human verdict, open hypotheses feed context), in-app report viewer +
  run-compare diff UI. Remaining documented sub-items (not whole phases): richer approval gates (review-on-
  output / plan / spend), P7-5 (offline CVE / bounded dataflow / reviewable dedup), FTS5 search,
  SSE live activity, real-key cassette recording (`make test-live`). (Ghidra decompiler is DONE —
  see Optional features below.)
- **Optional features (settings-driven, `settings.py` + `/api/settings` + `hexgraph config`; secrets status-only):**
  **Ghidra** (headless `WITH_GHIDRA=1` / bridge / enrich_recon), and **Fuzzing** (`fuzzing` task, off by
  default — the one thing that relaxes static-only, via the policy seam: libFuzzer+ASan on a generated
  harness, finding-per-crash, optional LLM triage). **Target soft-removal** (archive subtree, restore on
  re-add) and **firmware filesystem browser** (persisted unpacked tree, add any file as a child target;
  library exports → nodes; function nodes launch tasks).
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
- **Last verified:** `.venv/bin/python -m pytest -q` → 246 passed, 2 skipped (live test skips without a
  key; one Docker-gated when the sandbox image is absent); SPA builds clean. Sandbox image
  (`WITH_GHIDRA=1`) includes Ghidra + qemu + firmware extractors and works end-to-end.
- **UI quickstart (updated):** `make ui` once → `make sandbox-build` once →
  `hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo` → `hexgraph serve` → http://127.0.0.1:8765.
- **How to re-verify:** `make test`; or run the UI (see UI quickstart below).
- **v2 sequencing:** P0 seams/migrations → P1 typed graph → P2 context bundle/CAS → P3 task anchors →
  P4 React notebook UI → P5 finding/task management → P6 HITL/triage → P7 search/report/cross-target →
  P8 real-key vuln-target test. Thin future-proofing seams (entitlements, metering, executor, policy,
  principal, suggester) land in P0 with local defaults — **ask a seam, never branch on backend/tier/executor.**
- **UI quickstart:** `make sandbox-build` once → `hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo`
  → `hexgraph serve` → open http://127.0.0.1:8765 → click a target, pick task type + scenario, Run.
- **Open notes / gotchas:**
  - **Docker required** for recon/unpack/decompile/harness/demo; `jonsnow` is in the `docker` group.
    Build the sandbox image once with `make sandbox-build` (re-run after editing probes or the Dockerfile).
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
- [x] M2-T1 `Dockerfile.sandbox` (file/binwalk/strings/pyelftools/lief; Ghidra opt-in build arg).
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
      `make demo` runs ingest→recon→finding→graph offline, exit 0

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
- [x] M4-T4 `make demo` extended: static_analysis → spawn pattern_sweep follow-up → sibling finding +
      related_to + parent_finding_id. 66 tests pass.

## M5 — Polish ✅
- [x] M5-T1 Accept/dismiss finding status: POST /api/findings/{id}/status + UI Accept/Dismiss buttons
- [x] M5-T2 `engine/dedup.py` (signature = target+category+title+function+sink) + POST /api/projects/{id}/dedup
- [x] M5-T3 Export: `hexgraph findings <p> --export f.json`, GET /api/projects/{id}/export (graph+findings),
      graph export (`hexgraph graph --export`, from M2)
- [x] M5-T4 README finalized (markers flipped; CLI/UI/backends/roadmap accurate); `make demo` is the
      documented acceptance run (ends with the spawn chain)

## v2 execution — phases (detail in `docs/implementation-plan.md`)
- [x] P0 Foundations & seams: Alembic migrations (baseline `bbdb1d98bf54`) + `hexgraph db upgrade` (backup + legacy-adopt); seams `sandbox/executor.py` (get_executor), `policy.py`, `entitlements.py`, `metering.py`, `principal.py` with local defaults; reserved `HEXGRAPH_API_KEY`. 78 tests pass.
- [x] P1 Typed graph core: `node` table + content_hash identity (`engine/nodes.py`); polymorphic attributed `edge` (`engine/edges.py`, String type cols, no CHECK); findings attach via `about` edge; recon materializes bounded symbol/string nodes; decompile makes function nodes + `calls` edges; migration `0002_typed_graph`. 83 tests pass.
- [x] P2 Context Bundle + CAS: `engine/cas.py` content-addressed store; `engine/context.py` ContextBuilder (graph-walk + budget pack + drop tracking + deterministic `bundle_sha`); full trace (prompt/system/bundle/response/usage); `llm/cassette.py` response cassette keyed by bundle_sha (record/replay/auto); `engine/runs.py` analysis_run + diff_runs; CLI `prune`; migration `0003_context_runs`. 88 tests pass. (Staleness: deps recorded on bundle; UI surfacing deferred.)
- [x] P3 Task anchors (`anchor_kind`/`anchor_id`, migration `0004`) + edge-anchored context; `engine/capabilities.py` + `/api/capabilities`; `engine/suggester.py` FollowupSuggester+RuleBasedSuggester + `/api/findings/{id}/suggestions` (entitlement-gated); pattern_sweep edge carries `matched_from_finding_id`. 93 tests pass.
- [x] P4 Analyst-notebook UI (React+Vite+TS in `frontend/`, served at `/`): graph hub + visual grammar +
  progressive disclosure, Inspector (detail/triage/followups/suggestions), capability-filtered launchers,
  findings management (sort/filter/group/counts), cost badge. Verified via Playwright. `make ui` builds it.
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
  `hexgraph/eval.py` scored harness; `make test-live` (key-gated, cassette-backed, tight budget); no-key CI
  proves bugs statically present + scoring logic. 102 pass / 1 skipped.

## UI backlog
- Visual review done (headless Chromium screenshots). Requirements captured in
  [`docs/ui-backlog.md`](docs/ui-backlog.md) — P1/P2/P3, to tackle with M5 polish (some overlap M4 + M3-T6).
  Top P1s: graph finding-label overlap, non-interactive graph nodes, cramped detail panel,
  missing target-detail view, no live task feedback, no cost display.

## Project-specific skills created (note here as added)
- _(none yet — candidates: `regen-fixtures`, `run-task`, `add-mock-scenario`)_

## Session log (newest first)
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
  `ingest` MCP tool. 210 tests pass. NOTE: run `make sandbox-build` to bake the new fuzz/poc probes.
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
  collapsed to one-shot `make setup`. CLAUDE.md condensed to rules+orientation. 154 tests pass.
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
  findings/project export (CLI + API), README finalized. 69 tests pass; `make demo` green. Remaining
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
  `make demo` exits 0. 44 tests pass (Docker-gated tests skip without the sandbox image).
  Sandbox image: `make sandbox-build` (radare2 deferred to M3). UI uses vanilla JS not HTMX (noted).
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
