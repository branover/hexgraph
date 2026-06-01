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
  vulnrouter — auth bypass + RCE verified → 6 findings/11 nodes/29 edges. Plus **graph-quality + tool
  contracts**: every target-bound node gets a `contains` edge (no orphans); `engine/node_schemas.py`
  advertised via `get_schemas` with per-type `use_when`/recommended attrs + the sink-vs-symbol rule;
  `run_task` folds dupes; `test_tool_contract.py` locks it. `just sandbox-build` now forwards
  `--build-arg WITH_GHIDRA`. UI: PoC verification panel + re-verify, edit-any-field (finding+node),
  firmware file viewer, search-includes-targets, edge inspector, Author modals (`name·type·target` +
  type help + draw-to-connect), tighter Settings inputs.
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
- _(none yet — candidates: `regen-fixtures`, `run-task`, `add-mock-scenario`)_

## Session log (newest first)
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
  are sandbox-only) and unused `jinja2` from the `server` extra; dropped `lief` from `Dockerfile.sandbox`
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
