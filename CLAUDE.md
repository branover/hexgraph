# CLAUDE.md

Guidance for Claude Code working in this repo. These instructions override default behavior — follow them exactly. This file is durable orientation + rules, **not** a changelog. Per-phase status and history live in `PROGRESS.md`.

## What HexGraph is

A self-hosted, **local-only** agentic vulnerability-research workbench. Point it at a binary/firmware → it ingests the target, breaks firmware into child targets, runs AI-driven analysis tasks using the user's own model access, and records every result as a structured **finding** in a SQLite-backed **typed graph** (targets · nodes · findings · tasks). A loopback web UI browses the graph, launches tasks, and triages findings. The whole system exists to prove one loop: **target → task → structured finding → graph → spawn next task.**

## ▶ Start every session here

1. Read **`PROGRESS.md`** — its `▶ RESUME HERE` block is the source of truth for current state, next task, and how to re-verify.
2. Re-verify with `just test` (full suite, mock backend, offline) and `just demo` (full loop; needs Docker + sandbox image).
3. **Update `PROGRESS.md` as work lands** (checklist + `▶ RESUME HERE` + session log) and commit it with the code. Keep this file current only when a *durable rule or fact* changes — never add feature history here.

## How we work: git worktrees, PRs, and concurrency

Post-MVP, **every new feature or major atomic change happens on its own branch in a dedicated git worktree**, so multiple agents work in parallel without stepping on each other. Trivial one-line touch-ups can go on a normal branch; anything substantial gets a worktree.

**Git/GitHub rules (non-negotiable):**
- **Never commit or push to `main`.** `main` only changes by **merging a reviewed PR**. (There is no automated push guard or branch protection — this is a discipline you must keep, not something the repo enforces for you.)
- Branch off `main` with a typed name: **`build/<topic>`** (code), **`fix/<topic>`** (bugfix), **`docs/<topic>`** (docs).
- Commits: imperative, lowercase-prefixed subject (`feat:`/`fix:`/`docs:`/`db:`/…); end every commit with the trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Ship the whole change together:** code + its tests + `PROGRESS.md` update + (for any model change) an `alembic revision --autogenerate` migration. A PR that changes a model without a migration is incomplete.
- Open the PR with `gh pr create --base main`; write a real description (what/why, verification).

**The merge gate — a PR-review subagent, every time.** Before a worktree branch merges:
1. Run `just test` (and `just demo` if the loop is touched) green in the worktree.
2. **A review subagent — a *different* agent than whoever wrote the code — must review the PR diff** (correctness, the security invariants [loopback / sandbox / secret-never-logged / the opt-in execution policy], test quality, and that docs/PROGRESS/migrations were updated). **Who launches it depends on who can:**
   - If you are doing the work yourself and the `Agent` tool is available to you, **dispatch the reviewer yourself**.
   - **If you were *delegated* this work by a parent/orchestrator agent (you are a work-subagent) and cannot spawn a nested subagent: do NOT treat reviewing your own diff as a substitute, and do NOT merge on your own review. Finish the implementation, push the branch, open the PR, and STOP — report the PR number back. The agent that initiated you then launches the PR-review subagent against your PR** (and addresses/merges per the steps below). Whoever spawns work-subagents **owns** launching the reviewer for every PR those subagents produce — this is a standing orchestrator responsibility, not optional.
   - Self-reviewing inline is only an acceptable *fallback* when no agent in the chain can spawn a separate reviewer at all, and the PR must say so explicitly.
3. **Every requested change or piece of commentary the reviewer raises MUST be posted on the PR itself** — as a review with line-level comments / suggested changes (`gh pr review --comment` or `--request-changes`; `gh api .../pulls/{n}/comments` for inline suggestions), not only returned to the dispatching agent. This is a durable, public log for posterity. A verbose summary back to the dispatching agent is welcome **in addition**, never instead. The reviewer then **fixes the issues** (commit referencing the comment) or hands them back; re-verify after fixes.
4. Only after the review passes (its PR comments addressed): merge with **`gh pr merge --merge --delete-branch`** (the `--delete-branch` deletes the branch **both locally and on the remote**). There is **no CI yet**, so this review + local `just test` *is* the gate.
5. **Clean up completely:** `git worktree remove <path>`, and ensure the merged branch is gone **locally and remotely** (`git branch -d <branch>` + `git push origin --delete <branch>` if `--delete-branch` didn't, then `git fetch -p`). Then fast-forward the primary `main` checkout. **Standing invariant: the only worktrees and branches that should ever exist (local or remote) are ones actively being worked on** — `git worktree list`, `git branch`, and `git branch -r` should show just `main` plus the live work. Prune anything stale on sight.

**Creating a worktree (with its own isolated runtime):**
```bash
git worktree add ../hexgraph-wt/<topic> -b build/<topic> main
cd ../hexgraph-wt/<topic>
just install                                                        # OWN venv — required (= python3 -m venv .venv && pip install -e ".[server,dev]")
export HEXGRAPH_HOME="$PWD/.hghome"                                  # OWN data/DB/settings
```
(`just` is the task runner — install once with `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin` or `snap install just`; `~/.local/bin` on `PATH`.)

**Running code from worktrees concurrently — deconflict ALL shared state.** Nothing is worktree-aware by default; isolation comes entirely from per-worktree env + venv:
- **Own venv (required).** The editable install pins an *absolute* `src` path, so reusing another worktree's `.venv` silently imports the *wrong* worktree's code. Each worktree gets its own `.venv` (`just install`). `just ui` already builds the SPA into the worktree's own `src/hexgraph/web/dist` (gitignored) — no sharing.
- **Own `HEXGRAPH_HOME`.** All runtime state (the SQLite DB, `projects/`, `settings.json`, `config.toml`) roots at `HEXGRAPH_HOME` (default `~/.hexgraph`), which is otherwise **shared across every worktree**. Without a per-worktree home, two agents mutate the same graph and a newer-migration worktree silently upgrades the shared DB schema. (WAL keeps it lock-*safe*, but that is not isolation.) Copy `~/.hexgraph/config.toml` into the worktree home if you need the BYOK key.
- **Own `HEXGRAPH_PORT` when serving.** Two `hexgraph serve` on the default `8765` collide. Use `HEXGRAPH_PORT=876N hexgraph serve`; keep `HEXGRAPH_HOST=127.0.0.1` (the loopback assertion is a product invariant — never `0.0.0.0` to "spread out").
- **Sandbox image (`hexgraph-sandbox:latest`) is host-global.** Probe `.py` edits need no rebuild — they're **mounted from your worktree's package** at run time (set `HEXGRAPH_SANDBOX_NO_MOUNT=1` only to force the baked copy), so probe changes are already per-worktree. But a **Dockerfile/toolchain change (or `with_ghidra=1`) must NOT run `just sandbox-build`** — that clobbers the shared tag. Build a private tag and point only your processes at it: `docker build -f docker/sandbox.Dockerfile -t hexgraph-sandbox:wt-<topic> .` then `export HEXGRAPH_SANDBOX_IMAGE=hexgraph-sandbox:wt-<topic>`. (Containers are uuid-named + `--rm`; they never collide.)
- **MCP + Claude Code (the subtle one).** The MCP server is **stdio** (spawns per session, no port) and a registration **bakes an absolute interpreter/script path with no env**, while the server name is hardcoded `"hexgraph"`. So **`cd`-ing between worktrees does NOT change which code or DB the agent's MCP tools use** — it's frozen to the registered command + the spawning agent's ambient env (which falls back to `~/.hexgraph`). To test MCP changes that live only in your worktree, editable-install it, then register a **uniquely-named** server pinned to that worktree's python + home:
  ```bash
  claude mcp add hexgraph-<topic> --env HEXGRAPH_HOME=$PWD/.hghome -- $PWD/.venv/bin/python -m hexgraph.cli mcp
  ```
  Verify the command resolves to your code with `.venv/bin/python -m hexgraph.cli mcp --check`. Two agents must use **distinct MCP server names and distinct `HEXGRAPH_HOME`** — never share the default `hexgraph` registration across worktrees (it runs stale code and shares the DB).
- **Already safe, no action:** `just test` (the `hg_home` fixture isolates each test in a tmp home, mock backend, Docker/decompile disabled) and `just demo` (its own tmp home) are self-isolating across worktrees — only Docker throughput competes for the sandbox-gated subset.

## Non-negotiable constraints (these define the product)

- **Fully self-hosted.** Nothing calls a HexGraph-operated backend; no telemetry, no auto-update pings.
- **Loopback only.** API/UI bind `127.0.0.1`; a startup assertion refuses a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`.
- **BYOK / Claude Code / mock only.** No bundled keys, no proxying. Read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never log, store, or return it.** `HEXGRAPH_API_KEY` is reserved for future paid features — same rule.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes runs only inside the disposable Docker sandbox (`--network none`, read-only rootfs, mem/cpu/pids caps, tmpfs, hard timeout). **Executing the target is opt-in, gated solely by the policy seam** (`policy.current_policy()` / `assert_allows_execution()`): static-only is the **default**, and it **must be enforced whenever the user hasn't opted into a dynamic/execution analysis** — with neither `features.poc` nor `features.fuzzing` enabled, any attempt to run the target raises. Enabling PoC/fuzzing flips the policy to permit execution, still *inside the same locked-down sandbox* (foreign-arch via qemu-user). **Network egress is the same story**: `--network none` is the default and the *only* place it relaxes is the policy seam — opt-in `features.network` raises the bounded local-network tier (`assert_allows_egress(dest, scope)` + a per-target `NetworkScope` that refuses any non-loopback/private host; every outbound action is audited to `EgressEvent`). **Rehosting is its own separately opt-in gate** (`features.rehost` / `policy.assert_allows_rehost()`): full-system emulation of a firmware image boots inside the sandbox boundary, alongside the exec (poc/fuzzing) and network gates. So static-only/no-network is an **enforced default, not an absolute ban** — but **never relax a gate anywhere except the policy seam**. **The LLM never sees raw target bytes** — only tool output carried in `TaskContext`.
- **Zero token spend by default.** Mock backend is the dev/CI default; `just demo` runs the full loop offline with no key and exits 0.
- **The Finding schema is frozen** (`src/hexgraph/schemas/finding.schema.json`, shipped in-package). Every task and backend (mock included) emits exactly this shape; a contract test enforces it. New structure goes in the DB envelope, not the schema.
- **Migrations are mandatory.** The project DB is durable researcher knowledge, never silently reset. Any schema change ships an `alembic revision --autogenerate` committed with the model change.

## Architecture & the seam rule

**Ask a seam, never branch on backend identity, license tier, or executor.** Feature code calls a seam; concrete implementations swap behind it. The seams:

- **`LLMBackend`** (`llm/`, selected by `HEXGRAPH_LLM_BACKEND`, default `mock`): `MockLLMBackend` / `AnthropicAPIBackend` / `ClaudeCodeBackend`. **Never write `if backend == "mock"` in task code.** LLM tasks run an **agent loop** (`llm/runner.run_findings_agentic`): HexGraph advertises sandboxed tools (`engine/agent_tools.py` — decompile/strings/imports/…, fuzz when enabled), the model requests tool calls, HexGraph executes them in the sandbox and feeds results back until the model emits findings. The loop is a strict superset of a single pass (a backend answering on turn one is unchanged); the mock drives it offline via fixtures carrying a `tool_calls` key. The model never touches the environment — it directs, HexGraph runs the tools (so a plain BYOK API key is sufficient; no external coding agent required).
- **Executor** (`sandbox/executor.py` `get_executor()`): the container boundary for all target-byte handling. Future remote/dynamic executors drop in here.
- **Decompiler** (`sandbox/decompiler.py` `get_decompiler()`): radare2 default; Ghidra (headless/bridge) when enabled in Settings. `HEXGRAPH_DECOMPILER` overrides.
- **Rehoster** (`engine/rehost.py` `get_rehoster()`): boots a whole firmware image under full-system emulation. `FirmAERehoster` (vendor blobs, privileged container) and `QemuDiskRehoster` (full-OS disk images, KVM) implement it; `select_rehoster(firmware_path)` auto-selects by image type. Gated by `policy.assert_allows_rehost()`. The emulated device's web surface registers as a `web_app` child target.
- **Entitlements / Metering / Policy / Principal / Suggester** — thin local-default seams (`entitlements.py`, `metering.py`, `policy.py`, `principal.py`, `engine/suggester.py`); they allow/grant everything today so paid/dynamic/multi-user features land additively.

**Data model** (SQLite + SQLAlchemy, UUID ids): `project`, `target` (self-referential tree; a target is a *reachable surface* — a byte target with a `path`, or a dynamic surface reached via a Channel in `metadata_json` — `web_app` (HTTP), `service` (a bare raw-TCP/UDP listener, `engine.surfaces.register_socket_target`), or `remote` (SSH/telnet); see `docs/design-dynamic-surfaces.md`), `node` (typed sub-file entities: function/symbol/string/struct/hypothesis/pattern/input/sink/**socket**/**endpoint**/**param**), polymorphic attributed `edge` (`(src_kind,src_id)`→`(dst_kind,dst_id)` over target|node|finding|task; route→handler is **`routes_to`**), `task`, `finding`. The graph is relational — **Neo4j is out of scope.** Note: `finding.status` is a **plain String** (use `f.status`, never `.status.value`); `task.status` is still an Enum. SQLite runs in **WAL mode** (`db/session.py`) so the web app and an agent's MCP server (separate processes) share the DB concurrently; **foreign-key enforcement is deliberately OFF** (edges/annotations are polymorphic string refs, not FKs). `NodeType`/`EdgeType` are **String columns** so new vocab is zero-migration.

**Typed attributed edges & sockets:** edges carry type-specific attributes (`edge.attrs_json`); `engine/edge_schemas.py` is the registry of what's *meaningful* per type (e.g. `calls`→`call_sites`/`arg_constraints`, `listens_on`→`address`/`backlog`) + `SOCKET_KINDS`. It's guidance, not a hard schema — unknown keys pass, but **list attributes merge as sets** (`merge_edge_attrs`; `add_edge(merge=True)` / `create_edge(merge=True)` / `update_edge` accumulate `call_sites` rather than clobber). A `socket` node is a network/IPC endpoint **shared across binaries** (identity = `(project, kind, port|name)` via content_hash, `target_id=None`) so a server `listens_on` it and a client `connects_to` it resolve to one node — the firmware's network map (`mcp_tools.list_sockets`, `engine.nodes.materialize_socket`, `engine.authoring.create_socket`).

**Node identity & dedup:** function/symbol/struct identity is the *normalized* name within a target (`engine.nodes.normalize_symbol_name` strips decompiler prefixes so `sym.get_param` == `get_param`); `get_or_create_node` normalizes at creation. `engine/nodemerge.py` (`merge_duplicates`) folds existing duplicates by per-type canonical key (functions→normalized name, strings→value hash, targets→sha256), moving all edges/findings/annotations to the keeper — run automatically after LLM tasks, and on demand via `POST /api/projects/{id}/merge-duplicates` / the `merge_duplicates` MCP tool / the "Merge dupes" toolbar button.

## Where things live

```
src/hexgraph/
  config.py settings.py        # config.toml (user/secrets, never rewritten) + settings.json (managed, writable)
  setup_wizard.py setup_catalog.py  # `hexgraph setup` interactive wizard + its feature/gate registry
                               #   (each features.* entry: label, what it unlocks, its SECURITY IMPLICATION,
                               #    policy tier, required build steps — read by the wizard, never policy logic)
  models/finding.py            # the frozen Finding/Evidence/FollowupSuggestion Pydantic models
  llm/                         # backend seam: base, mock, anthropic_api, claude_code, registry, cassette
  sandbox/                     # runner (docker boundary), executor, decompiler; probes/ mounted from the install
                               #   (http_probe = live web assessment + session cookie jar)
  engine/                      # ingest, pipeline, recon, unpack, worker, nodes, edges, edge_schemas, nodemerge,
                               #   context, runs, findings, poc, fuzzing, tasks, followups, dedup, search, report,
                               #   crosstarget, authoring, annotations, hypotheses, filesystem, mcp_tools, targets,
                               #   removal, surfaces, rehost, node_schemas,
                               #   ghidra, ghidra_bridge, suggester, capabilities, cas
  api/app.py                   # FastAPI: all REST endpoints + serves the SPA at / (loopback)
  cli.py                       # hexgraph init|setup|db upgrade|ingest|targets|run|findings|graph|prune|rehost|config|serve
docker/                        # ALL Dockerfiles: app.Dockerfile (the full app for `docker compose up`),
                               #   sandbox.Dockerfile / build.Dockerfile / fuzz.Dockerfile (sibling analysis images,
                               #   build context = repo root), firmae/ + qemu/ (rehosting). docker-compose.yml is at repo root.
frontend/                      # React+Vite+TS SPA → built to src/hexgraph/web/dist by `just ui` (gitignored)
migrations/                    # Alembic; baseline bbdb1d98bf54. prepare_database() in db/migrate.py
tests/                         # pytest; fixtures under tests/fixtures (built by build.sh / `just fixtures`)
docs/                          # design-vision.md, implementation-plan.md, ui-backlog.md, mock-llm-provider.md
```
The frozen Finding schema and the mock-LLM fixtures ship **inside the package**:
`src/hexgraph/schemas/finding.schema.json` and `src/hexgraph/llm/fixtures/mock_llm/`
(resolved by `paths.py` relative to the package, packaged into the wheel). The MVP
`context/` build bundle has been retired — its live assets moved in-package, its spec
and notes superseded by this file + README + `docs/`.

Key disciplines: **probes are mounted from the install at run time** (`sandbox/runner.py` overlays `sandbox/probes/` read-only over the image's baked copy), so **editing or adding a probe needs no rebuild** — including `http_probe` (live web assessment) — only a toolchain change does (`just sandbox-build`, which forwards `--build-arg WITH_GHIDRA`; `with_ghidra=1` adds Ghidra + the enhanced unpack toolchain; set `HEXGRAPH_SANDBOX_NO_MOUNT=1` to force the baked-in copy). Tests use `init_db()` (create_all) on throwaway DBs and never migrate; persistent DBs migrate. Decompilation/harness-compile are best-effort and env-gated (`HEXGRAPH_DISABLE_DECOMPILE`, `HEXGRAPH_DISABLE_SANDBOX_BUILD`) — never gated on backend identity.

## Optional features & settings

`settings.json` (managed, written via `PATCH /api/settings` or `hexgraph config set`) holds non-secret prefs and optional-feature toggles, layered as **env > settings.json > config.toml > defaults**. Secrets are never written there and reported as presence-only. Optional features:
- **Ghidra** (`features.ghidra`): `headless` (analyzeHeadless in the sandbox, needs `just sandbox-build with_ghidra=1`), `bridge` (connect to a running Ghidra via `ghidra_bridge`), `enrich_recon` (materialize functions/call-graph/structs). Degrades to radare2 when off.
- **Fuzzing** (`features.fuzzing`, default off): the `fuzzing` task type. Enabling it (or PoC, below) makes `policy.current_policy()` return a dynamic profile (`allow_execution=True`) — the policy seam is **the only place the static-only invariant is relaxed**; the sandbox stays `--network none`, capped, timed. Compiles a `harness_generation` harness with libFuzzer+ASan and auto-creates a finding per crash. `engine/fuzzing.py`, `sandbox/probes/fuzz_probe.py`.
- **PoC verification** (`features.poc`, default off): the `poc` task + `verify_poc` MCP tool **execute the target** in the sandbox with an attacker input and confirm exploitation via an unforgeable `{{NONCE}}` oracle (engine substitutes a random token; "verified" = the injected behaviour really happened). `engine/poc.py`, `sandbox/probes/poc_probe.py`. Also policy-gated. **Foreign-arch targets run under qemu-user** — `poc_probe` picks `qemu-<arch>` from the ELF header and `verify_poc` mounts the parent firmware's extracted rootfs as the qemu sysroot (`-L`) so a dynamically-linked MIPS/ARM/… binary finds its libs (verified end-to-end on real MIPS firmware).

**Firmware extraction** (`sandbox/probes/unpack_probe.py`): bare squashfs → **sasquatch** (patched unsquashfs for vendor/LZMA squashfs; falls back to `unsquashfs`); cpio → `cpio`; **partitioned full-OS disk images** (MBR/GPT, e.g. an x86/ARM SD card or VM disk — recon detects these via `_is_disk_image` → `format=disk_image`) → **The Sleuth Kit** (`mmls` + `tsk_recover`, unprivileged, no loop-mount) pulls the rootfs out of the largest Linux/ext partition, falling back to binwalk (which also handles a squashfs-on-a-partition rootfs like OpenWrt-x86); wrapped/real vendor firmware (TRX/uImage → squashfs/jffs2/ubifs/cramfs, often nested) → **binwalk recursive** (`-eM`), which drives sasquatch / jefferson (JFFS2) / ubi_reader (UBIFS). All in the `WITH_GHIDRA=1`-or-default sandbox image (sleuthkit + e2tools included); rebuild after changing the toolchain.

**Firmware rehosting** (`features.rehost`, default off): boots a firmware (FirmAE for vendor blobs, qemu+KVM for full-OS disk images — `select_rehoster` picks by image type) → registers its live web UI as a `web_app` surface child. The probe joins the emulator container's netns to reach the device's private IP. Gated by `policy.assert_allows_rehost()`; `engine/rehost.py`, `docker/firmae`, `docker/qemu`. Boot needs `features.rehost`; assessing the running device needs `features.network`.

**Remote live devices** (`features.remote`, default off): the **live-remote tier** (`TIER_LIVE_REMOTE`, `policy.assert_allows_remote()` + `remote_scope(host,port)`). A `remote` target reached over **SSH/telnet** (a physical box on the bench, no firmware in hand) on which the agent runs the SAME read-only analysis as on a rootfs — `remote_list_files` / `remote_read_file` / `remote_run` (a fixed read-only tool allowlist; no arbitrary shell). Egress is pinned to the one operator-authorized host (any host — operator's responsibility, unlike the loopback/private web tier) and audited. **Credentials are secrets** — read at connect from env (`HEXGRAPH_REMOTE_PASSWORD`/`_KEY`) or `config.toml [remote]`, never stored in the DB. `engine/remote.py`, `sandbox/probes/remote_probe.py` (paramiko/telnetlib in the sandbox image).

**Findings are typed** (`finding.finding_type`, migration 0008 — DB envelope, not the frozen JSON schema): `vulnerability | recon | harness | fuzz_crash | poc | annotation | other`, classified from the producing task (`engine.findings.classify_finding`), used for sort/filter in the findings panel. A PoC that verified is surfaced as `verified` (derived from `evidence.extra.verification`).

**Entity removal** is graduated and mostly reversible (`engine/removal.py`, via API + MCP + UI). Targets can be **soft-removed** from the Targets pane (`target.archived`, migration 0007): archives the parent_id subtree, hiding its nodes/findings from graph/detail/search/report without deleting; re-adding the same bytes (sha256) restores them. Individual **nodes** archive/restore the same way (`node.archived`, migration 0011 — hides the node and the edges touching it) via `archive_node`/`restore_node` (MCP) and `archive_target`/`restore_target` for subtrees. Hard deletes: `delete_edge` (one edge, recreate to restore) and `delete_project` (operator-only, not an MCP tool). Firmware targets persist their **unpacked filesystem** (`metadata_json["filesystem"]`, files under `<data_dir>/unpacked/<id>/`) — browsable in the detail panel, any file addable as a child target (`engine/filesystem.py`).

**Coding-agent integration (MCP), two directions, both keep target bytes in the sandbox:**
- **Driver mode** — `hexgraph mcp` (stdio, optional `[mcp]` extra; `mcp_server.py` + `engine/mcp_tools.py`) exposes HexGraph's sandboxed primitives so an external agent (Claude Code/Codex/gemini-cli) inspects targets, populates the graph (findings/nodes/edges/hypotheses/annotations), and runs sandboxed tasks. Tools are grouped read/write/run and gated by `features.mcp.{read,write,run}` (+ `--tools` / Settings) so the agent's context stays small. `hexgraph mcp install` prints registration steps (`agent_setup.py`).
- **Delegate mode** — opt-in `features.agent` + an `agent_delegate` task (`engine/agent_delegate.py`): HexGraph launches the configured agent CLI headless, wired to the MCP server + VR skill, **restricted to HexGraph's sandboxed tools** (no shell on the target).
LLM tasks themselves use a tool-use **agent loop** (above) over a plain BYOK key — the model directs, HexGraph runs the tools; Claude Code/Codex are an *alternative backend/driver*, never required.

## Commands

- The repo's task runner is **`just`** (install: `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`, or `snap install just`; ensure `~/.local/bin` is on `PATH`). Run bare **`just`** for the grouped recipe menu (setup · run · build · test · demo · rehosting · maintenance). Recipe doc-comments state **when to rebuild** (e.g. `ui` after any `frontend/` change; `sandbox-build` only after a Dockerfile/toolchain change — probes are mounted at runtime, no rebuild).
- **`just setup`** — one-shot bootstrap (venv + deps + SPA) then launches the **interactive setup wizard** (`hexgraph setup`, `setup_wizard.py` + the `setup_catalog.py` feature/gate registry; Rich panels + questionary): pick which optional `features.*` to enable — each policy-relaxing one shown with its **security implication** + an explicit confirm — plus non-secret config (loopback-default bind, backend, Ghidra mode), then it writes settings via the settings layer (**never a secret** — those stay in env/config.toml, presence-only) and runs the chosen image builds + db init. **CI-safe / non-interactive:** with no TTY (or `just setup yes=1`, or `hexgraph setup --non-interactive|--yes|--defaults`) it applies the static-only baseline + sandbox image WITHOUT prompting, so an unattended `just setup` never hangs. Then **`just serve`** → http://127.0.0.1:8765.
- `just test` (= `pytest -q`, mock, offline; Docker-gated tests skip if the sandbox image is absent) · `just demo` (full loop, needs Docker) · `just test-live` (real-key scored eval, needs `ANTHROPIC_API_KEY`, cassette-backed).
- `just ui` (rebuild SPA) · `just sandbox-build [with_ghidra=1]` · `just fixtures`.
- **Containerized path (optional):** `just app-build` builds the full app image (`docker/app.Dockerfile` — Node builds the SPA, Python installs the package, includes the docker CLI); `just up` / `just down` run `docker-compose.yml` (one `app` service, published on **host loopback only** `127.0.0.1:8765:8765`, host Docker socket mounted so the app spawns its sandbox/build/fuzz siblings on the host daemon). The container sets `HEXGRAPH_IN_CONTAINER=1` so the loopback guard accepts its `0.0.0.0` bind (the host-loopback guarantee is preserved at the publish boundary). The host pip path (`just setup` → `just serve`) stays primary/dev.
- Rehosting: `just firmae-build` (FirmAE image; privileged + /dev/net/tun) · `just qemu-build` (QEMU+KVM image; needs `--device /dev/kvm`) · `just iotgoat` (fetch+rehost+register IoTGoat) · `just vulnrouter` (live vulnrouter web target + project).
- CLI: `hexgraph init | db upgrade | ingest <path> [--name --project --backend --no-recon] | targets <p> | run <target> --type T [--objective --model --backend --function --mock-scenario] | rehost <target> [--brand] | findings <p> | graph <p> --export f.json | prune <p> | config list|get|set | serve`.
- Runtime data under `~/.hexgraph/` (override with `HEXGRAPH_HOME`, db with `HEXGRAPH_DB_PATH`).

## Environment gotchas

- **`grep` is aliased to ripgrep (`rg`) on this system.** So GNU-grep flags don't apply: there's no `--include` (use `--glob`/`-g`), recursion and smart-case are on by default, and PCRE differs. Prefer the dedicated Grep tool; when you must shell out, use ripgrep syntax.

## Read before writing code

1. **This file (`CLAUDE.md`) + `README.md`** — the source of truth for constraints, data model, the seam rule, and the graduated opt-in policy model. (The MVP `context/SPEC.md` is retired; its constraints live here, evolved past the original static-only framing.)
2. `docs/mock-llm-provider.md` — the mock backend design (three fidelity layers, scenarios, contract test).
3. `src/hexgraph/schemas/finding.schema.json` — the canonical, frozen Finding schema (shipped in-package).
4. `docs/design-vision.md` + `docs/implementation-plan.md` — the v2 target shape and sequenced plan.
5. `docs/design-dynamic-surfaces.md` + `docs/design-rehosting.md` — dynamic web surfaces and firmware rehosting.

When a workflow becomes repetitive, capture it as a skill under `.claude/skills/` and note it in `PROGRESS.md`.

## Assessing the UI visually (Playwright)

No browser MCP here and `WebFetch` can't reach `127.0.0.1`; the UI is JS-driven, so fetching HTML isn't enough. Drive headless Chromium via Playwright (dev-only, **not** in `pyproject`):

```bash
.venv/bin/pip install playwright && .venv/bin/playwright install chromium
```

Seed data + serve on a spare port with an isolated `HEXGRAPH_HOME`, then screenshot in Python (`p.chromium.launch(args=["--no-sandbox"])`, `goto(..., wait_until="networkidle")` + a short `wait_for_timeout` so Cytoscape/fetches settle, then `page.screenshot(...)`). **View the PNGs with the Read tool** (it renders images). Kill the backgrounded `serve` PID when done. Record UI findings in `docs/ui-backlog.md`.
```python
b = await p.chromium.launch(args=["--no-sandbox"])
pg = await b.new_page(viewport={"width": 1440, "height": 900})
await pg.goto(f"{BASE}/projects/{PROJ}", wait_until="networkidle"); await pg.wait_for_timeout(1500)
await pg.screenshot(path="/tmp/ui/workspace.png")
```

**Judge the screenshot as a HUMAN would, not as an LLM.** An LLM can absorb far more on-screen information than a human eye and won't be bothered by misalignment, cramped spacing, inconsistent styling, or a dated look — humans are bothered by exactly those things, and they decide in seconds whether a UI feels inviting or overwhelming. So when you View a PNG, don't just check that the information is *present* — assess it like a person seeing it for the first time: **Does the eye flow naturally to the important content? Is there enough breathing room, alignment, and visual hierarchy that it feels calm rather than busy? Does it look modern and polished, or dated/scotch-taped? Would this make someone excited to dive in and explore, or intimidated and inclined to bounce?** Information completeness is necessary but NOT sufficient — a screen that is technically complete but feels cluttered, ugly, or overwhelming has failed. Iterate (adjust → `just ui` → re-screenshot → re-judge) until it would genuinely delight a human, not merely satisfy a parser. This is a vision to strive for on every UI change.

**Committed doc screenshots live in ONE canonical folder — `docs/images/`** — regenerated by `just capture` from the deterministic `just showcase` seed; every README/doc embeds them by **stable name**, so a UI change → re-run `just capture` → all docs update in place. Don't scatter images across the repo, and keep the captured set and the doc-referenced set identical.
