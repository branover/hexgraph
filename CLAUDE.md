# CLAUDE.md

Guidance for Claude Code in this repo; these instructions override default behavior. Durable orientation + rules, **not** a changelog — per-release history is in `CHANGELOG.md`, and current state is whatever `main` + the open PRs say.

## What HexGraph is

A self-hosted, **local-only** agentic vulnerability-research workbench. Point it at a binary/firmware → it ingests the target, breaks firmware into child targets, runs AI-driven analysis tasks on the user's own model access, and records each result as a structured **finding** in a SQLite-backed **typed graph** (targets · nodes · findings · tasks). A loopback web UI browses the graph, launches tasks, and triages findings. The whole system proves one loop: **target → task → structured finding → graph → spawn next task.**

## ▶ Start every session here

1. Orient from `main`: read this file + `README.md`, then `git log` / the open PRs for what's in flight.
2. Re-verify with `just test` (full suite, mock, offline) and `just demo` (full loop; needs Docker + sandbox image).
3. Update this file only when a *durable rule or fact* changes — never feature history (→ `CHANGELOG.md`).

## How we work: git worktrees, PRs, and concurrency

Post-MVP, **every new feature or major atomic change happens on its own branch in a dedicated git worktree** so agents work in parallel without colliding. Trivial one-line touch-ups can use a normal branch; anything substantial gets a worktree.

**Git/GitHub rules (non-negotiable):**
- **Never commit or push to `main`.** `main` changes only by **merging a reviewed PR**, enforced by the **`protect-main` ruleset**: a PR is required, **all review threads resolved**, **required checks green** (`tests (offline, py3.11)`, `tests (offline, py3.12)`, `frontend build`; strict, so the branch must be current with `main`), and **linear history** (no merge commits; direct/force pushes and `main` deletion blocked). **Required approvals is 0** — deliberate: GitHub won't let the lone owner approve their own PR, and a non-zero count could only be met by an `--admin` bypass that *also* skips strict CI. So **never `gh pr merge --admin`** (its only effect is to bypass CI). Merge needs collaborator **write** (owner-only), so 0 approvals can't let a fork PR self-merge; the **independent-review gate below is still required by discipline**. (If write collaborators are added, reconsider approvals=1 or `CODEOWNERS`.)
- Branch off `main` with a typed name: **`build/<topic>`** (code), **`fix/<topic>`** (bugfix), **`docs/<topic>`** (docs).
- Commits: imperative, lowercase-prefixed subject (`feat:`/`fix:`/`docs:`/`db:`/…); end every commit with the trailer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Ship the whole change together:** code + tests + (for any model change) an `alembic revision --autogenerate` migration; a model change without a migration is incomplete. **Any PR that changes UI behavior MUST update `docs/dev/ux-contract.md` in the same PR** (add/edit/retire the affected entries) — the review gate checks for it.
- Open the PR with `gh pr create --base main`; write a real description (what/why, verification).

**The merge gate — a PR-review subagent, every time.** Before a worktree branch merges:
1. Run `just test` (and `just demo` if the loop is touched) green in the worktree.
2. **A review subagent — a *different* agent than whoever wrote the code — reviews the PR diff** (correctness, the security invariants [loopback / sandbox / secret-never-logged / opt-in execution policy], test quality, docs/migrations updated). **Who launches it:**
   - Doing the work yourself with the `Agent` tool → **dispatch the reviewer yourself**.
   - **A work-subagent that can't spawn a nested subagent** → don't self-review or merge on your own review; finish, push, open the PR, STOP, and report the PR number. **Whoever spawned you launches the reviewer** — a standing orchestrator responsibility for every PR its work-subagents produce.
   - Self-reviewing inline is a *fallback* only when no agent in the chain can spawn a separate reviewer, and the PR must say so.
   - **The reviewer needs the review skills declared in its agent definition** — a subagent can only invoke skills its definition declares, else `/code-review` and `/security-review` are unavailable and it silently falls back to a weaker review. Use the checked-in **`pr-reviewer`** agent (`.claude/agents/pr-reviewer.md`; declares `Skill` + both skills) via `subagent_type: pr-reviewer`; it must run **both** `/code-review` and `/security-review` on the diff and post per step 3. (Give other subagents only the skills their task needs.)
3. **The reviewer's findings MUST be posted on the PR itself**, not just returned to the dispatching agent — the PR is the durable public log the gate requires. Post a summary review with `gh pr review <N> --comment --body-file <file>` (verdict APPROVE / REQUEST-CHANGES in the body **text**) plus line-level comments via `gh api repos/<owner>/<repo>/pulls/<N>/comments`. **Never `--request-changes` or `--approve`:** GitHub refuses both on your *own* PR ("Can not request changes on your own pull request"), and swallowing that error is a recurring reason findings never land — the verdict is body text, never a review *state*. **If `--comment` errors, fall back to `gh pr comment <N> --body-file <file>`** (a plain issue comment, no own-PR restriction); never abandon posting on one error, and verify the comment landed. The reviewer then **fixes blocking issues** (commit referencing the comment) or hands them back; re-verify after fixes.
4. Only after the review passes (comments addressed **and threads resolved**) and **CI is green**: merge with **`gh pr merge --squash --delete-branch`** (or `--rebase`; **not `--merge`** — linear history; `--delete-branch` removes it locally and remotely). Checks are **strict**, so if `main` moved, rebase onto it and let CI re-run first. CI (`.github/workflows`) runs the offline test matrix + frontend build + dependency audit + live sandbox tests on every PR; review **plus** green CI is the gate. A plain squash merge is refused until CI is green, so it can't bypass CI (the reason `--admin` stays off the table).
5. **Clean up:** `git worktree remove <path>`, ensure the branch is gone **locally and remotely** (`git branch -d <branch>` + `git push origin --delete <branch>` if `--delete-branch` didn't, then `git fetch -p`), and fast-forward the primary `main`. **Standing invariant: the only worktrees/branches that exist (local or remote) are ones being actively worked on** — `git worktree list`, `git branch`, `git branch -r` should show just `main` plus live work. Prune stale on sight.

**Creating a worktree (with its own isolated runtime):**
```bash
git worktree add ../hexgraph-wt/<topic> -b build/<topic> main
cd ../hexgraph-wt/<topic>
just install                                                        # OWN venv — required (= python3 -m venv .venv && pip install -e ".[server,dev]")
export HEXGRAPH_HOME="$PWD/.hghome"                                  # OWN data/DB/settings
```
(`just` is the task runner — install per **Commands** below; ensure `~/.local/bin` is on `PATH`.)

**Running worktrees concurrently — deconflict ALL shared state.** Nothing is worktree-aware; isolation comes entirely from per-worktree env + venv:
- **Own venv (required).** The editable install pins an *absolute* `src` path, so reusing another worktree's `.venv` imports the *wrong* code. Each worktree runs its own `just install`; `just ui` builds the SPA into the worktree's own `src/hexgraph/web/dist` (gitignored).
- **Own `HEXGRAPH_HOME`.** All runtime state (SQLite DB, `projects/`, `settings.json`, `config.toml`) roots at `HEXGRAPH_HOME` (default `~/.hexgraph`), otherwise **shared across every worktree** — without a per-worktree home, two agents mutate the same graph and a newer-migration worktree silently upgrades the shared schema. (WAL is lock-*safe*, not isolated.) Copy in `~/.hexgraph/config.toml` if you need the BYOK key.
- **Own `HEXGRAPH_PORT` when serving.** Two `hexgraph serve` on `8765` collide; use `HEXGRAPH_PORT=876N`, keep `HEXGRAPH_HOST=127.0.0.1` (loopback is a product invariant — never `0.0.0.0`).
- **Sandbox image (`hexgraph-sandbox:latest`) is host-global.** Probe `.py` edits need no rebuild (mounted from your worktree's package at runtime). But a **Dockerfile/toolchain change (or `with_ghidra=1`) must NOT run `just sandbox-build`** — it clobbers the shared tag; build a private tag instead: `docker build -f docker/sandbox.Dockerfile -t hexgraph-sandbox:wt-<topic> .` then `export HEXGRAPH_SANDBOX_IMAGE=hexgraph-sandbox:wt-<topic>`. (Containers are uuid-named + `--rm`; never collide.)
- **MCP + Claude Code (the subtle one).** The MCP server is **stdio** (per session, no port); a registration **bakes an absolute interpreter/script path with no env** and the server name is hardcoded `"hexgraph"`. So **`cd`-ing between worktrees does NOT change which code/DB the agent's MCP tools use** — it's frozen to the registered command + the spawning agent's ambient env (falling back to `~/.hexgraph`). To test worktree-local MCP changes, editable-install, then register a **uniquely-named** server pinned to that worktree's python + home:
  ```bash
  claude mcp add hexgraph-<topic> --env HEXGRAPH_HOME=$PWD/.hghome -- $PWD/.venv/bin/python -m hexgraph.cli mcp
  ```
  Verify it resolves to your code with `.venv/bin/python -m hexgraph.cli mcp --check`. Two agents need **distinct server names and `HEXGRAPH_HOME`** — never share the default `hexgraph` registration across worktrees (stale code, shared DB).
- **Already safe:** `just test` (the `hg_home` fixture isolates each test in a tmp home; mock backend, Docker/decompile disabled) and `just demo` (its own tmp home) self-isolate — only Docker throughput competes for the sandbox-gated subset.

## Non-negotiable constraints (these define the product)

- **Fully self-hosted.** Nothing calls a HexGraph-operated backend; no telemetry, no auto-update pings.
- **Loopback only.** API/UI bind `127.0.0.1`; a startup assertion refuses a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`.
- **BYOK / Claude Code / mock only.** No bundled keys, no proxying. Read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never log, store, or return it.** `HEXGRAPH_API_KEY` is reserved for future paid features — same rule.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes runs only in the disposable Docker sandbox (`--network none`, read-only rootfs, mem/cpu/pids caps, tmpfs, hard timeout). **Executing the target is opt-in, gated solely at the policy seam** (`policy.current_policy()` / `assert_allows_execution()`): static-only is the **enforced default** — with neither `features.poc` nor `features.fuzzing` on, any attempt to run the target raises. Enabling PoC/fuzzing flips the policy to permit execution, still inside the same locked-down sandbox (foreign-arch via qemu-user). **Egress is the same:** `--network none` by default, relaxed only at the policy seam — opt-in `features.network` raises a bounded local-network tier (`assert_allows_egress(dest, scope)` + a per-target `NetworkScope` refusing any non-loopback/private host; every outbound action audited to `EgressEvent`). **Rehosting is its own opt-in gate** (`features.rehost` / `policy.assert_allows_rehost()`), booting full-system emulation inside the sandbox. So static-only/no-network is an **enforced default, not an absolute ban** — but **never relax a gate except at the policy seam**. **The LLM never sees raw target bytes** — only tool output carried in `TaskContext`.
- **Zero token spend by default.** Mock backend is the dev/CI default; `just demo` runs the full loop offline with no key and exits 0.
- **The Finding schema is frozen** (`src/hexgraph/schemas/finding.schema.json`, shipped in-package). Every task and backend (mock included) emits exactly this shape; a contract test enforces it. New structure goes in the DB envelope, not the schema.
- **Migrations are mandatory.** The project DB is durable researcher knowledge, never silently reset. Any schema change ships an `alembic revision --autogenerate` committed with the model change.

## Architecture & the seam rule

**Ask a seam, never branch on backend identity, license tier, or executor.** Feature code calls a seam; concrete implementations swap behind it. The seams:

- **`LLMBackend`** (`llm/`, `HEXGRAPH_LLM_BACKEND`, default `mock`): `MockLLMBackend` / `AnthropicAPIBackend` / `ClaudeCodeBackend`. **Never write `if backend == "mock"` in task code.** LLM tasks run an **agent loop** (`llm/runner.run_findings_agentic`): HexGraph advertises sandboxed tools (`agent/agent_tools.py` — decompile/strings/imports/…, fuzz when enabled), the model requests tool calls, HexGraph runs them in the sandbox and feeds results back until the model emits findings. A strict superset of a single pass; the mock drives it offline via fixtures carrying a `tool_calls` key. The model never touches the environment — it directs, HexGraph runs the tools (so a plain BYOK key suffices; no external coding agent required).
- **Executor** (`sandbox/executor.py` `get_executor()`): the container boundary for all target-byte handling. Future remote/dynamic executors drop in here.
- **Decompiler** (`sandbox/decompiler.py` `get_decompiler()`): radare2 default; Ghidra (headless/bridge) when enabled in Settings. `HEXGRAPH_DECOMPILER` overrides.
- **Rehoster** (`engine/targets/rehost.py` `get_rehoster()`): boots a whole firmware image under full-system emulation. `FirmAERehoster` (vendor blobs, privileged container) and `QemuDiskRehoster` (full-OS disk images, KVM) implement it; `select_rehoster(firmware_path)` auto-selects by image type. Gated by `policy.assert_allows_rehost()`. The emulated device's web surface registers as a `web_app` child target.
- **Entitlements / Metering / Policy / Principal / Suggester** — thin local-default seams (`entitlements.py`, `metering.py`, `policy.py`, `principal.py`, `engine/suggester.py`); they allow/grant everything today so paid/dynamic/multi-user features land additively.

**Data model** (SQLite + SQLAlchemy, UUID ids): `project`, `target` (self-referential tree; a target is a *reachable surface* — a byte target with a `path`, or a dynamic surface reached via a Channel in `metadata_json` — `web_app` (HTTP), `service` (a bare raw-TCP/UDP listener, `engine.targets.surfaces.register_service_target`), or `remote` (SSH/telnet); see `docs/design-dynamic-surfaces.md`), `node` (typed sub-file entities: function/symbol/string/struct/hypothesis/pattern/input/sink/**socket**/**endpoint**/**param**), polymorphic attributed `edge` (`(src_kind,src_id)`→`(dst_kind,dst_id)` over target|node|finding|task; route→handler is **`routes_to`**), `task`, `finding`. The graph is relational — **Neo4j is out of scope.** `finding.status` is a **plain String** (use `f.status`, never `.status.value`); `task.status` is an Enum. SQLite runs in **WAL mode** (`db/session.py`) so the web app and an agent's MCP server (separate processes) share the DB concurrently; **foreign-key enforcement is deliberately OFF** (edges/annotations are polymorphic string refs, not FKs). `NodeType`/`EdgeType` are **String columns** so new vocab is zero-migration.

**Typed attributed edges & sockets:** edges carry type-specific attributes (`edge.attrs_json`); `engine/graph/edge_schemas.py` registers what's *meaningful* per type (e.g. `calls`→`call_sites`/`arg_constraints`, `listens_on`→`address`/`backlog`) + `SOCKET_KINDS`. Guidance, not a hard schema — unknown keys pass, but **list attributes merge as sets** (`merge_edge_attrs`; `add_edge(merge=True)` / `create_edge(merge=True)` / `update_edge` accumulate `call_sites` rather than clobber). A `socket` node is a network/IPC endpoint **shared across binaries** (identity = `(project, kind, port|name)` via content_hash, `target_id=None`) so a server `listens_on` it and a client `connects_to` it resolve to one node — the firmware's network map (`agent.mcp_tools.list_sockets`, `engine.graph.nodes.materialize_socket`, `engine.graph.authoring.create_socket`).

**Node identity & dedup:** function/symbol/struct identity is the *normalized* name within a target (`engine.graph.nodes.normalize_symbol_name` strips decompiler prefixes so `sym.get_param` == `get_param`); `get_or_create_node` normalizes at creation. `engine/graph/nodemerge.py` (`merge_duplicates`) folds existing duplicates by per-type canonical key (functions→normalized name, strings→value hash, targets→sha256), moving all edges/findings/annotations to the keeper — run automatically after LLM tasks, and on demand via `POST /api/projects/{id}/merge-duplicates` / the `merge_duplicates` MCP tool / the "Merge dupes" toolbar button.

## Where things live

```
src/hexgraph/
  config.py settings.py        # config.toml (user/secrets, never rewritten) + settings.json (managed, writable)
  setup_wizard.py setup_catalog.py  # `hexgraph setup` wizard + its feature/gate registry (per features.* entry:
                               #   label, what it unlocks, SECURITY IMPLICATION, policy tier, build steps — data, not policy)
  models/finding.py            # the frozen Finding/Evidence/FollowupSuggestion Pydantic models
  llm/                         # backend seam: base, mock, anthropic_api, claude_code, registry, cassette
  sandbox/                     # runner (docker boundary), executor, decompiler; probes/ mounted from the install
                               #   (http_probe = live web assessment + session cookie jar)
  engine/                      # pipeline, worker, context, runs, tasks, observations, llm_tasks,
                               #   suggester, capabilities, cas, audit  (the task-runner core + substrate)
                               # (sub-packaged by responsibility; see engine/<pkg>/ below)
  engine/build/                #   build-as-API: build, builds, source, revisions, oss_fuzz
  engine/re/                   #   static RE: binutils, floss, yara, taint, static_core, recon, enrichment,
                               #     solver, solving, emulation, ghidra (+ ghidra_project, ghidra_bridge)
  engine/graph/                #   the curated typed graph: nodes, edges, edge_schemas, node_schemas,
                               #     nodemerge, dedup, authoring, annotations, hypotheses, crosstarget,
                               #     removal, refs, search, graph
  engine/findings/             #   findings + proving: findings, poc, poc_repro, assurance, oracles,
                               #     reachability, followups, report
  engine/targets/              #   target acquisition/lifecycle/surfaces: ingest, unpack, targets,
                               #     filesystem, surfaces, rehost, remote, callback_listener
  engine/fuzz/                 #   fuzz campaigns: campaigns, fuzzing, fuzz_env, harness, harness_promote
  agent/                       # agent-integration layer (the INTERFACE engine/ implements): mcp_server +
                               #   mcp_catalog + mcp_tools (the MCP tool surface external agents drive),
                               #   agent_tools (the in-process LLM agent-loop tools), agent_delegate (delegate
                               #   mode), agent_setup (MCP registration + skill emission), vr_skill +
                               #   record_keeping (the VR skill spine/sub-files + the shared record-keeping rubric)
  api/app.py                   # FastAPI: all REST endpoints + serves the SPA at / (loopback)
  cli.py                       # hexgraph init|setup|db upgrade|ingest|targets|run|findings|graph|prune|rehost|config|serve
docker/                        # ALL Dockerfiles: app.Dockerfile (the full app for `docker compose up`),
                               #   sandbox.Dockerfile / build.Dockerfile / fuzz.Dockerfile (sibling analysis images,
                               #   build context = repo root), firmae/ + qemu/ (rehosting). docker-compose.yml is at repo root.
frontend/                      # React+Vite+TS SPA → built to src/hexgraph/web/dist by `just ui` (gitignored)
migrations/                    # Alembic; baseline bbdb1d98bf54. prepare_database() in db/migrate.py
tests/                         # pytest; fixtures under tests/fixtures (built by build.sh / `just fixtures`).
                               #   VR engagement scenarios: tests/fixtures/eval_fw/engagement-brief.md
                               #   (the Aria Router blind brief), scripts/engagement-{vulnrouter,rehosted}.md
docs/                          # USER-FACING feature docs (setup, graph-ui, fuzzing, mcp, …) + images/;
                               #   dev/ = internal ledgers (ui-backlog.md, ux-contract.md);
                               #   design/ = reference/design docs (design-vision, implementation-plan, …).
```
The frozen Finding schema and the mock-LLM fixtures ship **inside the package** (`src/hexgraph/schemas/finding.schema.json` and `src/hexgraph/llm/fixtures/mock_llm/`; resolved by `paths.py` relative to the package, packaged into the wheel).

Key disciplines: **probes are mounted from the install at runtime** (`sandbox/runner.py` overlays `sandbox/probes/` read-only over the image's baked copy), so **adding or editing a probe needs no rebuild** (including `http_probe`); only a toolchain change does (`just sandbox-build`, forwarding `--build-arg WITH_GHIDRA`; `with_ghidra=1` adds Ghidra + the enhanced unpack toolchain; `HEXGRAPH_SANDBOX_NO_MOUNT=1` forces the baked-in copy). Tests use `init_db()` (create_all) on throwaway DBs and never migrate; persistent DBs migrate. Decompilation/harness-compile are best-effort and env-gated (`HEXGRAPH_DISABLE_DECOMPILE`, `HEXGRAPH_DISABLE_SANDBOX_BUILD`) — never gated on backend identity.

## Optional features & settings

`settings.json` (managed; written via `PATCH /api/settings` or `hexgraph config set`) holds non-secret prefs + optional-feature toggles, layered **env > settings.json > config.toml > defaults**. Secrets are never written there (presence-only). Optional features:
- **Ghidra** (`features.ghidra`): `headless` (analyzeHeadless in the sandbox, needs `just sandbox-build with_ghidra=1`), `bridge` (connect to a running Ghidra via `ghidra_bridge`), `enrich_recon` (materialize functions/call-graph/structs). Degrades to radare2 when off.
- **Fuzzing** (`features.fuzzing`, default off): the `fuzzing` task type; enabling it (or PoC) flips `policy.current_policy()` to a dynamic profile (`allow_execution=True`) — the only place the static-only invariant relaxes — while the sandbox stays `--network none`, capped, timed. Compiles a `harness_generation` harness with libFuzzer+ASan and auto-creates a finding per crash. `engine/fuzz/fuzzing.py`, `sandbox/probes/fuzz_probe.py`.
- **PoC verification** (`features.poc`, default off): the `poc` task + `finding_verify_poc` MCP tool **execute the target** in the sandbox with an attacker input and confirm exploitation via an unforgeable `{{NONCE}}` oracle (engine substitutes a random token; "verified" = the injected behaviour really happened). Also policy-gated. `engine/findings/poc.py`, `sandbox/probes/poc_probe.py`. **Foreign-arch targets run under qemu-user** — `poc_probe` picks `qemu-<arch>` from the ELF header and `verify_poc` mounts the parent firmware's extracted rootfs as the qemu sysroot (`-L`) so a dynamically-linked MIPS/ARM/… binary finds its libs (verified end-to-end on real MIPS firmware).

**Firmware extraction** (`sandbox/probes/unpack_probe.py`): bare squashfs → **sasquatch** (patched unsquashfs for vendor/LZMA squashfs; falls back to `unsquashfs`); cpio → `cpio`; **partitioned full-OS disk images** (MBR/GPT — recon detects these via `_is_disk_image` → `format=disk_image`) → **The Sleuth Kit** (`mmls` + `tsk_recover`, unprivileged, no loop-mount) pulls the rootfs from the largest Linux/ext partition, falling back to binwalk (which also handles a squashfs-on-a-partition rootfs like OpenWrt-x86); wrapped vendor firmware (TRX/uImage → squashfs/jffs2/ubifs/cramfs, often nested) → **binwalk recursive** (`-eM`), driving sasquatch / jefferson (JFFS2) / ubi_reader (UBIFS). All in the default sandbox image (sleuthkit + e2tools included); rebuild after a toolchain change.

**Firmware rehosting** (`features.rehost`, default off): boots a firmware (`select_rehoster` picks FirmAE for vendor blobs vs qemu+KVM for full-OS disk images) → registers its live web UI as a `web_app` surface child. The probe joins the emulator container's netns to reach the device's private IP. Gated by `policy.assert_allows_rehost()`; `engine/targets/rehost.py`, `docker/firmae`, `docker/qemu`. Boot needs `features.rehost`; assessing the running device needs `features.network`.

**Remote live devices** (`features.remote`, default off): the **live-remote tier** (`TIER_LIVE_REMOTE`, `policy.assert_allows_remote()` + `remote_scope(host,port)`). A `remote` target reached over **SSH/telnet** (a physical box on the bench, no firmware in hand) on which the agent runs the SAME read-only analysis as on a rootfs — `remote_list_files` / `remote_read_file` / `remote_run` (a fixed read-only allowlist; no arbitrary shell). Egress is pinned to the one operator-authorized host (any host — operator's responsibility, unlike the loopback/private web tier) and audited. **Credentials are secrets** — read at connect from env (`HEXGRAPH_REMOTE_PASSWORD`/`_KEY`) or `config.toml [remote]`, never stored in the DB. `engine/targets/remote.py`, `sandbox/probes/remote_probe.py` (paramiko/telnetlib in the sandbox image).

**Findings are typed** (`finding.finding_type`, migration 0008 — DB envelope, not the frozen JSON schema): `vulnerability | recon | harness | fuzz_crash | poc | annotation | other`, classified from the producing task (`engine.findings.findings.classify_finding`), used for sort/filter in the findings panel. A verified PoC surfaces as `verified` (from `evidence.extra.verification`).

**Entity removal** is graduated and mostly reversible (`engine/graph/removal.py`, via API + MCP + UI). Targets **soft-remove** from the Targets pane (`target.archived`, migration 0007): archives the parent_id subtree, hiding its nodes/findings from graph/detail/search/report without deleting; re-adding the same bytes (sha256) restores them. **Nodes** archive/restore the same way (`node.archived`, migration 0011 — also hides the edges touching the node) via `archive_node`/`restore_node` (MCP), plus `archive_target`/`restore_target` for subtrees. Hard deletes: `delete_edge` (recreate to restore) and `delete_project` (operator-only, not an MCP tool). Firmware targets persist their **unpacked filesystem** (`metadata_json["filesystem"]`, files under `<data_dir>/unpacked/<id>/`) — browsable in the detail panel, any file addable as a child target (`engine/targets/filesystem.py`).

**Coding-agent integration (MCP), two directions, both keep target bytes in the sandbox:**
- **Driver mode** — `hexgraph mcp` (stdio, optional `[mcp]` extra; `agent/mcp_server.py` + `agent/mcp_tools.py`) exposes HexGraph's sandboxed primitives so an external agent (Claude Code/Codex/gemini-cli) inspects targets, populates the graph (findings/nodes/edges/hypotheses/annotations), and runs sandboxed tasks. Tools are grouped read/write/run and gated by `features.mcp.{read,write,run}` (+ `--tools` / Settings) to keep context small. `hexgraph mcp install` prints registration steps (`agent/agent_setup.py`).
- **Delegate mode** — opt-in `features.agent` + an `agent_delegate` task (`agent/agent_delegate.py`): HexGraph launches the configured agent CLI headless, wired to the MCP server + VR skill, **restricted to HexGraph's sandboxed tools** (no shell on the target).
LLM tasks themselves use the **agent loop** (above) over a plain BYOK key; Claude Code/Codex are an *alternative backend/driver*, never required.

### MCP tool conventions — keep these consistent as tools are added

The MCP tool surface lives in `agent/mcp_catalog.py` (`_CATALOG` — the `(group, name, fn, description, json_schema)` tuples that are the agent-facing API; thin implementations in `agent/mcp_tools.py`). The guard test `tests/test_tool_contract.py` **enforces every rule below**, so a tool that breaks one fails CI — satisfy the guard rather than relaxing it.

- **Names are `<domain>_<verb>[_object]`, lowercase, routable from the name alone** — under deferred (name-only) loading the name is the only zero-token signal, so it must telegraph purpose without a schema fetch. Domains: `proj` (projects) · `target` (the target lifecycle **and every tool that creates a target** — ingest/register/rehost) · `re` (static RE) · `fs` (a target's unpacked filesystem) · `obs` (the Observation store) · `graph` (the curated node/edge/hypothesis graph) · `finding` (findings, n-day, proving) · `src` (source trees + builds) · `fuzz` (campaigns) · `net` (live network + egress) · `task` (the task runner) · `meta` (schemas + health). A new tool MUST take a known prefix; extend the set only if nothing fits. **`ingest`** processes bytes into a target, **`register`** records a pre-existing live thing; if two tools share a noun but produce different things, the type goes in the name (`graph_create_socket` — a node — vs `target_register_service` — a live, fuzzable target).
- **Two name surfaces, same meaning.** `agent/mcp_catalog.py` holds the advertised MCP names (`<domain>_<verb_noun>`); the backing `mcp_tools`/`engine` **function** carries the same verb+noun **without** the domain prefix (a routing concern, and `re_*` would collide with Python's `re`). So advertised `target_register_service` ↔ function `register_service` (the catalog tuple's 3rd element is the mapping). A **semantic** rename — fixing an ambiguous verb/noun — propagates inward to the `mcp_tools` wrapper AND its `engine` function (e.g. `register_socket`→`register_service`, `add_file_as_target`→`promote_file`); a **prefix/reorder-only** change (e.g. `list_observations`→`obs_list`) leaves the function name untouched. Watch for collisions (`promote_file`, not `ingest_file` — `engine.targets.ingest.ingest_file` already exists). Separately, `agent/agent_tools.py` holds the in-process LLM agent-loop tools (`decompile_function`, …) that the **mock fixtures hardcode by name** — NOT renamed to chase the catalog (it would churn every fixture).
- **Closed value-sets are schema `enum`s from one source of truth — never hand-typed.** Import the canonical definition (`NodeType`/`EdgeType`, `SOCKET_KINDS`, `FINDING_TYPES`, the Finding `Literal`s, `hypotheses.RELATIONS`/`STATUSES`, …) at catalog load — the same definitions `meta_get_schemas` reads — so the enum can't drift from the engine. Hand-listing a set silently drifts, and a strict MCP client then rejects a call the engine would accept (exactly the `relation`/`status`/`remote-tool` drift caught in review). For anything new, define the set as an importable constant — a `str`-Enum, module-level tuple/`frozenset`, or `Literal` — in the owning engine/model and import THAT into both `meta_get_schemas` and the catalog. A few legacy sets stay hand-listed because their authority isn't host-importable (e.g. `REMOTE_TOOLS` mirrors the sandbox-only `remote_probe.TOOLS`); each carries a pointer comment + a guard-test assertion pinning it.
- **Gating is stated in the description, in a fixed slot.** Any tool that touches the network, executes, boots an image, fetches deps, or edits source ends its description with **`Gated: features.X`** — an agent must never discover a capability tier only by being refused (the gate is enforced at the policy seam; the clause lets the agent *plan*). A tool that should be **invisible until its feature is on** goes in `_FEATURE_GATED_TOOLS`.
- **Descriptions lead with what the tool operates on, and disambiguate siblings.** The first clause names the corpus / operated-on type, especially for confusable families (the three searches `graph_search`/`obs_search`/`re_search_decompiled`; the three readers `fs_read_file`/`src_read_file`/`net_remote_read_file`). Use the curation verbs consistently — **QUERY** (records an Observation, adds no nodes) / **PROMOTE** (adds a node) / **ENRICH** (attaches facts in place) — reference siblings by their current names, keep chaining hints (`→ then …`). One-line descriptions on non-obvious params; bare ids like `target_id` don't need one.
- **Keep the instructions in sync.** A tool rename/addition propagates **in the same PR** to the VR **SKILL** (`agent/vr_skill.py` + its sub-files) and **`docs/mcp.md`**. The SKILL teaches the *strategic workflow* (orient cheaply → map the surface → read code → recover/deepen → prove) — slot a new tool into that flow, don't just append. Design docs (`docs/design/`) reference tools as historical artifacts and need not be renamed.

## Commands

- The task runner is **`just`** (install: `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`, or `snap install just`; `~/.local/bin` on `PATH`). Bare **`just`** prints the grouped recipe menu (setup · run · build · test · demo · rehosting · maintenance); recipe doc-comments state **when to rebuild** (`ui` after any `frontend/` change; `sandbox-build` only after a Dockerfile/toolchain change — probes mount at runtime).
- **`just setup`** — one-shot bootstrap (venv + deps + SPA) then the **interactive setup wizard** (`hexgraph setup`; `setup_wizard.py` + the `setup_catalog.py` feature/gate registry): pick which optional `features.*` to enable (each policy-relaxing one shown with its **security implication** + explicit confirm) plus non-secret config (loopback-default bind, backend, Ghidra mode), then it writes settings via the settings layer (**never a secret** — those stay in env/config.toml, presence-only) and runs the chosen image builds + db init. **CI-safe:** with no TTY (or `--yes`/`--non-interactive`/`--defaults`) it applies the static-only baseline + sandbox image without prompting, so unattended `just setup` never hangs. (Thin wrapper around **`./setup.sh`**, which also works without `just`; flags pass through.) Then **`just serve`** → http://127.0.0.1:8765.
- **`just refresh`** (= `just setup --refresh` / `./setup.sh --refresh`) — the post-`git pull` **sanity-sync**: non-interactive, **keeps your config**, rebuilds only what's STALE vs the current source — reinstalls the package on a version change, rebuilds the SPA if stale, rebuilds any already-built image whose Dockerfile moved (preserving the Ghidra choice; rebuilds *with* Ghidra if settings want headless but the image lacks it), re-affirms the MCP registration, regenerates the VR skill where installed, migrates the DB. Never enables a feature or builds an image you didn't opt into. `run_refresh()` in `setup_wizard.py`.
- `just test` (= `pytest -q`, mock, offline; Docker-gated tests skip if the sandbox image is absent) · `just demo` (full loop, needs Docker) · `just test-live` (real-key scored eval, needs `ANTHROPIC_API_KEY`, cassette-backed).
- `just ui` (rebuild SPA) · `just sandbox-build [1]` (positional; `1` = bundle headless Ghidra — `with_ghidra=1` also accepted) · `just fixtures`.
- **Containerized path (optional):** `just app-build` builds the full app image (`docker/app.Dockerfile` — Node builds the SPA, Python installs the package, includes the docker CLI); `just up` / `just down` run `docker-compose.yml` (one `app` service on **host loopback only** `127.0.0.1:8765:8765`, host Docker socket mounted so the app spawns sandbox/build/fuzz siblings on the host daemon). The container sets `HEXGRAPH_IN_CONTAINER=1` so the loopback guard accepts its `0.0.0.0` bind (the host-loopback guarantee holds at the publish boundary). The host pip path (`just setup` → `just serve`) stays primary/dev.
- Rehosting: `just firmae-build` (FirmAE image; privileged + /dev/net/tun) · `just qemu-build` (QEMU+KVM; needs `--device /dev/kvm`) · `just iotgoat` (fetch+rehost+register IoTGoat) · `just vulnrouter` (live vulnrouter web target + project).
- CLI: `hexgraph init | db upgrade | ingest <path> [--name --project --backend --no-recon] | targets <p> | run <target> --type T [--objective --model --backend --function --mock-scenario] | rehost <target> [--brand] | findings <p> | graph <p> --export f.json | prune <p> | config list|get|set | serve`.
- Runtime data under `~/.hexgraph/` (override with `HEXGRAPH_HOME`, db with `HEXGRAPH_DB_PATH`).

## Environment gotchas

- **`grep` is aliased to ripgrep (`rg`).** GNU-grep flags don't apply: no `--include` (use `--glob`/`-g`), recursion and smart-case are on by default, PCRE differs. Prefer the dedicated Grep tool; when you shell out, use ripgrep syntax.

## Read before writing code

1. **This file + `README.md`** — constraints, the data model, the seam rule, the graduated opt-in policy model.
2. `docs/design/mock-llm-provider.md` — the mock backend (three fidelity layers, scenarios, contract test).
3. `src/hexgraph/schemas/finding.schema.json` — the canonical, frozen Finding schema.
4. `docs/design/design-vision.md` + `docs/design/implementation-plan.md` — the v2 target shape and sequenced plan.
5. `docs/design/design-dynamic-surfaces.md` + `docs/design/design-rehosting.md` — dynamic web surfaces and rehosting.

## Writing docs for humans

User-facing docs (`README.md`, the feature docs in `docs/`, `DISCLAIMER.md`, `THIRD_PARTY_NOTICES.md`) are written in natural human prose, for people, not as machine output. Read each line back: would a person write it this way, and want to read it? Avoid the usual LLM tells — em-dashes in every other sentence (reach for a comma, period, parentheses, or "and"/"but"), stacked terse fragments, the "Label: punchy phrase" staccato, dense fragment bullets, the robotic "X, Y, and Z, all bounded/audited/gated" parallelism. Prefer flowing sentences with connective tissue, vary short and long, add the transitions that make a section read as a whole. Keep every technical fact exact; change the voice, not the substance. (The `docs/design/` reference docs get a lighter touch — fix egregious slop, don't fully rewrite.)

When a workflow becomes repetitive, capture it as a skill under `.claude/skills/`.

## Assessing the UI visually (Playwright)

For the full UX walkthrough, **`docs/dev/ux-contract.md` is the living behavior contract** (every UI interaction with its expected functional + backend effect + qualitative bar) and the **`ux-assessment` skill** runs it as a two-role assessment (a VR-analyst agent populates every surface; a separate researcher-agent walks the contract and scores each entry). Re-run on every major UI change / fix evaluation; the quick captures below are for spot checks.

No browser MCP here and `WebFetch` can't reach `127.0.0.1`; the UI is JS-driven, so fetching HTML isn't enough. Drive headless Chromium via Playwright (dev-only, **not** in `pyproject`):

```bash
.venv/bin/pip install playwright && .venv/bin/playwright install chromium   # bundled chromium has no build on very new distros (e.g. Ubuntu 26.04); there, skip this and drive the system Chrome via channel="chrome" (below)
```

Seed data + serve on a spare port with an isolated `HEXGRAPH_HOME`, then screenshot in Python (launch with `--no-sandbox`, `goto(..., wait_until="networkidle")` + a short `wait_for_timeout` so Cytoscape/fetches settle, then `page.screenshot(...)`). **View the PNGs with the Read tool.** Kill the backgrounded `serve` PID when done. Record findings in `docs/dev/ui-backlog.md`.
```python
try:  # prefer system Chrome — bundled chromium has no build on very new distros (Ubuntu 26.04)
    b = await p.chromium.launch(channel="chrome", args=["--no-sandbox"])
except Exception:
    b = await p.chromium.launch(args=["--no-sandbox"])
pg = await b.new_page(viewport={"width": 1440, "height": 900})
await pg.goto(f"{BASE}/projects/{PROJ}", wait_until="networkidle"); await pg.wait_for_timeout(1500)
await pg.screenshot(path="/tmp/ui/workspace.png")
```

**Judge the screenshot as a HUMAN would, not as an LLM.** An LLM absorbs far more on-screen information than a human eye and isn't bothered by misalignment, cramped spacing, inconsistent styling, or a dated look — humans are, and decide in seconds whether a UI feels inviting or overwhelming. So don't just check the information is *present*: does the eye flow to what matters? Is there enough breathing room, alignment, and hierarchy to feel calm rather than busy? Does it look modern and polished, or dated/scotch-taped? Completeness is necessary but NOT sufficient — a technically-complete screen that feels cluttered or ugly has failed. Iterate (adjust → `just ui` → re-screenshot → re-judge) until it would genuinely delight a human. Strive for this on every UI change.

**Committed doc screenshots live in ONE canonical folder — `docs/images/`** — regenerated by `just capture` from the deterministic `just showcase` seed; every README/doc embeds them by **stable name**, so a UI change → re-run `just capture` → all docs update in place. Don't scatter images across the repo, and keep the captured and doc-referenced sets identical.
