# ⬡ HexGraph

A self-hosted, **local-only** agentic vulnerability-research workbench. Point it at a binary or
firmware image; HexGraph ingests the target, breaks firmware into child targets, runs AI-driven
analysis **using your own model access**, and records every result as a structured **finding** in a
SQLite-backed **typed graph** — targets, functions, sockets, hypotheses, and findings joined by
typed, attributed edges. A loopback-only web UI browses the graph, launches tasks, and triages
findings; the same operations are exposed to a coding agent over MCP.

Three principles are non-negotiable:

- **Local-only.** The API/UI bind to `127.0.0.1`. Nothing calls a HexGraph-operated server; no
  telemetry, no auto-update pings.
- **Bring-your-own-key, or none at all.** Model access is via your Anthropic API key, a local
  Claude Code session, or the built-in **mock** backend. The mock is the default and needs **no key
  and no network**, so you can run the entire loop for free.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes happens inside a disposable
  Docker container with no network and strict resource limits. HexGraph is **static/RE by default**;
  the *only* way the target is ever executed is the opt-in, policy-gated PoC/fuzzing path — and even
  then it runs inside that same locked-down sandbox (foreign architectures via qemu-user). **The LLM
  never sees raw target bytes** — only tool output (decompilation, strings, imports).

> ### Project status — pre-1.0
> The core loop works end-to-end (ingest → recon → AI analysis → structured finding → graph → spawn
> follow-up), including real vendor-firmware extraction, cross-binary n-day linking, and
> **verified, executable PoCs** (incl. foreign-arch MIPS/ARM via qemu). Still pre-1.0 — expect rough
> edges. Phase-by-phase status lives in [`PROGRESS.md`](PROGRESS.md).

---

## Two ways to drive HexGraph

Both populate the **same graph** and both keep target bytes inside the sandbox — use either or both.

1. **The web UI (you direct; HexGraph's LLM does the work).** `hexgraph serve` → open
   `http://127.0.0.1:8765`. Pick a target, launch a task (recon / static analysis / RE / pattern
   sweep / harness gen / fuzzing / PoC), and HexGraph runs an **agent loop** behind your chosen
   backend: the model requests sandboxed tools (decompile, strings, imports, xrefs, fuzz) and
   HexGraph executes them, looping until it emits findings. You triage results, then one-click a
   suggested follow-up. Works on the free mock backend, or your own key/Claude Code.

2. **Claude Code (or Codex / gemini-cli) as the driver, over MCP.** Run `hexgraph mcp install` to
   register HexGraph as an MCP server; your coding agent then inspects targets and **populates the
   graph autonomously** — recording findings, functions, sockets, edges, hypotheses, verifying PoCs —
   all through HexGraph's sandboxed tools (no shell on the target). Everything it writes shows up in
   the UI live (shared WAL-mode DB). You can also have **HexGraph drive the agent** headless via an
   `agent_delegate` task from the Run menu.

The model only ever *directs*; HexGraph runs the tools in the sandbox. A plain API key is enough —
no external coding agent is required (it's an alternative driver, not a dependency).

---

## Requirements

- **Python 3.11+**
- **Docker**, runnable by your user (`docker run --rm hello-world` should work). The analysis sandbox
  runs in a container; required for ingest/recon, decompilation, firmware unpack, and PoC/fuzzing.
- **[`just`](https://just.systems)** — the task runner for the recipes below. Install without sudo:
  `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`
  (then ensure `~/.local/bin` is on your `PATH`), or `snap install just`. Run `just` to see all recipes.
- Linux or macOS.

No API key is required — the default mock backend is fully offline.

---

## Setup

```bash
git clone <your-fork-or-path> hexgraph && cd hexgraph
just setup          # one-shot: venv + deps + SPA build + sandbox image + DB init
just serve          # → http://127.0.0.1:8765
```

`just setup` is the whole install. If you prefer the individual steps (or want Ghidra — see below):

```bash
just install                     # create .venv and install the hexgraph CLI + dev extras
just ui                          # build the React SPA into src/hexgraph/web/dist
just sandbox-build               # build the analysis sandbox image (hexgraph-sandbox:latest)
.venv/bin/hexgraph serve
```

**Ghidra (optional, larger image).** The default sandbox uses radare2. To also bundle headless
Ghidra (adds a JDK + ~400 MB) build with:

```bash
just sandbox-build with_ghidra=1
```

The sandbox image also bundles **firmware extractors** (sasquatch / jefferson / ubi_reader / binwalk)
and **qemu-user** (MIPS/ARM/PPC/…), so real vendor firmware extracts and foreign-arch PoCs run with no
extra setup.

---

## Quickstart (mock backend — no key, no network)

Run the whole loop on the bundled test targets and exit 0:

```bash
just demo
```

Or drive it yourself:

```bash
# Ingest the bundled firmware. Recon runs automatically (zero model calls) and
# unpacks it into child targets (sbin/httpd + usr/lib/libupnp.so) joined by contains edges.
.venv/bin/hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo
.venv/bin/hexgraph serve            # → http://127.0.0.1:8765
```

Open **http://127.0.0.1:8765**, click your project, and use the per-target task launcher.

---

## The web UI

Three panes:

- **Left — target tree.** The ingested target and any firmware children. Each has a launcher: pick a
  **task type** and (for the mock) a **scenario**, then **Run**. Firmware targets show a browsable
  unpacked filesystem; any file can be added as a child target.
- **Center — graph ⇆ source.** A segmented control switches the center pane between the **Graph**
  (targets, functions, **sockets**, hypotheses, harnesses, and findings as typed nodes, joined by typed
  edges — `contains` / `calls` / `taints` / `listens_on` / `built_from` / `located_in` / `harnesses` / …;
  rendered offline with Cytoscape.js) and a read-only **Source** view (an in-browser IDE over the
  project's managed source trees — see below). Click an edge to see its attributes (call sites, ports,
  addresses).
- **Right — findings.** Every finding, typed (vulnerability / poc / recon / harness / fuzz_crash / …)
  and filterable; click one for its evidence, reasoning, verification, and suggested follow-ups.

Click a finding's **suggested follow-up** to open a pre-filled launch modal for the next task. Use
**Confirm / Dismiss** to triage. The **Add node / Add edge** tools let you author functions, sockets,
hypotheses, and typed edges by hand. **Removing things is reversible by default:** archive a node or a
whole target subtree to declutter the graph (re-adding the same entity restores it), while individual
edges and whole projects are hard deletes.

**Mock scenarios** (mock backend) on `sbin/httpd`: `static_analysis/critical_overflow` (critical
overflow + `related_to` edge to `libupnp.so`), `/no_findings`, `/malformed_then_valid` (JSON-repair
retry), `reverse_engineering`, `pattern_sweep` (sibling match), `error_rate_limit` / `error_timeout`
(graceful failure), and a default always-success scenario.

### Source trees & the Source tab (read-only)

A project holds **trusted source** separately from its (hostile) targets: one or more **source
trees** — an imported library's source, or the harnesses/PoCs/build-scripts HexGraph itself
produces. A tree can be linked to a target (a `built_from` edge), and a project may hold several.
Files live on disk under the project data dir indexed by a manifest; a `source_file` graph node is
materialized **lazily** when something references it (so a 70k-file tree never explodes the graph).

The center pane's **Source** mode is an in-browser, **read-only** IDE: a dropdown switches between
the project's source trees, a file explorer browses each, and a code viewer shows a file with line
numbers. A finding that maps to source gets an **"Open in source"** button (Inspector → Evidence)
that jumps straight to the file and line. **Harnesses, PoCs, and scripts are all `source_file`s**
(role-tagged) — a generated harness becomes a managed file you can read in the tab, and a
**Backfill harnesses** action (API/MCP) promotes any older transient harnesses. *Editing source,
and building/fuzzing from it, are later phases* — for now the Source tab is browse + jump only.
Firmware-*extracted* files added as source are marked `extracted` (untrusted; displayed, never run
or parsed outside the sandbox). Over MCP: `list_source_trees` / `read_source_file` (read),
`import_source_tree` / `link_finding_to_source` (write).

---

## Dynamic web surfaces & firmware rehosting

HexGraph models a target as any **reachable surface**, not just a file on disk. Alongside byte
targets there are **`web_app` targets**: a running web surface reached over a Channel (a `base_url`),
holding **no bytes** of its own. A `surface_recon` task crawls one into `endpoint` and `param` nodes,
and — where it can identify the code behind a route — draws a **`routes_to`** edge from the endpoint
to its handler `function`. That edge is the **bridge between the static and dynamic views**: the same
graph holds both the binary you reversed and the live service it serves.

**Live assessment is gated by `features.network`** (off by default). With it on, HexGraph can actually
talk to the surface: an `http_request` tool (with a `session` cookie jar that persists across calls)
and a **web-flavoured `verify_poc`** whose oracle is the same unforgeable `{{NONCE}}` token used for
binary PoCs, plus `body_contains` / `status` checks. Egress is **bounded**: a per-target deny-all
allowlist that permits only loopback/private hosts (never a public address), and every outbound
request is audited to an `EgressEvent`.

**Firmware rehosting** (`features.rehost`, also off by default) boots a whole firmware image under
full-system emulation and registers the device's live web UI as a `web_app` child target — so you can
reverse the firmware *and* drive its running web server in one graph:

```bash
hexgraph config set features.rehost.enabled true    # to boot
hexgraph config set features.network.enabled true   # to then assess the running device
just iotgoat                                         # fetch + rehost + register IoTGoat
# or, by hand:
hexgraph rehost <firmware-target> [--brand <hint>]
```

`rehost` **auto-selects the emulator** by image type: qemu+KVM for a full-OS disk image (e.g. IoTGoat's
x86 OpenWrt `.img`), FirmAE for a vendor blob (squashfs/cramfs/…). Booting needs `features.rehost`;
assessing the running device with `surface_recon` / `http_request` / `verify_poc` needs
`features.network`. Build the rehosting images first with `just firmae-build` / `just qemu-build`.
`just vulnrouter` stands up a live vulnrouter web target + project for a guided engagement; worked
examples live in `docs/engagement-vulnrouter.md` and `docs/engagement-rehosted.md`.

---

## CLI reference

`.venv/bin/hexgraph <command>` (or `hexgraph` with the venv active):

```text
hexgraph init                              Initialize HexGraph (DB + ~/.hexgraph) — optional;
                                           ingest/serve auto-initialize on first use
hexgraph ingest <path> [--name N]          Ingest a binary/firmware; runs recon (auto-unpacks firmware)
                 [--project ID]            …add to an existing project
                 [--no-recon]              …register without analysis
                 [--backend B]             …mock | anthropic | claude_code (default: mock)
hexgraph targets <project>                 List targets in a project
hexgraph run <target> --type T             Run an analysis task (see task types below)
             [--objective TEXT] [--function F]
             [--model M] [--backend B] [--mock-scenario S]
hexgraph rehost <target> [--brand HINT]    Boot a firmware target under full-system emulation and
                                           register its live web UI as a web_app surface
                                           (needs features.rehost)
hexgraph findings <project> [--status S]   List findings (filter new|accepted|dismissed)
                 [--export FILE]           …or write findings as JSON
hexgraph graph <project> --export FILE     Export the project graph as JSON (nodes + edges)
hexgraph config list | get K | set K V     Read/write managed settings (optional-feature toggles, prefs)
hexgraph mcp [--tools read,write,run]      Run the MCP server for a coding agent (stdio)
hexgraph mcp install [--agent A]           Print how to register HexGraph with claude|codex|gemini
             [--write-skill DIR]           …also install the VR skill into a skills dir (e.g. .claude/skills)
             [--print-skill]               …print the VR skill markdown to stdout
hexgraph mcp --check                       List the MCP tools and exit
hexgraph serve [--host H] [--port P]       Start the loopback-only API/UI (default 127.0.0.1:8765)
```

Task types: `recon`, `static_analysis`, `reverse_engineering`, `pattern_sweep`, `harness_generation`
(plus `fuzzing`, `poc`, and `agent_delegate` when enabled in Settings). For web surfaces:
`surface_recon` / `web_recon` (live assessment needs `features.network`).

### Coding-agent integration (MCP)

```bash
.venv/bin/pip install "mcp"     # the MCP SDK (one-time)
.venv/bin/hexgraph mcp install  # prints the exact registration command for your agent
```

The MCP server speaks JSON-RPC over **stdio**; your agent spawns it on demand. Run by hand it prints a
"ready" line to stderr and blocks (correct) — confirm with `hexgraph mcp --check`. The **web UI and
the MCP server run at the same time** (separate processes sharing the WAL-mode SQLite DB), so an
agent's findings appear in the UI on reload and vice versa.

Tools are grouped **read / write / run** and gated by `features.mcp.{read,write,run}` (Settings →
Coding-agent tools, or `--tools`) so the agent's context stays small. The agent can read the graph
(`list_*`, `get_node`, `get_finding`, `xrefs`, `list_sockets`), write to it (`record_finding`,
`create_node`, `create_edge`, `create_socket`, `create_hypothesis`, `link_same_code`,
`propagate_finding`, …), and run sandboxed work (`ingest`, `run_task`, `verify_poc`). Call
`get_schemas` first — it advertises the Finding shape, node/edge vocab, per-type node-attribute schemas
(with the sink-vs-symbol rule), edge-attribute schemas, socket kinds, and the active decompiler. New
read tools also browse a firmware's unpacked filesystem (`list_filesystem` / `read_file`) and remove
entities (`archive_node` / `restore_node` / `delete_edge` / `archive_target` / `restore_target`).

---

## Model backends

Selected by `HEXGRAPH_LLM_BACKEND` (default `mock`) or per-task with `--backend`. Task code is
identical across backends — only the backend boundary changes. LLM tasks run a **tool-use agent loop**
over whichever backend you pick.

| Backend | Status | Notes |
|---|---|---|
| `mock` | ✅ | Deterministic, schema-valid findings from fixtures. No key, no network. Default for dev, CI, `just demo`. |
| `anthropic` | ✅ | BYOK via `ANTHROPIC_API_KEY` (env or config). Real token usage + cost. Install with `pip install -e ".[byok]"`. |
| `claude_code` | ✅ | Uses your local `claude` CLI (headless); fails clearly if absent. |

HexGraph **never logs or stores your API key.**

```bash
export ANTHROPIC_API_KEY=sk-ant-...
hexgraph run <target> --type static_analysis --backend anthropic --function cgi_handler
```

---

## Optional features (all off by default — nothing hidden)

Toggle in **Settings** in the UI, or from the CLI: `hexgraph config set <key> <value>`. The
static-only/local defaults hold unless you opt in.

| Feature | Enable | What it adds |
|---|---|---|
| **Ghidra** | `hexgraph config set features.ghidra.enabled true` (needs `just sandbox-build with_ghidra=1`) | Headless-Ghidra decompiler + optional recon enrichment; can also connect to a running Ghidra (`features.ghidra.mode bridge`). Degrades to radare2 when off. |
| **Fuzzing** | `hexgraph config set features.fuzzing.enabled true` | The `fuzzing` task: compiles a generated libFuzzer+ASan harness and **coverage-guided fuzzes the target** — when the target's own source is provided (task param `target_sources` / `metadata.fuzz_target_sources`) it is compiled WITH the harness under SanitizerCoverage+ASan so libFuzzer gets real coverage feedback from the code under test; with only an uninstrumented `.so` it still runs but coverage-blind (recorded honestly as `coverage_instrumented=false`). Crashes are deduped by a normalized stack-hash (one finding per root cause), the reproducer is minimized (libFuzzer `-minimize_crash`), and each carries a deterministic exploitability rating — all on `evidence.extra.fuzz`. **Relaxes the static-only policy to allow execution** (still `--network none`, capped, timed). |
| **PoC verification** | `hexgraph config set features.poc.enabled true` | The `poc` task + `verify_poc`: **executes the target** with an attacker input and confirms exploitation via an unforgeable `{{NONCE}}` oracle. Foreign-arch (MIPS/ARM/…) runs under qemu-user with the firmware rootfs as sysroot. Also policy-gated. |
| **Build from source** | `hexgraph config set features.build.enabled true` (needs `just build-image`) | **Build-as-API:** compile a managed source tree into an **instrumented artifact** via a *recorded, reproducible recipe* HexGraph runs in the sandbox (the `Builder` seam — you/the agent author a `BuildSpec`, never run a compiler). Instrumentation (SanCov+ASan/UBSan, libFuzzer/AFL++) is injected as CC/CXX/CFLAGS per the base-image contract, so the same recipe yields different profiles. A build of a source tree linked (`built_from`) to a target registers an **instrumented derived target** (`instrumented_build_of`→ the original) — the fuzzable twin, unlocking coverage-guided fuzzing. Reproducible: `recipe_sha = hash{phases,env,base_image,instrumentation,arch}`. **Its own policy gate** (`assert_allows_build`, separate from executing the target — you can build-and-inspect without running). **Vendored/offline only** (the build runs `--network none`; the audited fetch tier is a later phase). Uses the dedicated `hexgraph-build` image (`just build-image`). |
| **Network** | `hexgraph config set features.network.enabled true` | Bounded **local-network egress** for live web assessment (`http_request` + web `verify_poc`). Raises the policy from `--network none`; a per-target deny-all-but-loopback/private allowlist (no public hosts), every request audited to an `EgressEvent`. |
| **Rehost** | `hexgraph config set features.rehost.enabled true` | Boots a firmware image under **full-system emulation** (qemu+KVM for full-OS disk images, FirmAE for vendor blobs) and registers its live web UI as a `web_app` surface. Separate policy gate (`assert_allows_rehost`); pair with **Network** to assess the running device. Needs `just firmae-build` / `just qemu-build`. |
| **Coding-agent (MCP)** | `features.mcp.{read,write,run}` + `hexgraph mcp install` | Drive HexGraph from Claude Code/Codex/gemini-cli (above). |
| **Delegate** | `hexgraph config set features.agent.enabled true` | The `agent_delegate` task: HexGraph launches your agent headless, restricted to its sandboxed tools. |

Configuration layers as **env > `settings.json` (managed) > `config.toml` (hand-authored, BYOK
secret) > defaults**. Secrets live only in env or `config.toml` and are never written to
`settings.json` or returned by the API.

### Enabling execution (PoC / fuzzing) — end to end

By default the target is never run. To turn on verified PoCs:

```bash
hexgraph config set features.poc.enabled true     # flips the policy to allow sandboxed execution
# then either: launch a `poc` task on a target from the UI Run menu,
# or, driving over MCP, call verify_poc(target_id, poc, finding_id=...) with a
# spec like {"stdin": "...{{NONCE}}...", "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}
```

A confirmed PoC is surfaced as a `verified` finding. Foreign-arch (MIPS/ARM/…) firmware binaries run
under qemu-user automatically, with the parent firmware's extracted rootfs as the sysroot — no extra
setup. `features.fuzzing.enabled true` works the same way for the `fuzzing` task.

To use Ghidra instead of radare2: `just sandbox-build with_ghidra=1`, then
`hexgraph config set features.ghidra.enabled true` and re-run a decompile/recon task.

---

## Configuration

```toml
# ~/.hexgraph/config.toml   (HexGraph never rewrites this file)
[llm]
backend = "mock"        # mock | anthropic | claude_code
model   = ""

[api]
host = "127.0.0.1"
port = 8765

[anthropic]
# api_key = "sk-ant-..."   # BYOK; prefer the ANTHROPIC_API_KEY env var. Never logged or stored.
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HEXGRAPH_LLM_BACKEND` | `mock` | Backend selection. |
| `HEXGRAPH_MODEL` | — | Default model. |
| `HEXGRAPH_HOST` / `HEXGRAPH_PORT` | `127.0.0.1` / `8765` | API/UI bind address. |
| `HEXGRAPH_HOME` | `~/.hexgraph` | Root for the DB and per-project artifacts. |
| `HEXGRAPH_DB_PATH` | `$HEXGRAPH_HOME/hexgraph.db` | SQLite database path. |
| `HEXGRAPH_MOCK_SCENARIO` | — | Force a mock scenario for all tasks. |
| `HEXGRAPH_SANDBOX_IMAGE` | `hexgraph-sandbox:latest` | Analysis sandbox image. |
| `HEXGRAPH_BUILD_IMAGE` | `hexgraph-build:latest` | Build-from-source image (`features.build`). The recorded `base_image` of a BuildSpec; point at a private tag in a worktree. |
| `HEXGRAPH_BUILDER` | `sandbox` | Override the Builder seam (`sandbox` \| `mock`). |
| `HEXGRAPH_SANDBOX_NO_MOUNT` | — | `1` to use the image's baked-in probes instead of mounting the local copies (probes mount by default, so editing one needs no rebuild). |
| `HEXGRAPH_DECOMPILER` | `r2` | Override the decompiler seam (`r2` \| `ghidra`). |
| `HEXGRAPH_DISABLE_DECOMPILE` | — | `1` to skip decompilation in LLM tasks (offline/no-Docker dev + tests). |
| `HEXGRAPH_DISABLE_SANDBOX_BUILD` | — | `1` to skip the harness-compile sandbox step (dev/tests). |
| `HEXGRAPH_I_KNOW_WHAT_IM_DOING` | — | `1` to allow a non-loopback bind (warns loudly; not recommended). |
| `ANTHROPIC_API_KEY` | — | Your key for the `anthropic` backend. Read on demand; never logged or stored. |

---

## Security model

- **Loopback only.** The server refuses a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`
  (which still warns).
- **Hostile-target isolation.** Every operation on target bytes runs in a fresh container with
  `--network none`, a read-only root filesystem, a tmpfs scratch, memory/CPU/PID limits, and a
  wall-clock timeout. Only HexGraph's probe scripts run there.
- **Static by default; capability is opt-in and graduated.** Each tier is a separate, explicit
  opt-in flipping the single **policy seam** (`policy.current_policy()`), and nothing relaxes anywhere
  else:
  - **static-only** (default) — no execution, `--network none`;
  - **build from source** — `features.build` permits compiling a source tree into an instrumented
    artifact in the same `--network none`, capped, RO-source, non-root sandbox (`assert_allows_build`);
    a sub-capability of sandboxed-exec but its own gate, so you can build-and-inspect *without*
    permitting the target to run (running the built artifact still needs the exec gate);
  - **sandboxed execution** — `features.poc` / `features.fuzzing` allow running the target inside the
    same capped, timed, `--network none` sandbox (foreign-arch via qemu-user), never on the host;
  - **bounded local-network** — `features.network` permits egress only to loopback/private hosts via a
    **per-target deny-all-but-this allowlist** (no public addresses), every request audited to an
    `EgressEvent`;
  - **rehost** — a separate gate (`assert_allows_rehost`) that boots a firmware image under
    full-system emulation.
- **The LLM never sees raw target bytes** — only tool output.
- **Secrets are never persisted or logged.** Your API key lives only in env/config, read on demand.

---

## How it works

The whole system proves one loop: **target → task → structured finding → graph → spawn next task.**
Built around clean seams — change behavior by swapping behind a seam, never by branching on backend /
tier / executor:

- **`LLMBackend`** — `mock` / `anthropic` / `claude_code` are interchangeable; task code never knows
  which it talks to. LLM tasks run an agent loop that calls sandboxed tools.
- **Executor** — the single container boundary for all target-byte handling (a remote/dynamic executor
  drops in here).
- **Decompiler** — radare2 by default; Ghidra behind the same seam.
- **Rehoster** — full-system firmware emulation; FirmAE (vendor blobs) and qemu+KVM (full-OS disk
  images) drop in behind it, auto-selected by image type.
- **Policy** — the one place the static-only invariant is relaxed (sandboxed execution via PoC/fuzzing,
  bounded local-network via network, and rehosting — each its own opt-in gate).

**The Finding is the heart of the product.** Every task and backend emits the same frozen schema
(`src/hexgraph/schemas/finding.schema.json`); `finding_type` (DB envelope) classifies it for triage.

### Data model

SQLite via SQLAlchemy, UUID ids:

- `project`, `target` (self-referential `parent_id` tree of artifacts).
- `node` — typed sub-file/conceptual entities: `function`, `symbol`, `string`, `struct`,
  `hypothesis`, `pattern`, `input`, `sink`, **`socket`** (a network/IPC endpoint shared across
  binaries).
- `edge` — one polymorphic, **typed, attributed** relationship between any two entities
  (target | node | finding | task): `contains`, `links_against`, `calls`, `reads`/`writes`, `taints`,
  `bypasses`, `listens_on`/`connects_to`, `similar_to`, `derived_from`, `about`, … Edges carry
  type-specific attributes (a `calls` edge's `call_sites`/`arg_constraints`, a `listens_on` edge's
  `address`/`port`); list attributes merge on repeat.
- `task`, `finding`.

Artifacts live under `~/.hexgraph/projects/<id>/`. The graph is relational — **Neo4j is out of
scope.** SQLite runs in WAL mode so the UI and an agent's MCP server share it concurrently.

### Bundled test targets

Under `tests/fixtures/` (regenerate with `just fixtures`): `vuln_httpd` (unbounded `strcpy` in a fake
CGI handler), `libupnp.so` (same sink in `ssdp_recv`, a pattern-sweep sibling), and `synthetic_fw.bin`
(a squashfs firmware that unpacks into both). Escalating, obfuscated, CVE-class challenge targets live
under `tests/fixtures/challenges/` (`./build.sh` to rebuild; `README.md` there is the answer key).

---

## Development

```bash
just                 # list all recipes, grouped (setup / run / build / test / demo / rehosting / maintenance)
just test            # full suite (mock backend; sandbox/Docker tests auto-skip without the image)
just demo            # the full offline loop, exits 0 — doubles as a smoke test
just fixtures        # rebuild the bundled test targets
just sandbox-build [with_ghidra=1]   # rebuild the analysis sandbox image (only after a Dockerfile/toolchain change)
just build-image [with_cross=1]      # build the dedicated build-from-source image (features.build; with_cross is a Phase-7 stub)
just ui              # rebuild the SPA (after any frontend/ change)
just serve           # start the server from the venv
```

Source (`src/hexgraph/`): `models/` (Finding), `llm/` (backend seam + mock + agent runner),
`db/` (SQLAlchemy models), `sandbox/` (runner + executor + decompiler + probe scripts),
`engine/` (ingest, recon, unpack, nodes, edges, edge_schemas, context, findings, poc, fuzzing,
crosstarget, hypotheses, mcp_tools, …), `api/` (FastAPI + loopback guard + SPA), `cli.py`,
`mcp_server.py`. Build progress: [`PROGRESS.md`](PROGRESS.md).

---

## Out of scope (by design)

Accounts / multi-user, cloud/hosted compute, exploit *generation*, Neo4j, Kubernetes. Dynamic
execution exists only as the opt-in, policy-gated, sandboxed PoC/fuzzing path described above — never
unsandboxed, never on the host.

---

## License

**[AGPL-3.0](LICENSE).** HexGraph is free and open — use, run, study, and modify it freely. The
copyleft terms mean any modified version you distribute *or offer over a network* must also be released
under the AGPL-3.0, so the project (and improvements to it) stay open: no one can ship a closed,
proprietary fork. No license gates, no paid tiers.
