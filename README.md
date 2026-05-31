# ⬡ HexGraph

A self-hosted, **local-only** agentic vulnerability-research workbench. Point it at a binary or
firmware image; HexGraph ingests the target, breaks firmware into child targets, runs AI-driven
analysis tasks **using your own model access**, and records every result as a structured **finding**
in a SQLite-backed **graph** linking targets and findings. A loopback-only web UI browses the graph,
launches tasks, and triages findings.

Three principles are non-negotiable:

- **Local-only.** The API/UI bind to `127.0.0.1`. Nothing calls a HexGraph-operated server; no
  telemetry, no auto-update pings.
- **Bring-your-own-key, or none at all.** Model access is via your Anthropic API key, a local
  Claude Code session, or the built-in **mock** backend. The mock is the default and needs **no key
  and no network**, so you can run the entire loop for free.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes happens inside a disposable
  Docker container with no network and strict resource limits. **HexGraph never executes the target**
  (static/RE only).

> ### Project status — pre-1.0, v2 in progress
> The MVP loop works (ingest → recon → AI analysis → finding → graph → spawn). The **v2** build
> (typed graph, content-addressed context bundles, React analyst-notebook UI, task/finding management,
> HITL triage, search/report) is well underway — see `docs/implementation-plan.md` and `PROGRESS.md`
> for exact phase status. Build the UI with `make ui`. Still pre-1.0 — expect rough edges.

---

## Requirements

- **Python 3.11+**
- **Docker** (the analysis sandbox runs in a container; required for ingest/recon and the demo)
- Linux or macOS. Docker must be runnable by your user (`docker run --rm hello-world` should work).

No API key is required for development — the default mock backend is fully offline.

---

## Install

```bash
git clone <your-fork-or-path> hexgraph && cd hexgraph
make install          # creates .venv and installs HexGraph (server + dev extras)
make sandbox-build    # builds the analysis sandbox image (hexgraph-sandbox:latest)
```

`make install` creates a virtualenv at `.venv/` and installs the `hexgraph` CLI into it.
`make sandbox-build` builds the Docker image that the static-analysis tools run inside; it is needed
for any task that touches target bytes (recon, firmware unpack).

---

## Quickstart (mock backend — no key, no network)

Run the whole loop on the bundled test targets and exit 0:

```bash
make demo
```

Or drive it yourself:

```bash
# 1. Ingest the bundled firmware image. Recon runs automatically (zero model calls)
#    and unpacks it into child targets joined by `contains` edges.
.venv/bin/hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo

# 2. Start the loopback-only web UI (mock backend is the default).
.venv/bin/hexgraph serve            # → http://127.0.0.1:8765
```

Then open **http://127.0.0.1:8765**, click your project, and use the per-target task launcher
(see [The web UI](#the-web-ui)).

---

## The web UI

Open `http://127.0.0.1:8765` after `hexgraph serve`. The workspace has three panes:

- **Left — target tree.** The ingested target and any firmware children. Each target has a small
  launcher: pick a **task type** and (for the mock) a **scenario**, then **Run**.
- **Center — graph.** Targets and findings as connected nodes (`contains` / `links_against` /
  `related_to` edges, plus finding→target links). Rendered offline with a vendored Cytoscape.js.
- **Right — findings.** Every finding for the project; click one to see its evidence, reasoning, and
  suggested follow-ups.

After ingesting `synthetic_fw.bin` you'll see it unpack into two child targets —
`sbin/httpd` (executable) and `usr/lib/libupnp.so` (shared library). That's what success looks like.

**Mock scenarios you can try** (mock backend only) on the `sbin/httpd` child target:

| Task type / scenario | What you'll see |
|---|---|
| `static_analysis` / `critical_overflow` | A **critical** stack-overflow finding + a `related_to` edge to `libupnp.so` |
| `static_analysis` / `no_findings` | The clean "0 findings" path |
| `static_analysis` / `malformed_then_valid` | Exercises the JSON-repair retry, then a valid finding |
| `reverse_engineering` | An info-level annotation finding |
| `pattern_sweep` | A high-severity sibling match (the same `strcpy` sink in `libupnp.so`) |
| `error_rate_limit` / `error_timeout` | The task fails gracefully (retry/backoff then `failed`) |
| `(default)` | A deterministic, always-successful scenario |

Click a finding's **suggested follow-up** button to open a **pre-filled launch modal** for the next
task (with the parent finding and context carried forward) — review the model/budget, then **Launch
agent**. It runs against the resolved target (e.g. a sibling). `pattern_sweep` adds a finding on the
matched sibling and a `related_to` edge; `harness_generation` compiles the generated harness in the
sandbox. Use **Confirm / Dismiss** in the detail panel to triage a finding.

---

## CLI reference

All commands are available as `.venv/bin/hexgraph <command>` (or just `hexgraph` with the venv active).

```text
hexgraph init                              Initialize HexGraph (DB + ~/.hexgraph dirs) — optional;
                                           ingest/serve auto-initialize the DB on first use
hexgraph ingest <path> [--name N]          Ingest a binary/firmware; runs recon (auto-unpacks firmware)
                 [--project ID]            …add to an existing project instead of creating one
                 [--no-recon]              …register the target without running analysis
                 [--backend B]             …mock | anthropic | claude_code  (default: mock)
hexgraph targets <project>                 List targets in a project
hexgraph run <target> --type T             Run an analysis task against a target
             [--objective TEXT]            …free-text objective for the agent
             [--model M] [--backend B]     …per-task model / backend override
             [--function F]                …focus function
             [--mock-scenario S]           …force a specific mock scenario
hexgraph findings <project> [--status S]   List findings (optionally filter by new|accepted|dismissed)
                 [--export FILE]           …or write the findings as JSON to FILE
hexgraph graph <project> --export FILE     Export the project graph as JSON (nodes + edges)
hexgraph config list | get K | set K V     Read/write managed settings (optional features, prefs)
hexgraph mcp [--tools read,write,run]      Run the MCP server for a coding agent (stdio)
hexgraph mcp install [--agent A]           Print how to register HexGraph with claude|codex|gemini
hexgraph serve [--host H] [--port P]       Start the loopback-only API/UI (default 127.0.0.1:8765)
```

Task types for `--type`: `recon`, `static_analysis`, `reverse_engineering`, `pattern_sweep`,
`harness_generation` (plus `fuzzing` and `agent_delegate` when enabled in Settings).

### Coding-agent integration (MCP)

HexGraph can work *with* a coding agent (Claude Code / Codex / gemini-cli) in two directions, both
keeping target bytes inside the sandbox:

- **You drive the agent.** `hexgraph mcp install` registers HexGraph as an MCP server; your agent then
  uses the `hexgraph` tools to inspect targets, populate the graph (findings/nodes/edges/hypotheses),
  and run sandboxed tasks. Trim which tool groups it sees in **Settings → Coding-agent tools** (read /
  write / run) so its context isn't cluttered.
- **HexGraph drives the agent.** Enable **Settings → Delegate to a coding agent**, then launch an
  `agent_delegate` task from the Run menu — HexGraph runs your agent headless, wired to the MCP server
  and restricted to HexGraph's sandboxed tools (no shell on the target).

---

## Model backends

Selected by `HEXGRAPH_LLM_BACKEND` (default `mock`) or per-task with `--backend`. Task code is
identical across backends — only the backend boundary changes.

| Backend | Status | Notes |
|---|---|---|
| `mock` | ✅ Working | Deterministic, schema-valid findings from bundled fixtures. No key, no network. The default for dev, CI, and `make demo`. |
| `anthropic` | ✅ Working | BYOK via `ANTHROPIC_API_KEY` (env or config). Real token usage + cost estimate. Install with `pip install -e ".[byok]"` (or `anthropic`). |
| `claude_code` | ✅ Working | Uses your local `claude` CLI (headless print mode); fails clearly if the CLI isn't installed. |

HexGraph **never logs or stores your API key**. To use a real backend:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
hexgraph run <target> --type static_analysis --backend anthropic --function cgi_handler
```

Target decompilation (radare2, in the sandbox) is fed to real backends as prompt context; the LLM
never sees raw target bytes. The decompiler is behind a seam so Ghidra can be added later.

---

## Configuration

HexGraph reads optional config from `~/.hexgraph/config.toml`; environment variables override it.

```toml
# ~/.hexgraph/config.toml
[llm]
backend = "mock"        # mock | anthropic | claude_code
model   = ""            # optional default model

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
| `HEXGRAPH_SANDBOX_DEV` | — | `1` to dev-mount local probe scripts instead of the baked-in copies. |
| `HEXGRAPH_I_KNOW_WHAT_IM_DOING` | — | `1` to allow a non-loopback bind (warns loudly; not recommended). |
| `ANTHROPIC_API_KEY` | — | Your key for the `anthropic` backend. Read on demand; never logged or stored. |

---

## Security model

- **Loopback only.** The server refuses to bind to a non-loopback address. Override requires
  `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`, which still warns loudly.
- **Hostile-target isolation.** Every operation on target bytes runs in a fresh container with
  `--network none`, a read-only root filesystem, a tmpfs scratch, and memory/CPU/PID limits plus a
  wall-clock timeout. Only HexGraph's probe scripts run there — **the target is never executed**.
- **The LLM never sees raw target bytes** — only tool output (decompilation, strings, imports) is
  sent to a model.
- **Secrets are never persisted or logged.** Your API key lives only in env/config and is read on
  demand.

---

## How it works

The whole system proves one loop: **target → delegate task → structured finding → graph → spawn next
task.** It is built around three clean seams:

- **`LLMBackend`** — `mock`, `anthropic`, and `claude_code` are interchangeable; task code never
  knows which backend it talks to.
- **Task registry** — every task type implements one `plan → run → suggest_followups` protocol.
- **Sandbox runner** — the single container boundary for all target-byte handling.

**The Finding is the heart of the product.** Every task and every backend emits the same schema
(`context/schemas/finding.schema.json`), which is what makes triage and the graph possible.

### Data model

SQLite via SQLAlchemy, UUID ids: `project`, `target` (self-referential `parent_id` tree),
`edge` (`contains` | `links_against` | `related_to`), `task`, `finding`. Artifacts are stored on the
local filesystem under `~/.hexgraph/projects/<id>/`.

### Bundled test targets

Tiny, intentionally-vulnerable targets live under `tests/fixtures/` (regenerate with `make fixtures`):

- `vuln_httpd` — an ELF with an unbounded `strcpy` in a fake CGI handler, built with weak mitigations.
  (Inside `synthetic_fw.bin` it appears at the rootfs path `sbin/httpd`.)
- `libupnp.so` — a shared library with the same `strcpy` sink in `ssdp_recv` (a sibling for pattern
  sweeps). (Inside the firmware: `usr/lib/libupnp.so`.)
- `synthetic_fw.bin` — a squashfs firmware image that unpacks into the two binaries above.

---

## Development

```bash
make test            # full test suite (mock backend; sandbox tests auto-skip without Docker)
make demo            # the full offline loop, exits 0 — doubles as a smoke test
make fixtures        # rebuild the bundled test targets
make sandbox-build   # rebuild the analysis sandbox image
make serve           # start the server from the venv
make help            # list all targets
```

Source layout (under `src/hexgraph/`): `models/` (Finding), `llm/` (the backend seam + mock),
`db/` (SQLAlchemy models), `sandbox/` (runner + probe scripts), `tasks/` (handler protocol),
`engine/` (ingest, recon, unpack, graph, worker, pipeline), `api/` (FastAPI + loopback guard),
`web/` (templates + static assets), `cli.py`.

**Build progress is tracked in [`PROGRESS.md`](PROGRESS.md)** — the canonical, resumable record of
what's done and what's next. Start there if you're picking up the build.

---

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **M0** | Mock backend, `LLMBackend` seam, `Finding` model, contract test | ✅ Done |
| **M1** | Config, SQLite models, ingest, CLI, FastAPI on loopback | ✅ Done |
| **M2** | Sandbox + `recon`, firmware unpack, graph endpoint, web UI | ✅ Done |
| **M3** | `static_analysis` + `reverse_engineering`; real backends; decompiler; per-task model/cost | ✅ Done |
| **M4** | One-click follow-up spawn; `pattern_sweep`; `harness_generation` | ✅ Done |
| **M5** | Accept/dismiss triage, dedup, findings export, polish | ✅ Done (UI polish backlog in `docs/ui-backlog.md`) |

**Opt-in, off by default** (the v1 static-only/local defaults still hold unless you enable these in
Settings): a **Ghidra** decompiler/enrichment integration, **fuzzing** (libFuzzer over a generated
harness — relaxes the static-only policy *only when enabled*, still sandboxed/`--network none`/capped),
and **coding-agent** integration (an MCP server + an in-UI delegate task for Claude Code/Codex/gemini-cli).

Out of scope (by design): accounts/multi-user, cloud/hosted compute, dynamic/emulated execution of the
target as-is, exploit generation, Neo4j, Kubernetes.

---

## Running with Docker Compose

> 🚧 **Partially implemented.** `docker compose up` builds and starts the loopback-only UI service
> (published to `127.0.0.1:8765`). The container launches the analysis sandbox via the host Docker
> socket, so you must run `make sandbox-build` on the host first. This path is not yet fully smoke-tested
> end-to-end — the venv quickstart above is the recommended way to run HexGraph today.

```bash
make sandbox-build
docker compose up
```

---

## License

> 🚧 To be determined. HexGraph is intended to be fully free and open (no license gates, no paid tiers).
