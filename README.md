# ⬡ HexGraph

HexGraph is a self-hosted workbench for AI-assisted vulnerability research that runs entirely on
your own machine. You point it at a binary or a firmware image, and it does the unglamorous parts for
you: it ingests the target, pulls firmware apart into its component binaries, runs analysis tasks
driven by whatever model access you already have, and writes every result down as a structured
**finding** in a typed graph backed by SQLite. The graph ties everything together: targets,
functions, sockets, hypotheses, and findings, joined by typed and attributed edges. You browse all of
it, launch new tasks, and triage findings from a web UI that only ever listens on localhost, and the
same operations are available to a coding agent over MCP.

![The typed knowledge graph of a firmware engagement](docs/images/graph.png)

Three principles are non-negotiable, and they shape everything else:

- **It stays local.** The API and UI bind to `127.0.0.1` and nothing else. HexGraph never phones a
  server we operate; there is no telemetry and no auto-update ping.
- **You bring the key, or you bring nothing.** Model access comes from your own Anthropic API key, a
  local Claude Code session, or the built-in **mock** backend. The mock is the default, it needs no
  key and no network, and it lets you run the entire loop for $0.
- **Every target is treated as hostile.** All parsing, unpacking, and analysis of target bytes
  happens inside a disposable Docker container with no network and tight resource limits. HexGraph is
  static-only by default. Executing the target, reaching the network, and rehosting firmware are each
  a separate capability you opt into deliberately, and even then they run inside that same locked-down
  sandbox. The model never sees raw target bytes, only the output of the tools HexGraph runs for it
  (decompilation, strings, imports, and so on).

> **Status: pre-1.0.** The core loop works end to end today, from ingest through recon, AI analysis,
> a structured finding, the graph, and on to the next task it suggests. That includes extracting real
> vendor firmware, linking the same bug across binaries, coverage-guided fuzzing, and proofs of
> concept that actually execute and are verified (including foreign-arch MIPS and ARM targets under
> qemu). Expect rough edges. The phase-by-phase status lives in [`PROGRESS.md`](PROGRESS.md).

---

## Install

You will need Python 3.11 or newer, a Docker daemon your user can talk to (check with `docker run
--rm hello-world`), [`just`](https://just.systems), and Linux or macOS. No API key is required, since
the default mock backend runs fully offline.

```bash
git clone https://github.com/branover/hexgraph.git hexgraph && cd hexgraph
just setup          # venv + deps + web UI, then the interactive setup wizard
just serve          # → http://127.0.0.1:8765
```

`just setup` does the bootstrap and then hands off to an interactive setup wizard. The wizard walks
you through the optional features, and for each one that relaxes the security posture it shows you the
implication and asks you to confirm before turning it on. It then writes your settings and builds the
images you picked, and it can optionally register HexGraph's MCP server with a coding agent and install
the VR skill for you (both local-only, no secret). If you accept the defaults you stay in the
static-only posture; everything beyond that is something you turn on yourself, with eyes open. For the
wizard, the manual step-by-step, the non-interactive CI mode, and Ghidra, see
**[docs/setup.md](docs/setup.md)**.

> To install `just` without sudo:
> `curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`
> (make sure `~/.local/bin` is on your `PATH`), or `snap install just`. Run `just` on its own for the
> full, grouped recipe menu.

### Run it with Docker instead

If you would rather not install anything on the host, you can run the whole workbench in a container.
From a checkout, one command brings it up:

```bash
docker compose up --build      # or: just up   →  http://127.0.0.1:8765
```

That builds an app image bundling the web UI and the Python backend, runs the database migrations on
startup, and serves the workbench. The service is published only on the host loopback
(`127.0.0.1:8765:8765`), so it stays local to your machine exactly the way the pip install does. Your
`ANTHROPIC_API_KEY` is passed through from the environment if you have one set, no key is ever baked
into the image, and with nothing set the container falls back to the offline mock backend.

There is one thing worth understanding before you take this path. The compose file mounts the host's
Docker socket into the app container, because HexGraph needs to talk to a Docker daemon to launch its
disposable sandbox, build, fuzz, and rehosting containers. In this deployment those sibling containers
run on your host daemon, isolated the same way they are under the pip install. Mounting the daemon
socket effectively gives the app container root-equivalent control over your host's Docker. That is a
deliberate trade-off for a single-user, local, self-hosted tool you run on your own machine, and it is
not a hardened or multi-tenant posture. Do not expose this stack to untrusted users or networks. If
that trade-off is not one you want to make, the host pip path above is still the primary and
recommended way to run HexGraph for development.

Stop the stack with `docker compose down` (or `just down`); your project database and findings
persist in a named Docker volume.

By using HexGraph you agree to use it only against targets you are authorized to analyze. Please read
[DISCLAIMER.md](DISCLAIMER.md).

---

## The core loop

Everything in HexGraph exists to prove one loop: **target → task → structured finding → graph → spawn
the next task.** The fastest way to watch it happen is the demo, which runs the whole thing on the
bundled targets, offline, for free, and exits 0:

```bash
just demo
```

You can also drive it yourself. Ingest a target (recon runs automatically and unpacks firmware into
child targets), then launch tasks from the UI and triage the findings they produce:

```bash
.venv/bin/hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo
.venv/bin/hexgraph serve          # → http://127.0.0.1:8765
```

There are two ways to drive the loop. Both write into the same graph, and both keep target bytes
inside the sandbox.

The first is the **web UI**: pick a target, choose a task (recon, static analysis, RE, a pattern
sweep, harness generation, fuzzing, or a PoC), and run it. Behind your chosen backend, HexGraph runs
an agent loop. The model asks for sandboxed tools (decompile, strings, imports, xrefs, fuzz), HexGraph
executes them, and the loop continues until the model emits findings. You triage the results and can
one-click whatever follow-up it suggests.

The second is a **coding agent over MCP**. Running `hexgraph mcp install` registers HexGraph as an MCP
server, and Claude Code, Codex, or gemini-cli can then inspect targets and populate the graph on their
own through the same sandboxed tools. The details are in **[docs/mcp.md](docs/mcp.md)**.

In both cases the model only ever directs the work; HexGraph runs the tools. A plain API key is enough
on its own, and no external coding agent is required.

| Backend | Select with | Notes |
|---|---|---|
| `mock` (default) | — | Deterministic, schema-valid findings from fixtures. No key, no network. Powers dev, CI, and `just demo`. |
| `anthropic` | `--backend anthropic` / `HEXGRAPH_LLM_BACKEND=anthropic` | Your own key via `ANTHROPIC_API_KEY` (env or `config.toml`). Spends real tokens. Needs `pip install -e ".[byok]"`. |
| `claude_code` | `--backend claude_code` | Uses your local `claude` CLI, headless. |

HexGraph never logs or stores your API key.

---

## Features

Everything above the static-only baseline is off by default and toggled in **Settings** (or with
`hexgraph config set <key> <value>`). Each feature that relaxes the security posture is its own
separate, explicit opt-in.

| Feature | What it adds | Doc |
|---|---|---|
| **Typed graph + findings** | Targets, functions, sockets, endpoints, hypotheses, and findings as typed nodes joined by typed, attributed edges, all browsed, launched, and triaged in a three-pane UI. | [graph-ui.md](docs/graph-ui.md) |
| **Verification & the assurance ladder** | Every finding carries an assurance level (`code_present`/`input_reachable` × `static`/`dynamic`), and opt-in **PoC verification** executes the target against an unforgeable `{{NONCE}}` oracle (foreign-arch via qemu-user). | [verification-assurance.md](docs/verification-assurance.md) |
| **Fuzzing** | Coverage-guided, surface-aware, campaign-driven fuzzing (AFL++, libFuzzer, qemu-mode, boofuzz, desock), detached and crash-safe, with live triage, dedup, minimization, and one-click re-verification. Campaigns can run on a beefier host you own. | [fuzzing.md](docs/fuzzing.md) |
| **Build from source** | Compile a managed source tree into an instrumented, reproducible artifact through a recorded recipe HexGraph runs in the sandbox, with the build-to-fuzz handoff wired up automatically. Includes an in-browser **Source / IDE tab** with coverage shading. | [build-from-source.md](docs/build-from-source.md) |
| **Dynamic surfaces, rehosting & remote** | Model a running web service or a raw-TCP daemon as a first-class **surface**, **rehost** a whole firmware image under full-system emulation, or assess a physical **remote** device over SSH/telnet, all with bounded and audited egress. | [dynamic-surfaces-rehosting-remote.md](docs/dynamic-surfaces-rehosting-remote.md) |
| **Coding-agent integration (MCP)** | Drive HexGraph from Claude Code, Codex, or gemini-cli, or have HexGraph drive a headless agent in delegate mode. Either way the agent is restricted to HexGraph's sandboxed tools. | [mcp.md](docs/mcp.md) |

### The opt-in policy tiers, briefly

The enforced default is static-only with `--network none`. From there, each higher tier sits behind
its own gate and nothing relaxes anywhere except the single [policy
seam](docs/verification-assurance.md). `features.poc` and `features.fuzzing` allow sandboxed
execution; `features.build` compiles a source tree; `features.build_fetch` adds a separate, audited,
allowlisted dependency fetch; `features.network` permits bounded loopback and private-network egress;
`features.rehost` boots full-system emulation; `features.remote` reaches one authorized live device;
and `features.fuzz_remote` runs a campaign on a compute host you own. You turn on only what a given
engagement needs.

---

## CLI

Run `.venv/bin/hexgraph <command>` (or just `hexgraph` with the venv active):

```text
hexgraph ingest <path> [--name N] [--project ID] [--no-recon] [--backend B]
hexgraph targets <project>
hexgraph run <target> --type T [--objective TEXT] [--function F] [--backend B] [--mock-scenario S]
hexgraph rehost <target> [--brand HINT]      # boot firmware under emulation (needs features.rehost)
hexgraph findings <project> [--status S] [--export FILE]
hexgraph graph <project> --export FILE
hexgraph config list | get K | set K V       # managed settings + optional-feature toggles
hexgraph mcp [--tools read,write,run] | mcp install [--agent A] | mcp --check
hexgraph serve [--host H] [--port P]          # loopback-only API/UI (default 127.0.0.1:8765)
```

The task types are `recon`, `static_analysis`, `reverse_engineering`, `pattern_sweep`, and
`harness_generation`, plus `fuzzing`, `poc`, and `agent_delegate` once you enable them. Web surfaces
add `surface_recon` and `web_recon`. The full configuration story (environment variables,
`config.toml`, and how the layers override each other) is in **[docs/setup.md](docs/setup.md)**.

---

## Security model

- **Loopback only.** The server refuses to bind a non-loopback address unless you set
  `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`.
- **Hostile-target isolation.** Every operation on target bytes runs in a fresh container with
  `--network none`, a read-only root filesystem, a tmpfs scratch space, memory, CPU, and PID limits,
  and a wall-clock timeout. Only HexGraph's own probe scripts ever run in there.
- **Static by default, with capability that is opt-in and graduated.** Each tier is a separate,
  explicit opt-in that flips the single policy seam, and nothing relaxes anywhere else. The same
  sandbox hardening holds for every tier, with foreign-arch work running under qemu-user rather than
  on the host. The full ladder is in [docs/verification-assurance.md](docs/verification-assurance.md).
- **The model never sees raw target bytes**, only tool output.
- **Secrets are never persisted or logged.** Your API key, along with any SSH or remote-Docker
  credentials, lives only in your environment or `config.toml`. HexGraph reads it on demand and
  reports it as present or absent, never by value.

---

## How it works

HexGraph is built around a handful of clean seams. You change behavior by swapping an implementation
behind a seam, never by branching on the backend, the tier, or the executor.

- **`LLMBackend`** makes `mock`, `anthropic`, and `claude_code` interchangeable; task code never knows
  which one is in play.
- **Executor** is the single container boundary for all target-byte handling, whether that container
  runs on local or remote Docker.
- **Decompiler** is radare2 by default, with Ghidra available behind the same seam.
- **Rehoster** drives full-system firmware emulation, using FirmAE for vendor blobs and qemu+KVM for
  disk images.
- **Policy** is the one place, and the only place, the static-only invariant is relaxed.

The Finding is the heart of the product. Every task and every backend, the mock included, emits the
same frozen schema (`src/hexgraph/schemas/finding.schema.json`), and a `finding_type` field (kept in a
DB envelope, not the schema) classifies it for triage.

The data model is SQLite through SQLAlchemy, with UUID ids and WAL mode so the UI and an agent's MCP
server can share the database at the same time. It holds a `project`, a `target` (a self-referential
tree of reachable surfaces), `node` rows (typed sub-file and conceptual entities), a polymorphic
typed, attributed `edge`, a `task`, and a `finding`. The graph is relational, and Neo4j is
deliberately out of scope. More detail lives in [docs/graph-ui.md](docs/graph-ui.md).

A few test targets ship under `tests/fixtures/` (regenerate them with `just fixtures`): `vuln_httpd`
with its unbounded `strcpy`, `libupnp.so` as a pattern-sweep sibling, and `synthetic_fw.bin`, a
squashfs firmware that unpacks into both. A set of escalating, CVE-class challenge targets lives under
`tests/fixtures/challenges/`.

---

## Development

```bash
just                 # list every recipe, grouped
just test            # the full suite (mock backend; sandbox/Docker tests auto-skip without the image)
just demo            # the full offline loop, exits 0 — doubles as a smoke test
just ui              # rebuild the SPA (after any frontend/ change)
just showcase --reset && just capture   # regenerate the doc screenshots (see docs/images/README.md)
```

The source lives under `src/hexgraph/` (`models/`, `llm/`, `db/`, `sandbox/`, `engine/`, `api/`,
`cli.py`, `mcp_server.py`). For the working agreement, the seam rule, and the worktree-and-PR
discipline, read [`CLAUDE.md`](CLAUDE.md). Build progress is tracked in [`PROGRESS.md`](PROGRESS.md).

---

## Out of scope, by design

HexGraph does not do accounts or multi-user, cloud or hosted compute, exploit *generation*, Neo4j, or
Kubernetes. Dynamic execution exists only as the opt-in, policy-gated, sandboxed path described above.
It never runs unsandboxed, and it never runs on the host.

---

## License

HexGraph is released under [**AGPL-3.0**](LICENSE). It is free and open: use it, run it, study it, and
modify it as you like. The copyleft terms mean that any modified version you distribute, or offer to
others over a network, has to be released under the AGPL-3.0 too, which is what keeps the project open
and prevents a closed, proprietary fork. There are no license gates and no paid tiers.
