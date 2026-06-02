# Setup, configuration & the setup wizard

The fast path is two commands (see the [README](../README.md#install)):

```bash
just setup          # venv + deps + web UI, then the interactive setup wizard
just serve          # → http://127.0.0.1:8765
```

## The setup wizard

`just setup` runs the bootstrap and then launches an **interactive setup wizard**
(`hexgraph setup`). It walks you through:

- **Which optional features to enable.** Each policy-relaxing one (executing the target, network
  egress, rehosting, remote devices, …) is shown with its **security implication** and an explicit
  confirmation.
- **Non-secret config** — the loopback-only bind, the LLM backend, the Ghidra mode.

It then writes your settings and builds the images you chose. **HexGraph never prompts for or stores
a secret:** API keys / SSH / remote-Docker credentials live only in your environment or
`~/.hexgraph/config.toml` (the wizard only shows whether one is present). The default leaves the
**static-only** posture intact — you opt in to everything else, informed.

Re-run `hexgraph setup` any time to change features; `hexgraph config list` shows the current
settings.

> **Non-interactive / CI:** with no TTY, or `just setup yes=1` (or `hexgraph setup
> --non-interactive`), the wizard applies the static-only baseline + the sandbox image **without
> prompting**, so an unattended `just setup` never hangs.

## Manual install (or to add Ghidra)

```bash
just install                     # create .venv and install the hexgraph CLI + dev extras
just ui                          # build the React SPA into src/hexgraph/web/dist
just sandbox-build               # build the analysis sandbox image (hexgraph-sandbox:latest)
.venv/bin/hexgraph serve
```

The sandbox image bundles **firmware extractors** (sasquatch / jefferson / ubi_reader / binwalk /
The Sleuth Kit) and **qemu-user** (MIPS/ARM/PPC/…), so real vendor firmware extracts and foreign-arch
PoCs run with no extra setup.

**Ghidra (optional, larger image).** The default sandbox uses radare2. To also bundle headless Ghidra
(adds a JDK + ~400 MB):

```bash
just sandbox-build with_ghidra=1
hexgraph config set features.ghidra.enabled true     # then re-run a decompile/recon task
```

Ghidra modes (`features.ghidra.mode`): `headless` (analyzeHeadless in the sandbox), `bridge` (connect
to a running Ghidra via `ghidra_bridge`), `enrich_recon` (materialize functions/call-graph/structs).
Degrades to radare2 when off.

## Configuration

Settings layer as **env > `settings.json` (managed) > `config.toml` (hand-authored, BYOK secret) >
defaults**. Secrets live only in env or `config.toml` and are **never** written to `settings.json` or
returned by the API.

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
| `HEXGRAPH_BUILD_IMAGE` | `hexgraph-build:latest` | Build-from-source image (`features.build`). |
| `HEXGRAPH_BUILDER` | `sandbox` | Override the Builder seam (`sandbox` \| `mock`). |
| `HEXGRAPH_FUZZ_IMAGE` | `hexgraph-fuzz:latest` | Coverage-guided fuzz image (`features.fuzzing`). Point at a private tag in a worktree. |
| `HEXGRAPH_FUZZER` | _(by surface)_ | Force the Fuzzer seam to the offline `mock` engine; otherwise picked by attack surface. |
| `HEXGRAPH_EXECUTOR` | `local_docker` | The Executor seam (`local_docker` \| `remote_docker`). |
| `HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST` | — | **Secret.** A remote fuzz environment's Docker endpoint (`ssh://…` or `tcp://…`). Read on demand; never logged/stored. `…_<ID>_TLS_VERIFY` / `…_<ID>_CERT_PATH` add TLS for `tcp://`. |
| `HEXGRAPH_SANDBOX_NO_MOUNT` | — | `1` to use the image's baked-in probes instead of mounting the local copies. |
| `HEXGRAPH_DECOMPILER` | `r2` | Override the decompiler seam (`r2` \| `ghidra`). |
| `HEXGRAPH_DISABLE_DECOMPILE` | — | `1` to skip decompilation in LLM tasks (offline/no-Docker dev + tests). |
| `HEXGRAPH_DISABLE_SANDBOX_BUILD` | — | `1` to skip the harness-compile sandbox step (dev/tests). |
| `HEXGRAPH_I_KNOW_WHAT_IM_DOING` | — | `1` to allow a non-loopback bind (warns loudly; not recommended). |
| `ANTHROPIC_API_KEY` | — | Your key for the `anthropic` backend. Read on demand; never logged or stored. |

Runtime data lives under `~/.hexgraph/` (override with `HEXGRAPH_HOME`). The project DB is durable
researcher knowledge — schema changes ship Alembic migrations and the DB is never silently reset.

## Model backends

Selected by `HEXGRAPH_LLM_BACKEND` (default `mock`) or per-task with `--backend`. Task code is
identical across backends — only the backend boundary changes. LLM tasks run a **tool-use agent
loop** over whichever backend you pick (the model directs, HexGraph runs the tools in the sandbox).

```bash
export ANTHROPIC_API_KEY=sk-ant-...
hexgraph run <target> --type static_analysis --backend anthropic --function cgi_handler
```
