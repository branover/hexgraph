# Setup, configuration & the setup wizard

The fast path is two commands (see the [README](../README.md#install)):

```bash
just setup          # venv + deps + web UI, then the interactive setup wizard
just serve          # → http://127.0.0.1:8765
```

Don't want to install [`just`](https://just.systems)? There's a plain shell script that does the
same bootstrap and then drops you into the very same interactive wizard:

```bash
./setup.sh          # venv + deps + web UI, then the interactive setup wizard
.venv/bin/hexgraph serve
```

`setup.sh` passes any arguments straight through to the wizard, so `./setup.sh --yes` takes the
static-only defaults without prompting (handy for CI or a scripted install).

## The setup wizard

`just setup` runs the bootstrap and then launches an interactive setup wizard (`hexgraph setup`). The
wizard covers two things. First, which optional features you want to enable: for each one that relaxes
the security posture (executing the target, network egress, rehosting, reaching a remote device, and
so on) it shows you the security implication and asks you to confirm before turning it on. Second, the
non-secret configuration: the loopback-only bind address, the LLM backend, and the Ghidra mode.

Once you have answered, it writes your settings and builds the images you chose. The wizard never
prompts for a secret and never stores one. API keys, SSH credentials, and remote-Docker credentials
live only in your environment or in `~/.hexgraph/config.toml`, and the wizard only tells you whether
one is present. Accept the defaults and you stay in the static-only posture; everything beyond that is
something you opt into, informed.

Near the end the wizard also offers to wire HexGraph up to a coding agent, if you want to drive it
that way. It can register HexGraph's MCP server with Claude Code, Codex, or gemini-cli (you pick the
agent and whether to register it just for this project or for all of them), and it can drop the VR
skill, the file that teaches the agent the workflow and the hostile-target rules, wherever you like
(your global `~/.claude/skills`, a project `.claude/skills`, or a path you type in). Both steps are
just local edits to the agent's own config and a skill file on disk: nothing goes over the network,
and no secret is written, because the MCP command carries no key (the server reads any key from your
environment or `config.toml` when it runs). Both are optional and you can decline either one, and
re-running setup and choosing them again is harmless since the registration and the skill install are
idempotent.

You can re-run `hexgraph setup` any time you want to change which features are on, and `hexgraph config
list` shows the current settings. If you would rather register the MCP server by hand, `hexgraph mcp
install` prints the exact steps for each agent.

> **Non-interactive and CI.** When there is no TTY, or when you pass `--yes` (`just setup --yes`,
> `./setup.sh --yes`, or `hexgraph setup --non-interactive`), the wizard applies the static-only
> baseline plus the sandbox image without prompting, and skips the coding-agent and skill install
> entirely, so an unattended `just setup` never hangs.
>
> **A note on `XDG_RUNTIME_DIR`.** `just` writes a small temp script to run any shebang recipe (like
> `setup`), normally under `$XDG_RUNTIME_DIR` (e.g. `/run/user/$UID`). In stripped-down environments —
> minimal containers, `cron`, `su` without a login session — that variable can point at a directory
> that doesn't exist and can't be created, which historically surfaced as `error: I/O error in runtime
> dir`. The justfile now pins `just`'s temp dir to a writable location (`set tempdir := "/tmp"`), so
> this no longer bites you. If you ever hit a similar runtime-dir error from another tool, the root
> cause is the same broken `XDG_RUNTIME_DIR`; `export XDG_RUNTIME_DIR=$(mktemp -d)` is a quick
> per-shell workaround, and `./setup.sh` sidesteps `just` entirely.

## Manual install (or adding Ghidra)

```bash
just install                     # create .venv and install the hexgraph CLI + dev extras
just ui                          # build the React SPA into src/hexgraph/web/dist
just sandbox-build               # build the analysis sandbox image (hexgraph-sandbox:latest)
.venv/bin/hexgraph serve
```

The sandbox image bundles the firmware extractors (sasquatch, jefferson, ubi_reader, binwalk, and The
Sleuth Kit) and qemu-user (MIPS, ARM, PPC, and friends), so real vendor firmware extracts and
foreign-arch PoCs both run with no extra setup.

Ghidra is optional and makes for a larger image. The default sandbox uses radare2; to also bundle
headless Ghidra (which adds a JDK and roughly 400 MB):

```bash
just sandbox-build with_ghidra=1
hexgraph config set features.ghidra.enabled true     # then re-run a decompile/recon task
```

Two Ghidra modes are set with `features.ghidra.mode`: `headless` runs analyzeHeadless in the sandbox,
and `bridge` connects to a running Ghidra over `ghidra_bridge` (covered next). The separate
`features.ghidra.enrich_recon` toggle materializes functions, the call graph, and structs into the
substrate. With Ghidra off, HexGraph degrades to radare2.

### Bridge mode: connect to a Ghidra you already have open

Bridge mode is for the analyst who already runs Ghidra: HexGraph connects to it over loopback and
pulls decompilation straight from your live analysis of the **currently active program**. The bytes
never leave the machine, so HexGraph and Ghidra must be on the same host (for two hosts, tunnel
`127.0.0.1:4768` over SSH). It needs two pieces in place — the bridge client in HexGraph's environment,
and the bridge server running inside your Ghidra.

First install the client into HexGraph's venv:

```bash
pip install "hexgraph[bridge]"      # or: pip install ghidra_bridge   (pulls jfx_bridge)
```

Then install the server scripts into your Ghidra and start the server. The documented installer is
`python -m ghidra_bridge.install_server <your_ghidra_scripts_dir>`, but on recent setuptools it can
fail with `ModuleNotFoundError: pkg_resources`. If it does, either `pip install "setuptools<81"` and
retry, or copy the files by hand — `ghidra_bridge/server/*.py` plus the whole `jfx_bridge/` package
into your Ghidra scripts directory. With that in place, open your target in Ghidra, let auto-analysis
finish, and from the Script Manager run `ghidra_bridge_server_background.py`; it listens on
`127.0.0.1:4768`. Keep that program the active tab — the bridge always decompiles whatever Ghidra has
in front.

No GUI? Run a headless Ghidra as the server with the in-image build (it stays alive holding the program
as `currentProgram`):

```bash
docker run -d --name hg-ghidra-bridge --network host \
  -v /path/to/target:/work/target:ro -v /path/to/ghidra_bridge_scripts:/scripts:ro \
  hexgraph-sandbox:latest bash -lc \
  '/opt/ghidra/support/analyzeHeadless /tmp/pj hgbridge -import /work/target \
     -scriptPath /scripts -postScript ghidra_bridge_server.py'
```

Finally point HexGraph at it — `features.ghidra = {enabled: true, mode: "bridge", bridge: {host:
"127.0.0.1", port: 4768}}` (read live, no restart; `127.0.0.1:4768` are the defaults). The Settings
"Test" button (and the `meta_check_decompiler` tool) confirms it by running a one-function smoke decompile,
so a green result means decompilation actually works, not merely that the socket is open.

## Configuration

Settings layer from most to least specific: environment variables override `settings.json` (the
managed file), which overrides `config.toml` (the hand-authored file that holds your BYOK secret),
which overrides the built-in defaults. Secrets live only in the environment or in `config.toml`, and
they are never written to `settings.json` and never returned by the API.

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
| `HEXGRAPH_LLM_BACKEND` | `mock` | Which backend to use. |
| `HEXGRAPH_MODEL` | — | The default model. |
| `HEXGRAPH_HOST` / `HEXGRAPH_PORT` | `127.0.0.1` / `8765` | The API/UI bind address. |
| `HEXGRAPH_HOME` | `~/.hexgraph` | Root for the database and per-project artifacts. |
| `HEXGRAPH_DB_PATH` | `$HEXGRAPH_HOME/hexgraph.db` | The SQLite database path. |
| `HEXGRAPH_MOCK_SCENARIO` | — | Force a mock scenario for every task. |
| `HEXGRAPH_SANDBOX_IMAGE` | `hexgraph-sandbox:latest` | The analysis sandbox image. |
| `HEXGRAPH_BUILD_IMAGE` | `hexgraph-build:latest` | The build-from-source image (`features.build`). |
| `HEXGRAPH_BUILDER` | `sandbox` | Override the Builder seam (`sandbox` or `mock`). |
| `HEXGRAPH_FUZZ_IMAGE` | `hexgraph-fuzz:latest` | The coverage-guided fuzz image (`features.fuzzing`); point at a private tag in a worktree. |
| `HEXGRAPH_ANGR_IMAGE` | `hexgraph-angr:latest` | The dedicated angr symbolic-execution image (`features.angr`); point at a private tag in a worktree. |
| `HEXGRAPH_FUZZER` | _(by surface)_ | Force the Fuzzer seam to the offline `mock` engine; otherwise the engine is picked by attack surface. |
| `HEXGRAPH_EXECUTOR` | `local_docker` | The Executor seam (`local_docker` or `remote_docker`). |
| `HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST` | — | **Secret.** A remote fuzz environment's Docker endpoint (`ssh://…` or `tcp://…`), read on demand and never logged or stored. `…_<ID>_TLS_VERIFY` and `…_<ID>_CERT_PATH` add TLS for `tcp://`. |
| `HEXGRAPH_SANDBOX_NO_MOUNT` | — | Set to `1` to use the image's baked-in probes instead of mounting the local copies. |
| `HEXGRAPH_DECOMPILER` | `r2` | Override the decompiler seam (`r2` or `ghidra`). |
| `HEXGRAPH_DISABLE_DECOMPILE` | — | Set to `1` to skip decompilation in LLM tasks (offline or no-Docker dev, plus tests). |
| `HEXGRAPH_DISABLE_SANDBOX_BUILD` | — | Set to `1` to skip the harness-compile sandbox step (dev and tests). |
| `HEXGRAPH_I_KNOW_WHAT_IM_DOING` | — | Set to `1` to allow a non-loopback bind. It warns loudly and is not recommended. |
| `ANTHROPIC_API_KEY` | — | Your key for the `anthropic` backend, read on demand and never logged or stored. |

Runtime data lives under `~/.hexgraph/` (override it with `HEXGRAPH_HOME`). The project database is
durable researcher knowledge, so schema changes always ship an Alembic migration and the database is
never silently reset.

## Model backends

The backend is chosen by `HEXGRAPH_LLM_BACKEND` (default `mock`), or per task with `--backend`. Task
code is identical across all of them; only the backend boundary changes. Whichever you pick, an LLM
task runs a tool-use agent loop: the model directs the work and HexGraph runs the tools in the
sandbox.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
hexgraph run <target> --type static_analysis --backend anthropic --function cgi_handler
```
