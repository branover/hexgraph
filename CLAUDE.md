# CLAUDE.md

Guidance for Claude Code working in this repo. These instructions override default behavior — follow them exactly. This file is durable orientation + rules, **not** a changelog. Per-phase status and history live in `PROGRESS.md`.

## What HexGraph is

A self-hosted, **local-only** agentic vulnerability-research workbench. Point it at a binary/firmware → it ingests the target, breaks firmware into child targets, runs AI-driven analysis tasks using the user's own model access, and records every result as a structured **finding** in a SQLite-backed **typed graph** (targets · nodes · findings · tasks). A loopback web UI browses the graph, launches tasks, and triages findings. The whole system exists to prove one loop: **target → task → structured finding → graph → spawn next task.**

## ▶ Start every session here

1. Read **`PROGRESS.md`** — its `▶ RESUME HERE` block is the source of truth for current state, next task, and how to re-verify.
2. Re-verify with `make test` (full suite, mock backend, offline) and `make demo` (full loop; needs Docker + sandbox image).
3. **Update `PROGRESS.md` as work lands** (checklist + `▶ RESUME HERE` + session log) and commit it with the code. Keep this file current only when a *durable rule or fact* changes — never add feature history here.

## Non-negotiable constraints (these define the product)

- **Fully self-hosted.** Nothing calls a HexGraph-operated backend; no telemetry, no auto-update pings.
- **Loopback only.** API/UI bind `127.0.0.1`; a startup assertion refuses a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1`.
- **BYOK / Claude Code / mock only.** No bundled keys, no proxying. Read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never log, store, or return it.** `HEXGRAPH_API_KEY` is reserved for future paid features — same rule.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes runs only inside the disposable Docker sandbox (`--network none`, read-only rootfs, mem/cpu/pids caps, tmpfs, hard timeout). **Never execute the target** (static/RE only). **The LLM never sees raw target bytes** — only tool output carried in `TaskContext`.
- **Zero token spend by default.** Mock backend is the dev/CI default; `make demo` runs the full loop offline with no key and exits 0.
- **The Finding schema is frozen** (`context/schemas/finding.schema.json`). Every task and backend (mock included) emits exactly this shape; a contract test enforces it. New structure goes in the DB envelope, not the schema.
- **Migrations are mandatory.** The project DB is durable researcher knowledge, never silently reset. Any schema change ships an `alembic revision --autogenerate` committed with the model change.

## Architecture & the seam rule

**Ask a seam, never branch on backend identity, license tier, or executor.** Feature code calls a seam; concrete implementations swap behind it. The seams:

- **`LLMBackend`** (`llm/`, selected by `HEXGRAPH_LLM_BACKEND`, default `mock`): `MockLLMBackend` / `AnthropicAPIBackend` / `ClaudeCodeBackend`. **Never write `if backend == "mock"` in task code.** LLM tasks run an **agent loop** (`llm/runner.run_findings_agentic`): HexGraph advertises sandboxed tools (`engine/agent_tools.py` — decompile/strings/imports/…, fuzz when enabled), the model requests tool calls, HexGraph executes them in the sandbox and feeds results back until the model emits findings. The loop is a strict superset of a single pass (a backend answering on turn one is unchanged); the mock drives it offline via fixtures carrying a `tool_calls` key. The model never touches the environment — it directs, HexGraph runs the tools (so a plain BYOK API key is sufficient; no external coding agent required).
- **Executor** (`sandbox/executor.py` `get_executor()`): the container boundary for all target-byte handling. Future remote/dynamic executors drop in here.
- **Decompiler** (`sandbox/decompiler.py` `get_decompiler()`): radare2 default; Ghidra (headless/bridge) when enabled in Settings. `HEXGRAPH_DECOMPILER` overrides.
- **Entitlements / Metering / Policy / Principal / Suggester** — thin local-default seams (`entitlements.py`, `metering.py`, `policy.py`, `principal.py`, `engine/suggester.py`); they allow/grant everything today so paid/dynamic/multi-user features land additively.

**Data model** (SQLite + SQLAlchemy, UUID ids): `project`, `target` (self-referential tree of artifacts), `node` (typed sub-file entities: function/symbol/string/struct/hypothesis/pattern), polymorphic attributed `edge` (`(src_kind,src_id)`→`(dst_kind,dst_id)` over target|node|finding|task), `task`, `finding`. The graph is relational — **Neo4j is out of scope.** Note: `finding.status` is a **plain String** (use `f.status`, never `.status.value`); `task.status` is still an Enum.

## Where things live

```
src/hexgraph/
  config.py settings.py        # config.toml (user/secrets, never rewritten) + settings.json (managed, writable)
  models/finding.py            # the frozen Finding/Evidence/FollowupSuggestion Pydantic models
  llm/                         # backend seam: base, mock, anthropic_api, claude_code, registry, cassette
  sandbox/                     # runner (docker boundary), executor, decompiler; probes/ are baked into the image
  engine/                      # ingest, pipeline, recon, unpack, worker, nodes, edges, context, runs, findings,
                               #   tasks, followups, dedup, search, report, crosstarget, authoring, annotations,
                               #   hypotheses, ghidra, ghidra_bridge, suggester, capabilities, cas
  api/app.py                   # FastAPI: all REST endpoints + serves the SPA at / (loopback)
  cli.py                       # hexgraph init|db upgrade|ingest|targets|run|findings|graph|prune|config|serve
frontend/                      # React+Vite+TS SPA → built to src/hexgraph/web/dist by `make ui` (gitignored)
migrations/                    # Alembic; baseline bbdb1d98bf54. prepare_database() in db/migrate.py
tests/                         # pytest; fixtures under tests/fixtures (built by build.sh / `make fixtures`)
context/                       # the build spec: SPEC.md, schemas/finding.schema.json, fixtures/, docs/
docs/                          # design-vision.md, implementation-plan.md, ui-backlog.md
```

Key disciplines: **probes are baked into the sandbox image — re-run `make sandbox-build` after editing anything in `sandbox/probes/`** (or set `HEXGRAPH_SANDBOX_DEV=1` to mount them). Tests use `init_db()` (create_all) on throwaway DBs and never migrate; persistent DBs migrate. Decompilation/harness-compile are best-effort and env-gated (`HEXGRAPH_DISABLE_DECOMPILE`, `HEXGRAPH_DISABLE_SANDBOX_BUILD`) — never gated on backend identity.

## Optional features & settings

`settings.json` (managed, written via `PATCH /api/settings` or `hexgraph config set`) holds non-secret prefs and optional-feature toggles, layered as **env > settings.json > config.toml > defaults**. Secrets are never written there and reported as presence-only. Optional features:
- **Ghidra** (`features.ghidra`): `headless` (analyzeHeadless in the sandbox, needs `make sandbox-build WITH_GHIDRA=1`), `bridge` (connect to a running Ghidra via `ghidra_bridge`), `enrich_recon` (materialize functions/call-graph/structs). Degrades to radare2 when off.
- **Fuzzing** (`features.fuzzing`, default off): the `fuzzing` task type. **This is the only thing that relaxes the static-only invariant** — enabling it makes `policy.current_policy()` return a dynamic profile (`allow_execution=True`), gated through the policy seam; the sandbox stays `--network none`, capped, timed. It compiles a `harness_generation` harness with libFuzzer+ASan and auto-creates a finding per crash (optional LLM `triage` step). `engine/fuzzing.py`, `sandbox/probes/fuzz_probe.py`.

Targets can be **soft-removed** from the Targets pane (`target.archived`, migration 0007): archives the parent_id subtree, hiding its nodes/findings from graph/detail/search/report without deleting; re-adding the same bytes (sha256) restores them. Firmware targets persist their **unpacked filesystem** (`metadata_json["filesystem"]`, files under `<data_dir>/unpacked/<id>/`) — browsable in the detail panel, any file addable as a child target (`engine/filesystem.py`).

## Commands

- **`make setup`** — one-shot: venv + deps + SPA + sandbox image + db init. Then **`make serve`** → http://127.0.0.1:8765.
- `make test` (= `pytest -q`, mock, offline; Docker-gated tests skip if the sandbox image is absent) · `make demo` (full loop, needs Docker) · `make test-live` (real-key scored eval, needs `ANTHROPIC_API_KEY`, cassette-backed).
- `make ui` (rebuild SPA) · `make sandbox-build [WITH_GHIDRA=1]` · `make fixtures`.
- CLI: `hexgraph init | db upgrade | ingest <path> [--name --project --backend --no-recon] | targets <p> | run <target> --type T [--objective --model --backend --function --mock-scenario] | findings <p> | graph <p> --export f.json | prune <p> | config list|get|set | serve`.
- Runtime data under `~/.hexgraph/` (override with `HEXGRAPH_HOME`, db with `HEXGRAPH_DB_PATH`).

## Read before writing code

1. `context/SPEC.md` — source of truth (constraints, data model, task types, acceptance criteria).
2. `context/docs/mock-llm-provider.md` — the mock backend design.
3. `context/schemas/finding.schema.json` — the canonical Finding schema.
4. `docs/design-vision.md` + `docs/implementation-plan.md` — the v2 target shape and sequenced plan.

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
