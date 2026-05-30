# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

This repo is **mid-build**. The MVP described in `context/SPEC.md` is being implemented milestone by milestone (M0–M5).

**▶ RESUME PROTOCOL — do this first, every session:**
1. Read **`PROGRESS.md`** (repo root). Its `▶ RESUME HERE` block names the current milestone, the next task, and how to re-verify the last completed work. The `[ ]/[~]/[x]/[!]` checklist is the source of truth for what is done.
2. Run the resume verifier when one exists (`make demo` once M2 lands; `python -m pytest` before that).
3. Continue at the next unchecked task. **Update `PROGRESS.md` as tasks complete** (check the box, refresh `▶ RESUME HERE`, append to the session log) and commit it alongside the code it describes. Commit messages are prefixed with the task id (e.g. `M2-T3: ...`).
4. Keep this CLAUDE.md current as durable facts land (real commands, final layout, gotchas). When a workflow becomes repetitive, capture it as a skill under `.claude/skills/` and note it in `PROGRESS.md`.

**Dev commands (live as of M2):**
- `make install` — create `.venv`, install `-e ".[dev]"` (+`server` extra). Also `pip install pyelftools` if running probes on host.
- `make sandbox-build` — build the `hexgraph-sandbox:latest` analysis image (needed for recon/unpack/demo). Add `WITH_GHIDRA=1` later.
- `make test` / `.venv/bin/python -m pytest -q` — full suite, mock backend, offline. Docker-gated tests (recon/unpack/demo) skip automatically if the sandbox image is absent.
- `make demo` — full offline loop (ingest→recon→finding→graph) on bundled fixtures, exits 0. Needs Docker + sandbox image.
- `make fixtures` — rebuild `tests/fixtures/{vuln_httpd,libupnp.so,synthetic_fw.bin}` (committed; only re-run when sources change).
- CLI (all working): `hexgraph init | ingest <path> [--name] [--project] [--no-recon] | targets <p> | findings <p> [--status] | graph <p> --export f.json | serve`. `run` lands in M3.
- Runtime data under `~/.hexgraph/` (`hexgraph.db` + `projects/<id>/{artifacts,tasks}/`); override home with `HEXGRAPH_HOME`, db with `HEXGRAPH_DB_PATH`.

**Key seams as built:** target bytes are touched ONLY by probe scripts in `src/hexgraph/sandbox/probes/` run via `sandbox/runner.py` (docker `--network none --read-only` + caps + timeout). `engine/pipeline.py` orchestrates ingest→recon→unpack→recon-children. The UI is vanilla JS + a vendored Cytoscape (offline), not HTMX.

**Read before writing code, in this order:**
1. `context/SPEC.md` — the source of truth (constraints, data model, task types, milestones, acceptance criteria).
2. `context/docs/mock-llm-provider.md` — design of the mock LLM backend; build this first (milestone M0).
3. `context/schemas/finding.schema.json` — the canonical Finding schema every task and backend must emit.
4. `context/fixtures/` — ready-made mock responses (`mock_llm/`) and a description of the test targets to generate (`targets/README.md`).

## What HexGraph is

A self-hosted, local-only agentic vulnerability-research workbench. Point it at a binary or firmware image; it ingests the target, breaks firmware into child targets, runs AI-driven analysis tasks using the user's own model access, and records every result as a structured **finding** in a SQLite-backed **graph** linking targets and findings. A loopback-only web UI browses the graph, launches tasks, and triages findings.

## Non-negotiable constraints (SPEC §1, §7)

These define the product — violating them breaks it:
- **Fully self-hosted, no HexGraph server.** Nothing calls a HexGraph-operated backend; no telemetry, no auto-update pings.
- **Loopback only.** API/UI bind to `127.0.0.1`. A startup assertion must refuse a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1` (warn loudly even then).
- **BYOK / Claude Code / mock only** for model access. No bundled keys, no proxying. Read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never log or store it**.
- **Targets are hostile.** All parsing/unpacking/analysis of target bytes runs in a disposable Docker container with `--network none`, constrained `--memory`/`--cpus`/`--pids-limit`, tmpfs scratch, read-only artifact mount, hard timeout. **Never execute the target** (static/RE only in v1).
- **Develop with zero token spend.** Default backend in dev and CI is the mock. `make demo` must run the full loop offline with no key and no network and exit 0.

## Core architecture

The whole system is built to prove one loop: **target → delegate task → structured finding → graph → spawn next task**.

**Three seams keep the design extensible — keep them clean, do not leak across them:**
- **`LLMBackend` interface** — `MockLLMBackend`, `AnthropicAPIBackend`, `ClaudeCodeBackend` are interchangeable. Selected by `HEXGRAPH_LLM_BACKEND` (default `mock`), overridable per task. **Never write `if backend == "mock"` in task code** — task code must not know which backend it talks to. The seam is the backend boundary only.
- **Task registry** — task types (`recon`, `static_analysis`, `reverse_engineering`, `harness_generation`, `pattern_sweep`) share one `TaskHandler` protocol: `plan() → run() → suggest_followups()`. General flow: gather deterministic facts with sandboxed tools → ask the LLM to reason over those facts → emit findings. **The LLM never sees raw target bytes** — only tool output (decompilation, strings, imports) carried in `TaskContext`.
- **Sandbox runner** — the container boundary for all target-byte handling.

**The Finding is the heart of the product.** Define it once as a Pydantic model matching `context/schemas/finding.schema.json`. Every task and every backend (mock included) emits exactly this shape — that uniformity is what makes triage and the graph possible.

**Data model (SQLite via SQLAlchemy, UUID ids):** `project`, `target` (self-referential `parent_id` tree), `edge` (`contains` | `links_against` | `related_to`), `task`, `finding`. The graph is modeled relationally — **Neo4j is out of scope.**

**`recon` requires no LLM** — it is deterministic (file type, arch, hashes, imports, mitigation flags, `links_against` edges) and alone proves ingest → graph → findings with zero model calls. Auto-runs on ingest for every target.

## The mock backend (build first — milestone M0)

It is a first-class backend, not a test stub. Three fidelity layers (build in order):
1. **Fixture replay** — return the canned JSON at `context/fixtures/mock_llm/<task_type>/<scenario>.json`.
2. **Templated responses** — fill `{{placeholders}}` (`target_name`, `target_id`, `function`, `sibling_target_id`, `a_string`) from the real `TaskContext` so findings reference artifacts that actually exist and graph/spawn logic runs for real.
3. **Record/replay cassettes** — optional, do last; leave the hook.

**Scenario resolution precedence:** explicit per-task `mock_scenario` arg → env `HEXGRAPH_MOCK_SCENARIO` → deterministic `hash(task_id) % len(pool)`. `_manifest.yaml` maps each task type's default + available scenarios.

**Fault injection is required, not optional.** `error_*` scenarios must raise the *same exception types* the real client raises (rate-limit 429, timeout, transient server error, schema-validation failure) so retry/backoff and task-failure paths are tested. `malformed_then_valid` exercises the JSON-repair/retry path.

**Determinism:** seed randomness from `task_id`; no timestamps/UUIDs baked into compared output. Mock reports fake token counts tagged `cost_source: mock`, `cost_usd: 0`.

**Contract test (prevents mock drift):** one shared test asserts every fixture (and any recorded cassette) validates against `finding.schema.json`. It runs in CI; changing the schema forces fixtures to update or the test fails.

## Recommended stack (SPEC §3 — deviate only with reason)

- Backend: Python 3.11+, FastAPI, Uvicorn bound to `127.0.0.1`.
- Queue: prefer an in-process `asyncio` worker with a SQLite job table for v1 (structure so Celery+Redis drops in later).
- DB: SQLite + SQLAlchemy. Artifacts on local FS under `~/.hexgraph/projects/<id>/...`.
- Frontend: React+Vite (or HTMX), graph via Cytoscape.js or vis-network, dark theme.
- Sandbox tools (one Dockerfile): `file`, `binwalk`, `python-magic`, `pyelftools`, `lief`, `strings`; Ghidra headless (`analyzeHeadless`) as decompiler — `radare2`/`r2pipe` acceptable lighter substitute for v1; `AFL++`/`libFuzzer` for harness task. Make Ghidra an opt-in build arg if size is a problem.

## Build order (milestones — SPEC §9)

- **M0** — mock backend + `LLMBackend` interface + `Finding` model + contract test. (Schema-valid findings with no key.)
- **M1** — scaffolding, config, SQLite models, CLI `init`/`ingest`, FastAPI on loopback, docker compose. Lone ELF → project + one target.
- **M2** — sandbox container + `recon` task; binwalk firmware unpack → child targets + `contains` edges; graph JSON endpoint; minimal UI. **Core loop demonstrable with zero model calls.**
- **M3** — `static_analysis` + `reverse_engineering` against the mock, then wire real backends behind the same interface; per-task model selection + cost display.
- **M4** — suggested follow-ups + one-click launch (wire `parent_finding_id`); `pattern_sweep` (and `harness_generation` if time).
- **M5** — accept/dismiss, dedup, export, README quickstart.

Keep scope tight (SPEC §12): no auth/multi-user/cloud, no auto-router, no live fuzzing, no dynamic/emulated execution, no Neo4j, no Kubernetes. Build the smallest thing that proves the loop with clean seams.

## Planned commands (do not exist yet — create as you build)

The spec assumes these will exist; honor these names:
- `make demo` — full ingest → task → finding → graph → spawn loop on bundled fixtures, mock backend, no key/network, exit 0. Doubles as a smoke test.
- `pytest` — defaults to `HEXGRAPH_LLM_BACKEND=mock`.
- CLI: `hexgraph init | ingest <path> [--name] | targets <project> | run <target> --type static_analysis [--objective] [--model] [--mock-scenario] | findings <project> [--status new] | graph <project> --export graph.json | serve`.
- `docker compose up` — brings up the loopback-only UI.

## Test fixtures to generate (SPEC §11, `context/fixtures/targets/README.md`)

Generate and commit under `tests/fixtures/` so CI is hermetic:
- `vuln_httpd` — a tiny intentionally-vulnerable ELF (unbounded `strcpy` in a fake CGI handler), built `-fno-stack-protector -no-pie -z norelro` so recon reports weak mitigations matching the mock fixtures.
- `synthetic_fw.bin` — a small firmware image (squashfs/cpio) binwalk can unpack into 2–3 ELFs, including a second binary with a similar `strcpy` sink so `pattern_sweep` has a real sibling to match.
