# HexGraph Build Progress

The durable, resumable record of this build. **A new session should read this file first**,
then run the resume verifier, then continue at the next unchecked task.

## ▶ RESUME HERE
- **Current milestone:** M5 — Polish (accept/dismiss, dedup, findings export, README finalize)
- **Next task:** M5-T1 — accept/dismiss finding status (API endpoint + UI controls); status enum already
  on the Finding model (new|accepted|dismissed) and surfaced in the API.
- **Last verified:** `make test` → 66 passed; `make demo` exits 0 with the full
  ingest→recon→finding→graph→**spawn** chain (pattern_sweep homes a finding on the sibling + related_to).
- **How to re-verify:** `make test`; or run the UI (see UI quickstart below).
- **UI quickstart:** `make sandbox-build` once → `hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo`
  → `hexgraph serve` → open http://127.0.0.1:8765 → click a target, pick task type + scenario, Run.
- **Open notes / gotchas:**
  - **Docker is installed** and `jonsnow` is in the `docker` group (M2 unblocked).
    Verify with `docker run --rm hello-world` before M2-T1; a fresh shell may be needed
    for the group to take effect.
  - **git ownership fixed** by the user (`chown` to jonsnow); commits work now.
  - Python is 3.12.3 (spec asks 3.11+ — fine).
  - Mock reads fixtures + schema directly from `context/` (single source of truth, no duplication).
  - Backends return raw text; parsing + retry/JSON-repair live in `llm/runner.py` so the
    path is identical for mock and real backends. Tasks call `run_findings`, never `complete`.
  - Pydantic `Finding` (extra='forbid') mirrors the schema; DB `Finding` row adds the
    envelope (id/project_id/target_id/task_id/status/created_at).
  - DB is one SQLite file at `~/.hexgraph/hexgraph.db` (override `HEXGRAPH_DB_PATH`);
    artifacts copied under `~/.hexgraph/projects/<id>/artifacts/`. `init_db()` = create_all.
  - Loopback guard (`api/loopback.py`) is dependency-free + unit-tested; compose binds
    0.0.0.0 in-container but publishes only to host 127.0.0.1 (see docker-compose.yml note).
  - Ingest does NOT parse target bytes (only copies) — kind/format/arch/mitigations are
    filled by the sandboxed `recon` task in M2.

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
      `make demo` runs ingest→recon→finding→graph offline, exit 0

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
- [x] M4-T4 `make demo` extended: static_analysis → spawn pattern_sweep follow-up → sibling finding +
      related_to + parent_finding_id. 66 tests pass.

## M5 — Polish
- [ ] M5-T1 Accept/dismiss finding status (API + UI)
- [ ] M5-T2 `engine/dedup.py`
- [ ] M5-T3 graph + findings export  (graph export done in M2; findings export left)
- [~] M5-T4 `README.md` written ahead of schedule (full structure; unbuilt features marked
      "🚧 Not yet implemented"). Keep it updated as M3-T5/M4/M5 land; finalize `make demo` section.

## UI backlog
- Visual review done (headless Chromium screenshots). Requirements captured in
  [`docs/ui-backlog.md`](docs/ui-backlog.md) — P1/P2/P3, to tackle with M5 polish (some overlap M4 + M3-T6).
  Top P1s: graph finding-label overlap, non-interactive graph nodes, cramped detail panel,
  missing target-detail view, no live task feedback, no cost display.

## Project-specific skills created (note here as added)
- _(none yet — candidates: `regen-fixtures`, `run-task`, `add-mock-scenario`)_

## Session log (newest first)
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
  `make demo` exits 0. 44 tests pass (Docker-gated tests skip without the sandbox image).
  Sandbox image: `make sandbox-build` (radare2 deferred to M3). UI uses vanilla JS not HTMX (noted).
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
