# HexGraph Build Progress

The durable, resumable record of this build. **A new session should read this file first**,
then run the resume verifier, then continue at the next unchecked task.

## ▶ RESUME HERE
- **Current milestone:** M2 — Recon loop (sandbox + recon + firmware unpack + graph + UI)
- **Next task:** M2-T1 — `Dockerfile.sandbox` (file/binwalk/strings/pyelftools/lief/radare2; Ghidra opt-in)
- **Last verified:** `make test` → 39 passed (M0 + M1 complete); CLI init/ingest/targets smoke-tested
- **How to re-verify:** `make test` (or `.venv/bin/python -m pytest -q`)
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

## M2 — Recon loop  *(core loop demonstrable with ZERO model calls)*
- [ ] M2-T1 `Dockerfile.sandbox` (file/binwalk/strings/pyelftools/lief/radare2; Ghidra opt-in build arg)
- [ ] M2-T2 `sandbox/runner.py` docker run --network none + resource caps + timeout; never exec target
- [ ] M2-T3 `tasks/recon.py` deterministic facts → one recon finding/target; auto-run on ingest
- [ ] M2-T4 Firmware ingest: binwalk unpack → child targets + contains edges; links_against edges
- [ ] M2-T5 `engine/worker.py` asyncio worker + SQLite job table; POST /tasks
- [ ] M2-T6 `engine/graph.py` + GET /graph/{project}
- [ ] M2-T7 Minimal HTMX UI (tree / Cytoscape graph / findings; dark theme)
- [ ] M2-T8 `tests/fixtures/build.sh` (vuln_httpd, libupnp.so, synthetic_fw.bin); first `make demo`

## M3 — LLM tasks via the interface
- [ ] M3-T1 `sandbox/decompiler.py` Decompiler seam + R2Decompiler
- [ ] M3-T2 `tasks/static_analysis.py`
- [ ] M3-T3 `tasks/reverse_engineering.py`
- [ ] M3-T4 `cli.py run` + per-task model/backend override
- [ ] M3-T5 `llm/anthropic_api.py` + `llm/claude_code.py` + registry selection
- [ ] M3-T6 Cost display per-task + per-project; prompt/response trace under log_path
- [ ] M3-T7 Tests: static_analysis finding + fault-scenario handling

## M4 — Spawn the next thing
- [ ] M4-T1 `engine/followups.py` one-click launch + wire parent_finding_id
- [ ] M4-T2 `tasks/pattern_sweep.py` related_to edges + sibling findings
- [ ] M4-T3 `tasks/harness_generation.py` (compile in sandbox; stub if time)
- [ ] M4-T4 Extend `make demo` to spawn a follow-up

## M5 — Polish
- [ ] M5-T1 Accept/dismiss finding status (API + UI)
- [ ] M5-T2 `engine/dedup.py`
- [ ] M5-T3 graph + findings export
- [ ] M5-T4 README quickstart + security notes; finalize `make demo`

## Project-specific skills created (note here as added)
- _(none yet — candidates: `regen-fixtures`, `run-task`, `add-mock-scenario`)_

## Session log (newest first)
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
