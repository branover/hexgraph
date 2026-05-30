# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

The MVP described in `context/SPEC.md` is **complete** — all milestones M0–M5 are implemented, tested (69 passing), and committed on branch `build/hexgraph-mvp`. `make demo` runs the full loop offline and exits 0.

**Now executing v2.** The target shape is in **`docs/design-vision.md`**; the sequenced, trackable build is in **`docs/implementation-plan.md`** (phases P0–P8). `PROGRESS.md` tracks per-phase status.

**P0 landed** (foundations & seams):
- **Migrations:** Alembic (`alembic.ini`, `migrations/`, baseline rev `bbdb1d98bf54`). `hexgraph init` and `hexgraph db upgrade` run `db/migrate.py::prepare_database` (fresh→upgrade from baseline; legacy create_all'd DB→stamp; backs up to `<db>.bak` before upgrading). **Tests use `init_db()` (create_all) on throwaway DBs and never migrate; persistent DBs use migrations.** Discipline: any schema change ships an `alembic revision --autogenerate` migration committed alongside the model change.
**P7 landed (backend)** — search, report, cross-target:
- `engine/search.py` `search_project()` (LIKE over findings+nodes; **coverage-honest** — undecompiled code isn't searchable yet; FTS5 is a later optimization) → `GET /api/projects/{id}/search?q=`.
- `engine/report.py` `build_report_md()` — Markdown over confirmed/reported findings, **provenance embedded** (task/backend/model/bundle) → `GET /api/projects/{id}/report` (text/markdown).
- `engine/crosstarget.py` `link_same_code()` — `similar_to` edges between same-`content_hash` function nodes in *different* targets (n-day primitive) → `POST /api/projects/{id}/link-same-code`.
- **Node identity rule (corrected here):** within a target, identity is `(target, fq_name)`; `content_hash` is a cross-target *matching* attribute (so the same function in two binaries is two nodes linkable by `similar_to`, not one). `materialize_function(..., pseudocode=…)` upgrades the hash to the body hash (`force_hash`).
- **Deferred P7:** search/report UI + FTS5; P7-5 (offline CVE correlation, bounded dataflow hints, reviewable dedup).

**P8 landed** — cheap real-key validation harness:
- `tests/fixtures/vuln_fw/` — tiny ELFs each planting one statically-findable bug (cgi=strcpy overflow, cmd=system injection, creds=hardcoded secret) + `expectations.json` (binary→category, min rate); built by its `build.sh` (also `make fixtures`).
- `hexgraph/eval.py` `run_scored_eval()`/`score_detection()` — ingest→recon→static_analysis per binary, score vs expectations (manages its own sessions: commit before `run_task_sync`).
- `make test-live` / `tests/test_p8_realkey.py`: live test **skips without `ANTHROPIC_API_KEY`**; with a key, runs the real backend with `HEXGRAPH_CASSETTE=auto` (record once → replay $0) under a tight budget. No-key CI proves bugs are statically present (recon) + the scoring logic. Commit recorded cassettes for $0 CI replay.

**P6 landed (core)** — HITL triage + feedback:
- **Widened triage** `FindingStatus` = new|triaging|confirmed|dismissed|reported (now a **String** column, no CHECK — migration `0005_triage_envelope` rebuilds `finding`, maps legacy `accepted`→`confirmed`). HITL envelope columns: `origin` (agent|human|agent_edited), `dismissed_reason`, `supersedes_id`, `human_notes`.
- `POST /api/findings/{id}/status` + `PATCH /api/findings/{id}` (light edit stashes the agent's original severity/confidence in `evidence.extra.agent_original`, sets `origin=agent_edited`).
- **Feedback-into-context** (`engine/context.py`): confirmed findings → an `analyst_confirmed` (authoritative) context item; dismissed → a `do_not_report` item. Human ground truth flows into later agent context. **NOTE:** `f.status` is a plain string now — never `.status.value` (task status is still an Enum).
- **Remaining P6:** annotation table (rename/note/tag) + confirmed-rename rewrites tool output; hypothesis-node lifecycle UI; richer approval gates (review-on-output / plan / spend).

**P5 landed** (finding & task management at scale):
- API: `GET /api/projects/{id}/tasks`, `GET /api/tasks/{id}/detail` (task + produced findings + trace files), `POST /api/tasks/{id}/rerun`, `GET /api/findings/{id}/components` (the `about` graph entities), `POST /api/findings/bulk-status`.
- SPA: right-pane **Findings | Tasks** tabs; `TasksPanel`/`TaskDetail` (status/cost/model, context-bundle id, trace files, findings produced, Re-run); FindingsPanel bulk select + bulk Accept/Dismiss; Inspector provenance (↗ producing task, ◉ highlight components on graph); finding↔task↔components navigation.

**P4 landed** (the analyst-notebook SPA — React + Vite + TS):
- **`frontend/`** is the SPA (React + react-router + Cytoscape/dagre). `make ui` (= `npm install && npm run build`) builds it into `src/hexgraph/web/dist`, which FastAPI serves at `/` with a client-side-routing fallback (assets at `/assets`). **Build artifacts are gitignored — run `make ui` before `hexgraph serve`** (the app Dockerfile builds the SPA in a Node stage). The old vanilla `web/templates`+`web/static` UI is removed.
- Structure: `src/api.ts` (typed client — the only backend contract), `src/theme.css` (dark design system), `pages/{Projects,Workspace}.tsx`, `components/{Header,GraphView,FindingsPanel,Inspector}.tsx`.
- Delivered: graph hub (visual grammar shape=kind/severity, **progressive disclosure** hides bulk symbol/string nodes), capability-filtered per-target task launcher (+ mock scenario), findings management (sort/filter/group-by-target + severity counts), Inspector (detail + Accept/Dismiss + stored follow-ups + rule-based suggestions), cost badge.
- **UI-sexiness pass** (`docs/ui-sexiness.md`): refreshed design system (`theme.css`: layered surfaces, severity scale, buttons/chips, transitions, scrollbars), inline SVG icon set (`components/Icon.tsx`, offline), graph polish (node halos via cytoscape underlay, color-coded edges, hover/selection edge labels, fit/zoom/relayout controls + node-count chip), `Launcher.tsx` "Run ▾" popover (replaces raw selects; mock-scenario only when mock), polished findings cards (severity rail + icons + count summary) + Inspector (sectioned, chips, evidence grid, code copy), global **search** + **Report** + **Same-code** toolbar in the graph pane, richer Projects cards, loading skeletons.
- **Deferred P4 polish:** SSE live activity (currently polls `/api/tasks/{id}`), pre-flight context-bundle preview, node-click detail for non-finding nodes.

**P3 landed** (task anchors + capabilities + suggester seam):
- **Task anchor**: `task.anchor_kind`/`anchor_id` (NODE|EDGE|SELECTION|HYPOTHESIS|TARGET; null⇒target). `target_id` stays the resolved primary target. Edge-anchored tasks pull the other endpoint as sibling context. Migration `0004_task_anchor`.
- **Capability table** `engine/capabilities.py` (`capabilities_for(anchor_kind, subtype)`, `GET /api/capabilities`) — task *types* stay canonical; relational work is an anchor (ruling #8).
- **Suggester seam** `engine/suggester.py`: `FollowupSuggester` + `RuleBasedSuggester` default; `GET /api/findings/{id}/suggestions` (entitlement-gated `suggest.followups`). **Future paid `LLMSuggester` drops in via `get_suggester()`** — don't build it; the seam is here.
- `pattern_sweep` instance_of_pattern edge now carries `matched_from_finding_id` = the seed finding (B3).

**P2 landed** (context bundle + CAS + caching + runs — the spine):
- **CAS** `engine/cas.py` (`<data_dir>/cas/<sha256>`, dedup): tool outputs, bundles, response traces.
- **Context Bundle** `engine/context.py`: `build_context_bundle()` walks the graph, packs typed items under a token budget (`estimate_tokens` ≈ chars/4 — the *one* estimator), records drops, stores items in CAS, computes a deterministic `bundle_sha`, renders the prompt. Tables `context_bundle`/`context_item`; `task.context_bundle_id` links the run. `execute_llm_task` now builds the bundle (replacing the ad-hoc prompt) and writes a full trace under the task log: `prompt.txt`, `system.txt`, `bundle.json`, `response.json`, `usage.json`.
- **Cassettes** `llm/cassette.py` `CassetteBackend`/`maybe_wrap_cassette` keyed by `bundle_sha`; `HEXGRAPH_CASSETTE=off|record|replay|auto` (default off; mock doesn't need it). Records a real-model response once → replays at $0 (foundation for P8).
- **Analysis runs** `engine/runs.py`: `record_run()` per execution + `diff_runs()` (added/dropped/changed by finding signature). API: `GET /api/targets/{id}/runs`, `POST /api/runs/diff`. CLI: `hexgraph prune <project>` (CAS size report). **Migration `0003_context_runs`.**

**P1 landed** (typed graph core):
- **`node` table** (`NodeType`: function/symbol/string/struct/hypothesis/pattern/task) distinct from `target` (artifacts). `engine/nodes.py` `materialize_function/symbol/string` + `get_or_create_node` — content-addressed identity (`content_hash`), lazy materialization, bounded recon node sets.
- **Polymorphic `edge`** — `(src_kind,src_id)/(dst_kind,dst_id)` over `target|node|finding|task`, expanded `EdgeType` (calls/about/instance_of_pattern/…), typed attribution (`origin`/`confidence`/`weight`/`directed`). **`edge.type`/`node.node_type` are String columns (no SQLite CHECK) so new types are zero-migration.** `engine/edges.py` `add_edge()` (all edges go through it) + `delete_node_cascade()`.
- **Findings attach via an `about` edge** in `persist_finding` (to the function node when `evidence.function` is set, else the target); `finding.target_id` stays the coarse pointer.
- Recon materializes bounded symbol/string nodes; decompilation materializes the focus function node + callees + `calls` edges (probe now returns `focus.callees`). `engine/graph.py` returns typed nodes + polymorphic edges. **Migration `0002_typed_graph`** (rebuilds `edge`, adds `node`). **Re-run `make sandbox-build` after editing probes** (probes are baked into the image).

- **Seams (thin, local defaults — "ask a seam, never branch"):** `sandbox/executor.py` `get_executor()` (→ `LocalDockerExecutor`=`SandboxRunner`; all engine/task code constructs sandboxes via this), `policy.py` `current_policy()`/`assert_allows_execution()` (static-only; `run_probe(requires_execution=True)` is the future-dynamic hook), `entitlements.py` `require(feature)` (gates task dispatch; all-allow now), `metering.py` `record_usage()` (logs per-task usage; LLM tasks call it), `principal.py` `current_principal()` (local single user). `config.get_hexgraph_api_key()` reserves the future credits key.

**Forward-looking seam rule (from the plan):** today's constraints (local-only, BYOK/mock, static-only, single-user) are temporary. Phase 0 installs *thin* seams — **Entitlements, Metering, Executor, analysis Policy, Principal**, and (P3) **Suggester** — with local defaults that allow/grant everything. Feature code must **ask a seam, never branch on backend identity, license tier, or executor**. This is how future paid-credits features, fuzzing/dynamic/exploit tasks, k8s scale, and enterprise/multi-user land additively. The **Finding schema stays frozen**; new structure lives in the DB envelope. **Migrations are mandatory** for any schema change — the project DB is durable researcher knowledge, never silently reset.

**▶ RESUME PROTOCOL — do this first, every session:**
1. Read **`PROGRESS.md`** (repo root). Its `▶ RESUME HERE` block names the current state, the next task, and how to re-verify. The `[ ]/[~]/[x]/[!]` checklist is the source of truth for what's done.
2. Re-verify with `make test` (full suite) and `make demo` (full loop, needs Docker + sandbox image).
3. **Update `PROGRESS.md` as work lands** (check boxes, refresh `▶ RESUME HERE`, append to the session log) and commit it alongside the code. Keep this CLAUDE.md current as durable facts change. When a workflow becomes repetitive, capture it as a skill under `.claude/skills/` and note it in `PROGRESS.md`.

**Dev commands:**
- `make install` — create `.venv`, install `-e ".[server,dev]"`. For the real Anthropic backend add `pip install -e ".[byok]"`; to run probes on the host (rare) add `pip install pyelftools`.
- `make sandbox-build` — build the `hexgraph-sandbox:latest` analysis image (file/binwalk/squashfs-tools/cpio/pyelftools/lief/**radare2 6.1.4**/**gcc**). Add `WITH_GHIDRA=1` for the (not-yet-wired) Ghidra option. Required for recon/unpack/decompile/harness-compile/demo.
- `make test` / `.venv/bin/python -m pytest -q` — full suite, mock backend, offline. Docker-gated tests (recon/unpack/decompiler/harness/demo) skip automatically if the sandbox image is absent.
- `make demo` — full offline loop: ingest → recon → AI finding → graph → **spawn follow-up**, exits 0. Needs Docker + sandbox image.
- `make fixtures` — rebuild `tests/fixtures/{vuln_httpd,libupnp.so,synthetic_fw.bin}` (committed; only re-run when sources change).
- CLI (all working): `hexgraph init | db upgrade [--no-backup] | ingest <path> [--name] [--project] [--no-recon] | targets <p> | run <target> --type T [--objective] [--model] [--backend] [--function] [--mock-scenario] | findings <p> [--status] [--export f.json] | graph <p> --export f.json | prune <p> | serve`.
- Runtime data under `~/.hexgraph/` (`hexgraph.db` + `projects/<id>/{artifacts,tasks}/`); override home with `HEXGRAPH_HOME`, db with `HEXGRAPH_DB_PATH`.

**Key seams as built:** target bytes are touched ONLY by probe scripts in `src/hexgraph/sandbox/probes/` (recon/unpack/decompile/compile) run via `sandbox/runner.py` (docker `--network none --read-only` + mem/cpu/pids caps + tmpfs + timeout). `engine/pipeline.py` orchestrates ingest→recon→unpack→recon-children; `engine/llm_tasks.py` runs LLM tasks backend-agnostically (`get_backend()` + `run_findings()`); `engine/followups.py` spawns the next task wiring `parent_finding_id`. Decompiler seam in `sandbox/decompiler.py` (R2Decompiler now, Ghidra later). The UI is vanilla JS + a vendored Cytoscape (offline), not HTMX. Decompilation/harness-compile are best-effort and env-gated (`HEXGRAPH_DISABLE_DECOMPILE`, `HEXGRAPH_DISABLE_SANDBOX_BUILD`) — never gated on backend identity.

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

> **All milestones below are complete** (see `PROGRESS.md` for the per-task record). Kept here as a map of what each milestone delivered.

- **M0** — mock backend + `LLMBackend` interface + `Finding` model + contract test. (Schema-valid findings with no key.)
- **M1** — scaffolding, config, SQLite models, CLI `init`/`ingest`, FastAPI on loopback, docker compose. Lone ELF → project + one target.
- **M2** — sandbox container + `recon` task; binwalk firmware unpack → child targets + `contains` edges; graph JSON endpoint; minimal UI. **Core loop demonstrable with zero model calls.**
- **M3** — `static_analysis` + `reverse_engineering` against the mock, then wire real backends behind the same interface; per-task model selection + cost display.
- **M4** — suggested follow-ups + one-click launch (wire `parent_finding_id`); `pattern_sweep` (and `harness_generation` if time).
- **M5** — accept/dismiss, dedup, export, README quickstart.

Keep scope tight (SPEC §12): no auth/multi-user/cloud, no auto-router, no live fuzzing, no dynamic/emulated execution, no Neo4j, no Kubernetes. Build the smallest thing that proves the loop with clean seams.

## Commands (implemented — see "Dev commands" above for the full set)

- `make demo` — full ingest → task → finding → graph → spawn loop on bundled fixtures, mock backend, no key/network, exit 0. Doubles as a smoke test.
- `pytest` — defaults to `HEXGRAPH_LLM_BACKEND=mock` (set in `tests/conftest.py`).
- CLI: `hexgraph init | ingest | targets | run | findings | graph | serve` (full signature in "Dev commands").
- `docker compose up` — brings up the loopback-only UI (builds the app image; needs the sandbox image built on the host first; not yet end-to-end smoke-tested).

## Assessing the UI visually (Playwright)

There is **no Chrome/browser MCP connector in this environment**, and `WebFetch` can't reach
`127.0.0.1`. To actually *see* the rendered UI (the workspace is JS-driven, so fetching HTML isn't
enough), drive **headless Chromium via Playwright** and screenshot. Playwright is a **dev-only, one-off
tool — intentionally NOT in `pyproject` deps**. Findings from a review go in `docs/ui-backlog.md`.

Setup (once):
```bash
.venv/bin/pip install playwright
.venv/bin/playwright install chromium     # ~110MB, downloads to ~/.cache/ms-playwright
```

Seed data + start the server on a spare port with an isolated home, then screenshot:
```bash
export HEXGRAPH_HOME=$(mktemp -d)/hg
PROJ=$(.venv/bin/hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo | awk '/^project/{print $2}')
HTTPD=$(.venv/bin/hexgraph targets "$PROJ" | awk '/sbin\/httpd/{print $1}')
.venv/bin/hexgraph run "$HTTPD" --type static_analysis --mock-scenario critical_overflow --function cgi_handler >/dev/null
.venv/bin/hexgraph run "$HTTPD" --type pattern_sweep --mock-scenario match_found >/dev/null
.venv/bin/hexgraph serve --port 8801 >/tmp/serve.log 2>&1 &   # remember to kill the PID after
```
```python
# .venv/bin/python this; chromium needs --no-sandbox in this WSL/container env.
import asyncio
from playwright.async_api import async_playwright
PROJ, BASE, OUT = "<project-id>", "http://127.0.0.1:8801", "/tmp/ui"
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox"])
        pg = await b.new_page(viewport={"width": 1440, "height": 900})
        await pg.goto(f"{BASE}/projects/{PROJ}", wait_until="networkidle")
        await pg.wait_for_timeout(1500)                 # let fetches + Cytoscape settle
        await pg.screenshot(path=f"{OUT}/workspace.png")
        await pg.get_by_text("Stack buffer overflow", exact=False).first.click()
        await pg.wait_for_timeout(500)
        await pg.locator(".pane.detail").screenshot(path=f"{OUT}/detail.png")
        await b.close()
asyncio.run(main())
```
Then **view the PNGs with the Read tool** (it renders images). Gotchas: `--no-sandbox` is required here;
use `wait_until="networkidle"` + a short `wait_for_timeout` so the JS-rendered graph/findings are present;
kill the backgrounded `serve` PID when done.

## Test fixtures (SPEC §11, `context/fixtures/targets/README.md`)

Built and committed under `tests/fixtures/` (regenerate with `make fixtures` / `tests/fixtures/build.sh`):
- `vuln_httpd` — a tiny intentionally-vulnerable ELF (unbounded `strcpy` in a fake CGI handler), built `-fno-stack-protector -no-pie -z norelro` so recon reports weak mitigations matching the mock fixtures.
- `libupnp.so` — a shared library with the same `strcpy` sink in `ssdp_recv` (the `pattern_sweep` sibling).
- `synthetic_fw.bin` — a squashfs firmware image binwalk/unsquashfs unpacks into the two ELFs above.
