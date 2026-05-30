# HexGraph MVP — Build Specification

**Audience:** Claude Code (the developer). Complete, self-contained brief to build a working prototype.
**Author:** Brandon · **Status:** v1 prototype scope · May 2026
**Read first:** `README.md`, then `docs/mock-llm-provider.md`.

---

## 0. One-paragraph summary

HexGraph is a self-hosted, agentic vulnerability-research workbench. The MVP is a local tool you point at a single binary or firmware image. It ingests the target, breaks it into sub-targets (for firmware: the unpacked filesystem's executables and libraries), runs a small set of AI-driven analysis tasks against them using **the user's own model access** (an Anthropic API key **or** a local Claude Code connection — **or the bundled mock backend for development**), and records every result as a structured **finding** inside a local **graph** that links targets, components, and findings. A local web UI lets the user browse the graph, launch tasks, and triage findings. **No cloud, no accounts, no paid features, no internet-facing service.** The goal is to prove the core loop — *target → delegate task → triage-ready finding → graph → spawn next task* — on real inputs, cheaply.

---

## 1. Hard constraints (do not violate)

1. **Fully self-hosted.** Runs entirely on the user's machine via `docker compose up` (or `pip install` + CLI). No component calls a HexGraph-operated server.
2. **No internet-accessible service.** Web UI binds to `127.0.0.1` only. No `0.0.0.0` binds, no public ports, no telemetry, no auto-update pings.
3. **BYOK / Claude Code / mock only.** Model access is exclusively: (a) a user-supplied Anthropic API key from env/config, (b) a local Claude Code connection, or (c) the **bundled mock backend**. No bundled keys, no proxying through any HexGraph service.
4. **Develop and test with no real key and zero token spend.** The default backend in dev and CI is the mock (see §6 and `docs/mock-llm-provider.md`). `make demo` must run the full loop on the bundled fixtures with no credentials and no network.
5. **No paid features.** Everything is free and open. No license gates, "pro" stubs, or upsell hooks.
6. **Outbound network policy.** The only permitted outbound connection is to the model provider's API **when the user chose the API-key backend** (none for Claude Code or mock). Tool/analysis containers run with networking disabled.
7. **Treat targets as hostile.** Inputs are untrusted binaries/firmware. All parsing, unpacking, and analysis of target bytes happens inside a sandboxed container with no network and constrained CPU/memory/time. **Never execute the target.**

---

## 2. What the user can do (MVP user stories)

1. *Point it at a file:* `hexgraph ingest ./router_fw.bin` (or UI upload) → a **Project** with the file as the root **Target**.
2. *Break it down:* for firmware, unpack and register each executable/library as a child target with `contains` edges to the root. For a lone binary, register that one target.
3. *Tell me what this is:* each target gets automatic, deterministic triage — file type, architecture, format, libraries/imports, interesting strings, mitigation flags (NX, stack canary, PIE/ASLR, RELRO).
4. *Run an agent on it:* pick a target + task type (§5), optionally type an objective, launch. The task runs on the selected backend and produces findings.
5. *Show me what was found:* a Findings view lists structured findings with severity, confidence, evidence, reasoning; accept/dismiss.
6. *Show me how it connects:* a Graph view renders targets and findings as nodes with edges (`contains`, `links_against`, `finding_in`, `related_to`).
7. *Do the next thing:* from a finding, a suggested follow-up task launches in one click (static hit → "generate harness for this function"; any finding → "sweep siblings for the same pattern").

---

## 3. Recommended tech stack

Boringly reliable, easy to self-host. Deviate only with reason.

- **Backend:** Python 3.11+, **FastAPI**, **Uvicorn** bound to `127.0.0.1`.
- **Task queue:** Celery + Redis, **or (preferred for v1)** an in-process `asyncio` worker with a SQLite-backed job table. Structure code so a real queue drops in later.
- **Database:** **SQLite** for all metadata, targets, tasks, findings, and graph edges (model the graph relationally; **Neo4j is out of scope**). SQLAlchemy.
- **Artifact storage:** local filesystem under `~/.hexgraph/projects/<id>/...`.
- **Frontend:** SPA (React + Vite) or HTMX. Graph via **Cytoscape.js** or **vis-network**. Dark theme.
- **Sandbox:** Docker. Each analysis task in a disposable container (`--network none`, `--memory`, `--cpus`, `--pids-limit`, read-only artifact mount, tmpfs scratch, hard timeout).
- **Model abstraction:** a thin `LLMBackend` interface with implementations `AnthropicAPIBackend`, `ClaudeCodeBackend`, **`MockLLMBackend`** (see §6). Selectable per-project, overridable per-task.

**Bundled analysis tools (in the sandbox image):** `file`, `binwalk` (firmware unpack), `python-magic`, `pyelftools`, `lief` (ELF/PE/Mach-O imports + mitigations), `strings`; **Ghidra headless** (`analyzeHeadless`) as the decompiler workhorse — `radare2`/`r2pipe` is an acceptable lighter substitute for v1; `AFL++`/`libFuzzer` present for the harness task. Keep the sandbox image one Dockerfile; make Ghidra an opt-in build arg if size is a problem.

---

## 4. Data model (SQLite via SQLAlchemy; UUID ids)

- **project**: `id`, `name`, `created_at`, `llm_backend` (`mock`|`anthropic`|`claude_code`), `model_pref?`, `data_dir`.
- **target**: `id`, `project_id`, `parent_id?`, `name`, `path`, `kind` (`firmware_image`|`executable`|`shared_library`|`unknown`), `format`, `arch`, `metadata_json` (mitigations, imports, hashes, size), `created_at`.
- **edge**: `id`, `project_id`, `src_target_id`, `dst_target_id`, `type` (`contains`|`links_against`|`related_to`), `metadata_json`.
- **task**: `id`, `project_id`, `target_id`, `type`, `objective_text`, `status` (`queued`|`running`|`succeeded`|`failed`|`needs_triage`), `backend`, `model`, `cost_estimate`, `started_at`, `finished_at`, `log_path`, `parent_finding_id?`.
- **finding**: conforms to `schemas/finding.schema.json` — `id`, `project_id`, `target_id`, `task_id`, `title`, `severity` (`info`|`low`|`medium`|`high`|`critical`), `confidence` (`low`|`medium`|`high`), `category`, `summary`, `evidence_json`, `reasoning`, `status` (`new`|`accepted`|`dismissed`), `suggested_followups_json`, `created_at`.

**The structured finding shape is the heart of the product.** Define it once as a Pydantic model that matches `schemas/finding.schema.json`; every task — and every backend, including the mock — emits findings in exactly this schema. This is what makes triage uniform and the graph possible.

---

## 5. Task types (agents)

Registry of handlers sharing one interface:

```python
class TaskHandler(Protocol):
    type: str
    def plan(self, target, objective) -> list[ToolStep]: ...
    def run(self, ctx: TaskContext) -> list[Finding]: ...
    def suggest_followups(self, finding) -> list[FollowupSuggestion]: ...
```

General flow: **gather deterministic facts with tools → ask the LLM to reason over those facts → emit structured findings.** The LLM never sees raw binary bytes; it sees tool output (decompilation, strings, imports, metadata) + the objective. The `TaskContext` carries that tool output — the mock backend uses it for templated responses (see `docs/mock-llm-provider.md` §2).

**v1 must-have:**
1. **`recon`** (auto-runs on ingest for every target). Deterministic, **no LLM required**. Produces format, arch, hashes, size, imports/exports, linked libraries (→ `links_against` edges), notable strings, mitigation flags. Emits one `recon` finding per target. *This alone proves ingestion + graph + findings end-to-end with zero model calls.*
2. **`static_analysis`.** Ghidra/r2 headless decompile of a chosen target/function → feed pseudocode + recon facts to the LLM to identify vuln classes (memory corruption, command injection, unsafe parsing, hardcoded secrets, weak crypto). One finding per credible issue with the decompiled snippet as evidence, vuln class, severity, confidence, reasoning. Follow-ups: "generate harness for `func`", "sweep siblings for this pattern".
3. **`reverse_engineering`.** Human-useful annotation of a function/binary: rename functions, summarize purpose, identify structures and parsing routines. Emits `info`-severity documentation findings; may raise `links_against`/`related_to` edges when shared code is spotted.

**v1 nice-to-have (stub with TODOs if no time):**
4. **`harness_generation`.** LLM writes a libFuzzer/AFL++ harness for an identified parser/entry point and tries to compile it in the sandbox. Finding holds harness source + build result. (No actual fuzzing in v1.)
5. **`pattern_sweep`.** Given a finding's code pattern (e.g. unbounded `strcpy` sink), search sibling targets for the same pattern (signature match + LLM confirmation), creating `related_to` edges and new findings. Shows the graph's payoff.

**Out of scope for MVP:** live fuzzing campaigns, dynamic analysis/emulation (QEMU/Frida), network fuzzing, exploit generation, multi-user/collaboration, auth/SSO, hosted compute. Leave clean extension points (the task registry).

---

## 6. Model backend behavior

- **Config:** project picks `mock` | `anthropic` | `claude_code` (env `HEXGRAPH_LLM_BACKEND`, **default `mock`**). API: read `ANTHROPIC_API_KEY` from env or `~/.hexgraph/config.toml`; **never** log or store it. Claude Code: connect to the local session; if unavailable, fail clearly. Mock: see `docs/mock-llm-provider.md`.
- **The mock is a first-class backend, not an afterthought.** It implements the identical `LLMBackend` interface, requires no key and no network, returns deterministic, schema-valid responses driven by `fixtures/mock_llm/`, supports scenario selection and fault injection, and is the default in dev/CI. Build it **first** (milestone M0) so the entire pipeline can be developed against it.
- **Per-task model override:** allow choosing model strength per task (cheap for `recon` summaries, strong for `static_analysis`). This is the manual analog of the future auto-router — **do not** build the router now, but structure the call site so one could choose the model later. The mock ignores model choice except to report plausible (fake, $0) token counts.
- **Cost visibility:** estimate + display token/cost per task and a running per-project total. The mock reports fake counts tagged `cost_source: mock`, `cost_usd: 0`. No billing — transparency only.
- **Determinism & evidence:** store exact tool outputs and the prompt/response trace under the task's `log_path` so findings are auditable and reproducible.

---

## 7. Sandbox & security

- Every task touching target bytes runs in a fresh container: `--network none`, `--read-only` root, explicit `--memory`/`--cpus`/`--pids-limit`, tmpfs scratch, wall-clock timeout (kill + mark `failed` on expiry).
- Mount only the one artifact the task needs, read-only; write results to a mounted output dir.
- **Never `exec` the target.** Static/RE only in v1. Dynamic analysis is future work needing stronger isolation.
- API/UI bind to `127.0.0.1`. Startup assertion refuses a non-loopback bind unless `HEXGRAPH_I_KNOW_WHAT_IM_DOING=1` (warn loudly even then).
- Redact secrets from all logs.

---

## 8. Interfaces

**CLI:** `hexgraph init` | `ingest <path> [--name]` | `targets <project>` | `run <target> --type static_analysis [--objective] [--model] [--mock-scenario]` | `findings <project> [--status new]` | `graph <project> --export graph.json` | `serve`.

**Web UI (`127.0.0.1`):** Projects list/create; Workspace (left target tree, center graph, right activity + cost); Target detail (recon facts, tasks, Run-task launcher); Finding detail (severity/confidence chips, evidence, reasoning, accept/dismiss, one-click follow-ups). Dark theme.

**REST API (FastAPI):** CRUD for projects/targets/tasks/findings; `POST /tasks` to launch; `GET /graph/{project}` returning nodes+edges JSON; SSE/websocket or polling for task status.

---

## 9. Build order (milestones)

- **M0 — Mock backend + contracts (build first).** `LLMBackend` interface; `MockLLMBackend` with fixture replay, scenario selection, and fault injection (per `docs/mock-llm-provider.md`); `Finding` Pydantic model matching `schemas/finding.schema.json`; the contract test that validates all fixtures. At the end of M0 you can call the backend and get schema-valid findings with no key.
- **M1 — Skeleton.** Scaffolding, config, SQLite models, CLI `init`/`ingest`, FastAPI on loopback, docker compose. Ingest of a lone ELF → project + one target.
- **M2 — Recon loop (the proof).** Sandbox container + `recon` task producing real metadata + a structured finding; binwalk firmware unpack creating child targets + `contains` edges; graph JSON endpoint; minimal UI (tree + graph + findings). **Core loop demonstrable here with zero model calls.**
- **M3 — LLM tasks via the interface.** `static_analysis` + `reverse_engineering` end-to-end, developed entirely against the mock; then wire `AnthropicAPIBackend` and `ClaudeCodeBackend` behind the same interface. Per-task model selection + cost display.
- **M4 — Spawn-the-next-thing.** Suggested follow-ups on findings; one-click launch; wire `parent_finding_id`. Implement `pattern_sweep` (and `harness_generation` if time) — develop both against the `cross_target` / `compiles` mock scenarios.
- **M5 — Polish.** Accept/dismiss, dedup of near-identical findings, export (findings + graph JSON), README with quickstart + loopback/security notes + "develop with no key (mock is default)".

---

## 10. Acceptance criteria (definition of done)

- `docker compose up` (or documented `pip` path) brings up a loopback-only UI with no external dependency beyond the *optional* chosen model backend.
- **`make demo` runs the full ingest → task → finding → graph → spawn loop on the bundled test targets using the mock backend, with no API key and no network, and exits 0.**
- Pointing at (a) a single Linux ELF and (b) a small firmware image both work: targets created, firmware children appear with `contains` edges, recon findings generated **without any LLM call**.
- Switching `HEXGRAPH_LLM_BACKEND` to `mock` vs `anthropic` vs `claude_code` changes only the backend — the task pipeline is identical. With the mock, `static_analysis` on the vulnerable test binary yields ≥1 schema-valid finding with decompiled-snippet evidence and a coherent reasoning trace.
- With a real `ANTHROPIC_API_KEY` or local Claude Code, the same `static_analysis` task runs against the real model and still produces schema-valid findings (validated by the same contract test).
- The graph view shows targets + findings as connected nodes; clicking a finding shows evidence + ≥1 working suggested follow-up.
- Fault-injection scenarios (`error_rate_limit`, `error_timeout`, `malformed_then_valid`) are covered by tests and handled gracefully.
- No secrets in logs; server refuses non-loopback bind by default.

---

## 11. Test fixtures (provided in this bundle)

- `fixtures/mock_llm/` — ready-made mock responses per task type and scenario; `_manifest.yaml` maps defaults. Use directly to develop M0–M4 offline.
- `fixtures/targets/README.md` — describes the **test binary** (a tiny intentionally-vulnerable C program, e.g. an `strcpy` stack overflow in a fake CGI handler) and a **synthetic firmware** (squashfs/cpio with 2–3 small ELFs) you must generate and commit under the repo's `tests/fixtures/`. The acceptance run and `make demo` use these so the loop is demonstrable without hunting for real targets.
- `schemas/finding.schema.json` — the canonical schema all findings (mock and real) must satisfy; the contract test enforces it.

---

## 12. Explicitly out of scope (don't gold-plate)

No accounts/auth, no multi-user, no cloud, no payment/credits/auto-router, no hosted compute, no live fuzzing campaigns, no dynamic/emulated execution, no network fuzzing, no exploit generation, no Neo4j, no Kubernetes. Build the smallest thing that proves the loop, with clean seams (task registry, `LLMBackend`, sandbox runner) for later features.
