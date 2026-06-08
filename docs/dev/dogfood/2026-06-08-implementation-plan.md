# Dogfood implementation plan — gt-axe11000 run (2026-06-08)

Companion to [`2026-06-08-gt-axe11000.md`](2026-06-08-gt-axe11000.md). Every finding in that
report was **re-validated against the source** before planning; this doc records the validated
verdicts and a priority-ordered implementation plan. Where validation contradicted the report,
the corrected root cause is what the plan targets.

## Validation summary

| ID | Report says | Verdict | Corrected root cause (what the code actually does) |
|---|---|---|---|
| **F11** | `database is locked`; fix = add WAL + busy_timeout | 🟡 **partially real, misdiagnosed** | WAL **and** `busy_timeout=5000` are **already set** (`db/session.py:40-66`). Real gaps: no **retry/backoff** on `OperationalError`; `worker.run_task_sync` holds **one transaction across a multi-minute task** (a late lock rolls back all of it → "lost analysis"); raw SQL **leaks** at `agent/mcp_server.py:_call_tool`. The "poisons serial MCP calls" claim is mostly false (each MCP call gets a fresh short-lived session). |
| **F21** | mock task writes FP findings + constant `content_hash` (amplifies F11) | 🟡 **partially real, misattributed** | The HIGH/HIGH FPs come from the **backend-independent taint core** (`engine/re/static_core.py`), not the mock. The `content_hash` amplifier is **structurally impossible**: `Finding` has no `content_hash` column; the only UNIQUE hash is `fuzz_artifact.dedup_key`. Real kernel = taint core over-promotes intra-procedural/input-independent flows at high/high (overlaps F17). |
| **F04** | `target_ingest` returns 114 KB blob | ✅ real | `ingest` inlines one `{id,name}` per child (`agent/mcp_tools.py:2057`, `engine/pipeline.py:55`); 765 rows overflow. |
| **F06** | `finding_list` overflow, no filters | ✅ real | `list_findings` is uncapped/unfiltered (`mcp_tools.py:958`); ingest mints **one recon finding per child** (`pipeline.py:53`). **Deeper fix (PR 8):** recon should enrich the target + record an Observation, not mint a finding — findings are for vulnerabilities, not ordinary recon. |
| **F08** | decompiler misses stripped-ARM fns, no fallback | ✅ real | Ghidra-active installs have **no radare2 fallback** at the `get_decompiler()` seam (`sandbox/decompiler.py:80`); the r2 path already handles `fcn.ADDR`/addresses. (The error lists Ghidra's defined functions, not "only imports.") |
| **F09** | `re_function_xrefs` false "(none)" | ✅ real | No recon-substrate fallback, unlike `re_call_graph` (`agent/agent_tools.py:949` vs `:1063`). |
| **F10** | `obs_get` decompile = 33 KB noise | ✅ real | Per-function decompile stores the whole Ghidra dict (calls+structs) (`agent_tools.py:433`); no body-only view. |
| **F13** | `re_list_strings` is a 40-entry sample | ✅ real | Filters the recon sample capped at 40 (`sandbox/probes/recon_probe.py:32`), not the real string table. |
| **F15** | no greppable strings; FLOSS ARM-degraded | 🟡 partially real | No server-side full-strings grep (true); FLOSS PE/x86-only on the decoded path is **inherent + already documented** — not a bug. |
| **F12** | `finding_reachability` ignores `sink_node_id` | ✅ real | `sink_node_id` is declared but **dropped** when `finding_id` is also passed (`mcp_tools.py:2533`). |
| **F16** | no raw-range disasm; two inventories | ✅ real | `re_disassemble` is hard-wired to r2; `re_decompile_at` uses Ghidra → divergent function sets. No `pd N @ addr` path. |
| **F17** | angr mints HIGH/HIGH from empty reproducer | ✅ real | Promotion guard is only `concrete_input is not None` (`engine/re/solving.py:159`), not non-empty / data-dependent. |
| **F20** | `finding_record` required keys undocumented | 🟡 partially real | `title` missing from the hint; `category` enum values not inlined (the `finding` param is a bare object). |
| **F19** | `graph_link_evidence` doc misleading | 🔴 **not real** | The description already says "attach a finding to a hypothesis"; param is `hypothesis_id`. No fix. |
| F14/F18/F05/F01/F02 | minor/docs | credible | YARA rule tune; `re_recover_constant` arg-dependence pre-check; ingest progress; PATH/venv doc; project-dir doctor. |
| F03 / L1 | coverage gaps | n/a | Not defects — schedule a clean-home gate-UX pass and a rendered-UI pass next run. |

**Do NOT do (refuted / already done):** add WAL/busy_timeout (present); unify a finding `content_hash` (no such column); rewrite `graph_link_evidence` docs (already correct).

## Prioritized plan

Ordering = impact × hit-rate ÷ effort, re-ranked after validation. Each workstream = one
worktree/PR per the merge gate. **Wave 1 is four PRs with disjoint file sets** (land in any order).

### Wave 1 — parallel, non-overlapping

| PR | Workstream | Findings | Files (disjoint) | Effort |
|---|---|---|---|---|
| **1** | **Write-path resilience** | F11 (corrected) | `db/session.py`, `agent/mcp_server.py` | small |
| **2** | **Finding/assurance integrity** | F17 + real-F21 | `engine/re/solving.py`, `static_core.py`, `taint.py` | medium |
| **3** | **Summary-first, filterable read APIs** | F04 + F06 | `agent/mcp_tools.py` (ingest, list_findings), `mcp_catalog.py`, `engine/pipeline.py` | small |
| **4** | **Decompiler & xref fallbacks** | F08 + F09 + F10 | `sandbox/decompiler.py`, `agent/agent_tools.py`, `engine/re/recon.py` | small (probe-free, no rebuild) |

- **PR 1:** bounded retry/backoff on `OperationalError` at the write/transaction boundary; sanitize the error at `mcp_server._call_tool` (return `{"error":"transient write contention…"}`, never raw SQL). *Not* WAL/busy_timeout (already present).
- **PR 2:** gate angr promotion on a non-empty, data-dependent reproducer (`constrained_len > 0`), downgrade input-independent sinks to `code_present/static`; tighten `static_core` so input-independent/intra-procedural-only flows aren't auto-promoted high/high.
- **PR 3:** `ingest` returns a structured summary + child count (defer the list to `target_list`); `finding_list` gains `limit`/`offset` + `finding_type`/`status`/`severity`/`target_id`/`verified` filters (enums from the canonical constants), default-excludes/rolls-up `recon`.
- **PR 4:** r2 fallback at the `get_decompiler()` seam when Ghidra returns `focus=None` + clearer not-found message; recon-substrate fallback for `re_function_xrefs`; store a focus-only payload for per-function decompiles.

### Wave 2 — after Wave 1 merges (these share `agent_tools.py`/`mcp_catalog.py`)

| PR | Workstream | Findings | Notes |
|---|---|---|---|
| **5** | **String visibility** | F13 + F15 | back `re_list_strings`/new `re_grep_strings` with the full table + server-side filter + pagination |
| **6** | **Raw-range disassembly** | F16 | new `re_disassemble_range` tool (+ probe, catalog/SKILL/`docs/mcp.md`, guard test) |
| **7** | **Long-write-window restructure** | F11 (1b) | commit Observations incrementally in `worker.run_task_sync` so a late lock doesn't discard completed analysis (riskier — its own PR) |
| **8** | **Recon → target enrichment + Observation, NOT a finding** | F06 (deeper fix) | Stop minting one `recon` finding per child (`engine/re/recon.py` `build_recon_finding`/`execute_recon`). Keep `apply_facts_to_target` enrichment + node materialization; **record the raw recon facts as an Observation** instead; **relocate the risky-sink→`static_analysis` followup to the suggester seam** (`engine/suggester.py`, target-level) so the target→task spawn loop survives. Keep `finding_type='recon'` in the enum (back-compat; envelope-only, no migration). Updates ~6 tests that assert recon findings. **Sequence AFTER PR 3** (it owns the `finding_list` recon-default-exclude + recon-dependent tests). Rationale: findings should point at vulnerabilities, not ordinary recon. |

### Wave 3 — papercuts & docs (batchable)

| PR | Findings |
|---|---|
| **9** | F12 (thread `sink_node_id` + better error), F20 (inline `finding_record` schema), F14 (YARA rule), F18 (`re_recover_constant` pre-check), F05 (ingest progress), F01 (PATH/venv doc), F02 (project-dir doctor) |

## Status

| PR | Branch | State |
|---|---|---|
| plan doc | `docs/dogfood-plan` | open |
| 1 write-path | `fix/write-path-resilience` | — |
| 2 assurance | `fix/assurance-integrity` | — |
| 3 read-apis | `build/read-api-filters` | — |
| 4 re-fallbacks | `fix/re-decompiler-fallbacks` | — |

(Update as PRs open / merge.)
