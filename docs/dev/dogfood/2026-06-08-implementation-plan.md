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
| **F22** | no UDP live-surface request/verify primitive | ✅ real | No `net_udp_request` tool; `finding_verify_poc`'s raw path is **TCP-only** (`engine/findings/poc.py:80-135`). `target_register_service` ALREADY accepts `transport='udp'` (`engine/targets/surfaces.py:74`) + materializes a udp socket, but its probe/verify path is missing — so a registered UDP service is a live-probing dead end (its docstring overclaims `verify_poc` works). Forced the infosvr confirmation out to a host socket OUTSIDE HexGraph (capability-gap signal). |
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
| **6b** | **UDP live-surface primitive** | F22 | add `net_udp_request` (datagram send + bounded recv, same egress audit/scope as `net_tcp_request`, via the emulator netns when rehosted) + a `finding_verify_poc` `transport:'udp'` raw path (oracle `response_contains`, `{{NONCE}}`-capable, strips sent bytes). `target_register_service(udp)` already registers the service but its probe/verify path is missing — complete it, and fix the overclaiming docstring. New tool → catalog/SKILL/`docs/mcp.md` + contract-test + the §2d "non-HTTP live services" doc. Probe-only (no sandbox rebuild). **Sequence after PR 3** (shares `mcp_catalog.py`/`mcp_tools.py`); pairs with PR 6. Gated: `features.network`. |
| **7** | **Long-write-window restructure** | F11 (1b) | commit Observations incrementally in `worker.run_task_sync` so a late lock doesn't discard completed analysis (riskier — its own PR) |
| **8** | **Hidden-by-default child targets + recon-as-enrichment + selective reveal** | F06 deeper fix + **visibility regression (user-raised)** | **Root cause:** `unpack_firmware` (`engine/targets/unpack.py:41-58`) has registered a VISIBLE child target per ELF since M2 (`50a5d81`); the selective `promote_file` browser was layered on later (`c99e271`) but the eager registration was never gated — so a 765-ELF firmware floods the Targets pane + graph + mints 765 recon findings. There is no `visible`/`hidden` flag today (only `archived`) and no directory-level promote. **Chosen design (operator):** add a `target.visible` flag (migration; default `True`, but `unpack_firmware` sets firmware CHILDREN `visible=False`); unpack still registers every ELF (addressable/searchable) but HIDDEN; recon **still runs** per child to ENRICH `metadata_json` + record a recon **Observation**, but mints **NO finding** and **defers node materialization** so a hidden target contributes nothing to the curated graph; the graph + Targets list filter to `visible=True` by default; add reveal API/MCP/UI — `target_set_visible` per-target **and a directory/prefix reveal** ("reveal all ELFs under /usr/sbin"), revealing also materializes the recon nodes from the already-recorded facts (no re-run). Relocate the risky-sink→`static_analysis` followup to the suggester seam. Keep `finding_type='recon'` in the enum (back-compat). Updates ~6 recon-finding tests. Existing projects: new column defaults `True` (unaffected); optional "hide firmware children" doctor. **Sequence AFTER PR 3** (new MCP tools share `mcp_catalog.py`/`mcp_tools.py`). Larger (migration + UI) — may split into **8a** (visible flag + unpack-hides-children + graph/Targets filter + reveal) and **8b** (recon enrich-only, no finding, deferred node materialization). NB: recon still runs per hidden child, so the ~6-min ingest cost (F05) remains until reveal is made lazy. |

### Wave 3 — papercuts & docs (batchable)

| PR | Findings |
|---|---|
| **9** | F12 (thread `sink_node_id` + better error), F20 (inline `finding_record` schema), F14 (YARA rule), F18 (`re_recover_constant` pre-check), F05 (ingest progress), F01 (PATH/venv doc), F02 (project-dir doctor); **+ #225 review follow-ups**: `finding_list` `verified` filter post-filters the SQL page (a verified finding beyond page 1 is unreachable) → when `verified` is set, fetch-filter-then-slice; and `limit=0` should mean unlimited (or be documented), not "zero rows"; **+ #226 follow-up**: the focus-only Observation trim landed only on the agent-tools path — `engine/llm_tasks.py:194` (`_materialize_decomp_graph`) still records the full decompiler payload under `result_kind="decompilation"`; extract a shared focus-only helper for both sites; **+ #227 follow-ups**: `is_input_constrained` has a NUL-prefix-argv false-negative corner (the probe NUL-truncates argv → `constrained_len 0`); and `argue_reachability_for_finding` upgrades `evidence.extra.assurance` to `input_reachable` but never bumps the finding's `confidence` column (a recovered param flow then shows `input_reachable`+`medium`, which reads contradictory) — bump confidence on the reachability upgrade |

## Status

| PR | Branch | State |
|---|---|---|
| **#225** read-apis (F04/F06) | `build/read-api-filters` | **MERGED ✅** (`552c7d9`) |
| **#224** write-path (F11) | `fix/write-path-resilience` | **APPROVED ✅** · rebased onto main · CI running → merge |
| **#226** re-fallbacks (F08/F09/F10) | `fix/re-decompiler-fallbacks` | **APPROVED ✅** · awaiting rebase + merge |
| **#227** assurance (F17 + real-F21) | `fix/assurance-integrity` | **APPROVED ✅** · awaiting rebase + merge |
| **#228** journal-mention inspector (UI, user-raised) | `fix/journal-mention-inspector` | in review (Playwright click-through verified) |
| plan doc **#223** | `docs/dogfood-plan` | open (rebase + merge last) |

Post-PR3 items (sequence after **#225** merges; share `mcp_catalog.py`/`mcp_tools.py`): **#6b** UDP live-surface primitive (F22), **#8** hidden-by-default child targets + recon-as-enrichment (F06 deeper + visibility regression).

(Update as PRs open / merge.)
