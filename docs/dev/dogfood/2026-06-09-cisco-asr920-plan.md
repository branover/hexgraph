# Dogfood implementation plan — Cisco ASR 920 (2026-06-09)

Companion to the engagement-local friction scratch (`/home/jonsnow/engagements/cisco-asr-920/dogfood-scratch.md`).
Target: `asr920-universalk9_npe.16.09.08.SPA.bin` (Cisco IOS-XE signed pkg, 426 MB; FIT → PPC
initramfs cpio + nested squashfs + 7 `.SPA.pkg` packages). Every finding was **re-validated against
`origin/main` (`46e8359`)** by three parallel read-only validators before planning. This doc records
the validated verdicts, a priority-ordered PR plan, and **explicit decisions on what is NOT being
done and why** (per the operator's instruction to document non-self-justifying calls).

This run is on top of the *previous* dogfood's fixes (#224–#238). Several findings here turned out to
be already-addressed or symptoms of one root cause — noted inline.

## Validation summary

| ID | Sev | Verdict | Root cause (file:line) | Disposition |
|---|---|---|---|---|
| **F05** fs_list unbounded | MAJOR | ✅ real (tool-level) | `engine/targets/filesystem.py:51-80` + `agent/mcp_tools.py:75-88` return ALL files, no limit/offset/prefix. (#233 added ingest *progress*, not pagination.) | **PR A** |
| **F07** silent partial extraction | BLOCKER-for-surface | ✅ real | binwalk `-eM` recurses *some* nesting but leaves the 416 MB squashfs + 7 `.SPA.pkg` packed; the ingest summary (`engine/pipeline.py:71-105`, `mcp_tools.py` ingest ~2202) reports only ELF children, never flags un-recursed containers. | **PR B** |
| **F08** duplicate cpio extraction | MINOR | ✅ real | `unpack_firmware` (`engine/targets/unpack.py:48-65`) registers every ELF with no content-hash dedup; the FIT inner blob == top-level cpio → ~half the 803 children are byte-dupes. | **PR B** |
| **F09/F15** promote registers inner ELFs hidden, unreported | MAJOR | 🟡 discoverability | `promote_file`→`analyze_target`→`unpack_firmware` DOES register inner ELFs, but **hidden** (`visible=False`, the #229 convention) and the promote result (`{id,name,kind,parent_id,arch}`) never says "registered N hidden children" — so `target_list` (without `include_hidden`) shows 0 and the agent thinks promote did nothing. rpcontrol-vs-rpios inconsistency = a transient unpack difference, not a code split. | **PR B** |
| **F16** decompiler fallback untagged | MAJOR | ✅ real gap | `sandbox/decompiler.py:118-134`: on Ghidra→r2 fallback it adopts r2's `focus` but keeps `out["tool"]="ghidra_probe"` and adds no fallback/quality flag — caller sees r2dec output labeled Ghidra (a fabricated `strncpy()` call was chased as a false lead). | **PR C** |
| **F04** meta_check_features missing gates | MINOR | ✅ real | `agent/mcp_tools.py:1775-1822` `_feature_health_specs()` reports only floss/yara/angr/ghidra/emulation — not the poc/fuzzing/network/rehost/remote/build policy gates a proving run cares about. | **PR D** |
| **F11** `node:<name>` mention dangles | MINOR | 🔴 not real *as worded* | Mentions resolve by UUID only (`engine/journal.py`); there is no `node:<name>` syntax. The genuine papercut: `re_decompile_function`'s MCP wrapper returns a bare **string**, not the promoted node's id, so you must `graph_list_nodes` to mention it. | **PR E** (return node_id) |
| **F12** re_imports ≈ binutils_facts | MINOR | 🟡 docs only | Not redundant (one is recon-cached/instant, the other the authoritative sandbox probe) but the descriptions don't say so. | **PR E** (docs) |
| **F13** RE tools time out on 137 MB iosd | MAJOR/BLOCKER | 🟡 partial | The persistent Ghidra project **already exists** (`sandbox/decompiler.py:238-266` `project_mount` by content_hash — analysis paid once, reused). Real gap: the 300 s probe budget (`sandbox/resources.py:47`) kills the *first* whole-binary analysis of a huge ELF (+ a Ghidra import DB-buffer error). | **PR F** (size-aware timeout) + **defer** heap/import tuning |
| **F14** strings = dynsym sample on huge ELF | MAJOR | 🟡 symptom of F13 | #235 already made `re_list_strings` use the full `strings -a` table (5000-cap, paginated, source-flagged). On the monolith the *strings probe itself* times out → flagged fallback to the recon sample. Fixed by F13's timeout. | **fold into F13** |
| **F06** no granular unpack progress | MINOR | 🟡 partial | Stage-level `ingest_progress` exists (`pipeline.py`); the 150 s binwalk extract is opaque mid-run. | **defer** (see below) |
| **F03** no pre-ingest identify/sniff | MINOR | n/a (ADD) | To learn the container format you must ingest. | **defer** (see below) |
| **F01** CLI not on PATH · **F02** ToolSearch papercut · **F10** bshell note | MINOR | docs/harness/note | — | **defer/document** |

## Doing — prioritized PRs (each its own worktree + merge gate)

Ordering = impact ÷ effort. Reliability protocol carried from the prior dogfood: **foreground
`pr-reviewer`** (runs `/code-review` + `/security-review`, posts the verdict via `gh pr comment N
--body` inline — `--body-file` lands empty), **never background a test command** (run focused files
foreground; `HEXGRAPH_*_IMAGE=bogus` to skip heavy tests), confirm `state==MERGED` before cleanup,
squash-merge + `--delete-branch`, ff main. Base every worktree on `origin/main`. **Do not touch the
active engagement's primary checkout, its `~/.hexgraph`, or the app on :8765.**

- **PR A — F05 `fs_list` pagination.** Add `limit`/`offset`/`path_prefix`/`elf_only` to the `fs_list`
  tool + `engine.targets.filesystem.list_filesystem` (engine keeps `limit=None` = all, so the UI
  detail-panel call in `api/routers/targets.py:270` is unchanged; the MCP wrapper defaults to a
  bounded page). Return `{files, total, offset, next_offset, has_more, path_prefix}`, mirroring
  `re_list_strings`. Update the catalog description + contract test.
- **PR B — extraction honesty (F07 + F09 + F08).** (a) Ingest/promote summary flags containers left
  un-recursed (files matching firmware signatures with no `child_target_id`): "N containers
  unextracted: …, promote to unpack". (b) `promote_file` of a container reports the inner hidden
  children it registered + the `target_list(include_hidden=true)`/reveal hint. (c) Dedup byte-identical
  extracted artifacts by sha256 before registering a child (skip + record a dedup ref). Touches
  `engine/targets/unpack.py`, `engine/pipeline.py`, `engine/targets/filesystem.py`, `agent/mcp_tools.py`.
- **PR C — F16 decompiler engine tag.** On the Ghidra→r2 fallback set `tool` to r2's identity +
  `fallback_to_radare2=True` + a `quality` flag; surface a one-line warning in the `re_decompile_*`
  agent-tool output; assert it in `tests/test_decompiler_fallback.py`. `sandbox/decompiler.py`,
  `agent/agent_tools.py`.
- **PR D — F04 meta gates.** `meta_check_features` also reports the policy gates (enabled/disabled,
  read from the canonical `policy`/`setup_catalog` source — not hand-typed) alongside the dep probes.
- **PR E — F11 + F12.** `re_decompile_function` returns the promoted node id (mention-able directly);
  clarify the `re_imports` vs `re_binutils_facts` descriptions (cached/instant vs authoritative/full).
- **PR F — F13 size-aware probe timeout.** Raise the analysis-probe timeout for large targets (e.g.
  scale `ResourceSpec.timeout` by artifact size, or honor a higher `resources.sandbox.timeout`), so
  the first whole-binary Ghidra/recon pass on a 100 MB+ ELF isn't killed at 300 s — which also lets
  `re_list_strings` reach the full table (fixes F14). Document `re_disassemble_range` as the
  large-binary raw fallback in the SKILL.

## NOT doing now — decisions (the non-self-justifying calls)

- **F13 Ghidra heap/import tuning (the DB-buffer import failure on a 137 MB ELF).** A real limit, but
  the fix is Ghidra JVM heap + analysis-option tuning in the sandbox image (a Dockerfile/toolchain
  change with its own validation surface), larger and riskier than a timeout bump. PR F's timeout +
  the existing persistent-project reuse + `re_disassemble_range` fallback recover most of the value;
  the heap work is a separate, deliberately-scoped follow-up. **Deferred, not refused.**
- **F14 as its own fix.** Already addressed by #235 (full `strings -a`, paginated, source-flagged).
  The monolith failure is the F13 timeout, not a strings-pass defect — folding it in rather than
  re-touching the strings path. **Subsumed.**
- **F06 granular unpack progress.** Stage-level progress already lands in `ingest_progress`; making
  the 150 s binwalk *interior* observable needs probe↔host IPC / output-dir polling (medium effort,
  pure observability, no correctness impact). Low value-to-effort for an overnight batch; the agent
  can already tell ingest is *running* (a row appears) vs hung. **Deferred — would reconsider for
  multi-GB images where live-vs-hung matters more.**
- **F03 pre-ingest identify/sniff tool.** A new MCP surface (`target_identify`) to read magic bytes
  without ingesting. The workaround (ingest reports `format`) exists, and the value is marginal for a
  one-call savings; adding a tool widens the surface the agent must reason over. **Deferred — flagged
  as a possible future ADD, not obviously worth a new tool now.**
- **F02 ToolSearch `select:` race.** A harness/ToolSearch papercut, **not HexGraph** — out of scope
  for this repo. **Documented, no action.**
- **F01 CLI not on PATH.** A pure-docs nicety (the CLI lives at `.venv/bin/hexgraph`). Low value;
  could be a one-line README/setup-output note if another docs PR is in flight, but not worth its own
  cycle. **Deferred to opportunistic.**
- **F10 bshell.sh absent.** Note-only (reinforces F07/F09), no action item of its own.

## Status — final

| PR | Findings | State |
|---|---|---|
| 0 plan | — | this doc (PR #239) |
| A | **F05** fs_list pagination | **MERGED** (#240) |
| B | **F07 + F09** extraction honesty (F08 deferred) | **MERGED** (#241) |
| C | **F16** decompiler engine tag | **MERGED** (#242) |
| D | **F04** meta_check_features policy gates | **MERGED** (#243) |
| E | **F11 + F12** decompile-returns-node-id + re_imports docs | **MERGED** (#244) |
| F | **F13** size-aware probe timeout | **NOT STARTED — deferred (see below)** |

Six findings shipped across five PRs (#240–#244). One implementation item (F13) and the
already-documented minor deferrals (F08, F06, F03, F02, F01) remain.

### F13 — deferred, with rationale (the honest call)

F13 (RE tools time out on the 137 MB iosd monolith) is the one MAJOR finding left unimplemented.
It is **deferred, not refused**, for three reasons:

1. **Its highest-value pieces already exist.** The persistent Ghidra project (analysis paid once
   per target, reused via `project_mount`/content_hash) and the `re_disassemble_range` raw-byte
   fallback both shipped in the *prior* dogfood. What remains is the size-aware *timeout bump* so
   the FIRST whole-binary analysis of a huge ELF isn't killed at the 300 s probe budget
   (`sandbox/resources.py:DEFAULT_TIMEOUT`) — and that also fixes F14 (the strings probe falling
   back to the recon sample because it times out on the monolith).
2. **It's a shared-path change that wants a fresh, careful pass.** Scaling `ResourceSpec.timeout`
   by artifact size touches the seam every sandbox probe runs through; getting it wrong regresses
   *all* probe timeouts. That is precisely the kind of change to make at the start of a session
   with full headroom, not at the tail of a long one — better deferred than rushed.
3. **The other half of F13 was always out of scope here.** The Ghidra "DB buffer" *import* failure
   on a 137 MB ELF is a JVM-heap / analysis-option tuning problem in the sandbox image (a
   Dockerfile/toolchain change with its own validation surface) — a separate, deliberately-scoped
   follow-up.

**Scoped follow-up for F13 (size-aware timeout):** add a helper that returns a `ResourceSpec` whose
`timeout` scales with the artifact's size (e.g. `300 s + N·(size/100 MB)`, capped), and thread it
into the decompiler + recon probe invocations (`sandbox/decompiler.py` `_decompile_ghidra` /
`run_recon`) so a 100 MB+ ELF gets a proportionate budget; honor a higher `resources.sandbox.timeout`
override; verify the desock/normal-size path is unchanged. Document `re_disassemble_range` as the
large-binary fallback in the VR SKILL. Leave the Ghidra-heap import-failure tuning as its own item.
