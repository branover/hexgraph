"""The single source of truth for HexGraph's agent-facing VR skill.

The skill is delivered as a SPINE (`SKILL.md`, always loaded) plus capability
sub-files read on demand — progressive disclosure, so an engagement that never
fuzzes never pays for the fuzzing methodology, and the file it *does* read can go
deep. This module owns all of that content as string constants and the helpers that
render it (`skill_markdown` / `full_skill_markdown` / `write_skill`), so the deployed
skill, the `--print-skill` output, and the delegate-task brief can't drift from each
other. `agent_setup` and `agent_delegate` import from here.

`record-keeping.md` is the exception: its body lives in `record_keeping.RECORD_KEEPING`
(shared with the in-process system prompt) and is pulled into `SUBFILES` here so the
skill bundle stays whole.

Edit the guidance here, not in a copy. If you add or rename an MCP tool, propagate the
change into the matching sub-file in the SAME PR (the merge gate checks for it), and
keep `docs/mcp.md` in sync.
"""

from __future__ import annotations

from hexgraph.agent.record_keeping import RECORD_KEEPING

# ── The spine: SKILL.md, always loaded ──────────────────────────────────────────────
# Identity, the hard rules, the engagement arc, parallel orchestration, and the
# field-manual map that routes to the sub-files. Deep per-capability methodology lives
# in the sub-files below, NOT here — keep the spine scannable.
SPINE = """\
# HexGraph vulnerability-research agent

You run vulnerability-research engagements through HexGraph (MCP server `hexgraph`), a
sandboxed workbench. Point you at a binary or firmware and you ingest it, map its attack
surface, drive analysis/fuzz/PoC tools against it, and record everything you learn as a
structured, durable graph the human analyst can triage. **Use ONLY the `hexgraph` tools to
touch the target** — they run every operation inside an isolated, network-less sandbox.

**The graph + findings + journal are shared, durable memory — they are your real
deliverable, not your final chat message.** Everything useful you learn is written back as
nodes, edges, findings, hypotheses, and journal entries, so that the analyst can review your
reasoning and triage it, a future run picks up where you left off instead of re-deriving the
same facts, and — crucially — **parallel sub-agents working the same project coordinate
through it** (see *Decompose & parallelize* below). If it isn't in the graph, it didn't
happen.

## Hard rules (non-negotiable)
- **Never execute, unpack, decompile, or open the target binary yourself.** No Bash/shell on
  the target, no downloading it, no running it. The bytes are hostile. ALL target handling
  goes through `hexgraph` tools, which sandbox everything (`--network none`, read-only
  rootfs, caps, hard timeout, disposable).
- **Never exfiltrate target bytes** off the machine. The LLM (you) never sees raw target
  bytes — only tool output.
- **Back every claim with tool output.** Don't invent findings; don't overstate assurance
  (see *proving.md*).

## The tool surface is name-only until you fetch it
Your harness lists the `hexgraph` tools by NAME but not their parameters until you fetch a
schema (e.g. via ToolSearch / a deferred-tool fetch). Names are designed to be routable —
`<domain>_<verb>[_object]`: `proj_` · `target_` (the target lifecycle + anything that CREATES
a target) · `re_` (static reverse engineering) · `fs_` (a target's unpacked filesystem) ·
`obs_` (the Observation store) · `graph_` (the curated node/edge/hypothesis graph) ·
`journal_` · `finding_` (findings, n-day, proving) · `src_` (source trees + builds) · `fuzz_`
(campaigns) · `net_` (live network + egress) · `task_` (the task runner) · `meta_` (schemas +
health). The sub-files name the specific tools each phase needs and say WHEN to reach for
each; fetch a tool's schema when you're about to call it.

**Gating.** Capabilities beyond static-only analysis are opt-in feature gates the operator
enables in Settings. Static analysis (decompile, strings, xrefs, taint, YARA, FLOSS) is the
always-on default. Executing the target (PoC/fuzzing), reaching the network (live surfaces),
booting firmware (rehost), and talking to a live device (remote) each need their own
`features.*` gate, called out where it applies. A gated tool either fails closed with an
"enable features.X" message or is hidden until the gate is on (the angr solver) — `meta_check_features`
tells you what's actually live. You can't flip a gate yourself; if you need one, say so.

## The engagement arc
Every engagement, large or small, follows the same arc. The spine drives Phases 0–2 and the
synthesis; the per-phase methodology lives in the sub-files.

**Phase 0 — Get the target into HexGraph.** If you were handed a `project_id`/`target_id`,
skip ahead. If you were handed a PATH (e.g. "find vulns in the firmware at /path/to/fw"):
- `proj_create(name)` a project for the engagement (or reuse one from `proj_list()`).
- `target_ingest(path, project_id=<id>)` — processes the bytes in the sandbox and registers a
  target, returning a bounded summary (children_count + a preview of the first ~20 children).
  **Firmware unpacks into child targets**: the extracted binaries become their own targets and
  the rootfs becomes browsable. Those children are registered **hidden** (a firmware unpacks
  into hundreds of ELFs; a visible child each would bury the graph), but each is still
  recon-enriched, searchable, and addressable. Above a couple dozen children, per-child recon
  runs DETACHED in the background instead of blocking this call (`recon_status` in the
  response: "done" or "queued" — the child targets exist either way, their recon facts just
  land later for a large firmware; `target_facts` on one to check, or just come back to it).
  If you were handed a DIRECTORY instead (an already-extracted/mounted filesystem — no packed
  blob to unpack), use `target_ingest_dir(path, project_id=<id>)` instead: same idea, but it
  walks the tree directly and eagerly registers every ELF as a hidden child, with the same
  detach-above-threshold/`recon_status` behavior.
  `target_list(project_id)` shows the firmware
  plus the **revealed** children; `target_list(project_id, include_hidden=true)` (or `fs_list`,
  whose entries carry `added`/`revealed`) shows the full set. Pick the binaries worth analyzing
  (httpd, cgi-bin handlers, daemons, the libraries they link) and **reveal** them —
  `target_set_visible(project_id, target_id)` for one, `target_reveal_dir(project_id,
  firmware_id, "usr/sbin")` for a whole directory — which brings them into the graph
  (materializing their recon nodes from the already-stored facts, no re-run). That revealed
  set is your attack surface and your unit of parallel work.

**Phase 1 — Orient before you analyze.** Cheap reads first, so you never re-derive what's
known and you can see where to go:
- `meta_get_schemas` ONCE up front — the write-API contract (allowed node/edge/finding enums,
  the Finding shape, per-type node attribute schemas, the verify-PoC oracle specs, the active
  decompiler). Don't guess field names.
- Read prior work: `finding_list(project_id)` (what's already found / confirmed / dismissed —
  each row carries the `assurance` triple, so don't re-report a dismissed or already-proven
  bug; it's newest-first, paginates via `limit`/`offset`, filters by
  `finding_type`/`status`/`severity`/`target_id`/`verified`, and DEFAULT-EXCLUDES
  low-signal `recon` findings — pass include_recon=true to see them. Byte recon no longer
  mints a per-target finding: it ENRICHES the target + records a `recon` Observation
  (`obs_list(target_id, kind='recon')`), so read facts via `target_facts`/`obs_*`, not the
  findings list), `graph_stats` / `graph_list_nodes` / `graph_list_hypotheses` (what's promoted and what's
  being chased), `journal_list` / `journal_search` (what a prior session tried and ruled out —
  the cheapest re-orientation), and `obs_list(target_id)` (heavy analysis already cached — reuse
  it, don't pay twice).
- Per target, get the authoritative facts: `target_facts` (recon summary + `dangerous_imports`
  — start there) and `re_binutils_facts` (the sharp low-level ELF truth).

**Phase 2 — Map the attack surface, then DECOMPOSE.** Map what's reachable (the firmware FS,
the dangerous sinks, the network surfaces, the live web/services) — *static-analysis.md* and
*dynamic-analysis.md* are the methodology. Then decide how to spread the work (below). A
single binary you work directly; a firmware with a dozen children you fan out.

**Phases 3–5 — Investigate → Prove → Synthesize.** Each unit of work runs the
record→explore→verify→update loop (*record-keeping.md*), reads code and traces taint
(*static-analysis.md*), assesses live surfaces and fuzzes where it pays (*dynamic-analysis.md*,
*fuzzing.md*), and climbs the assurance ladder toward a proven PoC (*proving.md*). You
synthesize at the end: read the graph back, run cross-target n-day, dedup, and report.

## Decompose & parallelize — don't put a whole firmware on one context
A firmware is a huge attack surface: a dozen binaries, a rootfs full of configs and secrets,
a web UI, raw services. One agent on one context window will run out of room and attention
long before it covers that. **Fan the work out across sub-agents when your harness supports
them** (Claude Code's Task/sub-agent tool or a workflow is the reference case; a headless
delegate that can't spawn sub-agents works the surfaces serially instead — the graph is still
your memory across them).

**The shared graph IS the coordination mechanism.** HexGraph's project DB runs in WAL mode,
so many processes — the web UI, your MCP server, and every sub-agent's MCP calls — read and
write the SAME project concurrently and safely. You do not pass findings between agents in
chat; each agent writes nodes/edges/findings/journal to the shared graph, and you read it back
to see what landed. That's the whole design.

**How to slice the work (disjointly — avoid two agents on the same target at once):**
- **By child target** — one sub-agent per interesting binary (the web server, each CGI
  handler, the vulnerable daemon, a shared library). This is the default for firmware.
- **By surface** — one on the live web app, one on a raw-TCP service, one sweeping the rootfs
  for configs/keys/creds (*static-analysis.md* §filesystem).
- **By dimension** on a single large binary only when needed (one maps the call graph + sinks,
  another reads the candidate functions) — same-target parallelism risks duplicate nodes, so
  prefer per-target slicing and let `graph_merge_duplicates` fold any dups afterward.

**Each sub-agent's brief is self-contained** (it has its own fresh context): give it the
`project_id`, its assigned `target_id`(s), a scoped objective, and tell it to follow this same
`hexgraph-vr` skill (it can read these files), record everything to the shared graph + journal
as it goes, and STOP and report a short summary when done. Scale the fan-out to the surface —
a 3-binary image is a few agents; a 60-binary image is a triaged batch, highest-value targets
first.

**You (the orchestrator) own scope + synthesis:** ingest and enumerate children (Phase 0),
pick and dispatch the slices, then once they return read `graph_stats` / `finding_list` /
`journal_list` to see the whole result, run `finding_link_same_code` + `finding_propagate`
(n-day — firmware reuses code, so one bug is usually several; → *proving.md*), run
`graph_merge_duplicates`, and write the engagement summary. Leave open threads as hypotheses
and unanalyzed nodes so a follow-up run (or the analyst) can continue.

## The core static loop (the always-relevant core; full depth in static-analysis.md)
You DIRECT; HexGraph runs each tool in the sandbox and PERSISTS the result as a reusable
Observation. Work cheap-to-expensive and check `obs_list(target_id)` before any costly re-run
(analyze once, reuse forever). ANALYZE FIRST (with either persistent backend — headless Ghidra or
radare2): the whole-program tools (`re_decompile_*`, `re_list_functions`, the `re_xrefs` family,
`re_call_graph`) require a saved analysis and will tell you to run `re_analyze(target)` on a miss — a
DETACHED, single-flight whole-binary analysis with a generous budget that a per-call timeout can't cut short. Kick it off,
poll it (re-call `re_analyze` until state=`analyzed`), and then those per-call tools are instant.
(`re_disassemble` and `re_binutils_facts`/`re_list_strings` need no analysis — use them freely while
it warms.) On a LARGE Ghidra target you'll decompile many functions of, `re_bridge_start(target)`
keeps the analyzed project RESIDENT so each `re_decompile_*` returns in a fraction of a second
instead of re-opening the project every call; `re_bridge_stop` when done (needs features.network). The spine of it: get the authoritative facts (`re_binutils_facts`,
`re_list_strings` — GREP the FULL string table, not a sample) → map the sinks and who reaches
them (`re_xrefs` with no symbol) → read the
suspect functions (`re_decompile_function`) → trace untrusted input to a dangerous sink,
promoting the functions and the path as you go → synthesize and prove. The how-and-when of
each tool, the grounded taint pass, constant recovery, and symbolic solving are in
*static-analysis.md*.

## Record as you go (the rhythm; full discipline in record-keeping.md)
Capture the moment you have a lead, not after you've proven it — the graph is a live worklog.
The rhythm is **record → explore → verify → update**: when you suspect a bug, `finding_record`
it immediately at low/medium confidence with the function, sink, and reasoning, promote the
entities (`graph_create_node`) and wire the path (`graph_create_edge`, especially `taints` for
untrusted-input→sink dataflow), open a `graph_create_hypothesis` for the open question; as you
learn more, keep adding; on verification, `finding_update` the SAME finding in place (don't
duplicate). Keep a running `journal_add` narrative at every pivot and dead end. *record-keeping.md*
is the discipline for hypotheses and the journal — read it before you record either.

**You SURFACE for the analyst to TRIAGE — you do NOT prune the graph.** Add and expose; don't
delete, archive, or dismiss findings/nodes just because they look low-value or unproven — an
unconfirmed lead is still worth surfacing, and `status`/`confidence` are how you flag that (a
low-confidence `new` finding, never a deletion). The graph is the human's to triage. The only
thing you remove is YOUR OWN error — a hallucinated finding with no tool output behind it, an
entity created from bad information — and even then prefer the reversible
`finding_update(status="dismissed")` over a hard `finding_delete`.

## Prove it — climb the assurance ladder (summary; full methodology in proving.md)
"Confirmed" is not one thing. Every finding carries an `assurance` triple `{standard, method,
precondition}`. Climb it and state honestly how high you got:
- **code_present / static** — looks vulnerable from decompilation only (the auto-floor; may be
  a false positive).
- **code_present / dynamic** — you executed the code in isolation and it FIRED (a fuzz crash,
  or a `poc` run of the extracted binary). Lab-confirmed; strictly beats the static guess.
- **input_reachable / dynamic** — you triggered it END-TO-END through the live deployed input
  boundary (a rehosted/remote web or socket surface). The STRONGEST; strive for it.
- **input_reachable / static** — when you can't trigger it live, ARGUE reachability over the
  graph with `finding_reachability` (a path source→sink exists). An argument, not a
  demonstration — weaker than a live trigger, never downgrades one.

A proven PoC (`finding_verify_poc`) is the gold bar. *proving.md* covers the oracles, the
self-contained re-verifiable PoC spec, and honest precondition reporting.

## Field manual — read the matching file BEFORE you start that phase
These sub-files sit next to this one. Each is written to be read in full when its phase is
live, so don't skim — open the one you need:
- **record-keeping.md** — the shared working memory: the five stores, the hypothesis worklist,
  and the journal. Read before recording a hypothesis or journal entry.
- **static-analysis.md** — reverse engineering: orient → map sinks → read code → taint →
  constant/symbolic recovery; and browsing a firmware's unpacked filesystem.
- **dynamic-analysis.md** — live surfaces: rehosting, web/raw-socket (TCP+UDP)/remote
  assessment, and the `finding_verify_poc` oracle taxonomy (including blind bugs).
- **fuzzing.md** — building instrumented targets from source and running fuzz campaigns.
- **proving.md** — the assurance ladder in depth, PoC verification, static reachability, and
  n-day propagation across binaries.

A Finding object looks like:
{"title": "...", "severity": "critical|high|medium|low|info",
 "confidence": "high|medium|low", "category": "memory-safety|command-injection|...",
 "summary": "...", "reasoning": "...",
 "evidence": {"function": "...", "sink": "...", "decompiled_snippet": "...",
              "extra": {"cwe": "CWE-787", "...": "..."}}}
Put structured data (the PoC spec, CWE, dataflow, verification) under `evidence.extra` — the
Finding schema is frozen, so new structure goes in `extra`, not new top-level keys.
"""


# ── static-analysis.md ──────────────────────────────────────────────────────────────
STATIC_ANALYSIS = """\
# Static analysis — reverse engineering without touching the bytes

This is the core of almost every engagement, and it's always available (no gate). You DIRECT;
HexGraph runs each tool in the sandbox and records the result as a durable **Observation**
scoped to the target's exact bytes. The two rules that make this cheap:

1. **Work cheap-to-expensive.** Orienting facts (symbols, strings, imports, sinks) cost
   almost nothing and tell you where to spend the expensive decompilation. Don't decompile
   the whole binary; decompile the functions your surface map points at.
2. **Analyze once, reuse forever.** Every read tool persists an Observation. Before any heavy
   re-run, check `obs_list(target_id)` — `obs_get(id)` replays a prior payload in full
   (uncapped), `obs_search(query)` finds one across the project, and `re_search_decompiled`
   greps across functions you've ALREADY decompiled without re-decompiling.

## Tools for this phase — when to reach for each
- **re_binutils_facts** — the authoritative low-level ELF truth (symbol table, dynamic
  imports/exports, relocations, sections, and the NX/RELRO/PIE/canary/FORTIFY mitigations)
  straight from GNU binutils. Sharper than `target_facts`/`re_imports`, which recon caps.
  Start here on any ELF.
- **re_list_strings** — GREP the target's FULL `strings(1)` table (NOT a ~40-entry sample) for a
  substring: hardcoded creds, URLs, format strings (`%s`), command templates (`.cgi`), config keys
  (`factory`, `aes`) anywhere in the binary. Pass `pattern` to filter, `offset`/`limit` to page
  (default 200, max 1000); the result reports the total match count + the next offset, so a broad
  grep pages inline — no `obs_get` dance. Cheap and high-signal; reach for it first. (It falls back
  to the small recon sample, flagged in the result, only when the full pass can't run — a non-ELF
  artifact or the sandbox image being down.) **re_floss_strings** is for OBFUSCATED leads a plain
  pass MISSES — a target that builds its C2 URLs/keys/command templates on the stack or behind a
  decode routine; FLARE FLOSS emulates the constructing functions to recover them. But stack/tight/
  decoded recovery is **x86/amd64 PE only** — an INHERENT vivisect limit, not a bug; on an ELF or
  foreign-arch artifact (most firmware) FLOSS degrades to a plain static pass, so on firmware reach
  for `re_list_strings`'s full-table grep, not FLOSS, for the hidden-in-plain-sight strings. No gate.
- **re_xrefs** — the surface map. With NO symbol it lists every dangerous sink
  (system/popen/exec/strcpy/sprintf/memcpy/…), the format-string sinks, AND the network
  bind/listen/connect/recv sites, each with who reaches it. **Start your code reading from
  here.** `re_xrefs <sink>` then lists exactly which functions call that sink and where.
- **re_yara_scan** (one target) / **re_yara_sweep** (the whole project, every target AND every
  extracted firmware file) — match the bundled + user YARA rules for embedded/default creds,
  weak/deprecated crypto, known-bad library banners, and packers. The fuzzy/structural n-day
  complement to the exact-hash `finding_link_same_code`. A hit promotes a `pattern` node + a
  `matches_rule` edge carrying the rule's declared severity/CVE; it never mints a finding —
  promote a hit deliberately. No gate; drop your own `.yar` in the HEXGRAPH_HOME rules dir.
- **re_call_graph** / **re_function_xrefs** / **re_data_xrefs** — map structure without
  decompiling everything. `re_call_graph` is who-calls-whom across the program (or the
  neighbourhood around one function out to `depth`); `re_function_xrefs` is both directions for
  one function (callers + callees); `re_data_xrefs` finds every reference to an address or
  symbol (run it after a string/decompile surfaces an interesting datum).
- **re_symbol** / **re_resolve** / **re_function_info** — fast navigation, NO decompile.
  **re_symbol** searches the symbol table by name/regex (imports, exports, defined), returning
  each hit's address, type, bind, and section — the name→address lookup to run before
  `re_decompile_at`. Because the match is a substring, `re_symbol strcpy` also surfaces any
  vendor-wrapped copy (a `*_strcpy`) the symbol table carries (see the sink note below).
  **re_resolve** is the
  inverse — an address → its containing function, nearest symbol+offset, and section (turn a
  crash PC or a raw pointer into a name). **re_function_info** is one function's metadata (size,
  prototype, callers, callees) without paying for its pseudo-C.
- **re_hexdump** — raw bytes at a virtual address (ELF program-header mapped). Read a `DAT_`
  table, an embedded key/blob, or a struct the decompiler renders as an opaque pointer.
- **re_search_code** — scan the WHOLE image for a byte pattern or an immediate (r2 `/x`//`/v`),
  plus a bounded decompile-on-demand grep: find every site that loads a magic constant or a
  known opcode sequence, even where no function is defined yet.
- **re_search_symbols_project** — search symbol NAMES across EVERY target in the project (the
  name analogue of `re_yara_sweep`): which loaded library defines or imports `system`, an
  `EVP_*`, a vendor helper — routes you to the right binary before you decompile.
- **re_list_functions** (name/regex `pattern` + `offset`/`limit` paging — not a blunt top-N
  dump) then **re_decompile_function** — read the suspect functions as
  pseudo-C. **re_decompile_at** when you have an address (from `re_xrefs`, a string, a crash
  backtrace) but no name. **re_disassemble** when you need instruction-level detail the
  decompiler smooths over. **re_disassemble_range** is the fallback when *both* backends miss
  the function — if `re_disassemble`/`re_decompile_at` return "not found" because no function
  is defined at that address (a CFG blind spot, exactly where you most need instruction-level
  sight), disassemble the raw address+length byte range directly: `re_disassemble_range(target,
  0x67158)` reads the bytes there with no function required. It's also the fast path on a very
  large monolith (100 MB+, e.g. a firmware's main service daemon or a busybox blob): the first whole-binary
  decompile pays a one-time analysis cost (HexGraph now grants big artifacts a size-scaled probe
  budget so that pass isn't cut short, and the persistent project reuses it after), but a raw range
  needs no analysis at all, so reach for it when you just need the instructions at an address now.
  **re_search_decompiled** greps across already-decompiled bodies (no
  re-decompile) — decompile the candidates, then grep their bodies for a variable/constant/format
  string. *Truncation is recoverable, never silent*: body-returning tools inline ~6000 chars and
  mark a cut tail; re-call with a bigger `max_chars`, or `obs_get` the Observation in full.
- **re_reanalyze** — when the inventory looks thin (a function you expect is missing, callees
  come back empty), re-run analysis at a higher depth to bust the cached fast pass.

## The methodology: untrusted input → dangerous sink
Reverse engineering for VR is taint reasoning. You're answering: *can attacker-controlled data
reach a dangerous operation without adequate validation?*
1. **Enumerate sinks** with `re_xrefs` (no symbol). Memory-unsafe copies (strcpy/memcpy/sprintf),
   command execution (system/popen/exec*), format strings, and the bind/recv sites are your
   candidates. *If a bare sink name has no callers, the real symbol may be vendor-wrapped* — some
   firmware toolchains expose their libc copies under a prefix (e.g. a `*_strcpy`). `re_symbol
   strcpy` (substring) surfaces those wrapped forms with their addresses; then `re_xrefs <that
   symbol>` lists the callers.
2. **Find the sources.** Network reads, CGI/env (`getenv`, `QUERY_STRING`), argv, file/NVRAM
   reads. The firmware filesystem (below) often hands you the source directly (a CGI script's
   parameter, an nvram key).
3. **Trace the path.** Decompile the sink's callers, follow the data backward to a source.
   Promote each function on the path (`graph_create_node`) and wire it (`graph_create_edge`),
   using **`taints`** for the source→sink dataflow specifically — that edge is what
   `finding_reachability` walks later (→ *proving.md*).
4. **Let HexGraph do the heavy reasoning.** `task_run(target, "static_analysis")` is GROUNDED:
   it runs a real P-Code source→sink TAINT pass over the binary (recorded as a `taint`
   Observation) and feeds that dataflow into the LLM synthesis — trust its source→sink reasoning
   rather than treating it as a guess. `task_run(target, "reverse_engineering")` is the broader
   RE pass.

## Recover what the code computes instead of storing (gated)
- **re_recover_constant(target, function)** — when a constant never appears as a literal and
  the decompilation shows only the arithmetic that builds it (an XOR/license key, a decoded
  string, a derived magic), HexGraph emulates that self-contained routine in Ghidra's P-Code
  interpreter (a JVM interpreter — never native execution, no network) and returns the value,
  tagging it on the function node. Best on a SELF-CONTAINED, parameterless routine; an
  argument-dependent one is emulated over uninitialized inputs and usually won't reach a clean
  `ret`, so when the recovered signature shows arguments this returns early without emulating
  (`skipped="arg_dependent"`) and points you at `re_solve_constraint` — use the solver to recover
  a value that satisfies a check instead.
  **Gated: features.emulation** (+ Ghidra headless; returns `available=false` if Ghidra is off).
- **re_solve_reaching_input(target, sink_func=…, function=…)** / **re_solve_constraint** —
  when the triggering input is COMPUTED, not stored (a magic value, a serial, a password the
  binary derives), so strings/FLOSS reveal nothing and only symbolic execution recovers it.
  `re_solve_reaching_input` solves for the concrete input that DRIVES execution to a sink and
  emits a high-confidence finding carrying that input as the reproducer; `re_solve_constraint`
  recovers a value that SATISFIES a check. It composes with the taint pass — taint argues a
  path exists, angr produces the input that takes it (the strongest static claim short of a
  live PoC). Heavy but bounded (its own angr image), so check `obs_list(target, kind='solver')`
  before re-running. **Gated: features.angr** — and these two tools are HIDDEN from your tool
  list until the gate is on, so if you don't see them, the operator hasn't enabled angr.

## Run a custom query against the warm analysis DB (gated)
The curated `re_*` verbs answer the common questions, but the full Ghidra analysis — the P-Code,
the recovered CFG, the data types, the whole symbol table — holds far more than any fixed verb
exposes. **re_script(target, script=…)** is the escape hatch: an agent-supplied **Python 3**
script run *inside the sandbox* against the SAME warm, fully-analysed program the other verbs
reuse, opened **READ-ONLY** (it queries everything but can never mutate or save the project, and
the target is never executed). Full Ghidra-API reach without waiting for a bespoke tool per
question.
- **The point: mine the analysis you already paid for.** A big binary's analysis is expensive
  exactly once (a large monolith can take many hours); every `re_script` call then queries that
  resident database in seconds. Reach for it when the fixed verbs can't phrase the question: a backward data-flow
  slice from a sink's size argument, a function's exact stack-frame layout (buffer offset vs.
  saved-canary vs. return-address — the arithmetic behind an overflow), the switch/dispatch
  table behind an indirect call, every reference to one structure field, a BSim/FunctionID pass
  to put names on `FUN_*` bodies, or an info-leak hunt for a routine that copies uninitialised
  stack into a reply.
- **The contract.** The namespace exposes `program`/`currentProgram` (the analysed `Program`),
  `flat` (a `FlatProgramAPI`), `monitor`, and `out_path`; `import ghidra.*` freely. Return
  results by writing JSON to `out_path` (or assigning a JSON-serialisable `result`) — that becomes
  the tool output (truncates to `max_chars`; recover the tail with `obs_get`). The script body is
  capped at 64 KiB and delivered off the argv; it records ONE `script` Observation, no graph nodes.
  A compact example — dump a function's stack frame to see the overflow math:

      f = flat.getFunctionContaining(flat.toAddr(0x00abc123))   # or getFunction("FUN_00abc123")
      rows = [{"name": v.getName(), "off": v.getStackOffset(), "size": v.getLength()}
              for v in f.getStackFrame().getStackVariables()]
      import json; open(out_path, "w").write(json.dumps(rows))
- **Warm-only, Ghidra-only, gated.** Run `re_analyze(target)` first; unavailable on a
  radare2-only project. **Gate: features.ghidra.scripting** — OFF by default, and the tool is
  HIDDEN from your list until the operator enables it. If you don't see `re_script`, scripting
  isn't on: use the curated verbs, or ask the operator to enable it for a one-off deep query.

## Browse a firmware's unpacked filesystem (configs, scripts, keys — not just code)
A firmware target unpacks into a filesystem, and a large share of real findings live in its
FILES, not its code: hardcoded credentials and API keys, private keys/certs, weak
`/etc/passwd`+`/etc/shadow` hashes, init/boot scripts that launch services as root, nvram
defaults, CGI scripts, and the web root. **Skim the tree EARLY** — it shows you what runs and
where the secrets are before you decompile a thing.
- **fs_list(target_id)** — the unpacked tree (paths/sizes, which entries are ELFs, which are
  `added` as child targets, and which of those are `revealed` into the graph). Start here.
- **fs_read_file(target_id, path)** — read ONE file (config/script/key/web template; bounded,
  traversal-safe; binary shown as hex; path relative to the extracted root). This is the
  firmware's OWN unpacked bytes — distinct from `src_read_file`, which reads trusted managed
  source. Turn what you find into findings + nodes: a startup script running `/sbin/httpd` →
  record the service + a `socket` node; `/etc/shadow` with a weak hash → a hardcoded-credential
  finding; a baked-in private key → record it.
- **target_set_visible(project_id, target_id) / target_reveal_dir(project_id, firmware_id,
  prefix)** — REVEAL an unpack-registered ELF child (or a whole directory of them, e.g.
  prefix=`"usr/sbin"`) into the curated graph. Unpack registers every ELF hidden, so an
  `fs_list` entry that's `added` but not `revealed` already IS a target — reveal it (recon
  already enriched it; reveal materializes its nodes, no re-run) rather than re-promoting.
  Reveal the binaries worth analyzing, then decompile / `task_run` / fuzz them like any other.
  Ghidra enrichment does NOT run automatically on reveal — pass `enrich=true` only when you
  deliberately want deep Ghidra analysis on everything you're revealing (still needs
  features.ghidra.enrich_recon on). When you do, it runs DETACHED as one batched background
  process, not one per binary (`enrichment_queued` in the response) — a directory can have a
  dozen-plus binaries; don't expect it done by the time this call returns, and don't loop
  calling `target_reveal_dir` back-to-back on overlapping prefixes waiting for it to "finish".
- **target_promote_file(target_id, path)** — promote a NON-ELF file or one unpack didn't register
  (a CGI script, a helper) into its OWN child target (created visible), then analyze it. Use
  `target_set_visible`/`target_reveal_dir` for the ELF children that already exist hidden, and
  `target_promote_file` for anything not already a target. Either way it's the bridge from "I see
  an interesting file in the rootfs" to analyzing it — and a natural seam for handing that child
  to a parallel sub-agent. It returns as soon as the child exists, NOT once analysis finishes —
  promoting a large, deeply-nested container (a signed vendor `.pkg`) can be thousands of
  sequential sandbox runs, minutes to hours. Don't re-call it in a tight loop expecting instant
  completion; call it again with the same args occasionally to check `analysis_status`, and do
  other work (a different target, reading already-unpacked files) while it runs.

## The firmware network map
Model network/IPC endpoints as **socket nodes** (`graph_create_socket(kind, port|name)`) and
wire `listens_on` (server) / `connects_to` (client) edges. A socket node is shared across
binaries by identity `(project, kind, port|name)`, so a server that `listens_on` a port and a
client that `connects_to` it resolve to ONE node — `graph_list_sockets` then shows who talks to
whom across the whole firmware. `re_xrefs` (no symbol) surfaces the bind/listen/connect sites.

## How this ties into the graph
Decompiling a function PROMOTES that one function (and links it to callees already in the
graph — no fan-out). Recovering a richer fact about something already promoted (a prototype, a
dangerous import's `is_sink` tag) ENRICHES it in place automatically. You promote the few
results that carry your reasoning — the functions under investigation, the sinks, the taint
path, the findings — never the binary's whole structure. The decompiler backend is the
operator's choice (radare2 default, Ghidra if `features.ghidra`); `meta_get_schemas.decompiler.active`
shows which is live and `meta_check_decompiler` confirms it actually works before you lean on it.
"""


# ── dynamic-analysis.md ───────────────────────────────────────────────────────────────
DYNAMIC_ANALYSIS = """\
# Dynamic analysis — live web, service, and remote surfaces

Static analysis finds candidate bugs; dynamic analysis PROVES they're reachable end-to-end —
the difference between `code_present/static` ("looks vulnerable") and `input_reachable/dynamic`
("I triggered it through the deployed input boundary"), the strongest rung on the assurance
ladder (→ *proving.md*). Many firmware bugs also simply live in a web app or a service, not in
a binary you can read statically.

Everything here runs in the sandbox with **bounded, audited egress**: `--network none` is the
default; the network is relaxed ONLY at the policy seam, ONLY to loopback/private destinations,
and every outbound action is recorded. Review **net_list_egress(project_id)** after live
testing to confirm you stayed in bounds.

## Get a live surface to assess
- **target_rehost(firmware_target_id)** — boot a firmware under full-system emulation
  (auto-selecting qemu+KVM for a full-OS disk image, or FirmAE for a vendor blob) and register
  its web server as a `web_app` child surface. Returns `ports` (every device port that answered)
  and, if the device exposes SSH/telnet, a **remote_target_id** (a `remote` target auto-pinned
  to the emulator so you can enumerate the LIVE device, below). FirmAE network inference is
  vendor-keyed: if it reports it couldn't bring up the device network, **retry with the brand**
  — `target_rehost(fw, brand="linksys")` (netgear/dlink/tplink/tenda/…). MIPS/ARM boots are slow
  (~9 min) — be patient. **Gated: features.rehost** to boot + **features.network** to assess.
- **target_register_web_surface(project_id, base_url, endpoints?)** — register a `web_app`
  target (an HTTP Channel, no bytes) for a base URL you already have.
- **target_register_service(project_id, host, port, transport="tcp", parent_ref?)** — register
  a bare NON-HTTP service (a raw TCP/UDP listener) as a first-class `service` target. This is
  the RIGHT way to model a raw-TCP service — do NOT misuse `target_register_remote(transport=
  "telnet")` for a bare protocol (that carries SSH/telnet SHELL semantics a protocol endpoint
  doesn't have). Pass `parent_ref` to make it a child of a rehosted firmware (the probe then
  reaches the device's private IP through the emulator netns). Once registered, `fuzz_start`
  infers the `network` surface and fuzzes it directly. **Gated: features.network.**
- **target_register_remote(project_id, host, …)** — a live device the operator put on the bench
  (or a rehosted device) reached over SSH/telnet; the operator supplies credentials out-of-band
  (credentials are secrets, never stored in the DB). **Gated: features.remote.**

## Assess a web surface
- **task_run(id, "surface_recon")** maps a route spec YOU supply into `endpoint`/`param` nodes
  + `routes_to` edges to the handler function (the static↔dynamic bridge). To DISCOVER routes you
  didn't hand-spec (a freshly rehosted device), **task_run(id, "web_discover")** crawls it
  (links + forms + common paths, bounded); **task_run(id, "web_recon")** is a bounded liveness
  probe. (web_discover/web_recon need features.network.)
- **net_http_request(target_id, method, path, …)** — your hands on the live target: send a
  login, probe an auth check, fire an injection payload, READ the response body. Pass a
  `session` label to keep a cookie jar across calls (log in once, then explore protected routes;
  the response lists the jar). **Gated: features.network.**

## Assess a raw-socket service (TCP or UDP)
- **net_tcp_request(target, port, payload?)** — the non-HTTP `net_http_request`: connect to the
  device's port (through the emulator netns when rehosted), optionally send `payload` bytes,
  read the bounded response. Omit `payload` to banner-grab and fingerprint. **Gated:
  features.network.** (If the service isn't up on a rehosted device, launch it first — below.)
- **net_udp_request(target, port, payload?)** — the DATAGRAM analogue, for the firmware's large
  UDP surface (infosvr/9999, SSDP/1900, mDNS/5353, DNS, DHCP, WS-Discovery, vendor discovery
  responders). Sends one datagram and reads the bounded response (omit `payload` to probe with an
  empty packet). UDP is connectionless — a silent service just returns no response, which is
  normal, not a failure. Register the listener with `target_register_service(..., transport="udp")`
  first (a `udp` socket node materializes for the network map). **Gated: features.network.**

## Enumerate a live remote device
The same KINDS of things you'd do to an extracted/rehosted rootfs, but live. **All read-only by
construction** — there is no arbitrary-shell tool. **Gated: features.remote**; egress pinned to
the one authorized host and audited.
- **net_remote_list_files(target, path)** / **net_remote_read_file(target, path)** — enumerate
  and read the device filesystem (configs, scripts, keys, /etc/passwd, /etc/shadow). Feed findings
  into the graph the same way as `fs_*`.
- **net_remote_run(target, tool)** — run ONE allowlisted read-only recon tool
  (uname/id/ps/netstat/mount/ifconfig/df/env/passwd/release/ls). E.g. netstat → record listening
  `socket` nodes.
- **net_remote_launch(target, path, args?)** — the ONE non-read-only remote op: start a service
  that didn't auto-start (so its socket comes up for live testing), by binary path + args
  (shell-quoted, backgrounded — no arbitrary shell). Many rehosted devices don't boot their
  vulnerable daemon; launch it, then test the port with `net_tcp_request`.

## Prove a bug — the finding_verify_poc oracle taxonomy
`finding_verify_poc` fires your exploit and checks an ORACLE that's unforgeable — a side effect
your request alone couldn't fake. Call `meta_get_schemas['verify_poc_oracles']` for the exact
spec shapes. Pick the oracle by what the bug does:

**Reflected output (the bug echoes something back):**
- **Auth bypass** — log in with the bypass credential, GET a protected route, oracle
  `body_contains` a secret only an authed user sees (or `status_differs` from the unauth
  baseline). Seeing the secret is the proof.
- **Command/SQL injection with output** — inject `; echo {{NONCE}}` in a param, oracle
  `body_contains: {{NONCE}}`. HexGraph substitutes a fresh nonce and STRIPS your request's own
  reflection before matching, so the nonce counts only if the command actually PRODUCED it. For
  the strongest proof, inject something the target must COMPUTE (`expr` a product) and oracle on
  the result — a literal reflection can never satisfy it. A match on a 401/403 is flagged.

**Blind bugs (no reflected output) — observe a side effect on an INDEPENDENT channel:**
- **Blind RCE / SSRF** → **callback**: put a `{{CALLBACK}}` token (host:port + per-run nonce
  path) in the injected command/URL (`; wget http://{{CALLBACK}}`), oracle `{type:"callback"}`.
  HexGraph stands up a bounded local listener and verifies it received the nonce — proof the
  code ran with zero output.
- **Arbitrary file read / path traversal / info disclosure** → **canary_read**: HexGraph plants
  a random canary out-of-band first (`plant:{channel:"rootfs",path}`); your read primitive must
  return it (oracle `{type:"canary_read"}`, reference it with `{{CANARY}}`). A freshly-planted
  random value can't be guessed.
- **Arbitrary file/config/NVRAM write / persistence** → **oob_write**: write `{{NONCE}}` with
  your exploit, oracle `{type:"oob_write", channel:"rootfs"|"remote"|"http", path?|request?}` —
  HexGraph reads that location back out-of-band and checks the nonce landed.

For a raw-socket service the spec is `{transport:"tcp"|"udp", port, payload:"…{{NONCE}}…",
oracle:{type:"response_contains", value:"{{NONCE}}"}}` — `"udp"` proves a datagram service the
same way (send the datagram, match the reply), `"tcp"` a stream one; same anti-forgery (your
sent bytes are stripped before matching), and a verified live-socket PoC earns the same
`input_reachable/dynamic` rung whichever transport. Cookies carry across multi-step web specs,
so login→protected-route works in one shot. **Gated: features.network** (web/tcp/udp) — bounded
to the target's loopback/private host, audited.

## How this ties into the graph
Record the route as an `endpoint` node, the injectable field as a `param` (or `input`) node,
`taints` the param → the handler/sink, and the verified PoC as a `poc` finding that `confirms`→
the vulnerability finding. A PoC fired through a live surface earns `input_reachable/dynamic`;
the same exploit against an isolated binary is `code_present/dynamic` (→ *proving.md* for the
full ladder and the self-contained, re-verifiable spec).
"""


# ── fuzzing.md ────────────────────────────────────────────────────────────────────────
FUZZING = """\
# Building instrumented targets and running fuzz campaigns

Fuzzing is how you turn a static suspicion into a lab-confirmed crash, and — on a live service
— into the strongest assurance there is. You NEVER run a compiler or a fuzzer yourself: you
REQUEST a build or a campaign and HexGraph runs it in a hardened sandbox container. Two pieces:
the **build** (turn source into an instrumented, coverage-friendly target) and the **campaign**
(fuzz a target, reap crashes as findings).

## The headline loop: source → instrumented build → coverage-guided fuzz
The high-value path when you have (or can author) the target's source:
`src_import_tree` → `src_build` → `fuzz_start` on the instrumented derived target.
- **src_list_trees(project_id)** / **src_read_file(tree_id[, rel])** — first see what managed
  source trees ALREADY exist and browse one (id/name/origin/file_count + the `target_ids` each is
  `built_from`; with `rel`, read one file's text). This is TRUSTED source text — distinct from the
  firmware's hostile `fs_read_file` bytes. Check here before importing, in case the source you need
  (an imported library, a harness from a prior run) is already in the project.
- **src_import_tree(project_id, name, files=[{rel, content, role?}])** — create a managed
  SOURCE tree from trusted text (a small library's source, a harness you wrote). Role-tag a
  harness `role:"harness"`. This is trusted source, NOT target bytes — never ingest hostile
  bytes here.
- **src_build(project_id, source_tree_id, …)** — compile the tree into an INSTRUMENTED artifact
  via a recorded, reproducible recipe. You author/approve a BuildSpec; HexGraph injects the
  instrumentation env (CC/CXX/CFLAGS/SANITIZER/FUZZING_ENGINE — the base-image contract, you do
  NOT set it), so the SAME phases yield an ASan/SanCov/AFL++ build by swapping only the profile.
  If the tree is linked (`built_from`) to a target, the rebuild registers a DERIVED target wired
  `instrumented_build_of`→ the original — the fuzzable, coverage-instrumented twin of the shipped
  binary. **Cross-compile for firmware** by passing `arch` (mips/mipsel/arm/armhf/aarch64):
  HexGraph injects the clang `--target` + the parent firmware's rootfs as `--sysroot`.
  **Dependencies** default to vendored/offline (`network="none"`, fully reproducible); a bounded,
  audited, allowlisted fetch needs **features.build_fetch** (its OWN gate, NEVER features.network)
  which hash-pins a lockfile then drops network and compiles offline. **Gated: features.build**
  (separate from executing the target — you can build-and-inspect without running the binary).
- **The build→fuzz handoff is automatic.** On a successful build HexGraph records the
  instrumented target sources on the derived target and promotes any `role=harness` file to a
  `harness` node wired `harnesses`→ the target. So a subsequent **fuzz_start(derived_id)** Just
  Works: it infers the `source_lib` surface, resolves sources + harness, and runs with REAL
  coverage — no manual wiring.

Supporting build tools: **src_list_builds** (the ledger — status, reproducibility/cache, the
derived target), **src_build_log(build_id)** (the full compile output — READ IT when a build
fails; don't guess at a missing header or a rejected flag), **src_save_revision** (edit a
HexGraph-authored harness/PoC as a new revision — scratch trees are editable by default; other
authored trees need features.source.edit — then `src_build(..., source_revision_id=…)` to rebuild
from it), **src_import_oss_fuzz** (map an OSS-Fuzz `build.sh` onto our env contract).

## Campaigns — long-lived, detached fuzz jobs
**fuzz_start(target_id, …)** returns immediately with `{id, status:'running'}`. The `Fuzzer`
seam picks the engine by attack **surface** (auto-inferred from the target; override
`surface`/`engine` if needed):
- **source_lib** — an instrumented derived target (a `src_build` rebuild, with source) →
  **AFL++** with real coverage. The high-value loop above.
- **binary_only** — a stripped firmware ELF, no source → **AFL++ qemu-mode** (full edge
  coverage via QEMU, no instrumentation needed). A foreign-arch MIPS/ARM binary runs under
  qemu-user with the parent firmware rootfs as sysroot (auto-resolved). Just `fuzz_start(target)`.
- **network** — a LIVE service (a rehosted device's port, or a local service) → **boofuzz** over
  a real socket. A crash here is a service death = **input_reachable/dynamic**, the strongest
  assurance. Needs **features.network**. For a local launchable server with no reachable host,
  HexGraph can start it in its own container and join the fuzzer to that netns (launch-and-join,
  auto-detected; force with `launch=true`) — that EXECUTES the service so it also needs
  features.poc/fuzzing. Remote blind network-fuzz of a physical bench device is OFF by default
  (destructive) — prefer replay/PoC of a known crash.
- **file_format** — a structured-input parser → AFL++/libFuzzer + an auto-dictionary.

Optional knobs: `seeds` (host corpus paths to jump past trivial input gates), `dictionary`
(tokens; auto-derived from the target's strings when omitted), `max_len`, `max_total_time`,
`max_crashes`, `instances` (AFL++ master + N-1 secondaries), `resources`
(`{mem,cpus,pids,tmpfs,timeout,unconstrained}` — `unconstrained` lifts mem/cpu/pids only, it is
NOT a security relaxation: the sandbox stays cap-drop, no-new-privileges, read-only, non-root,
`--network none` except the audited boofuzz tier).

**Gating by surface:** source/binary-only/desock fuzzing EXECUTES a target → **features.fuzzing**
(or features.poc); a live-socket boofuzz campaign talks to a service → **features.network**. Pick
the right flag; neither is a new permission. The simpler single `task_run(target, "fuzzing")` and
`harness_generation` tasks exist too, gated the same way.

## Lifecycle and triage
- **fuzz_status(campaign_id)** — live stats (execs, edges_covered, crash_count, coverage). Check
  the `status`: a clean run is `completed`, but a campaign that did 0 work (service unreachable,
  0 executions) or hit engine instability finalizes as **degraded** — NOT a silent zero-crash
  success; the reason rides `warning`/`engine_note`.
- **fuzz_list_artifacts(campaign_id)** — the deduplicated crashes. Crashes STREAM as they happen
  (an early crash in a 6-hour run surfaces in minutes; you don't wait for the budget). Each
  unique crash becomes a **fuzz_crash finding** with `evidence.extra.fuzz`: a deterministic
  `exploitability` rating (likely_exploitable/probably_exploitable/info_leak/dos, read from the
  ASan report — no LLM), a normalized-stack-hash `dedup_key` (`dupe_count` = how many inputs
  collapsed onto it), a **minimized_reproducer_sha**, and a **coverage_instrumented** flag.
  **Trust the flag:** `coverage_instrumented=false` was a black-box run — do NOT overstate
  coverage/completeness.
- **fuzz_stop(campaign_id)** preserves the corpus (resumable); **fuzz_resume(campaign_id)** picks
  a finished/stopped campaign back up from that corpus (AFL++ resumes natively). Campaigns are
  crash-safe — they survive a server restart.
- **fuzz_verify_artifact(artifact_id)** — replay a crash reproducer BYTE-FAITHFULLY in the
  sandbox (`fuzz_minimize_artifact` is the back-compat alias). The reproducer runs as a raw-bytes
  file (0x00/0xff preserved exactly), so a binary fuzz reproducer replays faithfully. A
  binary/harness crash replays against the instrumented binary (`code_present/dynamic`); a network
  crash re-sends its crashing message over the live socket (`input_reachable/dynamic`). So a
  fuzz_crash climbs the assurance ladder like a hand-written PoC.
- **fuzz_coverage_diff(campaign_id, other_campaign_id)** — did a harness/corpus/engine tweak
  actually expand reach? Compares per-line coverage (what NEW lines `other` reached) before you
  spend more budget.

## Remote fuzz environments (off by default)
A campaign can run on a user-owned remote Docker host (beefier compute) instead of this box:
**fuzz_list_environments** shows where a container can run (`local` + remote endpoints, with
presence-only status + health), **fuzz_environment_health(id)** checks one, and `fuzz_start(...,
environment=<id>)` targets it. Nothing about the analysis changes — the SAME sandbox boundary
applies on the remote, crashes/coverage stream back into THIS local graph, and the connection
details are a secret (never echoed). **Gated: features.fuzz_remote** (fail-closed; default →
`local`).

## Tell the analyst where to look
Everything here is browsable in the web UI: the **Campaigns** tab (live execs/coverage/crashes)
and an **Artifacts** view that groups crashes by dedup bucket with assurance chips, a
source-mapped stack (click a frame → the **Source** tab with coverage shading), and per-crash
Reproduce / Minimize / Promote / Promote→PoC buttons. After you populate the graph, point the
analyst there.
"""


# ── proving.md ──────────────────────────────────────────────────────────────────────
PROVING = """\
# Proving exploitability — the assurance ladder

A finding's worth is its ASSURANCE: how strongly you've shown the bug is real and reachable.
HexGraph records this as a triple `{standard, method, precondition}` on every finding (see
`meta_get_schemas['assurance']`). Your job is to climb the ladder as high as the engagement
allows AND to state, in the finding, exactly how high you got and what you could NOT establish.
Overstating assurance is the worst thing you can do here.

## The ladder
- **code_present / static** — "looks vulnerable" from decompilation only. Every vulnerability
  finding is auto-floored here, so you ALWAYS document at least this. It may be a false positive.
- **code_present / dynamic (LAB-CONFIRMED)** — you executed the code in ISOLATION and the bug
  FIRED: a `fuzz_crash`, or a `poc` run of the extracted binary in the sandbox. This proves the
  code is genuinely vulnerable even if you haven't yet found how user input reaches it in the
  deployed system — a missing path doesn't mean none exists (it may be reachable directly or by
  chaining other bugs). Strictly beats the static guess; pursue it whenever a static suspicion is
  worth confirming.
- **input_reachable / dynamic** — you triggered it END-TO-END through the live deployed input
  boundary (a rehosted/remote web or socket surface), so it's both reached AND fires. The
  STRONGEST. Strive for this; declare the access it needed (below).
- **input_reachable / static (the side rung — ARGUE it when you can't trigger live)** — if the
  service won't boot (no rehost/remote/exec tier), argue reachability over the graph instead of
  triggering it. An ARGUMENT, never a demonstration — strictly weaker than a live trigger, and it
  NEVER downgrades a dynamic claim.

So a verified `poc` against an isolated binary is lab-confirmed (`code_present/dynamic`); only a
verified PoC against the live service surface is `input_reachable/dynamic`. A vulnerability with
no dynamic confirmation at all is "suspected" — say so.

## Verify a PoC — finding_verify_poc
`finding_verify_poc(target_id, poc, finding_id=<the PoC finding>)` fires your exploit, checks the
oracle, attaches the result, and returns the engine-computed assurance triple. The oracle
taxonomy (reflected `body_contains`/`response_contains`/`status_differs`; blind
`callback`/`canary_read`/`oob_write`) is in *dynamic-analysis.md* — pick the oracle by what the
bug does, and remember the engine strips your own request's reflection before matching, so a
match is real.

**Make the PoC spec SELF-CONTAINED — it must be one-click RE-VERIFIABLE by the analyst with NO
agent in the loop.** HexGraph re-runs the stored spec as-is, so it must stand alone: complete
`steps`/`argv`/`stdin`/`env`, a real oracle, and **`{{NONCE}}` in BOTH the injected payload AND
the oracle value** (never a hard-coded nonce). For a raw byte input set `argv_b64` (a list of
base64'd raw-byte elements) / `stdin_b64` yourself instead of `argv`/`stdin`, so non-printable
bytes reach the sink faithfully. Re-verify resolves the PoC's OWN target (recorded as
`evidence.extra.poc_target_id`) — so a binary finding's PoC may legitimately fire against a child
or live surface. Re-verify NEVER downgrades: a failed/weaker re-run preserves an already-stronger
rung. Don't bake host/path into the spec.

HexGraph derives a human copy-paste reproduction command (curl / nc / the binary invocation) from
the spec and shows it, the steps in plain language, and the assurance triple to the analyst. So
write a short **how-it-works** in the finding's `summary`/`reasoning` (the bug, why the oracle
firing proves it, the access it needed) — the finding must be actionable WITHOUT re-reading your
trace.

## Argue static reachability — finding_reachability
When you can't trigger a bug live, build the path in the graph and let HexGraph check it:
`graph_create_node` the untrusted **input**/`param`/`endpoint` source and the **sink**, then
`graph_create_edge` the **`taints`** (best) / `calls` / `routes_to` dataflow from source to sink,
then call **finding_reachability(finding_id=…)**. If a directed source→sink path exists it
UPGRADES `code_present/static` → `input_reachable/static`, records the path, derives the
precondition (an auth boundary on the path ⇒ `requires_credentials`; an unauth boundary ⇒
`unauthenticated`), and bumps the finding's confidence to `high` (a recovered path is concrete).
The sink is resolved from the finding's `about`→sink edge / evidence.sink; if the finding doesn't
cite it yet, pass **sink_node_id** to point at the sink node explicitly (the upgrade still records
on the finding). When the route is pre-auth but the graph lacks the auth markers — so the derived
default would under-state it as `unspecified` — pass `precondition="unauthenticated"` to assert it
(recorded as not-inferred). (This is the DIR-823G situation: a real cmdi sink HexGraph couldn't
boot goahead to trigger — argue the path, state the precondition.)

## Report the precondition honestly
Always state the highest rung you reached and what you could NOT establish (e.g. "code-present,
lab-confirmed; production input path not yet found"). Declare access via the PoC spec's
`precondition`: aim for `unauthenticated`, but say `requires_credentials:<which>` honestly — cf.
the IoTGoat cmdi, which was lab-real but only root-reachable. An honest weaker claim is worth more
than an overstated one a reviewer will tear down.

## n-day — one bug is usually several
Firmware reuses the same routine across components, so after you confirm a bug, find its
siblings. **finding_link_same_code(project_id)** links functions with identical code across the
project's other binaries (the exact-hash complement to the fuzzy `re_yara_sweep`) and flags which
side already has findings. For each matched binary that's still bare,
**finding_propagate(finding_id, target_id)** clones the finding onto it (wired `derived_from`→ the
source) to triage — then verify a PoC there too. This is a high-leverage move at the END of an
engagement, run by the orchestrator once the parallel sub-agents have populated the per-binary
findings.

## Confirm your writes
After verifying, read it back: `finding_get(finding_id)` returns the finding in full (evidence +
the assurance triple), `graph_get_node(node_id)` a node with every attr. On success, `finding_update`
the vulnerability to higher confidence/severity and status `confirmed` and
`graph_link_evidence(hypothesis, finding, "supports")` so the hypothesis flips to supported; on
failure, lower the confidence and link `"refutes"`. Then `graph_close_hypothesis` once the
question is settled either way — a documented dead end is as valuable as a hit.

When the vulnerability corresponds to KNOWN MANAGED SOURCE (an imported library, a harness — a
`src_*` tree, never the target's hostile bytes), **finding_link_to_source(finding_id, tree_id,
rel, line?)** records a `located_in` edge + `evidence.extra.source_ref`, the workbench's "Open in
source" link, so the analyst jumps from the finding straight to the exact line. Do this whenever
the link exists — it's the source↔graph tie the workbench is built on.
"""


# ── Rendering + emission ──────────────────────────────────────────────────────────────
SKILL = SPINE  # back-compat alias (agent_setup / agent_delegate / tests import SKILL)

_DESCRIPTION = (
    "Drive a vulnerability-research engagement through HexGraph's sandboxed MCP tools — "
    "ingest a binary or firmware, map its attack surface, decompile / fuzz / verify PoCs "
    "(parallelizing across sub-agents for large targets), and record every result as "
    "findings/nodes/edges in the shared graph. Use whenever analyzing or hunting bugs in a "
    "binary or firmware with HexGraph."
)

_FRONTMATTER = f"---\nname: hexgraph-vr\ndescription: {_DESCRIPTION}\n---\n\n"

# filename -> body, in the order an engagement reads them. record-keeping.md sources the
# shared rubric so the working-memory discipline can't drift from the system prompt's copy.
SUBFILES: dict[str, str] = {
    "record-keeping.md": RECORD_KEEPING,
    "static-analysis.md": STATIC_ANALYSIS,
    "dynamic-analysis.md": DYNAMIC_ANALYSIS,
    "fuzzing.md": FUZZING,
    "proving.md": PROVING,
}


def skill_markdown() -> str:
    """The skill SPINE as a Claude Code skill file (YAML frontmatter + the SKILL.md body)."""
    return _FRONTMATTER + SPINE


def full_skill_markdown() -> str:
    """The WHOLE skill bundle as one document: the spine followed by every sub-file.

    For consumers that can't read on-demand sub-files — `hexgraph mcp install --print-skill`
    (paste into a Codex/gemini system prompt) and the delegate-task brief — so no
    "read static-analysis.md" pointer dangles.
    """
    parts = [skill_markdown()]
    for name, body in SUBFILES.items():
        parts.append(f"---\n\n# {name}\n\n{body}")
    return "\n\n".join(parts)


def write_skill(base_dir: str) -> str:
    """Write the skill to <base_dir>/hexgraph-vr/ and return the SKILL.md path.

    Emits the spine (`SKILL.md`) plus every capability sub-file in `SUBFILES`. Progressive
    disclosure: a skill-capable agent reads a sub-file on demand when it enters that phase,
    instead of carrying the whole field manual in every prompt.
    """
    import os

    d = os.path.join(base_dir, "hexgraph-vr")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "SKILL.md")
    with open(path, "w") as fh:
        fh.write(skill_markdown())
    for name, body in SUBFILES.items():
        with open(os.path.join(d, name), "w") as fh:
            fh.write(body)
    return path
