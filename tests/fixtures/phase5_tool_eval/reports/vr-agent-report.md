# Phase 5 Tool Evaluation — VR-Agent Report (Role A)

**Date:** 2026-06-06 · **Against:** merged `origin/main` (`b4d77e6`) · **Backend:** mock (zero HexGraph-side token spend; the VR agent is the LLM).

## How this was run
Four blind challenges, each built to **force** one Phase 5 tool. The VR agent ran as a **headless `claude` driver** inside an isolated eval worktree, connected to the freshly-registered `hexgraph-eval` MCP server (with `SKILL.md` regenerated from the merged `agent_setup.py`). It was handed **only** the per-challenge blind brief + the compiled binary, and restricted to the hexgraph MCP tools + `Write` (no shell / file-read / search) — so it could neither read the challenge source nor touch raw bytes outside the sandbox. The **no-guilty-knowledge** guarantee was structurally enforced, not merely requested.

## Result: all four tools validated ✅
| Challenge | Tool forced | Verdict | Planted insight recovered (baseline could not) |
|---|---|---|---|
| **A** `mitis_relayd` | `re_binutils_facts` | **PASS** | NX/PIE/canary/**FORTIFY-off** posture (FORTIFY surfaced *only* by binutils); then traced an unauth command-injection `RUNDIAG → system()` |
| **B** `stringcrypt.exe` | `re_floss_strings` | **PASS** | C2 URL `http://relay.mitis-labs.net/ingest` (stack-built) + key `MITISKEY-7F3A9C` (XOR) — both invisible to `strings` |
| **C** `vantage_iot_fw` | `re_yara_sweep` | **PASS** | 4 rule classes across 2 ELFs → **4 `pattern` nodes + 8 `matches_rule` edges** auto-promoted, deduped |
| **D** `licensegate` | `re_solve_reaching_input` | **PASS** | computed serial `3b25065c4b20040f` → `system("/bin/grant_admin")`; the finding carries the reproducer |

Determinism held for all four (cached re-runs, empty graph-delta on re-run). Every result was reached from the binary + brief alone.

## ⚠️ Process finding the eval caught: stale sandbox image
The **first** B/C runs failed: the local `hexgraph-sandbox:latest` predated the FLOSS (#167) / YARA (#169) toolchain, so `flare-floss` and `yara-python` were missing and both probes errored at runtime. The VR agent met the objectives **manually anyway** (radare2 stack-string resolution; decompilation of the weak defaults) — real resilience — but the intended tools did nothing, and **`re_yara_sweep` returned `match_count: 0`, indistinguishable from a clean scan.** Rebuilding the image (`hexgraph-sandbox:eval`, floss+yara) and re-running validated both. The dead-tool runs are in the Appendix; they drive several plan items below.

## Cross-cutting tool-UX findings (for the implementation plan)
1. **Result truncation (A).** `re_decompile_function`'s inline result is head-truncated (`_MAX=6000`), which hid the `system()` sink in the tail. Fix: an **actionable truncation marker** (embed the observation id + sizes + recovery knobs) and an **agent-supplied `max_chars`** (default 6000, clamped) on the body-returning `re_*` tools. Human counterpart: a dedicated **source viewer**.
2. **Solver reproducer ergonomics (D).** `concrete_input` is the full argv buffer (8 real bytes + filler) with no "which bytes matter" hint → add `constrained_len`/`minimal_input`. No **byte-faithful dynamic-verify** path for a solver argv reproducer (`finding_verify_poc` text-mangles argv — unsafe for non-printable bytes). The `vulnerability/other` framing fits a crackable gate poorly → a `weak-gate`/`logic` finding type.
3. **Tool robustness (B/C).** **YARA silent failure** — `match_count: 0` when every file *errored* looks identical to a clean scan; surface `scanned_ok` vs `errored`, refuse `0` when all errored. Add a **`meta_check_features` health preflight** distinguishing gated-off from configured-but-broken (there's `meta_check_decompiler` but nothing for floss/yara/angr/emulation). **Setup gap:** an "up-to-date build" must rebuild the **sandbox image** on a toolchain change, not just the venv/SPA.
4. **Graph ergonomics (A).** A `graph_stats`/counts verb (listing 100+ nodes to count is unworkable + truncates); `graph_set_node_attr` (re-create-merge to set `is_sink` is awkward); a first-class **CWE field** on Finding (stashed in `evidence.extra` today); a lightweight **promote-callee** verb (corroborates the one-click-promote idea); an explicit `precondition` on `finding_reachability` (couldn't express "unauthenticated").
5. **Schema naming (C).** `graph_create_edge`'s param is `type`, but the vocab is advertised under `edge_types` — passing `edge_type` errors. Mildly misleading.
6. **Decompiler fidelity (A/D).** radare2 pseudo-C is noisy for constraint extraction; Ghidra would help (operator-fixed, no agent toggle — documented).
7. **What worked (keep it):** `re_xrefs` with no symbol = highest-leverage first move; `binutils_facts` genuinely sharper than baseline; the Observation/graph split + **legible determinism** (cached re-runs that say *why* nothing duplicated); clean node-merge; bidirectional provenance; the angr "you direct, HexGraph runs it" experience.

---



# Challenge A — full agent writeup

# HexGraph VR engagement report — Mitis EdgeRelay `relayd`

**Target:** `mitis_relayd` (host path `tests/fixtures/phase5_tool_eval/mitis_relayd`)
**Project:** `580df76e-b334-4ee4-9ada-bad0844ce55a`  **Target id:** `5cd4b5a4-95ce-4b24-8757-d790616083a1`
**Format:** ELF x86-64, type `EXEC`, dynamically linked (libc, libm). Single binary, no firmware children.
**Bottom line:** The "hardened" claim is false. The binary ships with **no** standard exploit mitigations, and it contains an **unauthenticated OS command injection** that reaches `system()` with an attacker-controlled argument. Realistic, pre-auth RCE.

---

## (a) What I found — and which tool surfaced each lead vs. the baseline that did not

### The two objective answers

**1. Runtime memory-protection posture (the "hardening" question).** The binary carries essentially none of the modern protections:

| Mitigation | State | Consequence |
|---|---|---|
| NX | **off** | data/stack is executable — shellcode-on-stack viable |
| PIE | **off** (ELF `EXEC`, fixed base, entry `0x403250`) | static addresses, no image ASLR — no leak needed for gadgets |
| Stack canary | **off** | linear stack overflow can overwrite the return address undetected |
| FORTIFY_SOURCE | **off** | no `_chk` variants for the unsafe libc calls it links |
| RELRO | **partial** | GOT is writable — GOT-overwrite control-flow hijack viable |

It also links the dangerous libc calls `system`, `strcpy`, `strcat`, `sprintf`, `memcpy`. This is the *opposite* of hardened.

**2. Path from input to code execution.** `handle_request()` parses each request line with `sscanf(req, "%15s %255[^\n]", opcode, arg)`. On the `RUNDIAG` opcode it does:
```
0x4037a7  snprintf(string, 0x140, "/usr/libexec/mitis/diag-%s.sh", arg)
0x4037cf  system(string)
```
`%255[^\n]` captures everything up to newline — spaces, `;`, `|`, `$()`, backticks — with **no** shell-metacharacter sanitization. `main()` reads request lines with `fgets` and calls `handle_request(line)` in a loop with **no authentication**. So `RUNDIAG x;<cmd>;` ⇒ `system("/usr/libexec/mitis/diag-x;<cmd>;.sh")` ⇒ `<cmd>` runs. **Unauthenticated command injection (CWE-78).**

### Which tool surfaced the lead vs. the baseline (the control)

| Fact | Baseline pass (`target_facts` / `re_imports`) | Deeper tool that actually surfaced it |
|---|---|---|
| `system`, `strcpy`, `sprintf`, `strcat`, `memcpy` linked | ✅ listed as `dangerous_imports` | — (baseline sufficient for *presence*) |
| Mitigations nx/pie/canary/relro | ✅ summary present | `re_binutils_facts` confirms authoritatively from the ELF header |
| **FORTIFY_SOURCE = off** | ❌ **omitted** from baseline summary | ✅ **only** `re_binutils_facts` returned `fortify=False` |
| **Which function reaches `system`** | ❌ baseline lists `system` as an import only | ✅ **`re_xrefs`** (no symbol): "system: reached from sym.handle_request" |
| The RUNDIAG command-template + the `system(snprintf(...))` chain | ❌ invisible | ✅ **`re_decompile_function(handle_request)`** (+ full disasm via `obs_get`) |
| No auth on the input path | ❌ invisible | ✅ **`re_decompile_function(main)`** — fgets loop → `handle_request`, no auth gate |

**Verdict on whether the deeper tools were necessary:** Yes. The baseline established the *ingredients* (mitigations summary + dangerous imports) but could not answer the objective. It omitted FORTIFY, and — crucially — it never showed that the *request handler* reaches `system`, nor the unsanitized command template, nor the absence of an auth boundary. `re_xrefs` collapsed the search to one caller in a single call; decompilation proved the chain.

---

## (b) The graph I populated — auto-population vs. my deliberate promotions

### Deterministic auto-population (tools wrote these with no `graph_create_*` from me)

- **At ingest (recon):** ~100+ `symbol` nodes (every import; `memcpy` already tagged `is_sink:true`), a ~22-entry sample of `string` nodes, the `contains` edges binding them to the target, and one auto `recon` finding ("Attack-surface summary"). Note: recon facts (arch/mitigations/imports) live **on the target**, not as Observations — `obs_list` was empty until I ran a tool.
- **From my QUERY tools (each recorded a reusable Observation, added NO graph nodes):** `binutils_facts`, `xrefs`, `strings`, `list_functions` → 4 Observations. `re_xrefs` also auto-tagged `is_sink` on dangerous imports already in the graph.
- **From `re_decompile_function` (the one query that DOES promote):** promoted `handle_request` and `main` as `function` nodes (enriched in place with recovered prototype/locals) and drew the `calls` main→handle_request edge. 2 more Observations.

Total Observations: **6** (and they stayed 6 through the determinism re-run).

### My deliberate promotions (manual `graph_create_*` / `finding_*`)

| Kind | Count | What |
|---|---|---|
| `input` node | 1 | `relay_request_line` (trust=preauth, source = fgets request line) |
| `symbol` node (merge) | — | re-asserted `system` with `is_sink:true`, `library:libc` |
| `taints` edges | 2 | input→`handle_request`; `handle_request`→`system` (addr `0x4037cf`, sanitized=none) |
| `calls` edge | 1 | `handle_request`→`system` (call_site `0x4037cf`, attacker-controlled arg) |
| `hypothesis` node | 1 | "relayd is realistically exploitable for unauth RCE…" → status **supported** |
| `link_evidence` (supports) | 2 | both findings → the hypothesis |
| `annotate` (note) | 1 | on `handle_request` (proposed) |
| **Findings** | 2 | cmdi (critical) + hardening posture (high) |

**Findings (3 total: 1 auto recon + 2 mine):**
- `24f5e872` — *Unauthenticated command injection … RUNDIAG* — **critical/high**, category `command-injection`. Assurance climbed **`code_present/static` → `input_reachable/static`** via `finding_reachability` (taint-backed path `relay_request_line --taints--> handle_request --taints--> system`; precondition inferred, no auth boundary found).
- `890a979f` — *Shipped relayd carries NO standard exploit mitigations* — **high**, category `other`, `code_present/static`.

**Honest assurance statement:** Both findings are **static** (code_present, and the cmdi argued up to input_reachable/static). Neither was dynamically confirmed — I did **not** run `finding_verify_poc` or a live socket, because this engagement was scoped to the static toolset (PoC/network execution tiers were not exercised). The cmdi is a textbook, high-confidence static result; the strongest remaining rung (`input_reachable/dynamic`) would require executing the binary or a rehosted/live `relayd` socket.

### Determinism check (before/after)
- Re-ran the key tool `re_binutils_facts`. Result returned flagged **`(cached)`**.
- Observation count: **6 → 6** (no new row; same `content_hash`, reused).
- `function` node count: **2 → 2**. No duplicate nodes/edges created.
- Conclusion: query results are content-addressed and idempotent; re-running a heavy analysis is free and graph-neutral, exactly as documented.

---

## (c) Tool-experience assessment (UX feedback — first-class deliverable)

### What worked well
- **`re_xrefs` with no symbol was the single highest-leverage call.** One query produced "system ← handle_request" and the format-string map. It turned an 31-function binary into one obvious target instantly. This is the right default first move and it earns its place in the SKILL.
- **`re_binutils_facts` is genuinely sharper than the baseline.** It surfaced `fortify=False`, which the `target_facts`/`re_imports` mitigations summary omitted entirely. For a "is this actually hardened?" objective, the authoritative readelf pass mattered — the baseline alone would have under-reported the posture.
- **The Observation/graph split is clean and the provenance is trustworthy.** Knowing that decompile *promotes* but xrefs/strings/binutils *don't* let me query aggressively without polluting the graph. The cached re-run + stable counts made the determinism story easy to verify.
- **`finding_reachability` is a nice touch.** After I wired the `taints` path it upgraded the assurance and recorded the exact path + inferred precondition — a clean way to make a static claim stronger than "looks vulnerable" without overclaiming a live trigger.
- **`obs_get` returning the full disassembly** of an already-run decompile (no re-run) was exactly what I needed to confirm the `system()` call site after the pseudo-C was truncated.

### What was awkward or surprising
- **Decompiler output is raw radare2 pseudo-C, and `re_decompile_function`'s inline result was truncated** (the tail with the actual `system()` call was cut). I had to `obs_get` the Observation to see the RUNDIAG branch's `system()` — easy once I knew, but a first-timer could miss the sink. The pseudo-C is also quite low-level (`qword [var_e0h] = 0` ×30, goto-labels) — readable but noisy; Ghidra would be cleaner. (`meta_get_schemas.decompiler.active` = radare2, working — fine, just noting the fidelity.)
- **`graph_list_nodes` with no `node_type` filter is unusable for counting** on a binary with 100+ import symbols — the response is enormous and got truncated, so I couldn't get an exact total node count from one call. I worked around it with type-filtered calls. A `graph_counts` / summary verb (per-type tallies) would be the obvious fix.
- **Two `calls` edges main→handle_request existed after one decompile** (one with provenance, one with empty attrs) in the initial edge listing — looked like a near-duplicate. Not harmful (merge folds dupes), but mildly confusing when auditing what I "owe."
- **The annotation lands `status:proposed`** and there's no agent-side way to see it reflected on the node without re-reading — expected (analyst approves), just worth knowing it won't show as applied.

### What I expected but did not get
- **A precise input-boundary identity.** `main` reads with `fgets`, but I could not tell from the static view whether the FILE* is `stdin`, a socket fd, or a pipe — the daemon's actual listen/accept wasn't visible in `main`/`handle_request` (likely in `relay_init`, which I did not decompile). So "unauthenticated network-reachable" rests on the daemon-nature of the binary + the no-auth dispatch, not on an observed `bind/listen`. `re_xrefs` reported no network sink sites, which is itself informative (the socket setup may be in a callee I didn't promote, or it reads stdin under a supervisor). I'd have liked the reachability/precondition to flag "source boundary unconfirmed" rather than silently inferring `unspecified`.
- **A CWE field on the Finding schema.** I had to stash `cwe: CWE-78` in `evidence.extra`. Fine, but a first-class CWE field would make findings more triage-friendly.

### Things I reached for that did not exist (missing verbs / fields)
- **A graph summary/count verb** (`graph_stats(project_id)` → per-type node/edge tallies). Counting by paging the full node list does not scale and made the "before/after counts" step harder than it should be.
- **A way to set a single node attribute** without re-`graph_create_node`. To (re)assert `is_sink:true` on `system` I re-created the node to trigger the merge. It worked, but a `graph_set_node_attr` would be clearer than relying on create-merge semantics.
- **An explicit `precondition` argument on `finding_reachability`** (or the ability to mark a node/edge as an "unauth boundary") — it inferred `unspecified` because there was no auth marker on the path, but I *know* the path is unauthenticated (no auth code exists between fgets and dispatch). I could only express that in the finding's `evidence.extra.auth_precondition`, not drive the reachability precondition. The cmdi is really unauthenticated; the recorded precondition says `unspecified`, which slightly *under*-states it.
- **A lightweight "promote this callee" verb.** `re_decompile_function(main)` listed `relay_init`, `relay_log`, `fgets` as "callees not yet in the graph" — to model `relay_init` I'd have to decompile it. Reasonable (no fan-out by design), just noting that promoting a known-relevant callee as a bare node (without a full decompile) would sometimes be handy.

### Net
The toolset met the objective cleanly and the cheap→expensive ordering (`binutils_facts` → `xrefs` → targeted decompile) was efficient: four queries pinned the posture and the sink, two decompiles proved the chain, and the graph now tells the whole story (input → handler → sink, two findings, one supported hypothesis) without re-reading the binary. The main friction points are ergonomic (no count/summary verb, truncated decompile output, can't directly assert an unauth precondition), not capability gaps.


---


# Challenge B — full agent writeup

# VR Report — `stringcrypt.exe` (Mitis Relay Agent)

**Engagement:** Recover the IOCs (C2 endpoints, API keys, credentials) carried by a
PE32+ "relay agent" recovered from a compromised analyst workstation, plus the routine
that produces them. The interesting material is *not* stored as plain text.

**Workbench:** HexGraph MCP (`hexgraph-eval`), all target handling sandboxed. Target never
opened/run/`strings`'d by me directly.

- Project: `21fd90ee-c676-4971-a63b-a6e384021911`
- Target: `a99c8699-7bb9-449f-a929-0cf3e708473d` (`stringcrypt.exe`)

---

## (a) What I found, and which tool surfaced it

### The recovered IOCs
| IOC | Value | Class | How it's hidden |
|---|---|---|---|
| C2 / exfil endpoint | `http://relay.mitis-labs.net/ingest` | network indicator | built **byte-by-byte on the stack** at runtime (`fcn.140001594`) |
| API key / credential | `MITISKEY-7F3A9C` | secret (CWE-798) | stored **XOR-0x5A encrypted** in `.rdata @0x140004000`, decrypted at runtime (`fcn.140001530`) |
| Banner (corroborating) | `Mitis Relay Agent` | identity string | plain `.rdata` literal (printed by the orchestrator) |

### The routine that produces them (decompilation-grounded)
- **`fcn.1400018b0`** — orchestrator / beacon-init (proposed rename `beacon_init`). Prints
  `puts("Mitis Relay Agent")`, then calls the two decoders into stack buffers.
- **`fcn.140001530`** — **XOR-0x5A string decryptor** (proposed rename `decrypt_xor5a`). Loops
  over a `.rdata` ciphertext buffer (`arg1 = 0x140004000`), `byte ^= 0x5A`, writes plaintext to
  `arg3`, null-terminates at `arg2`. Called with `len = 0xf = 15 = len("MITISKEY-7F3A9C")` →
  produces the **API key**.
- **`fcn.140001594`** — **stack-string builder** (proposed rename `build_c2_url`). Appends the
  literal bytes `h,t,t,p,:,/,/,r,e,l,a,y,.,m,i,t,i,s,-,l,a,b,s,.,n,e,t,/ …` one at a time into a
  stack buffer → produces the **C2 URL**.

### The control: baseline strings did NOT surface this; FLOSS did
- **`re_list_strings` (baseline, obs `7a9ba5c9…`)** — 40 strings, **all MinGW/CRT boilerplate**:
  `GetLastError`, `GetStartupInfoA`, `TlsGetValue`, `__getmainargs`, the
  `"!This program cannot be run in DOS mode."` stub, section names (`.text`/`.rdata`/`.reloc`…),
  and register-spill garbage (`ATUWVSH`, `T$ H`). **Zero** URLs, hosts, keys, or credentials.
  A surface triage would call this sample innocuous. *(There were no convincing "decoy" IOCs
  either — the cover is blandness, not misdirection.)*
- **`re_floss_strings` (obs `75cec394…`)** — `stack=0 tight=0 decoded=4 static=151`. The **4
  decoded** strings are exactly the two IOCs (each appearing twice). FLOSS recovered them by
  *emulating the decode routines in the sandbox* — and, crucially, the payload tagged each
  decoded string with its `decoding_routine` VA, which pointed me straight at
  `0x1400018b0 / 0x140001530 / 0x140001594`. This is the single tool that turned an "innocuous"
  binary into an attributed C2 beacon. **The deeper tool was necessary.**
- I then **confirmed the mechanism with `re_decompile_function`** (the XOR-0x5A loop and the
  byte-by-byte stack writes), so the finding rests on FLOSS emulation *and* decompilation, not a
  single tool's word.

### Assurance (stated honestly)
`code_present / static`. The IOCs and the producing routines are proven by FLOSS emulation +
decompilation. I did **not** execute the target, so the *live* beacon callout to the C2 was not
observed (static-only; PoC/network tiers not used — and not appropriate for "recover the IOCs").

---

## (b) The graph I populated — auto-population vs. my manual curation

### Deterministic AUTO-population (tools, no minting by me)
- **Observations: 12.** Every tool run persisted one: `list_strings`, `floss_strings`,
  `list_functions`, 2× `decompile_at`, 6× `decompile_function`, 1× `disassemble`.
- **Nodes (auto): 29.**
  - **20 `string` nodes** — recon **sampled them at ingest** (all boilerplate; the IOCs were
    *not* among them, because they aren't literals).
  - **9 `function` nodes** — promoted as a side effect of *my* `re_decompile_*` calls (decompiling
    a function promotes it). Includes 2 address-named stubs from `decompile_at`
    (`0x140002129`, `0x140002630`).
- **Edges (auto): 30** — 29 `contains` (target→node) + 1 `about` (a pre-existing recon
  finding → target). **No `calls` edges auto-wired** (I happened to decompile the caller before
  its callees were promoted, so the no-fan-out rule left them unconnected — I added them).
- **Findings (auto): 1** — `0644da12…` "Attack-surface summary" (recon, info).

### My deliberate MANUAL curation (the analysis result)
- **+2 `string` nodes** — the two IOCs (`c0416439…` C2 URL, `01e81cea…` API key), each with a
  `note` explaining it's runtime-constructed and a `provenance` list back to the FLOSS +
  decompilation observations. *These are the nodes that did not and could not arrive
  automatically.*
- **+1 `hypothesis`** (`5ad6b847…`) — "stringcrypt.exe is a C2 beacon that conceals its IOCs via
  XOR/stack-string construction." Now **`supported`** after I linked the finding as evidence.
- **+1 `vulnerability` finding** (`0e8fabe3…`, high/high, `hardcoded-secret`, CWE-798) — captures
  both IOCs, the three routines, the XOR key, and the missed-by-strings/found-by-FLOSS contrast,
  with the assurance triple.
- **+4 edges** — `beacon_init → decrypt_xor5a` (`calls`, with `arg_constraints: len=0xf`),
  `beacon_init → build_c2_url` (`calls`), `decrypt_xor5a → APIkey` (`writes`),
  `build_c2_url → C2 URL` (`writes`). (`finding_record` also auto-added an `about→primary` edge to
  the orchestrator, and `link_evidence` a `supports` edge.)
- **+6 annotations** (proposed) — `rename` + `note` on each of the three routines.

### Counts (before → after my curation)
| | Observations | Graph nodes | Graph edges | Findings |
|---|---|---|---|---|
| After auto-pop only | 12 | 29 | 30 | 1 |
| After my curation | 12 | **32** (+2 string, +1 hypothesis) | **38** (+2 contains, +1 about[hyp], +1 about[finding→primary], +1 supports, +2 calls, +2 writes) | **2** |

### Determinism check (re-ran FLOSS)
Re-ran `re_floss_strings` → returned **`(cached)`**, byte-identical output. Afterward:
**still 1 `floss_strings` observation** (same id `75cec394…`, same `content_hash`), **still 32
nodes, 38 edges** — **no duplication**. Analyze-once / reuse-forever holds, and a repeated query
adds nothing to the curated graph.

---

## (c) Tool-experience assessment (UX feedback)

**What worked well**
- **FLOSS is the star of this scenario and was effortless.** One call, and it not only recovered
  the decoded IOCs that `strings` missed but, in the full Observation payload (`obs_get`), gave
  the `decoding_routine` / `decoded_at` virtual addresses — a direct pivot from "what" to "where."
  That address attribution is the feature that made the routine-identification step fast.
- **The substrate/graph split is exactly right here.** Querying freely (strings, floss, 8
  decompiles) cost the graph nothing; only my 3 deliberate promotions + finding entered it. The
  "no fan-out on decompile" rule kept the graph clean.
- **Determinism/caching is real and visible.** The `(cached)` flag + stable `content_hash` made
  the re-run check trivial to verify, and `obs_list` is a good worklog.
- **`provenance` on nodes + `node_refs` on observations** give clean bidirectional traceability
  from an IOC string back to the exact tool run that produced it.
- **`finding_record` auto-linking** the finding to the `evidence.function` node (`about/primary`)
  was a pleasant surprise — one less edge to wire by hand.

**Awkward / surprising / mismatched-from-expectation**
1. **`re_floss_strings` decoded-string output is lossy at the tool boundary.** The tool's text
   return gave only the *strings*; the **`decoding_routine` addresses live only in the full
   `obs_get` payload**. I nearly missed the fastest pivot. Surfacing "decoded → routine VA" in the
   tool's direct return (even as a compact list) would help.
2. **Address→hex math is on me, and it bit me.** FLOSS reports addresses as **unsigned decimal**
   (`5368715440`); I had to subtract the `0x140000000` image base by hand and got it wrong on the
   first pass (chased phantom `0x140002xxx` functions that turned out to be CRT thunks / a
   non-existent boundary) before recomputing to the real `0x1400018b0 / 0x140001530 / 0x140001594`.
   FLOSS emitting hex VAs (or HexGraph normalizing them) would remove a whole class of error.
3. **`re_decompile_at` on an address with no r2 function boundary still promotes an empty stub
   node.** `decompile_at(0x140002630)` returned an empty body yet created a `function` node named
   `"0x140002630"` with no prototype. That's an orphan-ish artifact I didn't intend to mint — I'd
   expect a no-op (or a clear "no function here") rather than a promoted empty node. Same call also
   named the node by raw address even when it *did* resolve a function (`0x140002129` →
   `fcn.140001e30`), so the node name disagrees with the resolved function. A small naming/promotion
   inconsistency between `decompile_function` and `decompile_at`.
4. **radare2's decompiler output was genuinely poor on this PE** — heavy `goto`/`orphan`-block
   spaghetti, mislabeled the CRT startup, and didn't define a function at FLOSS's reported
   `decoding_routine` for one case. It was *good enough* to read the XOR loop and the stack writes,
   but for anything subtler I'd have wanted Ghidra (`decompiler.active = radare2`, no MCP toggle —
   correctly an operator setting, but worth noting the quality gap on Windows binaries).
5. **Recon under-parsed the PE.** `target_facts` and `re_imports` both returned **empty**
   imports/arch/mitigations, and `re_binutils_facts` is **ELF-only** (failed cleanly with a good
   message). So for a PE there's *no* authoritative import/mitigation view — I had to infer imports
   from the FLOSS static-strings list (`KERNEL32.dll`, `msvcrt.dll`, `Sleep`, `VirtualProtect`…)
   and `re_list_functions`' `sub.msvcrt.dll_*` thunks. A PE-aware facts path (the obvious
   counterpart to `re_binutils_facts`) is the biggest gap for Windows malware triage.

**Things I reached for that didn't exist / I wanted but couldn't make**
- **A "decoded-string" node subtype or a `references`-from-data edge.** I modeled each IOC as a
  `string` node and used a `writes` edge from the decoder (the decoder *produces* the bytes), which
  fits, but there's no first-class way to say "this string is the *output* of this decode routine
  at this `.rdata` source." A `decodes`/`derives` edge (source-data → routine → plaintext-string)
  would capture the obfuscation chain more precisely than `writes`.
- **`re_recover_constant` would have been the *ideal* tool here** (recover a value the code
  computes), but it needs `features.emulation` + Ghidra, which aren't on in this env — so FLOSS was
  the right substitute. Worth noting the two overlap for "string built at runtime."
- **A way to attach the XOR key / `.rdata` source offset as structured fields** on the finding or
  the edge. I put `XOR 0x5A @ 0x140004000` in free-text `note`/`field`/`evidence.extra`; a small
  typed slot for "obfuscation: {scheme, key, src_addr}" would make this queryable across a corpus.

**Net:** for this exact task (hidden IOCs in a Windows PE) the toolset was effective and the
FLOSS → decompile → curate loop was smooth. The friction was all around the *edges* of FLOSS
(decimal addresses, routine VAs hidden in the payload) and the *thin PE recon* (no PE facts/imports
analogue to the ELF path).


---


# Challenge C — full agent writeup

# HexGraph VR eval — Task C: supply-chain / weak-defaults triage of `vantage_iot_fw.bin`

**Target:** `tests/fixtures/phase5_tool_eval/vantage_iot_fw.bin` — Vantage VG-IoT-100 gateway, firmware 1.4.0
**Project:** `5433e1e6-192a-48fb-ad5c-825568d1adea` (`vantage_iot_fw`, freshly ingested for this run)
**Root target:** `a3cc60ad-bc8a-4e5c-b645-643c7c9a4e84` (firmware_image, unpacked via sasquatch)
**Objective:** corpus-wide hygiene triage for shipped-with-known-weak-defaults — default creds, broken crypto, outdated bundled services — spanning *more than one* executable.

---

## Corpus

Recon unpacked the squashfs into a small, deliberately multi-file corpus:

| Path | Target id | Kind | Notes |
|------|-----------|------|-------|
| `usr/sbin/logsvc` | `684a4e2e-7595-4924-85db-10df41138497` | ELF x64 | console logger / login |
| `usr/bin/kvstore` | `c94be8af-7b72-4036-9a3e-dea0697236a7` | ELF x64 | key/value store "sealing" |
| `etc/banner` | (file) | text | `Vantage IoT Gateway VG-IoT-100 / firmware 1.4.0` |

The weak-default signal is split **across both executables** — default creds + stale services in `logsvc`, broken crypto in `kvstore` — exactly the "spread across more than one file" shape the brief warned about. A single-file read would have caught at most half.

---

## (a) What I found, which tool surfaced it, and the baseline that did NOT

### The baseline pass (facts + strings) — present but unclassified
`target_facts` and `re_list_strings` on both binaries ran first. They **did** dump the raw evidence:

- `logsvc` strings: `admin:admin`, `login ok (default credential)`, `hint: factory login is %s`, `ssh: Dropbear sshd v2015.67`, `http: micro-httpd`, `DEFAULT_LOGIN`
- `kvstore` strings: `DES-CBC`, `MD5_Init`, `factory-defaults`, `sealed with %s`, `config crypto profile:`

But this is the trap the brief describes: to the eye these sit in a flat list **interleaved with ordinary noise** (`PTE1`, `GLIBC_2.34`, `__gmon_start__`, loader paths, mangled symbol fragments). Nothing in the baseline output *says* "`admin:admin` is a default credential," "`Dropbear v2015.67` is the pre-CVE-2016-7406 build," or "`DES-CBC`/`MD5` are broken primitives." `target_facts.dangerous_imports` was **empty** for both — these are hygiene/SBOM issues, not dangerous-libc-call bugs, so the recon dangerous-import heuristic surfaced nothing. A casual per-file reviewer skims past all of it.

### The classifier — `re_yara_sweep` (corpus-wide)
The objective is a known-bad triage across the whole image, so the right tool is the project-wide YARA sweep, not per-file reading. One call —
`re_yara_sweep(project, ruleset="all")` — scanned **6 artifacts (3 byte-targets + extracted files)** and classified the noise into **4 distinct known-bad rules**, telling me exactly *which* files matched and *why each is a concern* (rule category + declared severity + CVE):

| Rule | Category | Sev (declared) | CVE | Matched file(s) |
|------|----------|------|-----|-----------------|
| `hexgraph_default_admin_creds` | embedded_credential | medium | — | `usr/sbin/logsvc` |
| `hexgraph_dropbear_old_banner` | known_bad_library | medium | CVE-2016-7406 | `usr/sbin/logsvc` |
| `hexgraph_des_constants` | weak_crypto | low | — | `usr/bin/kvstore` |
| `hexgraph_weak_hash_md5_sha1_banner` | weak_crypto | low | — | `usr/bin/kvstore` |

That is the whole value proposition in one result: the *same* strings the baseline left as undifferentiated text came back **labelled, attributed to a file, and severity/CVE-tagged**.

### Grounding each lead in code (decompilation)
A YARA hit is a string match, so I confirmed each in the actual code before promoting it:

- **`logsvc:check_login`** — loads `obj.DEFAULT_LOGIN = "admin:admin"` and does `strcmp(input, "admin:admin")`; the equal branch is "login ok (default credential)". A real hardcoded factory credential (CWE-798), not just a stray string.
- **`logsvc:print_about`** — iterates the `ABOUT[]` banner array (`…console logger` / `build: vantage-logsvc 1.4.0` / `ssh: Dropbear sshd v2015.67` / `http: micro-httpd`), confirming the advertised bundled-service versions.
- **`kvstore:print_crypto_profile`** — `cipher = DES-CBC` (`obj.CIPHER`), `mac = MD5_Init` (`obj.CONFIG_MAC`) as the `factory-defaults` / `sealed with %s` profile.
- **`kvstore:config_mac`** — **stronger finding than the banner**: the "MAC" is computed as `eax = (eax<<5) - eax + byte`, i.e. `h = h*31 + c`, a non-cryptographic rolling hash over the data — not a keyed MAC at all, so the integrity tag is trivially forgeable (CWE-916/CWE-328).

**Findings recorded (3):**
1. `6d535ebc…` — Hardcoded factory default credential `admin:admin` in logsvc — **high** / hardcoded-secret
2. `1c59ddc2…` — Deprecated/broken cryptography (DES-CBC + MD5/x31 MAC) in kvstore — **high** / weak-crypto
3. `7a184484…` — Outdated bundled services (Dropbear v2015.67 / micro-httpd) in logsvc — **medium** / other

All three are **code_present / static**. Honest limits: the firmware was not rehosted and the SSH/HTTP daemon bytes are not in this minimal image, so none was triggered through a live input boundary — these are hygiene/SBOM leads, not demonstrated exploits.

---

## (b) The graph I populated — auto vs manual

### Deterministic auto-population (the tool did this; I minted nothing)
- **At ingest (recon):** raw `string`/`symbol` nodes + `contains` edges for both binaries and the image, plus 3 `recon` attack-surface findings. (Baseline substrate — useful but unclassified, see above.)
- **From `re_yara_sweep`:** **4 `pattern` nodes** (project-level, `target_id=null`, **deduped one-per-rule**), each carrying `rule`, `severity`, `category`, `cve`, and `provenance → yara_matches Observation`; **8 `matches_rule` edges** (each rule links *both* the firmware-image file entry on the root target *and* the child target → 4 rules × 2 sources = 8); and one `yara_matches` **Observation per scanned target** with bidirectional `node_refs` back to the patterns. I created **none** of these — the sweep promoted them.

### My manual promotions (deliberate curation)
| Kind | Count | What |
|------|-------|------|
| `vulnerability` findings | 3 | the three weak-defaults above, each grounded in a pattern Observation + decompilation |
| `hypothesis` node | 1 | `c05daab7…` — "VG-IoT-100 1.4.0 ships systemic weak-by-default hygiene failures across components" |
| `function` node enrichments | 3 | `check_login`, `print_crypto_profile`, `config_mac` (summaries + `is_sink`; merged onto recon-promoted nodes) |
| `supports` evidence edges | 3 | each finding → the hypothesis (drove its status `open → supported`) |
| `instance_of_pattern` edges | 4 | each finding → the YARA `pattern` node(s) it instantiates |

The hypothesis is the synthesis the brief asked for: it ties the three independent findings (spanning two binaries) into one supply-chain narrative, and is now `supported` by all three.

---

## (c) Determinism check (before / after)

| Metric | Pre-sweep | After sweep #1 | After sweep #2 (re-run) |
|--------|-----------|----------------|--------------------------|
| `pattern` nodes | 0 | 4 | **4** (same IDs) |
| `matches_rule` edges | 0 | 8 | **8** |
| `yara_matches` Observations | 0 | 1 per target | **same rows reused** (id `35c0a30a…`, identical `created_at`) |

Re-running `re_yara_sweep` returned an **identical** payload (`promoted_count=8`, same four `pattern_node_id`s). `obs_list(kind='yara_matches')` still showed a single Observation with the original timestamp — the call hit the content-hash–scoped store, not a re-scan. Spot-checking the DES pattern's edges showed exactly **2** `matches_rule` edges (root + kvstore), not 4 — the second sweep **merged into existing nodes/edges** rather than appending. No duplicate classification nodes or edges were created. (No live/network testing was performed, so there was nothing to audit in `net_list_egress`.)

---

## Tool-experience assessment (UX — first-class deliverable)

### What worked well
- **`re_yara_sweep` is the star of this task.** One call did the whole corpus (every byte-target *and* every extracted file), and the return value is genuinely actionable on its own: per-file, per-rule, with category + declared severity + CVE. It turned a flat strings dump into a triaged worklist. For a "scan the whole image for known-bad" objective this is exactly the right altitude.
- **The auto-population is clean and honest.** Deduping one `pattern` per rule across the corpus (so one node, many `matches_rule` edges) is the right model — it makes "this rule hit N places" a graph query instead of N redundant nodes. And it deliberately stops short of minting findings, leaving severity judgement to me. The repeated reminders that it "never fabricates a severity / never auto-mints a finding" matched the actual behaviour.
- **Determinism is real and observable.** Same Observation id + timestamp on re-run, no duplicate nodes/edges. The content-hash–scoped Observation store made the cheap-before-expensive discipline trivial — I could see at a glance that a re-run was free.
- **Provenance is bidirectional and complete.** Pattern node → `provenance:[observation_id]`, Observation → `node_refs:[pattern…]`, edge `attrs.observation_id` + `namespace`. I never had to guess where a classification came from; every finding could cite the exact rule + Observation that produced it.
- **Decompilation grounding was frictionless.** `re_decompile_function` by name across both binaries in one batch; the radare2 output's inline annotations (`obj.DEFAULT_LOGIN // "admin:admin"`) made confirming each YARA hit a few seconds of reading. The `*31` non-crypto MAC in `config_mac` was visible right in the pseudocode.

### Awkward / surprising
- **`graph_create_edge` parameter is `type`, not `edge_type`.** Every other create-call in the surface (`graph_create_node` uses `node_type`, `finding_record` uses `finding_type`) namespaces the type with the object prefix, so I reflexively passed `edge_type` and got a hard validation error on all four edges before correcting. A tiny inconsistency, but it cost a round-trip. Either accepting `edge_type` as an alias or renaming to `edge_type` for symmetry would remove the foot-gun.
- **The recon-auto string nodes are noisy.** At ingest the graph is pre-seeded with dozens of `string` nodes including pure junk (`PTE1`, `\{lS`, `q8J|`, `#NM_`). That's the *substrate*, fine in principle, but it means `graph_list_nodes` on a fresh project is mostly noise you scroll past to find the 4 patterns. A `node_type` filter exists (I used it) and is the right escape hatch — but a default view that de-emphasises raw recon strings would help.
- **Severity wording is split between the rule and the analyst.** The YARA rules declare e.g. `hexgraph_default_admin_creds` = *medium* and the DES/MD5 rules = *low*, but as exploitable findings I rated default-creds and broken-crypto **high**. That divergence is correct (a rule's declared severity is a generic prior; my finding severity is context-aware), and the docs are explicit that the sweep won't fabricate a finding severity — but it's worth flagging that an analyst should expect to *raise* severity off the rule prior, not take it at face value.

### Expected but did not get / reached for and missing
- **No "outdated bundled service" version-aware rule beyond a banner regex.** `hexgraph_dropbear_old_banner` keys on the version string and cites one CVE; I'd have liked the rule to encode the *range* (≤2015.71 → CVE-2016-7406/7407/7408/7409) so the finding's CVE list came from the matcher rather than my own knowledge. As-is, the "outdated service" arm of the triage leans on the analyst to know the CVE history. A CPE/version-range ruleset (or an SBOM-style component extractor) would make this arm as turnkey as the creds/crypto arms.
- **No one-call "promote this YARA hit to a finding."** The flow is deliberately two-step (sweep classifies → analyst mints a finding), which I agree with for severity reasons. But for a pure-hygiene sweep where the analyst *does* want a finding per hit, a `finding_from_pattern(pattern_node_id, severity)` helper would cut the hand-authoring of three near-boilerplate findings. Minor; the manual path is fine and keeps me honest.
- **`etc/banner` confirmed the model/version but isn't wired into the graph.** I read it via `fs_read_file` and used it for context (VG-IoT-100 / 1.4.0), but there's no natural node type for "a non-credential config file fact." It lives only in this report and the finding prose. Not a gap that blocked anything, just an observation that file-level facts have no first-class home unless they're a credential/key.

### Bottom line
For a corpus-wide weak-defaults triage, the intended workflow held up cleanly: **baseline strings show the bytes but not their meaning → `re_yara_sweep` classifies them across the whole image and tells you which file → decompile to ground each → promote findings + a unifying hypothesis, all with deterministic, deduped, fully-provenanced auto-population underneath.** The single rough edge was the `graph_create_edge` `type` parameter naming; everything else was smooth and the determinism guarantees were verifiable, not just claimed.


---


# Challenge D — full agent writeup

# VR Eval D — `licensegate` (HexGraph Phase-5 tool eval)

**Target:** `tests/fixtures/phase5_tool_eval/licensegate` — x86-64 ELF, NX, no PIE, no canary, partial RELRO.
**Project:** `81801ba1-d857-4593-8b03-96a094e06ccb` · **Target id:** `a4dbec45-de6c-4299-ad32-888a7990da72`
**Date:** 2026-06-06

---

## (a) Is the check satisfiable? Yes — and here is the serial.

**Verdict: SATISFIABLE.** The license gate accepts an 8-byte serial and the privileged action is reachable.

**Recovered serial (8 bytes):**
- hex: `3b 25 06 5c 4b 20 04 0f`
- repr: `;` `%` `0x06` `\` `K` `0x20`(space) `0x04` `0x0f`

It contains **non-printable bytes (0x06, 0x04, 0x0f)** — which is exactly why no amount of string/constant inspection could reveal it, and why a guess can't hit it. It is *computed* by the check, not stored.

### Which tool produced it
`re_solve_reaching_input(target, sink_func="system", function="main", budget="default")` — **angr 9.2.221** symbolic execution in the dedicated angr sandbox image. It solved in **0.85 s / 59 steps** (`input_model: argv`) and reached the `system` call site. Returned `solved: true` with the concrete input and auto-minted the finding `1ad14cd5-0ce8-44f7-ad29-29874a0caded` (assurance **input_reachable / static**), whose `evidence.reproducer` carries the solved input.

> Note on the raw return: the solver's `concrete_input` is the full 25-byte argv buffer (`3b25065c4b20040f` + trailing **unconstrained** filler). Only the **first 8 bytes** are meaningful — the constraints touch `s[0..4]` and `rolling_sum` reads exactly 8 bytes (`esi=8`). I cross-checked against the decompilation to isolate the 8 real bytes.

### The check, reconstructed (from `re_decompile_function check_serial` / `rolling_sum`)
On the 8 serial bytes `s[0..7]`, **all four** must hold:
1. `7*s[0] + s[1] == 450`           → `7*0x3b + 0x25 = 413+37 = 450` ✓
2. `s[2] ^ s[3] == 0x5a`            → `0x06 ^ 0x5c = 0x5a` ✓
3. `s[4] | 0x20 == 0x6b` (`s[4]` ∈ {`K`,`k`}) → `0x4b | 0x20 = 0x6b` ✓
4. `rolling_sum`: `Σ_{i=0..7} s[i]*(i+1) == 1234`
   → `1·0x3b + 2·0x25 + 3·0x06 + 4·0x5c + 5·0x4b + 6·0x20 + 7·0x04 + 8·0x0f = 1234` ✓

All four verified arithmetically; angr's SMT solution agrees.

### The path it unlocks (`path_addrs` from the solver)
`main (0x401268)` → length gate → `check_serial (0x4011e5)` → 4 constraint blocks (`0x401206`, `0x401229`, `0x401242`) → `rolling_sum (0x401176)` loop ×8 → `eax=1` (`0x401261`) → `main` success block (`0x4012dd`): `puts("License valid.")` → **`system("/bin/grant_admin")`** (PLT `0x401060`, sink reached at `0x401080`).
Confirmed by `re_xrefs system`: the only caller is `main @ 0x4012f6`.

### The baseline pass revealed nothing (the control)
- `target_facts` / `re_imports`: exports `check_serial`, `rolling_sum`; dangerous import `system`. (Good for orientation, no serial.)
- `re_list_strings`: `/bin/grant_admin`, `usage: licensegate <serial>`, `Access denied`, `License valid.` — **no valid serial, and no constant equal to it.** The magic numbers that exist (450, 0x5a, 0x6b, 1234) are *constraint operands*, not the answer; the serial only emerges from solving the system of constraints. This is the proof that a deeper tool (symbolic execution) was necessary.

---

## (b) The graph I populated — auto vs. manual

### Baseline (before any of my analysis)
- Nodes: **28** recon-prematerialized (5 symbols incl. `system` already tagged `is_sink=true`, 20 strings, 3 functions with prototypes/addresses=null).
- Findings: **1** (auto recon "Attack-surface summary", `finding_type=recon`).
- Solver Observations: **0**.

### Deterministic AUTO-population by `re_solve_reaching_input` (I did NOT mint these)
- **+1 finding** — `vulnerability` `1ad14cd5…` "Solver-reachable sink: system…", severity high, **assurance input_reachable/static**, `evidence.reproducer` = solved input, `evidence.extra.solver` = full `path_addrs` + provenance (angr version, steps, elapsed, observation_id).
- **+1 `calls` edge** `main → system`, attrs `{by: "angr-solver", observation_id: 55bcaea6…}` (the grounded path).
- **+1 `about` edge** finding → `main` (role `primary`).
- **+0 new nodes** — it correctly *reused* the existing `system` symbol (`is_sink=true`) instead of minting a redundant `sink` node, and the existing `main` node.
- **+1 `solver` Observation** `55bcaea6…` (payload in CAS, content-hash scoped to the bytes).

### My DELIBERATE manual promotions
- **+1 hypothesis node** `c4a36372…` ("the gate is satisfiable…") — created *before* the solve; driven to status **supported** afterward via `graph_link_evidence(confirms)`.
- **+1 `input` node** `dec8d727…` "argv[1] serial" — `source`, `trust=untrusted`, and the recovered serial (`3b25065c4b20040f`) recorded on it.
- **Enriched (merged, not duplicated) 3 function nodes** `main` / `check_serial` / `rolling_sum` — added `address`, `summary`, `params`, and the 4-constraint list to `check_serial`. (`graph_create_node` merged into the recon-prematerialized nodes — no duplicates.)
- **+2 `taints` edges** — `input → system` (the source→sink dataflow, with via_param describing the gate) and `input → check_serial` (validation site).
- **+1 annotation** (`note`, status `proposed`) on `check_serial` recording the full gating constraint + the satisfying serial, with provenance back to obs `55bcaea6`.
- **+1 evidence link** (hypothesis ← finding, `confirms`).

### Net counts after everything
Findings **2** (1 recon + 1 solver vuln) · input nodes **1** · solver Observations **1**.

### (Determinism check, step 6)
Re-ran the identical `re_solve_reaching_input` call:
- `cached: true`, **same** `observation_id 55bcaea6…`, **`finding_id: null`** — with the explicit note *"this solve was already recorded… no duplicate finding was created."*
- `obs_list(kind=solver)` still **count=1**; `finding_list` still **2**; input nodes still **1**.

**Before → after the re-run: zero new findings, zero new nodes, zero new edges.** Idempotency holds (content-hash–scoped Observation reuse).

---

## (c) Tool-experience assessment (candid)

### What worked well
- **`re_solve_reaching_input` is the headline and it delivers.** One call with a sink selector, no angr script, solved in under a second, and it *auto-grounded the result into the graph*: the finding carries the reproducer + full `path_addrs`, and the `calls main→system` edge is tagged `by: angr-solver` with the `observation_id`. This is the "you direct, HexGraph runs it" promise actually realized.
- **Determinism / caching is genuinely well designed and *legible*.** The re-run didn't just silently dedup — it told me `cached:true`, returned `finding_id:null`, and printed *why* ("no duplicate finding was created"). That explicit feedback is exactly what you want for an idempotent analysis store. The content-hash scoping (same bytes → same Observation) is the right model.
- **Provenance is bidirectional and real.** Finding `evidence.extra.solver.observation_id` ↔ the `solver` Observation; the auto-edge carries the same id. I could trace any claim back to the tool run.
- **Node-merge semantics are clean.** `graph_create_node` on the recon-prematerialized `main`/`check_serial`/`rolling_sum` *merged* (filled address, unioned my summary/constraints) instead of creating duplicates — so enriching is safe and I didn't have to look up node ids first.
- **Orientation was fast.** `target_facts` immediately surfaced `check_serial`/`rolling_sum` exports and `dangerous_imports=[system]`; `re_xrefs system` pinned the single sink caller. The decompiler annotations ("callees not yet in the graph — promote any by decompiling it") nudge you toward the right promotion discipline.

### Awkward / surprising
- **The solved input is the whole argv buffer, with no "which bytes matter" hint.** `concrete_input` came back as 25 bytes (8 real + 17 unconstrained filler). Nothing in the result says only the first 8 are constrained — I had to read the decompilation (`rolling_sum n=8`, constraints on `s[0..4]`) to know that. The **`reproducer` stored on the finding is the 25-byte buffer**, so a human copying it as "the serial" would get a superset. A `constrained_len` / `minimal_input` field (or trimming trailing unconstrained bytes) would remove a real foot-gun.
- **radare2's `main` decompilation of the length gate is confusing/borderline wrong-looking.** `v = strlen-7; if((unsigned)v > 0) goto check_serial` actually only rejects `strlen==7` and lets everything else through — an odd gate that took a second read to trust. The pseudo-C also keeps raw register ops (`eax <<<= 3`), so I reconstructed all four constraints by hand. Workable, but Ghidra would have made constraint extraction faster; the decompiler is operator-fixed (`active: radare2`) with no agent toggle, which is the documented behavior but worth noting for a constraint-heavy target.
- **Calling this a "vulnerability" (category `other`) is a framing stretch.** The gate works as designed; the real finding is "the license check is *crackable* — a satisfying serial exists." Fine for the eval, but a triager would likely reclassify. A `finding_type`/category like "weak-gate" or "logic" would fit better.

### Expected-but-didn't-get / reached-for-and-missing
- **No byte-faithful dynamic verification path for an argv reproducer.** To climb `input_reachable/static` → `code_present/dynamic` (lab-confirmed) I'd run the binary with the solved serial and oracle on `"License valid."`. But `finding_verify_poc` is `features.poc`-gated **and** (per the skill) text-mangles stdin/argv — risky for an argv containing `0x06/0x04/0x0f`, which could yield a misleading false-negative. `fuzz_verify_artifact` *does* replay raw bytes faithfully, but that's for fuzz crash artifacts, not solver reproducers. **The one real gap:** a byte-faithful "verify this solved argv input" handoff so the solver's raw-byte reproducer can be confirmed end-to-end without hand-massaging. (I deliberately did **not** attempt `finding_verify_poc` here to avoid recording a false-negative; documented as the recommended next step instead.)
- **`finding_reachability` was unnecessary** — the solver already lands at `input_reachable/static`, so the taint path I built (`input → system`) is corroborating rather than upgrading. Not a gap; noting I correctly didn't need it.
- I expected an optional **printable-serial preference or a "non-printable bytes present" flag** on the solve; it returns raw bytes only (correct behavior, minor usability note — tie-in with the "which bytes matter" point above).

### Bottom line
The deep tool (angr via `re_solve_reaching_input`) recovered a computed, non-printable serial that the entire baseline pass provably could not, grounded it into the graph with full provenance, and the re-run proved the store is idempotent. The workflow felt purpose-built for exactly this "solve for the computed input" task. The single thing I'd add is a byte-faithful dynamic-verify path for a solver-produced argv reproducer, plus a hint distinguishing constrained from filler bytes in the solved input.


---


# Appendix: the stale-image (FLOSS/YARA dead) first runs

These two runs ran against the pre-toolchain sandbox image; the intended tools errored and the agent fell back to manual analysis. Retained as the source of the tool-robustness findings above.

# HexGraph VR Eval — `stringcrypt.exe` (Mitis Relay Agent)

**Target:** `tests/fixtures/phase5_tool_eval/stringcrypt.exe` (PE32+ / x86-64 Windows agent)
**Project:** `3fa4cb7b-5c96-4aba-9636-8dfa2a7ac303` · **Target id:** `07a5782b-740f-4b3f-af76-f4da0f2bb71c`
**Objective:** recover IOCs (C2 endpoints, keys, credentials) and the routine that builds them.

---

## (a) What I found, and which tool surfaced it — vs. the baseline control

### The baseline strings pass (the control) — productive-looking, but all decoys
`re_list_strings` returned **40 strings, none of them an IOC**: only mingw/PE-runtime
boilerplate — `GetLastError`, `GetStartupInfoA`, `TlsGetValue`, `__getmainargs`,
`!This program cannot be run in DOS mode.`, the section names (`.text`/`.rdata`/`.idata`/…),
the pseudo-relocation runtime template, and register-spill fragments (`ATUWVSH`, `T$ H`).
**No URL, no host, no key, no credential appears as a contiguous literal.** `target_facts`
and `re_imports` even came back *empty* (recon did not parse the PE import table). So a
surface dump looks busy and tells an IR analyst nothing — exactly the trap the brief described.

### The real IOCs — built at runtime, recovered by reading the constructor routines
The intended "deeper" tool here is **`re_floss_strings` (FLARE FLOSS)**, which emulates the
string-construction/decoding routines. **It is not installed in this sandbox** (`floss: No such
file or directory`), so I fell back to **`re_decompile_function` (radare2)** and read the
builders directly. That worked cleanly for the stack-built string:

**IOC #1 — C2 beacon endpoint (fully recovered, high confidence):**
```
http://relay.mitis-labs.net/ingest
```
- Built byte-by-byte on the stack in **`fcn.140001594`** — 35 individual `mov byte[buf+i], imm8`
  stores (`0x68 'h'`, `0x74 't'`, … `'/ingest'`, `0x00`). radare2 even resolved the assembled
  constant in the epilogue as `"http://relay.mitis-labs.net/ingest"`. Never a contiguous literal,
  which is why the strings pass missed it.
- Invoked by the orchestrator **`fcn.1400018b0`** at `0x1400018f1`, right after `puts("Mitis Relay Agent")`.

**IOC #2 — XOR-0x5A obfuscated embedded secret (mechanism fully recovered; cleartext blocked):**
- **`fcn.140001530`** is a single-byte XOR decoder: `out[i] = in[i] ^ 0x5A`, NUL-terminated.
- **`fcn.1400018b0` @ `0x1400018e5`** calls it with `src = .rdata:0x140004000`, `len = 15`,
  `dst = stack buffer`. `re_data_xrefs(0x140004000)` confirms that blob is referenced **only**
  from `fcn.1400018b0 @ 0x1400018db`. By construction this is a second hidden IOC — almost
  certainly the **API key / credential** the agent uses to authenticate its beacon (it is decoded
  next to the C2 URL and XOR-folded together with it into a checksum byte at `0x140007040`).
- **The 15-byte cleartext could not be dumped with the available toolset** (see §c). I recorded
  the decoder, key (`0x5A`), source address, length, and consumer — everything except the
  plaintext, which needs a working FLOSS or emulation tier.

**The pivot routine:** `fcn.1400018b0` ("Mitis Relay Agent" init) is the single function that
produces both indicators — print banner → XOR-decode the secret → assemble the C2 URL → fold →
print `OK`. That is the routine an analyst should pivot from.

---

## (b) The graph I populated — tool auto-population vs. my manual promotions

### Auto-populated by the tools (I minted nothing here)
- **~19 `string` nodes** materialised by **recon at ingest** — the boilerplate decoys above.
- **4 `function` nodes** auto-promoted by my **`re_decompile_function` queries**
  (`fcn.140001180`, `fcn.140001530`, `fcn.140001594`, `fcn.1400018b0`), each enriched in place
  with prototype / locals / `calling_convention` / `provenance=[observation_id]`. Decompiling a
  function promotes *that* function only — no callee fan-out, exactly as documented.
- **1 spurious `function` node** (`0x140004000`) auto-created by my **`re_decompile_at` on the
  data address** — a real artifact: the tool promoted a "function" for a `.rdata` data location.
  I **archived it** (`graph_archive_node`) as my own error.
- **5 `decompilation` Observations + 1 `strings` Observation + xrefs/data_xrefs** in the durable
  Observation store (the substrate), reused on re-query.

### Manually promoted by me (deliberate curation)
- **2 findings** (`finding_type=recon`):
  - `56af9216…` — *Hidden C2 beacon endpoint built at runtime* (high / high).
  - `a8a488a2…` — *XOR-0x5A obfuscated embedded secret (15 bytes) at .rdata:0x140004000* (medium / medium).
- **2 new `string` nodes**: the C2 URL IOC (`1f044006…`) and a placeholder for the XOR secret
  (`05ba7362…`, value flagged `cleartext UNRECOVERED`).
- **3 function summaries** merged onto the auto-promoted nodes (`fcn.1400018b0` / `594` / `530`) —
  enrichment of existing nodes, not new nodes. (Confirmed merge-by-(target,name): same node ids returned.)
- **1 `hypothesis` node** (`af9551d8…`): "the XOR blob decodes to the beacon's API key/credential" —
  driven to **`supported`** by linking finding `a8a488a2` via `graph_link_evidence`.
- **6 edges**: `fcn.1400018b0 —calls→ fcn.140001530` (call_sites `0x1400018e5`, arg_constraints
  src/len), `fcn.1400018b0 —calls→ fcn.140001594` (`0x1400018f1`),
  `fcn.140001594 —writes→ C2-URL string`, `fcn.140001530 —reads→ XOR-secret string` (`.rdata:0x140004000`),
  and 2 `about` edges (finding → its pivot function).

**Final active graph:** 4 function + 21 string (19 decoy + 2 IOC) + 1 hypothesis = **26 nodes**, **6 agent edges**, **2 findings**.

### Determinism check (before/after)
Re-ran `re_decompile_function(fcn.140001594)`:
- Output **byte-identical**.
- `decompilation` Observation count **5 → 5** — the existing observation `0e51ff6d` (ts `20:48:03`)
  was **reused, not re-created** (cache hit, scoped by content_hash).
- Function-node count **4 → 4** — **no duplicate promoted.**

Re-running a heavy analysis against identical bytes is idempotent: no new Observation, no new node.

---

## (c) Tool-experience assessment (UX feedback — first-class deliverable)

### What worked well
- **The Observation store / cache is excellent.** Heavy decompiles persist, `obs_get` returns the
  full payload (I pulled the complete URL from the cached `fcn.140001594` decompilation rather than
  re-running), and re-running is a transparent cache hit. The substrate-vs-graph split is the right
  model and held up in practice.
- **Auto-promotion on decompile + merge-by-name is smooth.** Querying built up the function inventory
  for me; my later `graph_create_node` calls *merged* summaries onto those nodes instead of
  duplicating — exactly what you want, and the returned node confirmed what landed.
- **radare2 resolving the assembled stack-string** to `"http://relay.mitis-labs.net/ingest"` in the
  function epilogue was a genuinely delightful surprise — it turned a 35-store byte soup into the
  answer directly.
- **`re_data_xrefs` on the raw address** cleanly confirmed the encoded blob's single consumer.
- **Schema-first (`meta_get_schemas`)** made findings/nodes/edges unambiguous — the sink-vs-symbol
  rule, `evidence.extra` free-form, edge attribute schemas. I never had to guess a field.
- **Honest gating messages.** `re_recover_constant` told me *exactly* which feature to enable.

### What was awkward, surprising, or missing
1. **FLOSS — the single most appropriate tool for this exact task — is not installed.**
   `re_floss_strings` is advertised (feature on) but the sandbox image lacks the `floss` binary, so it
   fails at runtime with a raw `[Errno 2] ... 'floss'`. This is the headline gap: the brief is
   practically a FLOSS test case (stack strings + a decode routine), and the intended path is dead.
   Two asks: (a) **fix the image / fail more gracefully** — if the feature is advertised, the binary
   should be present, or the error should say "FLOSS not installed in this image" rather than a bare
   errno; (b) it would have recovered *both* IOCs in one call, including the XOR plaintext I couldn't get.
2. **No raw-byte / hexdump verb.** Once I had the decoder (`out=in^0x5A`), the source address
   (`.rdata:0x140004000`), and the length (15), I was *one `read 15 bytes` away* from the secret —
   I could have XOR'd them myself. But there is no tool to read N bytes at an address.
   `re_disassemble` is function-indexed and rejects a data address; `re_decompile_at` on data returns
   an empty body (and pollutes the graph with a bogus function node). **A `re_read_bytes(address, len)`
   verb would have fully closed this case** and is the single highest-value addition I'd request.
3. **`re_recover_constant` is the natural fallback but is gated off** (`features.emulation`), and it
   also requires *Ghidra*, while the active decompiler here is radare2 — so even toggling the feature
   may not help in this image. For a parameterless self-contained decoder it would be perfect; for
   this one it takes args anyway, so it likely wouldn't have reached a clean `ret`. Net: no usable
   emulation path to the 15 bytes.
4. **`re_binutils_facts` is ELF-only** and fails on a PE with `not an ELF binary`. Reasonable, but it
   means on a Windows PE I lose the "authoritative sections + symbol table + mitigations" orientation
   the skill recommends as the *first* move. `target_facts`/`re_imports` *also* returned empty on this
   PE (no imports/sections parsed at all), so PE recon overall was notably thinner than the ELF story —
   I had zero import/section/mitigation facts to orient from and had to go straight to decompilation.
5. **`re_decompile_at` on a data address silently promotes a junk `function` node.** Minor, but it
   means an exploratory "what's at this address?" query mutates the curated graph with a mistyped node
   the analyst must clean up. Decompiling a non-code address should no-op (or warn) rather than mint a node.
6. **Finding taxonomy has no "IOC" / "malware-config" type.** For a C2 endpoint and an embedded
   credential I used `finding_type=recon` + `category=hardcoded-secret`, which is serviceable but not a
   clean fit — these are threat-intel indicators, not a code vuln and not generic recon. A `category`
   or `finding_type` for IOCs/malware config would model this engagement class better. Likewise the
   `socket`/`endpoint` node types are oriented to *listening* services; there's no natural node for an
   *outbound* C2 endpoint, so I modeled the URL as a `string` IOC (which is fine, but a first-class
   "indicator" node would be nicer for IR triage).

### Bottom line
The objective is met on the primary indicator: **`http://relay.mitis-labs.net/ingest`**, plus the full
builder/decoder/orchestrator routines, all tool-grounded and recorded in the graph. The secondary
indicator (the XOR-0x5A credential) is fully *characterized* but its cleartext is **unrecoverable in
this environment** because the three tools that could have produced it — FLOSS, emulation, and a
raw-byte read — are respectively uninstalled, gated/Ghidra-only, and nonexistent. That gap, not the
binary, is what stopped me one step short.
# HexGraph VR Eval — Phase 5, Scenario C
## Supply-chain / weak-defaults hygiene triage of `vantage_iot_fw.bin`

**Target:** `tests/fixtures/phase5_tool_eval/vantage_iot_fw.bin` — Vantage IoT Gateway VG-IoT-100, firmware 1.4.0 (per `etc/banner`).
**Project:** `7294b6a8-bcfb-49c1-b27e-36649ff605c5`
**Date:** 2026-06-06
**Backend:** mock (zero token spend)

---

## (a) What I found, across which files — and which tool surfaced it

### The corpus
`target_ingest` unpacked the squashfs image (`method: sasquatch`) into a small filesystem and auto-registered **two child ELF targets** plus one config file:

| File | Target id | Kind |
|---|---|---|
| `usr/sbin/logsvc` | `0b124c61…` | x86-64 ELF (16 200 B) |
| `usr/bin/kvstore` | `88e63d3d…` | x86-64 ELF (16 080 B) |
| `etc/banner` | — | text (firmware version string) |

The objective's signal is genuinely **spread across both executables** — neither file alone tells the whole story.

### The leads (each grounded in tool output, not a guess)

**1. logsvc — hardcoded default/factory credential `admin:admin`** (finding `364dbcae`, severity high)
Not just a suspicious string: `re_decompile_function check_login` shows the code path explicitly —
`obj.DEFAULT_LOGIN @0x404040 → "admin:admin"`, loaded into `rsi`, then `strcmp(arg1, "admin:admin")`; a match falls through to `puts("login ok (default credential)")`. Supporting strings in the same binary: `admin:admin`, `login ok (default credential)`, `hint: factory login is %s`, `usage: %s user:pass`, symbol `DEFAULT_LOGIN`. CWE-798 / CWE-1392.

**2. kvstore — deprecated/broken cryptography (DES-CBC + MD5 MAC)** (finding `8908bfc4`, severity high)
`re_decompile_function print_crypto_profile` shows the shipped "factory-defaults" crypto profile is `cipher = DES-CBC` (`CIPHER @0x404020`) and `mac = MD5_Init` (`CONFIG_MAC @0x404028`). DES-CBC is a withdrawn 56-bit cipher; MD5 is collision-broken and a bare hash is not a MAC. **Worse:** `re_decompile_function config_mac` reveals the routine labeled "MD5_Init" is actually a trivial **djb2 rolling hash** (`h = h*33 + byte` over key then value) — a non-cryptographic 32-bit checksum, so the `sealed with %s` integrity tag is forgeable. CWE-327 / CWE-328.

**3. logsvc — outdated bundled service banners (Dropbear sshd v2015.67, micro-httpd)** (finding `d42bd970`, severity medium)
Strings `ssh: Dropbear sshd v2015.67` and `http: micro-httpd`. Dropbear 2015.67 is a 2015-era build predating fixes for e.g. CVE-2016-7406/7407/7408 and CVE-2017-9078; micro-httpd is long unmaintained. **Honest caveat recorded in the finding:** these are version *banners embedded in logsvc* — the standalone dropbear/httpd binaries are not present in this extracted rootfs — so this is an advertised-version hygiene lead, not a confirmed running-service vuln. CWE-1104 / CWE-1395.

### Which tool surfaced/classified the leads vs. the baseline that did NOT

- **The baseline per-file pass (`re_list_strings`, `re_binutils_facts`) genuinely DID contain every signal** — `admin:admin`, `DES-CBC`, `MD5_Init`, `Dropbear sshd v2015.67` all appear in the raw string dumps. But exactly as the brief predicted, **they are unclassified noise to the eye**: each sits in a flat ~40-line list interleaved with `/lib64/ld-linux…`, `GLIBC_2.34`, `__do_global_dtors_aux`, GCC build tags, etc. Nothing ranks them, tags them "weak-default / weak-crypto / outdated-service", or tells you they cluster into one supply-chain story across two files. A casual reader skims past them.
- **The tool that was *supposed* to classify them corpus-wide — `re_yara_sweep` — is BROKEN in this sandbox** (see section (c)). So the classification step that should have been one tool call I had to perform *manually*: read the strings, recognize the known-bad indicators from domain knowledge, and confirm each in decompilation. `re_decompile_function` was the workhorse that turned "suspicious literal" into "grounded finding" (it proved `admin:admin` is an auth comparison and that the "MD5" MAC is really djb2 — something neither strings nor YARA would have told me).

---

## (b) The graph I populated — tool auto-population vs. my manual promotions

### Deterministic auto-population by the tools (NOT me)
- **Ingest/recon** registered: **2 child ELF targets**, **~64 `string` nodes** + **9 `symbol` (import) nodes** sampled across the three targets, the `contains` edges wiring them to their targets, and **3 `recon` findings** (`info`/`finding_type=recon`: "Attack-surface summary for …" — one per target).
- **`re_yara_sweep` auto-population: NONE.** `match_count=0, promoted_count=0` — **but because the probe errored, not because the image is clean.** No `pattern` nodes, no `matches_rule` edges were (or could be) created. This is precisely the auto-population step the eval expected to observe, and it did not occur.

### My deliberate promotions
- **3 `vulnerability` findings:** `364dbcae` (default cred), `8908bfc4` (weak crypto), `d42bd970` (outdated services). Each carries function/sink/strings/decompiled-snippet evidence, CWE list, and an explicit `assurance` triple (all `code_present/static` — honest floor; see (c)).
- **3 `function` nodes promoted via `re_decompile_function`:** `check_login` (logsvc), `config_mac` + `print_crypto_profile` (kvstore).
- **4 `string` nodes** promoted/enriched with analyst notes: `admin:admin`, `ssh: Dropbear sshd v2015.67`, `DES-CBC`, `MD5_Init`.
- **1 `hypothesis` node** tying the legs together: *"VG-IoT-100 fw 1.4.0 ships with known-weak factory defaults across MULTIPLE executables (default cred in logsvc + DES/MD5/djb2 crypto in kvstore + outdated Dropbear/micro-httpd banners) — a device-wide supply-chain hygiene failure, not a single-file issue."* Status auto-moved to **`supported`** once evidence was linked.
- **Edges I created:** 3 `supports` (each finding → hypothesis) + 4 `references` (function → the weak-default string it uses). (`finding_record` also auto-created the `about` edges from each finding to its primary function/target.)

### Counts (before/after the determinism re-run — identical)
| | Nodes | Edges | vuln findings | pattern nodes | matches_rule edges |
|---|---|---|---|---|---|
| After my promotions | 73 | 87 | 3 | 0 | 0 |
| After re-running list_strings + yara_sweep | **73** | **87** | 3 | 0 | 0 |

---

## (c) Tool-experience assessment (first-class deliverable)

### What worked well
- **`target_ingest` → child targets → `fs_list`** was a clean, obvious on-ramp. The firmware-as-a-corpus model (root image + child ELF targets + browsable `etc/banner`) matched the task perfectly, and `fs_list` flagging which files are ELFs / already child targets is exactly right.
- **`re_decompile_function` is excellent and was the hero tool here.** It promoted the function node, listed callees, and inlined the resolved string constants right in the pseudocode (`// "admin:admin"`, `CIPHER → "DES-CBC"`). It let me upgrade three string-level suspicions into code-grounded findings — and it caught the thing strings/YARA never could: the "MD5_Init" MAC is actually a djb2 hash.
- **Observation store + graph determinism is genuinely solid.** Re-running `re_list_strings` returned the same payload with **no new Observation** (still one `list_strings` obs, original timestamp), and re-running `re_yara_sweep` produced byte-identical output. The graph stayed at **73 nodes / 87 edges** with zero duplicate nodes or edges. The substrate-vs-graph separation (query freely, promote deliberately) is intuitive and the `node_refs`/`provenance` back-links are a nice touch.
- **`finding_record` ergonomics** are good: rich `evidence.extra` free-form object, separate `finding_type` arg, and it auto-wires `about` edges so the finding isn't an orphan. `graph_create_hypothesis` + `graph_link_evidence` auto-recomputing the hypothesis to `supported` felt right.

### What was broken / surprising
- **🔴 The designated tool for this objective is non-functional in this sandbox.** `re_yara_sweep` (and by extension `re_yara_scan`) fail on **every** file with `YARA scan failed: probe yara_probe.py failed (exit 1): ModuleNotFoundError: No module named 'yara'`. The feature gate is on (the probe runs), but the `yara`/`yara-python` runtime dependency is **missing from the sandbox image**. This is the exact tool the brief steers you toward for "classify known-bad indicators across the entire image and tell which files matched," and it does nothing. **This is the single biggest finding of the eval from a tooling standpoint.**
- **🔴 The failure mode is dangerously silent-looking.** The top-level result reads `{"scanned": 6, "match_count": 0, "promoted_count": 0, "hits": []}` — which at a glance looks identical to a **successful clean scan** ("we checked 6 files, found no known-bad patterns"). You only learn it scanned *nothing* by reading the `errors[]` array. A triage tool that can't distinguish "clean" from "didn't run" will produce false all-clear. Unlike FLOSS (which the skill says degrades to a static-strings pass on ELF), **YARA has no graceful degradation** — it just errors per file. At minimum the summary should surface `scanned_ok` vs `errored` counts, or refuse to report `match_count: 0` when every file errored.
- **Minor: `graph_create_edge` parameter name.** The schema advertises the vocabulary under the key **`edge_types`**, so I reasonably passed `edge_type=…` and got `'type' is a required property`. The param is `type`. Small, but the schema naming actively misleads toward the wrong param name.

### What I expected but didn't get / reached for and couldn't find
- **A feature-health preflight beyond the decompiler.** `meta_check_decompiler` exists and is great — but there's no `meta_check_features` / availability probe for YARA, FLOSS, angr, emulation. I'd have liked to learn YARA was broken *before* spending a sweep against it, the same way I can verify the decompiler is live. Given optional features can be "enabled but missing their runtime dep," a health check that distinguishes *gated-off* from *configured-but-broken* would prevent the silent-zero trap above.
- **A first-class "weak-defaults / hygiene" classifier independent of YARA.** The whole objective is a known taxonomy (default creds, deprecated ciphers/hashes, outdated service banners). With the one classifier tool down, I had to be the classifier by hand. A lightweight rule pass that doesn't depend on the `yara` native module — even just a curated string/banner ruleset run in-process — would have met this objective directly and survived the missing dependency.
- **A version→CVE banner matcher.** For "outdated bundled service versions with a track record of vulnerabilities," I supplied the Dropbear-2015.67 CVE context from my own knowledge. A tool that maps a recovered version banner to known CVEs (offline DB) would make that lead reproducible and analyst-verifiable rather than dependent on the agent's memory.
- **YARA scanning the firmware *image* itself errored too**, so even a whole-image signature pass (packers, embedded keys in non-ELF regions) was unavailable — worth noting the outage is total, not just per-ELF.

### Net
The objective was **met** — three grounded, corpus-spanning weak-default leads (default credential in logsvc; DES/MD5/djb2 crypto in kvstore; outdated Dropbear/micro-httpd banners) plus a connecting supply-chain hypothesis, all promoted into the graph with provenance — **but it was met *in spite of* the intended tool, not because of it.** `re_yara_sweep` being dead forced a manual classify-from-strings-then-confirm-in-decompiler workflow. Decompilation and the Observation/graph determinism were the bright spots; the broken-but-silent YARA path is the headline risk. All findings are honestly floored at `code_present/static` (this is a static hygiene triage; no execution/rehost attempted) — the analyst should next confirm the production input paths (is logsvc's `check_login` reachable pre-auth on a live console/socket? does kvstore's sealed store gate anything attacker-facing?).
