# Phase 5 tooling — evaluation plan (binutils · FLOSS · YARA · angr)

**Status:** ready to run for binutils / FLOSS / YARA; the angr leg runs once Phase 5C-B (the angr probe + image) lands.
**Audience:** this file is the **orchestrator's** copy and contains **answer keys (spoilers)**. The VR agent is given only the per-challenge blind briefs in `BRIEFS.md` — never this file and never the challenge sources.

## 0. What this evaluates and why

Phase 5 added four external-tool capabilities, each behind its own MCP/agent verb. This plan proves, end to end, that each one (a) actually surfaces a real insight a researcher needs, (b) **deterministically auto-populates the graph** from tool usage alone (no LLM judgement), and (c) renders correctly and legibly in the web UI. It does that with two cooperating roles and a set of purpose-built targets:

- **Role A — the VR agent** performs real static RE against each target *through HexGraph's sandboxed tools* (the MCP driver surface), forced by the target's construction to use the specific tool under test, and records its insights in the typed graph — both the deterministic auto-population the tools do on their own and the deliberate promotions a researcher makes.
- **Role B — the simulated user** opens the web UI cold (Playwright) on the populated project and validates that every result is surfaced correctly, the graph is right, and the UI is readable, bug-free, and pleasant — scoring it against `docs/dev/ux-contract.md` the way the existing **`ux-assessment` skill** already does.

The targets are built so that **the planted insight is reachable only with the intended tool** — a plain `recon` / `strings` pass is not enough. And the VR agent works **only from the compiled binary and a blind brief**: it has no source, no answer key, and no CVE-recognizable identifiers, so a result is evidence the tool did the work, not that the agent guessed.

## 1. The tools under test and their **deterministic** graph effects

Each tool records an Observation and (where designed) auto-promotes graph structure with **zero LLM involvement**. That auto-population is the determinism contract this eval pins down: given the same bytes and the same tool call, the graph delta is identical and idempotent (a re-run dedups).

| Tool (verb) | Records | **Deterministic auto-population** (no LLM) | What the VR agent adds *manually* |
|---|---|---|---|
| `binutils_facts` | a `binutils_facts` Observation (symbols, imports/exports, relocations + jump-slots, sections, mitigations) | `is_sink=true` enrichment on any **dangerous import already a node**; the 5 **mitigation flags folded onto the target's `metadata_json`** | a `hypothesis` that the exec-stack + reachable `system` import is exploitable; promote the `system` import to a `symbol`/`sink` node |
| `floss_strings` | a `floss_strings` Observation (stack/tight/decoded/static strings) | none by design (results, not always-welcome facts) | promote the recovered C2 URL / credential to a `string` node + an `annotation` recording the decode routine as the lead |
| `yara_scan` / `yara_sweep` | a `yara_matches` Observation per artifact | **one `pattern` node per matched rule** (deduped across the project, carrying the rule's declared `severity`/`cve`) + a **`matches_rule` edge** from each matched target | a `finding` (type `recon`/`other`) citing a confirmed match; a `hypothesis` linking the weak-crypto + default-cred matches |
| angr (`solve_*`, **5C-B**) | a `solver` Observation (the recovered input / satisfying value + the path) | promotes the few grounded path nodes/edges + a high-confidence `vulnerability` `finding` **carrying the concrete reaching input** in the envelope | link the solved input to the sink; annotate the constraint that defined it |

**The determinism check is part of the eval:** after the VR agent runs a tool, re-running the same verb on the same target must (a) reuse the Observation (the `cached` flag flips true) and (b) create **no** duplicate `pattern`/`matches_rule`/enrichment — the graph delta on a second run is empty. This is asserted in Part 1 step 6 for every challenge.

## 2. The challenges — each forces exactly one tool

All are **x86-64** (so a future `verify_poc` runs natively) except the FLOSS target, which **must** be a Windows **PE32+** because FLOSS's stack/decoded-string emulation (vivisect) supports PE only — on ELF it degrades to a plain static-strings pass, which would *not* force the tool. Vendor/product names are fictional and version strings are scrubbed so nothing is solvable by CVE-recognition.

| Challenge | Forces | Format | Planted insight | Why a plain recon/strings pass is **not** enough (the catch) |
|---|---|---|---|---|
| `mitis_relayd` (`mitis_relayd.c`) | **binutils_facts** | ELF x86-64, `-z execstack` | An **executable stack** (NX off) and a reachable `system()` call | recon reports neither an exec-stack nor the full relocation/jump-slot map; the `system` import is **buried past recon's import cap** by ~80 benign imports. Only `binutils_facts` reports `nx=false` and the `system` jump-slot. |
| `stringcrypt.exe` (`stringcrypt.c`) | **floss_strings** | PE32+ x86-64 | A C2 URL and an API key, one **built byte-by-byte on the stack**, one **XOR-decoded at runtime** | a plain `strings` / `list_strings` shows only decoy plaintext; neither secret appears as a contiguous literal. Only `floss_strings` (stack + decoded recovery) yields `http://relay.mitis-labs.net/ingest` and the key. |
| `vantage_iot_fw.bin` (`logsvc.c` + `kvstore.c`) | **yara_scan / yara_sweep** | squashfs of two ELF x86-64 | A **default credential** (`admin:admin`), a **weak-crypto** marker (`DES-CBC`, `MD5_Init`), and a **known-bad library banner** (`Dropbear sshd v2015`) — spread across **two** binaries | the strings exist but are unclassified noise to a casual read; only a **`yara_sweep`** across the unpacked firmware promotes the three rule-graded `pattern` nodes (`embedded_credential`, `weak_crypto`, `known_bad_library`) and shows *which* files matched — the corpus-wide n-day lead. |
| `licensegate` (`licensegate.c`) | **angr** (5C-B) | ELF x86-64 | A serial/license check whose only-valid input is **computed**, not stored | the valid serial is defined **implicitly by arithmetic constraints** (`s[0]*7+s[1]==0x1c2`, `s[2]^s[3]==0x5a`, `(s[4]|0x20)=='k'`, a rolling checksum == `0x4d2`) gating a `system("/bin/grant_admin")` sink. `strings`/FLOSS show nothing; only **symbolic execution** solves for the satisfying input. |

## 3. Part 1 — VR agent: step-by-step RE actions

The VR agent is handed exactly one `BRIEFS.md` entry per target (no source, no spoilers) and drives HexGraph via the MCP driver tools (`agent/mcp_tools`). Enable the features under test first (`features.binutils` is always-on; `features.floss`, `features.yara`, and `features.angr` are opt-in — turn them on in Settings / `hexgraph config set`). For every challenge the agent runs the **same skeleton**, with the tool-specific step in bold:

**Per-challenge skeleton**
1. **Ingest** the target: `ingest_file <path>` (for the firmware, `ingest` then let recon unpack the squashfs into child targets).
2. **Baseline recon**: `target_facts` / `read_imports` / `list_strings`. *Record what the baseline does and does NOT reveal* — this is the control that proves the tool was necessary.
3. **Run the forced tool** (the step the target is built to require — details per challenge below).
4. **Observe the deterministic auto-population**: `list_observations(target_id)` shows the new Observation; `list_nodes` / `list_edges` show whatever the tool auto-promoted (per §1). The agent must NOT have to mint these — they appear from the tool call.
5. **Manually populate the insight**: create the deliberate graph the researcher would (`create_node` / `add_edge` / `create_finding` / `create_hypothesis` / `annotate`) per §1's "manual" column — grounding each in the tool's Observation (`provenance`).
6. **Determinism re-run**: call the same verb again; assert the Observation is `cached` and `list_nodes`/`list_edges` are unchanged (no duplicate promotion). Record the before/after counts.
7. **Assess the tool — for the report.** Capture, while it's fresh: what worked, what was awkward or surprising, what output you *expected* and didn't get, and anything you *reached for that didn't exist* (a missing verb, a missing field on a result, a graph element you wanted to create but couldn't, a confusing description). This tool-UX feedback is a first-class deliverable, not an afterthought — it is how we learn whether the tools are actually sufficient and pleasant to do real RE with.

**Challenge-specific step 3 (the forced tool):**

- **`mitis_relayd` → `binutils_facts(target_id)`.** The agent must conclude from the result that `mitigations.nx == false` (executable stack) and that `system` appears in `imports` / `jump_slot_imports` even though `read_imports` (recon, capped) omitted it. Step 5 manual: a `hypothesis` ("exec-stack + reachable system() ⇒ shellcode-on-stack / command-exec exploitable"), and confirm the auto `is_sink` enrichment landed on the `system` symbol if it was already a node (else promote it first, then re-run to see the enrichment).
- **`stringcrypt.exe` → `floss_strings(target_id)`.** The baseline `list_strings` shows only decoys (`"Mitis Relay Agent"`, `"OK"`). `floss_strings` must surface the **stack string** and the **decoded string** (the C2 URL `http://relay.mitis-labs.net/ingest` and the key). Step 5 manual: promote the URL to a `string` node + an `annotation` on the decode function as "C2 config builder — pivot here."
- **`vantage_iot_fw.bin` → `yara_sweep(project_id)`** (after recon unpacks it). The sweep must promote three `pattern` nodes — `embedded_credential` (from `admin:admin` in `logsvc`), `weak_crypto` (from `DES-CBC`/`MD5_Init` in `kvstore`), `known_bad_library` (from `Dropbear sshd v2015`) — each with the matched targets via `matches_rule`. Step 5 manual: a `recon` finding citing the default-cred match, and a `hypothesis` connecting the weak-crypto + default-cred into "shipped-with-known-weak-defaults."
- **`licensegate` → the solver (5C-B).** The agent identifies the check function (via `decompile`/`xrefs`), then asks the solver to **solve for an input that reaches the `system` sink** / satisfies the check. The solver returns the concrete serial; the auto-promoted `vulnerability` finding carries it. Step 5 manual: link the solved serial to the `system` call site and annotate the gating constraint.

**The VR agent's report (`reports/vr-agent-report.md`, produced at eval time).** When the challenges are done, the VR agent writes a report covering, per challenge: what it found and *which tool surfaced the lead* (alongside the baseline pass that did not); the graph it populated, **separating the deterministic auto-population from its manual promotions**; and its candid **tool-experience assessment** from step 7 — what worked, what didn't, what was missing or surprising, what it expected to exist and didn't. This experience write-up is half the point of the eval.

## 4. Part 2 — simulated user: step-by-step web-UI actions

Run via the **`ux-assessment` skill's two-role pattern**: Role A (above) has already populated the project; Role B opens the UI cold (Playwright, `p.chromium.launch(args=["--no-sandbox"])`, `wait_until="networkidle"`), walks `docs/dev/ux-contract.md` entry by entry, and additionally validates these Phase-5-specific surfaces. For each, the user (a) performs the action, (b) verifies the **backend effect** (the screenshot is evidence, not the check — confirm via the API/graph), and (c) scores **functional + readability + aesthetics + buginess** (1–5 each) and narrates the first-time experience.

1. **Targets pane** — the four challenges (and the firmware's unpacked children) are listed; `mitis_relayd` shows its **mitigation badges** (NX off / no canary / no PIE) sourced from the binutils metadata fold. *Validate:* the badges match the binutils Observation; the exec-stack is visually flagged as weak (not silently "ok").
2. **Detail panel → Observations / Tool Results tab** — each target's `binutils_facts` / `floss_strings` / `yara_matches` (and later `solver`) Observation is present, expandable, and its payload readable (no truncation that hides the lead; the recovered C2 URL and the matched rule names are visible). *Validate:* the Observation count and `result_kind`s match `list_observations`.
3. **Graph view** — the deterministic auto-population renders: the `pattern` nodes from YARA with `matches_rule` edges to the firmware children; `is_sink`-flagged symbols from binutils; the solver's `vulnerability` finding node (5C-B). *Validate:* node/edge counts and types match the graph API; the pattern nodes show the rule severity/category; edges are labeled `matches_rule`.
4. **Findings panel** — the promoted findings appear with the **correct `finding_type`** (the YARA recon-finding as `recon`/`other`; the angr finding as `vulnerability`, surfaced `verified`-adjacent with its concrete input), filterable/sortable by type. *Validate:* `list_findings` agreement; the angr finding's envelope shows the solved serial.
5. **Settings** — the `features.floss` / `features.yara` / `features.angr` toggles are present, default-off, with their honest security/heavy-compute notes; (D8 follow-up) the **YARA user-rules directory** is surfaced here. *Validate:* toggling reflects in `get_schemas`/the advertised verbs.
6. **Cross-cutting UI assessment** — readability (dense tool payloads don't overwhelm), aesthetics (does the eye find the lead quickly?), buginess (no console errors, no broken layout on the long binutils import list or the multi-match YARA pattern set), and the newcomer's "would I trust and want to dig in here?" judgement. Record findings in `docs/dev/ui-backlog.md` per the existing loop.

**The simulated user's report (`reports/ui-assessment-report.md`, produced at eval time).** The user writes a report covering: for each Part-2 surface, whether the VR agent's analysis and findings are **correctly and legibly surfaced** (with the backend cross-check, not just the screenshot); the per-axis scores (functional / readability / aesthetics / buginess); a narrated first-time-user walkthrough; and a prioritized list of UI deviations, bugs, and aesthetic gaps (cross-linked to `docs/dev/ui-backlog.md`). It must explicitly answer: *would a researcher trust these results and want to keep using this UI?*

## 5. The deterministic auto-population contract (the load-bearing guarantee)

The product promise is that **tool usage populates the graph deterministically** — a researcher (or their agent) does not have to hand-build the substrate, and two runs of the same tool on the same bytes converge. This eval asserts, with no LLM in the loop:

- **binutils:** running `binutils_facts` on `mitis_relayd` always folds `{nx:false, relro:…, pie:false, canary:false, fortify:false}` onto the target metadata and tags `is_sink` on any present dangerous import — identical every run; a second run is a no-op (the Observation dedups by content_hash).
- **YARA:** `yara_sweep` always promotes exactly the three `pattern` nodes for the three planted matches, one per rule, deduped across the two firmware binaries, with `matches_rule` edges from each matching file — re-running adds nothing (pattern identity = rule; edges merge).
- **angr (5C-B):** solving `licensegate` always promotes the same path nodes + a `vulnerability` finding carrying the same concrete serial (the constraints have a unique/first solution the probe pins deterministically with a fixed seed/budget).
- **FLOSS:** records its Observation deterministically (the recovered string set is fixed for fixed bytes); it mints no nodes by design, so the only determinism claim is Observation dedup.

A passing eval includes a **graph-diff snapshot**: export the graph after the first tool run and after the determinism re-run; the delta must be empty for every challenge.

## 6. Answer keys (SPOILERS — orchestrator only; never given to the VR agent)

- **`mitis_relayd`** — built `cc -fno-stack-protector -no-pie -z execstack -O0`. `main` dispatches ~80 libc calls (the import-cap padding) and, on a crafted request opcode, calls `system(cmd)` where `cmd` is assembled from request bytes. The *only* tool that reveals the exec-stack and the buried `system` jump-slot is `binutils_facts`. Expected: `mitigations.nx == false`, `system ∈ jump_slot_imports`, mitigation fold + `is_sink` enrichment.
- **`stringcrypt.exe`** — `decode()` XORs `"\x1f\x0a…"` with key `0x5a` to yield `MITISKEY-7F3A9C` (the API key); a second secret, the C2 URL `http://relay.mitis-labs.net/ingest`, is pushed onto the stack one byte at a time in `build_cfg()`. Decoys (`"Mitis Relay Agent"`, `"OK"`) are plain literals to make `strings` look productive. Expected FLOSS output: both secrets under `decoded_strings` / `stack_strings`.
- **`vantage_iot_fw.bin`** — squashfs of `/usr/sbin/logsvc` (embeds `"admin:admin"` default login + a `"Dropbear sshd v2015"` banner string in a version table) and `/usr/bin/kvstore` (embeds `"DES-CBC"` + references `MD5_Init` for a config MAC). The three planted strings hit `hexgraph_default_admin_creds`, `hexgraph_dropbear_old_banner`, and `hexgraph_weak_hash_md5_sha1_banner` / `hexgraph_des_constants`. Expected: three `pattern` nodes after `yara_sweep`, matched across the two child targets.
- **`licensegate`** — `check_serial(s)` over an 8-byte input requires a set of arithmetic constraints (a per-byte weighted sum hitting a target, an XOR equality, a case-folded byte match, and a rolling checksum); on success it calls `system("/bin/grant_admin")`. No valid serial is stored in the binary. Expected: angr returns a satisfying 8-byte input reaching the `system` call; the finding carries the concrete bytes. **Note (by design):** the satisfying input necessarily contains **non-printable bytes** — no all-ASCII serial meets the weighted-sum target — so it can neither be typed nor found as a string, only *solved*. A verified witness is the byte sequence `28,254,64,26,75,2,1,1`; angr should recover this or another satisfying assignment.

## 7. Success criteria

The eval **passes** when all of the following hold (per tool, plus the cross-cutting UI bar):

**Functional (the tool did the work):**
- For each challenge, the **baseline pass fails to reveal the planted insight** and **the forced tool reveals it** — proving the tool was necessary, not incidental. (binutils: nx=false + buried `system`; FLOSS: both hidden secrets; YARA: the three rule matches across two files; angr: the satisfying serial.)
- The VR agent reached every result **from the binary + brief only** — no source, no answer key, no CVE identifier in the target (the "no guilty knowledge" guarantee is structurally enforced by the briefs + scrubbed binaries).

**Deterministic auto-population (no LLM):**
- The §1 auto-promotions appear from the tool call alone, and the §5 graph-diff on the determinism re-run is **empty** (idempotent / deduped) for every challenge.

**UI (the simulated user):**
- Every Phase-5 surface in Part 2 (steps 1–5) renders the correct, backend-verified data, with no console errors or broken layout.
- The aesthetics/readability score is **≥ 4/5** on each axis, or every deduction is logged in `docs/dev/ui-backlog.md` with a concrete fix. A newcomer can find each tool's lead without help.

**Reports (both required):**
- The VR agent's `reports/vr-agent-report.md` — per-challenge findings, the graph populated (auto vs. manual, called out separately), and the candid tool-experience assessment (what worked / didn't / was missing / surprising).
- The simulated user's `reports/ui-assessment-report.md` — the surfaced-correctly verdicts + cross-checks, the per-axis UI scores, the narrated walkthrough, and the prioritized UI-deviation list.
- An eval run that doesn't produce both substantive reports is **incomplete**, regardless of the other checks.

**Gate:** any failed functional check, any non-empty determinism delta, any unlogged UI regression, or a missing/empty agent report fails the eval.

## 8. How to run

1. Build the targets once: `tests/fixtures/phase5_tool_eval/build.sh` (needs `cc`, `mksquashfs`, and `docker` for the mingw PE; outputs are committed so this is only re-run when a source changes).
2. Enable the features: `hexgraph config set features.floss.enabled true` / `features.yara.enabled true` / (after 5C-B) `features.angr.enabled true`.
3. Role A (VR agent): drive the MCP tools per Part 1, one challenge at a time, handing the agent only the matching `BRIEFS.md` entry.
4. Role B (simulated user): invoke the `ux-assessment` skill against the populated project and additionally walk Part 2.
5. Score against §7; log UI findings in `docs/dev/ui-backlog.md`.
6. **angr:** run the `licensegate` leg only after Phase 5C-B merges (the solver probe + image). Until then it is built and documented but skipped.
