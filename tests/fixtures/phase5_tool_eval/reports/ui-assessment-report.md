# HexGraph UI Assessment — Phase 5 surfaces (cold, first-time researcher)

**Date:** 2026-06-06
**UI:** http://127.0.0.1:8771 (loopback, mock backend, zero spend)
**Method:** Playwright/headless Chromium walkthrough of all four seeded projects, each screenshot judged as a human would, every claim cross-checked against the live API (`/api/projects/{id}`, `/graph/{id}`, the observations endpoints, `/api/settings`) and, where it mattered, against the frontend source.
**Console health:** **0 errors** across a full sweep (4 projects × Map/Graph/Table/Matrix/Source + Settings). The only console noise is a single benign Cytoscape "custom wheel sensitivity" warning, which is the intentionally-tuned `wheelSensitivity ≈ 1.4` from the contract. The app is not buggy at the runtime level.

## TL;DR — would a researcher trust these results and want to keep using this UI?

**Yes, with real reservations.** The analyses are correct and, for the most part, surfaced legibly and honestly — the standout is the finding Inspector, which reads like an analyst's notes (the stringcrypt C2/API-key write-up and the vantage `admin:admin` write-up are genuinely excellent: lead with the IOC, show the decompiled mechanism, and state honest static-only assurance). The graph, table, observations store, and findings triage all work and cross-check clean against the backend. A newcomer would believe these results and feel invited to dig in.

But three gaps undercut the Phase-5 story specifically, and one of them is a credibility problem:

1. **The angr finding never shows its solved input.** The whole point of the licensegate finding is that symbolic execution *recovered a concrete reaching input* (`evidence.reproducer = 3b25065c4b20040f…`, plus the full `solver` block with the path addrs and angr version). The Inspector renders `function/sink/address` but has **no code path** for `evidence.reproducer` — so the researcher is told "the exact reaching input has been recovered (recorded as the reproducer)" and then is never shown it. The lead is buried.
2. **FLOSS / YARA / angr have no Settings presence at all.** The three Phase-5 features that produced everything being assessed are enabled in `settings.json` (`floss/yara/angr = enabled:true`) yet appear **nowhere** in the Settings page or anywhere in the frontend source. No toggle, no security/heavy-compute note, no YARA user-rules directory. They're invisible and unmanageable from the UI.
3. **Mitigations render as a raw JSON blob.** Both the NodeInspector RECON FACTS and the finding EVIDENCE block print `{"nx":false,"canary":false,"pie":false,…}` verbatim. A newcomer has to mentally parse `"nx":false` *and* know that false-is-bad. There is no weak/ok color-coding, no badges. (Mitigations *are* flagged honestly elsewhere — the binutils Tool Result summary literally says "weak: nx, canary, pie, relro=partial" — so the data and the honest framing exist; they just don't reach the inspector in a human-readable form.)

None of these are runtime bugs; they're surfacing gaps. The data is all correct in the backend. But for a Phase-5 evaluation whose headline features are FLOSS/YARA/angr, "the features work but you can't see angr's answer or manage the features" is a notable shortfall.

---

## Per-surface assessment

Scores are 1–5 (Functional / Readability / Aesthetics / Buginess; for Buginess, 5 = no bugs).

### Surface 0 — Projects landing + app shell
**Screens:** `00_projects.png`, the header on every workspace shot.

A calm, scannable grid of four cards: name · `mock` backend · short id · target-count · finding-count. **Counts match the API exactly** (mitis 1/3, licensegate 1/2, stringcrypt 1/2, vantage 3/6). The header carries the backend chip, a `$0 · mock` cost chip (reassuring zero-spend signal), and a `local · 127.0.0.1` chip — the loopback/zero-spend invariants are visibly surfaced. The tagline "Local-only vulnerability-research workbench — point it at a binary or firmware image" sets the tone well.

- Functional **5** · Readability **5** · Aesthetics **4** (clean and modern; the grid breathes, though the lone second-row card leaves a large empty right side) · Buginess **5**

---

### Surface 1 — Targets pane + mitigation badges
**Screens:** `22_mitis_inspector_detail.png` (the NodeInspector), `96_vantage_ws_hires.png` (the folder tree).

**Folder tree + rollups (vantage): excellent.** The Targets pane folds the firmware's path-named children into a `usr/ → bin/ , sbin/` directory tree with child-count badges and **severity rollup badges** (usr shows 5, bin 1+2, sbin 1+3) — TGT-03/04 working, the hot folders pull the eye before you expand. Leaf targets show per-target finding counts (TGT-05). mitis/licensegate/stringcrypt each render as a single clean leaf row with kind · arch (`executable · x64`, `unknown`).

**Mitigation badges (mitis): the brief's specific ask is only half-met.** The brief asks whether NX-off / no-canary / no-PIE appear as badges and whether the exec-stack is *visibly flagged weak, not silently "ok."* The honest answer:
- The **weakness IS surfaced as a first-class HIGH finding** — "Shipped relayd carries NO standard exploit mitigations (vendor 'hardened' claim is false)" — which is arguably the strongest possible framing.
- The **binutils Tool Result summary IS honest**: "…weak: nx, canary, pie, relro=partial" (cross-checked against the `binutils_facts` payload: `nx=False, canary=False, pie=False, relro=partial` — exact match).
- **But the NodeInspector RECON FACTS row dumps it as raw JSON** — `mitigations  {"nx":false,"canary":false,"pie":false,…}` — with no per-flag badge and no weak/ok coloring. This is the opposite of "visibly flagged weak"; a newcomer can't tell at a glance that `nx:false` is the bad one. There are no per-target mitigation badges on the target *row* either.

So: weakness is *flagged* (via the finding and the obs summary) but *not legibly badged* in the inspector. The imports list (115) renders as a tidy wrapped chip grid that handles the density gracefully — no overwhelm there.

- Functional **4** (data correct, finding-as-flag is great) · Readability **3** (raw-JSON mitigations hurt; imports grid is good) · Aesthetics **3** (the JSON blob is the ugly spot) · Buginess **5**

---

### Surface 2 — Detail panel → Observations / Tool Results
**Screens:** `26_detail_after_scroll.png` (the cards), `30_binutils_modal.png` (the raw-payload modal).

**This surface is a quiet win.** Selecting a target loads the NodeInspector, and below RECON FACTS the **Tool Results** section lists each observation as a calm card: kind chip · tool chip · relative time ("just now") · one-line summary. For mitis: 6 cards — 2× `decompilation`/`decompile_function`, `function list`/`list_functions` ("31 functions"), `strings`/`list_strings` ("40 strings"), `xrefs`/`xrefs` ("dangerous-sink map"), `binutils facts`/`binutils_facts`. **This matches the API exactly** (6 obs, kinds `{decompilation:2, function_list:1, strings:1, xrefs:1, binutils_facts:1}`).

Cross-checked the other corpora via API too: stringcrypt has **12** observations including the `floss_strings` one (FLOSS: 4 decoded, 151 static) whose payload contains the C2 URL and `MITISKEY` (verified in the raw payload); vantage's firmware target has **4** `yara_matches` observations whose summaries name the matched rules.

Clicking a row opens the OBS-03 raw-payload modal (`30_binutils_modal.png`): title, tool, kind, the honest "weak: …" summary, the analyzed-bytes hash, "recorded just now · agent", size (12502 B), and the full pretty-printed JSON payload, scrollable, with a copy button. **Payloads are not truncated to hide the lead** — the FLOSS decoded strings and the binutils mitigations are all readable.

- Functional **5** · Readability **5** (card idiom is consistent and calm) · Aesthetics **4** · Buginess **5**

*(One UX note: the Tool Results section sits below a 115-entry imports chip-grid, so reaching it on mitis requires a long scroll inside the inspector. On a busier binary this would bury the observations.)*

---

### Surface 3 — Graph view (auto-population)
**Screens:** `10_mitis_workspace.png`, `60_licensegate_finding.png`, `40_vantage_expanded.png`, `41_pattern_isolate.png`, `50_table_nodes.png`, `51_table_edges.png`.

The deterministic auto-population renders and cross-checks clean:

- **vantage YARA patterns + edges:** 4 purple `pattern` diamonds (`hexgraph_default_admin_creds`, `hexgraph_dropbear_old_banner`, `hexgraph_weak_hash_md5_sha1_banner`, `hexgraph_des_constants`) connect down to the firmware. Graph API: `pattern×4`, edges `matches_rule×8` + `instance_of_pattern×4`. The legend includes **PATTERN** and **INSTANCE_OF_PATTERN** chips. Pattern node attrs carry full YARA metadata (severity medium/medium/low/low, category embedded_credential/known_bad_library/weak_crypto, rule name, even a `cve: CVE-2016-7406` on the Dropbear rule). **One label nuance:** the *visible* graph edges to the pattern nodes are the orange `instance_of_pattern` ones; the `matches_rule` edges exist in the data and the Table/Edges view but aren't the prominently-labeled ones on canvas. The brief expected edges "labeled `matches_rule`" — they're present in the model and the table, less so on the default canvas.
- **mitis sinks:** `system` (libc) and `memcpy` are `is_sink:true` symbols (verified via graph API). Search for "system" surfaces the sink symbol + the hypothesis + the two relevant findings, grouped (SEARCH-01 working).
- **licensegate solver vuln node:** the orange finding diamond renders inside the expanded room, wired `main → check_serial → rolling_sum` with the `argv[1] serial` input node — the solver path is visually legible.

Legend chip **pin-isolate** (GRAPH-32) works: clicking PATTERN dims everything else and keeps the four patterns lit. The **Table view** is the standout for density (`50_table_nodes.png`): a sortable CODE/TYPE/TARGET/DEGREE/FINDINGS table where all 4 pattern nodes, both child executables, and the findings read instantly — this is the right tool when the canvas labels get small.

**Aesthetic caveat:** at default zoom the collapsed/skeleton frames leave a lot of dead vertical space (mitis is a single room card up top with a lone hypothesis node way at the bottom; vantage has a big gap between the firmware room and the pattern diamonds), and the pattern/function leaf labels are too small to read without zooming. It's calm, but it can read as *empty* rather than *curated* on the single-binary projects.

- Functional **5** · Readability **4** (table excellent; canvas labels small, `matches_rule` not the prominent edge) · Aesthetics **3.5** (dead space + tiny labels on small graphs) · Buginess **5**

---

### Surface 4 — Findings panel + Inspector
**Screens:** `60/61/62_licensegate_finding*.png`, `70_stringcrypt_finding.png`, `71` (vantage, via text dump), `90_vantage_findings_filtered.png`.

**The finding write-ups are the best thing in the product.** Each Inspector leads with severity/category/confidence chips, lifecycle pills (triaging → confirmed → reported), Edit/Confirm/Dismiss/Task/Delete actions, then a summary, EVIDENCE, REASONING, NEXT STEPS, HYPOTHESES, ANNOTATIONS — it reads in sections, not as a wall.

- **stringcrypt (FLOSS):** the summary shows the recovered **C2 URL `http://relay.mitis-labs.net/ingest`** and **API key `MITISKEY-7F3A9C`** in plain text, a DECOMPILED evidence block showing the XOR-0x5A decoder + stack-string builder, and REASONING that explains FLOSS recovered the decoded strings with honest `code_present/static` assurance ("the live network beacon was NOT executed"). The lead is front-and-center, not truncated. Exemplary.
- **vantage (YARA):** the `admin:admin` credential finding shows the decompiled `strcmp(input, DEFAULT_LOGIN=="admin:admin")` and explicitly credits the YARA rule `hexgraph_default_admin_creds (category embedded_credential)`. Honest CWE-798 framing.
- **licensegate (angr): the gap.** Summary and reasoning are excellent and honest (input *solved*, not guessed; `input_reachable / static`; "verify dynamically with verify_poc to raise this"). **But the solved serial is never shown.** EVIDENCE renders only function `main` / sink `system` / address `0x401080`. The API has `evidence.reproducer = 3b25065c4b20040f4020080801010204012020028080044020` and a full `evidence.extra.solver` block (concrete_input_hex, input_model `argv`, angr 9.2.221, 39 path addrs). Confirmed at source: `Inspector.tsx` renders `ev.function/sink/address/file/decompiled_snippet/extra.mitigations` and `ev.extra.repro_command` — there is **no branch for `ev.reproducer`**. So the one piece of evidence that makes an angr finding special is invisible.

**finding_type correctness & filtering:** verified vs API — YARA/recon findings are `recon`/`other`, the angr finding is `vulnerability` with category `other` (the "other" chip in the UI is the *category*, which is correct, not a finding_type bug). The findings filter-by-type select offers only the present types (`recon`, `vulnerability`) and filtering to "vulnerability" correctly drops the recon/attack-surface cards while keeping per-target grouping (`90_…`). Severity summary dots and grouping toggle work.

- Functional **4** (everything works except the angr reproducer isn't rendered) · Readability **4.5** (write-ups superb; mitigations-as-JSON in EVIDENCE is the one blemish) · Aesthetics **5** · Buginess **5**

---

### Surface 5 — Settings (the Phase-5 toggles)
**Screens:** `80_settings_top.png`, `80_settings_full.png`, plus a full text/heading enumeration.

**This is the biggest deviation.** The Settings page is otherwise good — Model access with presence-only BYOK keys and the explicit "API keys are never stored or transmitted" note (honesty), an always-visible Container-resources card with the "not a security relaxation" framing, and policy-relaxing feature cards each carrying a `· executes code` / `· executes the target` / `· contacts a live target` security clause: Ghidra, Fuzzing, Source & Build, PoC verification, Network egress, Remote fuzz environments, Coding-agent tools (MCP), Delegate-to-agent.

But **FLOSS, YARA, and angr appear nowhere.** Confirmed three ways: (1) the rendered page text contains none of the strings floss/yara/angr/symbolic/deobfuscate; (2) the enumerated feature-card set has no such card; (3) `grep -ri 'floss|yara|angr'` over the entire `frontend/src` returns **zero** matches. Meanwhile `settings.json` has `floss.enabled / yara.enabled / angr.enabled = true`. So the three headline Phase-5 features:
- can't be toggled from the UI,
- carry no security note (angr/FLOSS are heavy-compute; YARA runs bundled + user rules) — the brief's expected ⚠ heavy-compute/security framing is simply absent,
- and the **YARA user-rules directory is not surfaced anywhere** (the brief explicitly asked for it).

A researcher who wanted to add a YARA rule, or disable the expensive angr pass, or even *understand* why these analyses ran, has no UI affordance for any of it.

- Functional **2** (the page works, but three of the assessed features are entirely missing from it) · Readability **4** (what's there is clear) · Aesthetics **4** · Buginess **5** *(not a crash — a coverage gap)*

---

### Cross-cutting — readability / aesthetics / buginess / the gut check

- **Buginess: clean.** 0 console errors across the full sweep; no broken layouts on the 115-entry import list (wrapped chip grid) or the multi-match YARA set (4 patterns render fine). The one wheel-sensitivity warning is intentional.
- **Readability:** dense payloads are handled well almost everywhere — the observations modal, the imports grid, the Table view, and the finding write-ups all stay legible. The two readability sins are both the *same root cause*: raw `JSON.stringify(mitigations)` shown to a human (inspector RECON FACTS + finding EVIDENCE).
- **Aesthetics:** modern, dark, consistent card idiom; the eye finds the lead in the findings panel quickly. The weak spots are the **single-binary graphs feeling empty** (lots of dead canvas, tiny leaf labels) and the small physical render of some panels. It looks polished, not scotch-taped.
- **Honesty (a HexGraph core value): strong.** `$0 · mock`, presence-only keys, "weak: …" mitigation summaries, the `input_reachable / static — not executed` assurance language, the `· executes the target` security clauses — the product is consistently honest about what it did and didn't prove. The irony is that the *most rigorous* result (angr's solved input) is the one whose evidence is hidden.

---

## Prioritized list of deviations, bugs, and aesthetic gaps

**P0 — credibility / feature-completeness**
1. **angr finding never displays its solved input.** `Inspector.tsx` EVIDENCE has no branch for `evidence.reproducer` (or the `evidence.extra.solver` block). The finding *claims* a reproducer was recovered but never shows the bytes (`3b25065c…`), the input model (`argv`), or the path. Add a reproducer/solver render block (with a copy button, like the repro-command block). *Contract: FIND-03 says the Inspector shows the evidence; this evidence is dropped.*
2. **FLOSS / YARA / angr have no Settings UI.** Enabled in `settings.json`, absent from the page and from `frontend/src` entirely. Add the three feature cards with their heavy-compute/security notes, and **surface the YARA user-rules directory**. *Contract: SET-03 expects every optional feature toggle with its implication.*

**P1 — readability / honesty**
3. **Mitigations rendered as raw JSON** in both the NodeInspector RECON FACTS and the finding EVIDENCE (`JSON.stringify(ev.extra.mitigations)`). Replace with per-flag badges color-coded weak/ok (NX off / no canary / no PIE / partial RELRO), so "weak, not silently ok" is visible at a glance — the binutils obs summary already proves the honest wording exists ("weak: …"); reuse that framing in the badges.
4. **`matches_rule` edges aren't the prominently-labeled edge on canvas.** The pattern nodes show orange `instance_of_pattern` edges; `matches_rule` (8 of them) lives in the data/Table but isn't the labeled canvas edge the brief expected. Confirm which edge type is intended for the YARA→target relationship and make the canvas label match.

**P2 — aesthetics / friction**
5. **Single-binary graphs read empty.** Large dead vertical gaps (mitis room-card-at-top + lone hypothesis-at-bottom; vantage firmware-room→pattern-diamonds gap) and leaf labels too small to read at default zoom. Tighten the default frame / fit so the curated content fills the canvas.
6. **Tool Results buried under the imports grid.** On a binary with a long imports list, the (valuable) observations section requires a long scroll inside the inspector. Consider collapsing the imports grid by default or moving Tool Results above it.
7. **Search Enter didn't visibly land a focus** (`92_…`): typing "system" + Enter left the results popover open and didn't expand the skeleton room to frame the node. Minor — the popover-click path may work better — but Enter-to-focus is the expected fast path.

**Nits (no action urgent)**
- Projects grid leaves a large empty right column when only the second row has one card.
- The intentional Cytoscape wheel-sensitivity console warning fires on every graph mount (cosmetic log noise only).

---

## Backend cross-check summary (the screenshot is evidence, the API is the check)

| Claim in UI | API check | Verdict |
|---|---|---|
| Project counts (1/3, 1/2, 1/2, 3/6) | `/api/projects/{id}` | ✅ exact |
| mitis NX/canary/PIE off, partial RELRO | `binutils_facts` payload `nx/canary/pie=False, relro=partial` | ✅ exact (UI shows as JSON, not badges) |
| mitis 6 Tool Results, kinds as listed | target observations endpoint | ✅ exact |
| stringcrypt FLOSS recovered C2 URL + API key | `floss_strings` payload contains both | ✅ exact |
| vantage 4 YARA pattern nodes + metadata | graph API `pattern×4`, full attrs (sev/cat/cve) | ✅ exact |
| vantage `matches_rule`×8 + `instance_of_pattern`×4 | graph API edge counts | ✅ data present (canvas labels `instance_of_pattern`) |
| licensegate angr `vulnerability` finding | `finding_type=vulnerability`, `category=other` | ✅ (the "other" chip is the category, correct) |
| licensegate solved reproducer | `evidence.reproducer=3b25065c…` present in API | ⚠️ present in DB, **not rendered in UI** |
| FLOSS/YARA/angr enabled | `settings.json` `*.enabled=true` | ✅ enabled, ⚠️ **no UI for them** |
| finding-type filter offers only present types | recon + vulnerability | ✅ exact |
| Loopback + $0 mock | header chips | ✅ |

**Screenshots:** all under `/tmp/eval_ui/` (e.g. `00_projects.png`, `22_mitis_inspector_detail.png`, `26_detail_after_scroll.png`, `30_binutils_modal.png`, `40_vantage_expanded.png`, `50_table_nodes.png`, `60_licensegate_finding.png`, `70_stringcrypt_finding.png`, `80_settings_full.png`, `90_vantage_findings_filtered.png`).
