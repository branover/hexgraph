# Showcase screenshots — manifest

These PNGs are generated from a single reproducible **showcase** project on the mock
backend (offline, $0). Regenerate them any time the UI changes:

```bash
just showcase --reset   # (re)seed the showcase project into HEXGRAPH_HOME
just capture            # serve it + re-shoot every image below (Playwright, 1440x900, dark)
```

`scripts/seed_showcase.py` builds the project (a consumer-router engagement:
firmware tree → unpacked-FS children + a standalone binary + a web_app surface + a
raw-TCP service + a source tree; findings spanning the type/assurance ladder; a
finished mock fuzz campaign with crash artifacts + coverage; egress-audit events).
`scripts/capture_screenshots.py` drives headless Chromium through the UI.

All shots are 1440×900 at 1.5× device scale, dark theme.

## README hero shots (pick 2–3)

| Image | Slot | Caption |
|-------|------|---------|
| `graph.png` | **Hero 1 — the typed knowledge graph** | The whole engagement as one color-coded graph: firmware → binaries → functions/strings/sockets/endpoints, with typed edges (calls, taints, routes_to, listens_on, links_against…), a live legend, the target tree, and the findings list. The core "knowledge graph of a target" value. |
| `finding-verified-poc.png` | **Hero 2 — a verified finding** | A critical unauthenticated command-injection finding: the assurance chip (`input_reachable · dynamic · unauthenticated`, green = reachable through the live boundary), the PoC steps, a copy-paste repro command, and the live trigger output with the unforgeable nonce. |
| `artifacts-triage.png` | **Hero 3 — fuzzing → triage** | A finished fuzz campaign's crash inbox: a deduped heap-buffer-overflow with its assurance chip (`code_present · dynamic` — lab-confirmed in isolation), exploitability rating, a source-mapped stack, and one-click Reproduce / Minimize / Promote → PoC. |

## Per-feature shots (docs)

| Image | Feature / doc | Caption |
|-------|---------------|---------|
| `graph-selected.png` | Graph interaction | Selecting a function node lights its connected edges and opens the node inspector (decompile / annotate / run a task). |
| `source-coverage.png` | Source / IDE tab + coverage | Syntax-highlighted source browser with the fuzz harness, a Build button, and per-line coverage shading driven by a campaign's coverage map. |
| `campaigns.png` | Campaigns tab | The live/finished campaign list (status, execs, edges, crashes, coverage %) with Stop/Resume. |
| `fuzz-modal.png` | Fuzz modal | Launch a detached, hardened fuzz campaign — surface auto-inferred, engine selectable, stop conditions + resource caps. |
| `build-modal.png` | Build modal | A recorded, reproducible instrumented build recipe (ASan / SanCov toggles, arch, vendored/offline dependency posture). |
| `filesystem-browser.png` | Firmware unpacked FS | Browse a firmware's extracted rootfs and add any binary/library as a child target. |
| `egress-audit.png` | Egress audit log | Every outbound action against a live target, recorded allowed/denied — public hosts are refused (loopback/private only). |
| `findings-list.png` | Findings panel | Findings grouped by target with severity chips, finding-type tags (verified-poc / fuzz-crash) and confidence. (Secondary — overlaps `graph.png`.) |
| `projects.png` | Projects landing | The local-only project list. (Minor context shot.) |
