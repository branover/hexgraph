# HexGraph UX Evaluation — from a vulnerability researcher's chair

**Evaluator persona:** a working VR/RE engineer deciding whether HexGraph earns a place in the
day-to-day toolbox. I followed the README as a new user would, used the **mock** backend, and tried
to reverse-engineer the bundled `synthetic_fw.bin` firmware image **entirely through the web UI**
(driven headlessly with Playwright). Everything ran in an isolated `HEXGRAPH_HOME=/tmp/hexgraph-eval`
so the main install was never touched.

Date: 2026-05-30 · Backend: `mock` · Commit/branch: `build/hexgraph-mvp`

> Format: each section records what I did, then **👍 / 👎 / 💡** notes (works well / rough / idea).
> This doc is meant to feed UX improvements, so I err toward over-reporting friction.

---

## 0. First impressions from the README

The README is genuinely good — the three non-negotiables (local-only, BYOK-or-mock, hostile-target
isolation) are stated up front and made me trust the tool before running anything. The mock-backend
table that maps task type / scenario → expected outcome is exactly what a new user needs.

- 👍 Clear threat model stated immediately ("targets are hostile", LLM never sees raw bytes). For a
  VR audience this is the single most important trust signal and it's front-and-center.
- 👍 "Zero token spend by default" + a `make demo` that exits 0 means I can evaluate the whole loop
  for free before committing a key. Excellent for adoption.
- 👎 The README never tells you the firmware *unpacks into two ELFs* until the very bottom ("Bundled
  test targets"). The quickstart would be stronger if it said "after ingest you'll see `vuln_httpd`
  and `libupnp.so` as children" so a new user knows what success looks like.
- 👎 The mock-scenario table is keyed to "the `sbin/httpd` target", but the bundled firmware unpacks
  to `vuln_httpd` / `libupnp.so` (per the data-model section). The naming mismatch made me unsure
  which child target to launch tasks against. (Confirmed below — see §3.)
- 💡 A single "expected end state" screenshot in the README would orient a first-time user faster
  than any prose.

---
