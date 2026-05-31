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

## 1. Setup & ingest (CLI, isolated home)

I isolated everything with `HEXGRAPH_HOME=/tmp/hexgraph-eval` and an explicit `HEXGRAPH_DB_PATH`.

```
$ hexgraph init
Initialized HexGraph at /tmp/hexgraph-eval (schema upgraded, rev 0007_target_archived)   # ~1.0s

$ hexgraph ingest tests/fixtures/synthetic_fw.bin --name demo
project 6d611523-…
target  e8ac3261-…  demo
  child 70e00856-…  sbin/httpd
  child e3851c27-…  usr/lib/libupnp.so
recon complete: 3 target(s), 0 links_against edge(s)                                     # ~2.4s
```

- 👍 Ingest is fast (~2.4s including firmware unpack in the sandbox) and the tree output is clear:
  project id, root target, two children with ids. A VR will immediately recognize this as
  "firmware → extracted rootfs binaries."
- 👍 Isolation via `HEXGRAPH_HOME` works perfectly — nothing touched the real `~/.hexgraph`.
- 👎 **README naming inconsistency, confirmed.** The quickstart and mock-scenario table call the
  target `sbin/httpd`; the "Bundled test targets" section calls it `vuln_httpd`. Reality is a third
  spelling: children are `sbin/httpd` and `usr/lib/libupnp.so` (full rootfs paths). Pick one and use
  it everywhere — a new user matching the scenario table to the tree will hesitate here.
- 👎 `recon complete: … 0 links_against edge(s)`. The README implies a `links_against` relationship
  between httpd and libupnp. Recon found none, so the dependency edge a researcher would *want*
  (which binary loads which library) isn't auto-derived. Not a bug, but a missed expectation for
  firmware work — see §5.
- 💡 The README quickstart omits `hexgraph init`; ingest appears to auto-init the DB. Good, but the
  quickstart should say so explicitly, or drop `init` from the docs entirely to avoid implying it's
  required.

---
