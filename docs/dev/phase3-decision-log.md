# Phase 3 — decision log

Decisions and divergences made while implementing Phase 3 (decompiler output → graph
truth, per `docs/design/design-re-tooling.md` §7), recorded for maintainer review.
Planned as a reviewable PR stack:

- **PR1 — rich function facts + real structs** (this PR).
- **PR2 — switch/jump-table edges**.
- **PR3 — C++ class/vtable kinds + overrides/virtual-call edges** (a deferral candidate —
  see below).
- **PR4 — rename/retype round-trip into the persistent Ghidra project**.

## PR1 decisions

### 1. Focus-centric, not whole-inventory
Rich function facts (prototype / signature / calling convention / params / locals) are
emitted on the decompiled **focus** — i.e. exactly when a function is decompiled, which is
the deliberate **promote** act — rather than for every function in the inventory. Reason:
the probe's inventory `functions` field is consumed as a list of **name strings** by the
`list_functions`/`decompile` display paths (`agent_tools.run_tool`), so turning it into a
list of dicts would break formatting across both backends. Emitting the rich set on the
focus delivers "rich function nodes via the always-welcome path" for the functions the
user actually curates, with zero change to the display path. Whole-inventory rich
enrichment (all ~400 functions) is a deferrable follow-up that would require the
dict-vs-string refactor.

### 2. The enrichment plumbing was already done in Phase O — PR1 is the probes
`_ATTRIBUTE_WHITELIST["function"]` already lists `address/prototype/signature/params/
param_count/local_count/locals/calling_convention/demangled_name`, `_func_attrs_from`
already maps every synonym, and `_extract_structs` already drops `item.get("builtin")`.
So PR1's real work is making the **probes emit** those keys; the consuming side (and its
tests) already exist. This keeps PR1 small and low-risk.

### 3. radare2 (the default backend) gets rich facts too — not Ghidra-only
The design names no specific backend, and radare2 is the default, so the radare2 focus
now carries the rich set via `afij` (recovered signature → prototype, calling convention,
arg/local counts) and `afvj` (the arg/local variables). r2's `signature` IS the recovered
C prototype, so it's exposed under both `prototype` and `signature`. The parser
(`_function_facts`) is fully defensive — malformed/odd r2 JSON yields empty facts, never a
failed decompile — and unit-tested with a fake r2 (the real r2 path is validated by the
live-sandbox CI lane). The `afvj` parsing handles **both** shapes r2 emits across versions
(a `{storage_class: [vars]}` map and a flat `[vars]` list), and classifies a parameter by
the **union** of arg markers (`isarg`/`arg` boolean, or the legacy `kind=="arg"`) — `kind`
itself is the *storage class* (reg/bpv/…), not an arg/local discriminator, so it is NOT
used for the split. An unmarked variable defaults to a **local** (omitting a param is
better than a wrong one; the prototype + `param_count` from `afij` still convey the args).
(These shape/marker fixes came from the independent merge-gate review of this PR.)

### 4. Ghidra real-struct filter via the source archive
The Ghidra POST_SCRIPT now sets `builtin: True` on a struct whose **source archive is
BUILTIN** (with a system-category-path fallback), so the always-welcome extractor keeps
only program-recovered (DWARF/GDT) layouts and drops compiler/libc noise — the filter that
already existed in `_extract_structs` but had nothing setting the flag. Field `offset` is
now emitted too (real layout). The Ghidra focus also gains prototype / calling convention /
params / locals via the function's `getSignature()`/`getParameters()`/`getLocalVariables()`,
each guarded so one failing Jython API call drops only that fact.

### 5. demangled_name deferred
The whitelist accepts `demangled_name`, but neither backend emits it reliably yet (r2's
`afij` doesn't surface it cleanly; Ghidra demangling is a separate analysis step). Left
unset for now — additive when a reliable source is wired (Phase 3 PR3's C++ work is the
natural home).

### 6. Zero migration
No new tables/node/edge kinds in PR1 — only richer `attrs_json` on `function` nodes via
existing whitelist keys, and the `builtin`/`offset` keys on struct payloads. Per design
§8, migration-free.

### 7. Tests
`tests/test_function_facts.py`: unit-tests the radare2 `_function_facts` parser (afij/afvj
→ rich attrs, count fallbacks, defensive on garbage) and proves the full rich set
(prototype/cc/params/locals) enriches a promoted function node through
`record_observation` → join-at-create. The builtin-struct filter is already covered by
`tests/test_ghidra.py`. The probes' actual emission (r2 + Ghidra Jython) is validated by
the live-sandbox / WITH_GHIDRA CI lanes.
