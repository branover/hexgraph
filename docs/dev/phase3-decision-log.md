# Phase 3 — decision log

Decisions and divergences made while implementing Phase 3 (decompiler output → graph
truth, per `docs/design/design-re-tooling.md` §7), recorded for maintainer review.
Planned as a reviewable PR stack:

- **PR1 — rich function facts + real structs** (merged, #144).
- **PR2 — switch/jump-table edges** — **DEFERRED** (maintainer decision 2026-06-05):
  jump-table targets are intra-function addresses, not function entry points, so modeling
  them as edges between function nodes rarely materializes under the both-endpoints rule;
  better as a function attribute or revisited later.
- **PR3 — C++ class/vtable kinds + overrides/virtual-call edges** — **DEFERRED** (maintainer
  decision 2026-06-05): no C++ target in scope, and it fights the always-welcome model
  (class/vtable nodes can only be promoted, not auto-enriched).
- **PR4 — rename/retype round-trip into the persistent Ghidra project** (this PR).

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

## PR4 decisions (rename/retype round-trip — full)

### 1. The persistent project already saves — no separate "write" probe needed
The warm decompile already runs `analyzeHeadless … -process` **without `-readOnly`**, so
analyzeHeadless **saves the program back into the persistent project** after the postScript
runs. So the rename round-trip is a tiny prelude added to the *existing* POST_SCRIPT
(`getFunctionContaining(toAddr(addr)).setName(new_name, USER_DEFINED)`), not a new write
path: the `-process`/`-import` save persists it. The host passes `--rename <addr> <name>`,
which becomes postScript args; the prelude renames then focuses on that function so the
emitted result reflects the new name, and `GhidraDecompiler.rename_function` runs it under
the slot lock (a Ghidra project is not concurrency-safe — the write holds the lock for its
whole duration; if the lock can't be taken it refuses rather than risk corruption).

### 2. Cache-coherence solved by keying the re-decompile on the NEW name
The flagged subtlety — a rename doesn't change `content_hash`, so the Observation dedup
(`tool, args, content_hash, result_kind`) would serve the STALE pre-rename decompile — is
sidestepped without an epoch/version dimension: the re-decompile is recorded under
`args={"function": new_name}`, which differs from the pre-rename `args={"function":
old_name}`, so it's a naturally DISTINCT Observation. The new name IS the cache-bust. The
old observation is left intact as historical provenance.

### 3. Re-enrich + refresh the node body
Recording the fresh decompile re-indexes the renamed function's always-welcome facts
(prototype/cc/params), which enrich the node (whose name is already the new name). The
node's stored `pseudocode` attr is also refreshed directly (it isn't a whitelisted
enrichment fact), so the body reflects the rename, not just the attrs.

### 4. Best-effort, gated, radare2 pays nothing
`_apply_rename` calls `propagate_function_rename` in a `try/except` and the function itself
returns a status dict (never raises) — a Ghidra hiccup never breaks the confirmed graph
rename. It is a NO-OP unless **headless Ghidra is the active backend** (radare2 has no
persistent project to write to), so the default-backend path pays only a couple of config
checks, never a Docker run. Address (`^0x…$`) and new-name (a C/C++ identifier) are
validated before any probe — `setName` takes the name as a Java arg, not a shell command,
so this guards against garbage, not injection.

### 5. Synchronous, with a known latency note
Propagation runs synchronously inside the annotate-confirm path. Under headless Ghidra the
warm `-process` run is a few seconds; a cold import (renaming a never-decompiled function)
is minutes. Renames typically follow a decompile (warm), so the common cost is seconds.
Making propagation asynchronous (a background task) is a sensible follow-up if the latency
bites; kept synchronous here for correctness/simplicity.

### 6. Validation honesty
The Python orchestration (gating, validation, the cache-bust re-record, the wiring, the
graph-rename-survives-a-Ghidra-failure invariant) is covered offline by
`tests/test_rename_roundtrip.py` with the decompiler faked. The actual Ghidra **project
write** (the Jython `setName` + the `-process` save) cannot run without Ghidra, so it is
validated by: reasoning about documented analyzeHeadless behavior; the existing WITH_GHIDRA
decompile-gate CI lane, which compiles + runs the shared POST_SCRIPT (so a syntax error or
break in the rename prelude is caught even though the gate doesn't pass rename args); and
the independent review. **Recommended before relying on it heavily: a manual verification
of the rename-persists behavior on a real headless-Ghidra setup** (or a follow-up that adds
a WITH_GHIDRA-gated end-to-end rename test once a Ghidra fixture harness exists).

### 7. retype
The same path supports retype in principle (the postScript could `setReturnType`/edit the
DataTypeManager alongside `setName`), but this PR ships **rename** only — the annotate
`rename` kind is the wired trigger. retype is an additive follow-up on the same seam.

### 8. Zero migration
No new tables/node/edge kinds — the round-trip writes to the Ghidra project on disk and
records a (existing-kind) `decompilation` Observation. Per design §8, migration-free.
