# Phase 2 — decision log

Decisions and divergences made while implementing Phase 2 (address-level access +
breadth verbs, per `docs/design/design-re-tooling.md` §7), recorded for maintainer
review. Phase 2 ships as a 3-PR stack mirroring Phase O:

- **PR1 — address-level access** (this PR): decompile/disassemble/analyze by address +
  reanalyze.
- **PR2 — breadth verbs**: `call_graph` + bidirectional/data xrefs.
- **PR3 — search_decompiled + discoverability/instruction wiring**.

## PR1 decisions

### 1. Address focus auto-detected, not a separate verb arg
A focus given to the decompiler is a function NAME or a hex ADDRESS; the probe detects
which (`_ADDR = ^0x[0-9a-fA-F]+$`) rather than taking a `kind` flag. An address resolves
to the function *containing* it (analyze-at-address) by a pure-Python scan over r2's own
`aflj` offset/size table (`_containing_function`) — no address is ever interpolated into
an r2 command before it passes the strict hex regex, so an attacker-influenced address
can't inject a command (the same discipline as the existing `_SAFE_NAME` guard).

### 2. `decompile_at` is a distinct verb; `disassemble` is overloaded
`decompile_at(address)` is its own read verb (PROMOTE, same contract as
`decompile_function`) so its schema and the discoverability index stay clean — an
address decompile records under `tool="decompile_at"`, a name one under
`tool="decompile_function"`. `disassemble`, by contrast, gained an optional `address`
alongside `function` (one or the other) because it's a pure QUERY with no promote
semantics to keep separate.

### 3. Disassembly stays radare2-only (the design's "wire disassemble under Ghidra")
The `disassemble` verb continues to always use radare2 — it gives real instruction
listings, whereas the Ghidra path is a *decompiler* and returns empty disasm. The design
§7 line "wire `disassemble` under Ghidra" is satisfied functionally by the existing
r2 listing (which works under both decompiler settings); emitting a Ghidra-faithful
listing from the POST_SCRIPT was deferred as low-value. **Decision point for the
maintainer:** accept r2-always disasm, or fund Ghidra listings? The Ghidra POST_SCRIPT
*does* now resolve an address focus and emit the focus `address`, so address-level
*decompilation* works under Ghidra; only the assembly listing is r2-only.

### 4. `reanalyze` is a thin lever, not a depth model
There is no analysis-depth notion anywhere in the probes today. `reanalyze` raises depth
the only meaningful way each backend offers: radare2 runs `aaaa` (the deeper, more
aggressive pass) instead of `aaa`; Ghidra drops the warm persistent-project slot so the
next run re-imports cold (a persisted project isn't re-analyzed in place). It busts the
in-process decompile cache via a distinct cache key and records its refreshed inventory
under `tool="reanalyze"`. A richer per-pass depth dial was judged out of scope.

### 5. The decompiler seam gained `address`/`reanalyze` keyword-only params
`Decompiler.decompile(artifact, function=None, *, address=None, reanalyze=False,
project=None)` — keyword-only with defaults, so every existing caller
(`decompile(path, fn, project=p)`) is unchanged. The Ghidra-bridge impl accepts them for
seam parity but ignores `reanalyze` (re-analysis is the analyst's to drive in their live
Ghidra) and passes an address through for the bridge to resolve.

### 6. Zero migration
No new tables, no new node/edge kinds. The new Observation `result_kind`s reuse existing
String-column vocab (`decompilation`, `disassembly`, `function_list`), so the
enrichment extractor for `decompilation` fires on an address decompile exactly as on a
name decompile. Per design §8 this is correctly migration-free.

### 7. Offline tests for the curation plumbing; address resolution unit-tested pure
`tests/test_address_access.py` exercises the new verbs at the engine layer with a faked
decompiler (no Docker — the curation/observation contract, not the sandboxed
decompiler), plus pure-unit tests for the probe's `_containing_function`/`_ADDR` and the
seam's `_focus_args`. End-to-end address resolution against a real binary is covered by
the Docker-gated decompiler tests / the live-sandbox CI lane.
