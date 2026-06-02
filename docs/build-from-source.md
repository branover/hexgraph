# Build from source & the Source / IDE tab

A project holds **trusted source** separately from its (hostile) targets, browses and edits it in an
in-browser IDE, and — with `features.build` — compiles it into an **instrumented, reproducible
artifact** via a recorded recipe HexGraph runs in the sandbox. The design rationale lives in
[design-fuzzing-and-source.md](design-fuzzing-and-source.md).

![The Source tab with coverage shading](images/source-coverage.png)

## Source trees & the Source tab

A **source tree** is an imported library's source, or the harnesses / PoCs / build-scripts HexGraph
itself produces. A tree can be linked to a target (a `built_from` edge), and a project may hold
several. Files live on disk under the project data dir indexed by a manifest; a `source_file` graph
node is materialized **lazily** when something references it (so a 70k-file tree never explodes the
graph).

The center pane's **Source** mode is an in-browser IDE: a dropdown switches between trees, a file
explorer browses each, and a code viewer shows a file with line numbers. A finding that maps to source
gets an **"Open in source"** button that jumps straight to the file and line; a fuzz crash's
symbolized stack frame jumps the same way.

- **Coverage shading** (with fuzzing enabled) — pick a campaign and covered lines tint green /
  uncovered amber, so you see exactly where the fuzzer is stuck (the single most useful
  harness-improvement signal).
- **Harnesses, PoCs, and scripts are all `source_file`s** (role-tagged) — a generated harness becomes
  a managed file you can read; a **Backfill harnesses** action promotes older transient harnesses.
- **Editable IDE** (`features.source.edit`) — for HexGraph-authored files (harness / PoC / script +
  scratch), an **Edit → Save** creates a **new revision** (never an in-place mutation — content in
  CAS + a diff), the file shows its **revision history** (one-click revert, append-only), and a build
  can be launched **rebuild-from-a-revision**. Imported / extracted / vendor source
  (`origin=git|archive|extracted|upload`) stays **read-only** — editing it would break the
  reproducible build's content hash. Firmware-*extracted* files are marked `extracted` (untrusted;
  displayed, never run or parsed outside the sandbox).
- **MCP:** `list_source_trees` / `read_source_file` (read), `import_source_tree` /
  `link_finding_to_source` / `save_source_revision` (write).

## Build-as-API (`features.build`)

With **`features.build`** enabled (`just build-image`), HexGraph compiles a managed tree into an
instrumented artifact via a **recorded, reproducible recipe** the API runs in the sandbox — *you never
run a compiler by hand*.

![The Build modal — a recorded, reproducible instrumented recipe](images/build-modal.png)

You author/approve a `BuildSpec` (`system`, ordered explicit-argv `phases`, an `instrumentation`
profile, `artifacts` to capture, NON-secret `env`); HexGraph **injects the toolchain**
(`CC`/`CXX`/`CFLAGS`/`SANITIZER`/`FUZZING_ENGINE` per the base-image contract), so the *same* phases
yield an ASan+SanCov, an AFL++, or a plain build by swapping only the profile.

In the UI: a capability-gated **Build modal** (Source tab) shows a **read-only recorded-recipe
preview** (no free-text command box) with instrumentation toggles, an **arch** selector (cross), a
**dependency posture** (vendored / fetch), and the injected env + `recipe_sha`; the Builds list shows
**reproducible / cached / locked / instrumented** badges. Over MCP: `build_target`,
`import_oss_fuzz` / `save_source_revision`, `list_builds` / `coverage_diff`.

## The build→fuzz handoff is automatic

If the tree is `built_from` a target, the rebuild registers an **instrumented derived target** (wired
`instrumented_build_of`→ the original) — the fuzzable twin. The build records the instrumented target
sources on the derived target (`metadata_json.fuzz_target_sources`, the harness excluded) and
**promotes any `role=harness` file** to a `harnesses`→ edge, so a subsequent `start_fuzz_campaign` on
the derived target infers `source_lib` and runs coverage-guided with **no manual wiring**.

## Reproducibility & the network posture

Reproducibility is the contract: `recipe_sha` + the source byte-content hash + the toolchain digest
(+ a lockfile) make a build replayable; a **reproducibility badge** shows when all are recorded, and a
**cache-key hit** reuses the prior artifact and skips the rebuild (`SOURCE_DATE_EPOCH` + ccache make
rebuilds deterministic + incremental).

- **The compile phase ALWAYS runs `--network none`.** Vendored / offline is the default and the
  recommendation. Source is mounted read-only, output only to `/out`, non-root, ephemeral; a malicious
  `configure` can burn CPU and exit — it cannot persist or exfiltrate. Building runs **untrusted
  third-party code**, so it has its **own fail-closed gate** (separate from executing the target — you
  can build-and-inspect without permitting the binary to run).
- **Bounded dependency fetch (`features.build_fetch`, default off).** When a build genuinely needs to
  fetch deps, enabling this raises a **separate, audited, ALLOWLISTED** fetch phase: a distinct sandbox
  container with network ON but bounded to a registry allowlist (crates.io / pypi.org / github.com /
  distro mirror — operator-extendable, *never* "any host"; enforced by an egress backstop that drops
  any off-list connect), producing a **hash-pinned lockfile** + an **SBOM-lite**. HexGraph then drops
  the network and runs the compile `--network none` against the snapshotted deps — **fetch-then-offline**
  (different containers, so a fetched dep can be recorded but never run during compile). Its own gate —
  never folded into `features.network`.
- **Cross-compile for firmware** (`arch` on the recipe, `WITH_CROSS=1` image, `just build-image
  with_cross=1`). clang is the cross-compiler: pass a firmware arch (`mips`/`mipsel`/`arm`/`armhf`/
  `aarch64`) and HexGraph injects `--target=<triple>` + the **parent firmware's extracted rootfs as
  `--sysroot`**, so the instrumented binary is binary-compatible with the device userland (runs under
  qemu-user). A cross-build failure degrades gracefully to qemu-mode binary-only fuzzing.
- **OSS-Fuzz `build.sh` import.** Paste an OSS-Fuzz-style `build.sh` (`POST
  .../builds/import-oss-fuzz` or the `import_oss_fuzz` MCP tool): it's stored as a `role=script` source
  file, mapped to HexGraph's `$CC/$CXX/$CFLAGS/$LIB_FUZZING_ENGINE/$SRC/$OUT` contract, and runs
  essentially unchanged via a single shell phase.

**Run-to-run coverage diff** (`coverage_diff` MCP tool / `/api/campaigns/{id}/coverage-diff`) compares
two campaigns' per-line coverage — *what new edges did this run reach?* — to judge whether a
harness/corpus/engine change actually improved reach.
