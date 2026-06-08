"""Build-as-API: turn a managed source tree into an instrumented, reproducible artifact.

The agent never runs a compiler — it authors/approves a BuildSpec and requests a build,
which HexGraph runs in the sandbox. Modules:
- **build** — the BuildSpec + the build runner (instrumentation env, cross-compile, the
  vendored/fetch dependency policy, the reproducibility contract).
- **builds** — the build ledger (status, recipe_sha triple, lockfile/SBOM, derived target).
- **source** — managed source trees (trusted text we possess/author; NOT target bytes).
- **revisions** — editable harness/PoC revisions (edit-then-rebuild).
- **oss_fuzz** — map an OSS-Fuzz `build.sh` onto our env contract.
"""
