"""Fuzz campaigns. Modules:
- **campaigns** — the long-lived, detached multi-surface campaign runner + reaper
  (AFL++ source / qemu-mode / boofuzz / desock), crash dedup, artifacts, coverage.
- **fuzzing** — the single `fuzzing` task (the simpler one-shot path).
- **fuzz_env** — local + remote fuzz environments (where a campaign's container runs).
- **harness** + **harness_promote** — harness generation + promotion of a generated
  harness to a managed `source_file(role=harness)` + a `harness` graph node.
"""
