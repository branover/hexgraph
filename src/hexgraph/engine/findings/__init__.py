"""Findings, proving, and reporting. Modules:
- **findings** — the Finding records + `classify_finding` (finding_type from the task).
- **poc** + **poc_repro** — PoC verification (the unforgeable oracles) + the re-runnable,
  self-contained reproducer.
- **assurance** — the assurance triple/ladder ({standard, method, precondition}).
- **oracles** — the verify-PoC oracle taxonomy (reflected + blind callback/canary/oob_write).
- **reachability** — the static input-reachability argument over the graph.
- **followups** — suggested next tasks derived from a finding.
- **report** — the findings report.
"""
