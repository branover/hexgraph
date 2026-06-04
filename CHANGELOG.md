# Changelog

All notable changes to HexGraph are recorded here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and the project will adopt
[semantic versioning](https://semver.org/) properly once it reaches 1.0. Until then,
expect breaking changes between minor versions.

## [Unreleased]

### Added
- **`setup.sh`** — a no-`just` bootstrap, now the single source of truth for the setup
  sequence (venv + deps + web-UI build, then the interactive setup wizard). `just setup` is a
  thin wrapper that calls it, so the two paths can't drift. For people who would rather not
  install the `just` task runner. Arguments pass through to the wizard, so `./setup.sh --yes`
  takes the static-only defaults without prompting.

### Changed
- `just setup` now forwards flags straight through to the wizard, so the non-interactive
  invocation is **`just setup --yes`** (or `--non-interactive` / `--defaults` / `--rebuild`).
  The old `just setup yes=1` form never actually bound the parameter — `just` parsed `yes=1`
  as a positional value, so it only reached the baseline via the no-TTY fallback; use `--yes`
  instead.

### Fixed
- `just setup` (and any other shebang recipe) no longer fails with `error: I/O error in
  runtime dir` in environments where `$XDG_RUNTIME_DIR` points at a directory that doesn't
  exist and can't be created — minimal containers, `cron`, `su` without a login session, or
  a WSL shell with no systemd user session. The justfile now pins `just`'s temp dir to a
  writable location (`set tempdir := "/tmp"`).

## [0.1.0] — 2026-06-03

The first tagged, public pre-release. HexGraph is a self-hosted, local-only workbench for
AI-assisted vulnerability research: you point it at a binary or a firmware image, and it
ingests the target, pulls firmware apart into its component binaries, runs AI-driven
analysis tasks using your own model access, and records every result as a structured
**finding** in a typed, SQLite-backed graph. A loopback web UI browses the graph, launches
tasks, and triages findings; the same primitives are available to a coding agent over MCP.

Everything below has been built and exercised end to end, but this is pre-1.0 software and
the rough edges are real.

### The core loop
- Ingest a target, run recon, drive AI analysis, emit a structured finding against the
  frozen `finding.schema.json`, write it into the graph, and spawn the next task it
  suggests. `just demo` runs the whole loop offline, for $0, and exits 0.

### What's in it
- **Local-only and self-hosted.** The API and UI bind `127.0.0.1` and refuse otherwise; no
  telemetry, no auto-update pings, nothing calls a HexGraph-operated server.
- **Bring your own key, or nothing.** A mock backend (the default) runs the full loop with
  no key and no network; an Anthropic BYOK backend and a local Claude Code backend are the
  paid paths. Secrets are read on demand and never logged, stored, or returned.
- **Every target is treated as hostile.** All handling of target bytes happens inside a
  disposable Docker sandbox (`--network none`, read-only root, dropped capabilities,
  resource caps, a hard timeout). The model only ever sees tool output, never raw bytes.
- **A typed, attributed knowledge graph** of targets, functions, sockets, endpoints,
  hypotheses, and findings, with node dedup and a network map of shared sockets.
- **Graduated, opt-in capability.** Static-only is the enforced default; execution
  (PoC/fuzzing), bounded network egress, source builds, audited dependency fetch, firmware
  rehosting, remote live devices, and remote fuzz compute are each a separate opt-in that
  relaxes the single policy seam and nothing else.
- **Verification and an assurance ladder.** Findings carry an assurance level, and opt-in
  PoC verification executes the target against an unforgeable nonce oracle, foreign-arch
  included, under qemu-user.
- **Coverage-guided, surface-aware fuzzing** (AFL++, libFuzzer, qemu-mode, boofuzz, desock)
  with detached, crash-safe campaigns, dedup, minimization, and one-click re-verification —
  optionally on a remote compute host you own.
- **Build from source** into instrumented, reproducible artifacts through a recorded
  recipe, with an in-browser Source/IDE tab and coverage shading.
- **Dynamic surfaces, rehosting, and remote**: model a running web service or a raw-TCP
  daemon as a first-class surface, boot a whole firmware image under full-system emulation,
  or assess a physical device over SSH/telnet, all with bounded, audited egress.
- **Real vendor-firmware extraction** (sasquatch, jefferson, ubi_reader, sleuthkit, binwalk)
  and **MCP integration** in both driver and delegate modes.

### Project / release engineering
- Continuous integration (offline test matrix, frontend build, dependency audit, and a
  live-Docker lane that actually exercises the sandboxed egress/exec/rehost paths).
- Open-source onboarding: `SECURITY.md`, `CONTRIBUTING.md`, a code of conduct, and issue /
  PR templates.

### Known limitations
- Pre-1.0: interfaces and the data model may change between minor versions (the project DB
  migrates forward and is never silently reset).
- Single-user, local, self-hosted by design. It is not hardened for multi-tenant or
  internet-facing use; do not expose an instance to untrusted users or networks.
- The heavier dynamic features (rehosting, KVM disk-image boot, remote devices) need extra
  host capabilities (privileged containers, `/dev/kvm`) and are the most operationally
  involved to run.

[0.1.0]: https://github.com/branover/hexgraph/releases/tag/v0.1.0
