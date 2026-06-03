# Contributing to HexGraph

Thanks for wanting to help. HexGraph is a self-hosted, local-only workbench for AI-assisted
vulnerability research, and it holds itself to a few hard rules that keep it safe to point at hostile
targets. The most important thing you can do before writing code is to understand those rules, because
a change that breaks one of them won't be merged no matter how good it is otherwise.

## Get set up

You'll need Python 3.11+, a Docker daemon your user can talk to, [`just`](https://just.systems), and
Linux or macOS.

```bash
git clone https://github.com/branover/hexgraph.git && cd hexgraph
just setup     # venv + deps + the SPA, then the interactive setup wizard
just test      # the full suite (mock backend, offline; Docker-gated tests auto-skip)
just demo      # the whole loop offline, for $0 — doubles as a smoke test
```

Run bare `just` for the grouped recipe menu. The deeper orientation — the data model, the seam rule,
the worktree-and-PR discipline in full — lives in [`CLAUDE.md`](CLAUDE.md); this file is the short
version for humans.

## The invariants you must not break

These define the product. If your change touches any of them, it has to keep them true.

- **Fully self-hosted and local-only.** The API and UI bind `127.0.0.1`; a startup assertion refuses a
  non-loopback bind. Nothing calls a server we operate — no telemetry, no auto-update pings.
- **Bring your own key, or nothing.** Model access is the user's own Anthropic key, a local Claude Code
  session, or the offline mock backend. There are no bundled keys and no proxying.
- **Secrets are never persisted, logged, or returned.** API keys and SSH / remote-Docker credentials
  live only in the environment or `config.toml`, read on demand, reported as present-or-absent.
- **Targets are hostile.** All parsing, unpacking, and analysis of target bytes runs only inside the
  disposable sandbox container (`--network none`, read-only root, resource caps, hard timeout). The
  model never sees raw target bytes, only tool output.
- **Capability is opt-in and graduated, and relaxes in exactly one place.** Static-only with no network
  is the enforced default. Execution, network egress, rehosting, and remote access are each a separate
  opt-in that flips the **policy seam** (`policy.py`) — and that seam is the *only* place any of it
  relaxes. Never gate behavior on a backend, a tier, or an executor anywhere else.
- **The Finding schema is frozen** (`src/hexgraph/schemas/finding.schema.json`). New structure goes in
  the database envelope, never in the schema.

## How a change lands

Substantial work happens on its own branch (in a dedicated git worktree, so parallel work doesn't
collide — see `CLAUDE.md` for the full setup). Trivial touch-ups can use a plain branch.

1. **Branch off `main` with a typed name:** `build/<topic>` for features, `fix/<topic>` for bugfixes,
   `docs/<topic>` for docs.
2. **Ship the whole change together.** Code comes with its tests, a `PROGRESS.md` update, and — this is
   not optional — a migration for any model change (`alembic revision --autogenerate`) and a
   `docs/dev/ux-contract.md` update for any change in UI behavior. A model change without a migration,
   or a UI-behavior change without a contract update, is an incomplete PR.
3. **Keep the suite green.** `just test` must pass (and `just demo` if you touched the core loop). Note
   that a green *offline* run exercises none of the Docker-gated live paths — if your change touches
   execution, egress, rehosting, or remote, run `just test-ci` with the sandbox image built.
4. **Open a PR against `main`** with `gh pr create --base main` and a real description: what changed,
   why, and how you verified it.
5. **Every PR is reviewed by someone other than its author** before it merges — that review is the
   gate. `main` only ever changes by merging a reviewed PR; nobody pushes to it directly.

## Commit messages

Imperative mood, lowercase type prefix: `feat:`, `fix:`, `docs:`, `db:`, `test:`, and so on. Keep the
subject tight and let the body explain the why when it isn't obvious.

## Reporting bugs and security issues

Functional bugs and feature ideas go in the [issue tracker](https://github.com/branover/hexgraph/issues).
**Security vulnerabilities in HexGraph itself do not** — please follow [SECURITY.md](SECURITY.md) and
report them privately.

## A note on writing docs

User-facing docs are written for people, in real prose, not as machine output. If you edit one, read it
back and ask whether a person would actually write it that way and want to read it. Keep every technical
fact exact; it's the voice we're after, not a different substance.
