# HexGraph Codex instructions

## Shared project guidance

- Before doing repository work, read `CLAUDE.md` completely. It is the shared, authoritative project guide for HexGraph even when the active agent is Codex.
- Then read `README.md` and inspect the current branch, recent history, and relevant open work as the task requires.
- Apply every security, architecture, testing, worktree, PR, documentation, and public-repository confidentiality rule in `CLAUDE.md` unless this file gives a Codex-specific translation below.

## Project memory

- At the start of work that could benefit from prior implementation history, read `.codex/memories/MEMORY.md` if it exists. It is a local-only link to this directory's Claude project memory.
- Load only the linked memory notes relevant to the current task. Treat them as historical context that may be stale; verify current behavior in code, tests, git history, and open PRs.
- Never commit `.codex/memories/` or quote real-engagement identifiers from it in code, docs, commits, PRs, or review comments.

## Codex translations

- References in `CLAUDE.md` to Claude Code, the `Agent` tool, `Read`, `Grep`, or Claude skills mean the equivalent Codex client, subagent, file-inspection, search, or project-skill capability.
- For substantial implementation work, follow the repository worktree and branch rules. The Codex app's isolated worktree support satisfies the dedicated-worktree requirement.
- For the merge gate, delegate the independent review to the project custom agent named `pr-reviewer`. The reviewer must not be the agent that authored the change. If that profile is unavailable, use a separate subagent and include the full rubric from `.codex/agents/pr-reviewer.toml`.
- The Claude-specific `Co-Authored-By: Claude Opus ...` trailer applies only to work authored by that Claude model. Do not falsely add it to Codex-authored commits; preserve every other commit-message rule.
- The `ux-assessment` workflow is exposed to Codex from `.agents/skills/ux-assessment` and remains shared with Claude's source skill.

## Shell commands

- The global RTK instruction remains in force: prefix shell commands with `rtk`, including commands copied from `CLAUDE.md` examples.
