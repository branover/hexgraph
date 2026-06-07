#!/usr/bin/env bash
# PreToolUse guard for the HexGraph merge gate.
#
# Purpose: a PR / merge-gate *review* must be delegated to the `pr-reviewer`
# subagent (.claude/agents/pr-reviewer.md), which carries the corrected posting
# instructions (post ON the PR via `gh pr review --comment`; never
# `--request-changes`/`--approve` on your own PR). If review work is dispatched
# to any other subagent type, that agent reads only the generic instructions and
# the recurring "findings never land on the PR" failure returns. This hook denies
# such a spawn with a message telling the orchestrator to re-dispatch correctly.
#
# FAIL-OPEN by design: any uncertainty (no jq, empty/garbled stdin, non-Agent
# call) -> allow. The hook must never break ordinary subagent spawning.

set -u

# jq is required to read the hook payload; without it, fail open.
command -v jq >/dev/null 2>&1 || exit 0

input="$(cat)"
[ -n "$input" ] || exit 0

subagent_type="$(printf '%s' "$input" | jq -r '.tool_input.subagent_type // ""' 2>/dev/null)" || exit 0
prompt="$(printf '%s' "$input" | jq -r '.tool_input.prompt // ""' 2>/dev/null)" || exit 0

# Already the correct reviewer -> allow.
[ "$subagent_type" = "pr-reviewer" ] && exit 0

# Heuristic: a PR/merge-gate review delegation mentions BOTH a review verb AND a
# PR/merge context. Both must be present to deny, to keep false positives low.
review_re='review|reviewer'
pr_re='\bPR\b|pull request|pull/[0-9]|merge gate|merge-gate|git diff|origin/main\.\.\.|--squash'

if printf '%s' "$prompt" | grep -iqE "$review_re" \
   && printf '%s' "$prompt" | grep -iqE "$pr_re"; then
  reason='Merge-gate / PR reviews must be dispatched to subagent_type=pr-reviewer (.claude/agents/pr-reviewer.md) — it carries the required posting instructions: post findings ON the PR via `gh pr review <N> --comment` (verdict in the body; NEVER --request-changes/--approve on your own PR), falling back to `gh pr comment`. Re-spawn this review with subagent_type: pr-reviewer.'
  jq -n --arg r "$reason" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
fi

exit 0
