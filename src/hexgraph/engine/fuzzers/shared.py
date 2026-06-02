"""Shared helpers for the Fuzzer seam — image selection + input resolution.

Kept separate from the engine implementations so they stay import-light. The
`fuzz_image()` selector honours the worktree discipline (HEXGRAPH_FUZZ_IMAGE / a
Settings override / the default tag). The resolvers reuse the Phase-0
`fuzzing.resolve_harness` / `resolve_target_sources` so the seam introduces no new
harness/source resolution logic.
"""

from __future__ import annotations

import os

DEFAULT_FUZZ_IMAGE = "hexgraph-fuzz:latest"


def fuzz_image() -> str:
    """The dedicated fuzz image tag (design §5.4 D4). Worktree discipline: set
    HEXGRAPH_FUZZ_IMAGE to a private tag for testing; NEVER clobber the shared tag."""
    from hexgraph import settings

    return (os.environ.get("HEXGRAPH_FUZZ_IMAGE")
            or settings.get("features.fuzzing.image", DEFAULT_FUZZ_IMAGE)
            or DEFAULT_FUZZ_IMAGE)


def derive_dictionary(session, target, *, limit: int = 256) -> list[str]:
    """Auto-derive an AFL++/libFuzzer dictionary of magic-byte / keyword tokens from
    the TARGET's notable strings (the strings tool / list_strings), so the fuzzer gets
    past trivial `memcmp`/keyword gates faster. Best-effort: returns a bounded, deduped
    list of short printable tokens. Reuses the sandboxed strings probe — no new bytes
    handling. Never raises (a dictionary is an optimization, not a requirement)."""
    tokens: list[str] = []
    try:
        from hexgraph.engine.agent_tools import ToolContext, run_tool
        from hexgraph.db.models import Project

        project = session.get(Project, target.project_id)
        ctx = ToolContext(session=session, project=project, target=target)
        out = run_tool(ctx, "list_strings", {})
        seen: set[str] = set()
        for line in (out or "").splitlines():
            s = line.strip().strip('"')
            # keep short, printable, identifier/keyword-ish tokens useful as magic bytes
            if 2 <= len(s) <= 32 and s.isprintable() and " " not in s and s not in seen:
                seen.add(s)
                tokens.append(s)
            if len(tokens) >= limit:
                break
    except Exception:  # noqa: BLE001 — a dictionary is best-effort
        return []
    return tokens
