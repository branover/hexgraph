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


def target_source_mounts(target_sources: list[str]) -> tuple[list[tuple[str, str]], list[str], list[str]]:
    """Mount the target sources for a coverage build PRESERVING their directory layout, so a
    source that `#include`s its own header (the normal multi-file/library case) compiles
    (battle-test L: the flat `/src/target_N.c` mount with no `-I` broke a self-including
    header). We mount each source's CONTAINING directory read-only at a deterministic guest
    path and reference the file inside it — so a sibling header sits next to its .c in the
    guest AND the dir is added to the include path. Returns
    (extra_ro_mounts, target_source_guest_paths, include_dir_guest_paths):

      • extra_ro_mounts  — (host_dir, guest_dir) per unique source directory.
      • guest sources    — the guest path of each source (inside its mounted dir, real basename).
      • include dirs     — the guest dirs to pass as `-I` (deduped, in order).

    Deterministic + collision-free: distinct host dirs get distinct guest dirs (/src/d0,
    /src/d1, …); two sources from the SAME dir share one mount (so a lib's .c + .h land
    together). Non-existent paths are dropped (the probe degrades to coverage-blind)."""
    dir_guest: dict[str, str] = {}
    mounts: list[tuple[str, str]] = []
    guest_sources: list[str] = []
    include_dirs: list[str] = []
    for ts in target_sources:
        if not (ts and os.path.isfile(ts)):
            continue
        host_dir = os.path.dirname(os.path.abspath(ts)) or "/"
        if host_dir not in dir_guest:
            gdir = f"/src/d{len(dir_guest)}"
            dir_guest[host_dir] = gdir
            mounts.append((host_dir, gdir))
            include_dirs.append(gdir)
        guest_sources.append(f"{dir_guest[host_dir]}/{os.path.basename(ts)}")
    return mounts, guest_sources, include_dirs


def derive_dictionary(session, target, *, limit: int = 256) -> list[str]:
    """Auto-derive an AFL++/libFuzzer dictionary of magic-byte / keyword tokens from
    the TARGET's notable strings (the strings tool / list_strings), so the fuzzer gets
    past trivial `memcmp`/keyword gates faster. Best-effort: returns a bounded, deduped
    list of short printable tokens. Reuses the sandboxed strings probe — no new bytes
    handling. Never raises (a dictionary is an optimization, not a requirement)."""
    tokens: list[str] = []
    try:
        from hexgraph.agent.agent_tools import ToolContext, run_tool
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
