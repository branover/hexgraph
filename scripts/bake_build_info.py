#!/usr/bin/env python3
"""Stamp `src/hexgraph/_build_info.py` so a packaged install (no `.git`) can still report
its real build identity.

Run this at BUILD time (wheel build, app image build) from a checkout that still has git:

    python scripts/bake_build_info.py

It writes the version that `hexgraph.version` resolves from git — the SemVer in
`[project] version` of `pyproject.toml` (release-please's source of truth) — plus the short
SHA and the build timestamp. At runtime `resolve_build_identity()` prefers live git and only
falls back to this baked module when `.git` is absent, so a stale baked value can never
shadow a real checkout.

The generated file is gitignored: it is a build artifact, never committed.
"""

from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path

# Make the in-tree package importable without an install (build envs vary).
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from hexgraph.version import _from_git  # noqa: E402

_OUT = _ROOT / "src" / "hexgraph" / "_build_info.py"


def main() -> int:
    bi = _from_git()
    if bi is None:
        print("bake_build_info: no git checkout to derive from; not writing _build_info.py",
              file=sys.stderr)
        return 0  # non-fatal: runtime falls back to the declared version
    built_at = bi.built_at or _dt.datetime.now(_dt.timezone.utc).isoformat()
    _OUT.write_text(
        '"""Generated at build time by scripts/bake_build_info.py — do not edit, do not commit."""\n\n'
        f"VERSION = {bi.version!r}\n"
        f"GIT_SHA = {bi.git_sha!r}\n"
        f"BUILT_AT = {built_at!r}\n"
    )
    print(f"bake_build_info: wrote {_OUT} → {bi.version} ({bi.git_sha})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
