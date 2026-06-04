"""Build identity — one place that resolves the running code's version + git SHA.

The whole point: answer "is the deployed/running code current?" from any of the three
surfaces that report it (`GET /health`, the MCP startup banner, `hexgraph --version`),
without that answer ever drifting from the actual checked-out commit.

Versioning scheme (Conventional Commits + release-please):
  - The version is plain SemVer and lives in ONE place: `[project] version` in
    `pyproject.toml`. release-please manages it.
  - major/minor bumps are DELIBERATE, driven by commit type: a `feat:` commit bumps the
    MINOR, a breaking change (`feat!:` / a `BREAKING CHANGE:` footer) bumps the MAJOR
    (while pre-1.0 a breaking change bumps MINOR, not straight to 1.0 — `bump-minor-pre-major`).
  - patch bumps are AUTOMATIC from `fix:` commits.
  - release-please watches `main`, keeps a standing "release PR" that rolls up the pending
    bumps + CHANGELOG, and when that PR merges it writes the new version into
    `pyproject.toml` and cuts the git tag + GitHub release. We never edit the version or
    tag by hand.

Resolution order (robust across install modes):
  1. Source / editable install WITH a `.git` dir → read `[project] version` straight from
     `pyproject.toml` at the git root at RUNTIME. This is the dev / eval case where
     staleness actually bites: an editable install's importlib.metadata stays frozen at the
     version captured when it was installed, so after release-please bumps pyproject we'd
     report a stale number. Reading the file keeps it current. The SHA + timestamp come
     from live git.
  2. Packaged install WITHOUT `.git` → read a BAKED `_build_info.py` stamped at build time
     (see `scripts/bake_build_info.py`, wired into the wheel build / app.Dockerfile).
  3. Neither → fall back to the declared/installed package version
     (`hexgraph.__version__`). Never crash.

Privacy: this runs on the operator's own loopback machine, so exposing the short SHA is
fine. We deliberately do NOT expose absolute build paths or any dirty-tree diff — only the
short SHA, the resolved version, and a commit/build timestamp.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class BuildIdentity:
    """Resolved build identity. `source` is for diagnostics: git | baked | declared."""

    version: str
    git_sha: str | None
    built_at: str | None
    source: str

    def as_dict(self) -> dict[str, str | None]:
        return {
            "version": self.version,
            "git_sha": self.git_sha,
            "built_at": self.built_at,
        }


def _git(args: list[str], cwd: Path) -> str | None:
    """Run a git command, returning stripped stdout or None on any failure.

    Deliberately swallows everything (git missing, not a repo, command error) — build
    identity must never break the process that asks for it.
    """
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def _git_root() -> Path | None:
    """The git work-tree root that contains this package, or None if not under git."""
    # Anchor on the package dir so this works from an installed source checkout too.
    if not _git(["rev-parse", "--is-inside-work-tree"], _PACKAGE_DIR):
        return None
    top = _git(["rev-parse", "--show-toplevel"], _PACKAGE_DIR)
    return Path(top) if top else None


def _read_pyproject_version(root: Path) -> str | None:
    """Read `[project] version` from `<root>/pyproject.toml`, or None if unreadable.

    This is the single source of truth that release-please bumps; reading it at runtime is
    what keeps an editable install's reported version current after a bump.
    """
    pyproject = root / "pyproject.toml"
    try:
        import tomllib

        with pyproject.open("rb") as f:
            data = tomllib.load(f)
    except (OSError, ValueError):  # missing, unreadable, or malformed TOML
        return None
    version = data.get("project", {}).get("version")
    return str(version) if version else None


def _from_git() -> BuildIdentity | None:
    """Derive the build identity from the surrounding git checkout, or None.

    Version comes from `pyproject.toml` at the git root (release-please's source of truth);
    the SHA + timestamp come from live git.
    """
    root = _git_root()
    if root is None:
        return None

    version = _read_pyproject_version(root)
    if version is None:
        # Git present but no readable pyproject version — let the caller fall back.
        return None

    sha = _git(["rev-parse", "--short=12", "HEAD"], root)
    built_at = _git(["log", "-1", "--format=%cI"], root)  # committer date, ISO-8601
    return BuildIdentity(version=version, git_sha=sha, built_at=built_at, source="git")


def _from_baked() -> BuildIdentity | None:
    """Read the build-time-stamped `_build_info.py`, if present (packaged install)."""
    try:
        from hexgraph import _build_info  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — absent in source/editable installs
        return None
    version = getattr(_build_info, "VERSION", None)
    if not version:
        return None
    return BuildIdentity(
        version=str(version),
        git_sha=getattr(_build_info, "GIT_SHA", None),
        built_at=getattr(_build_info, "BUILT_AT", None),
        source="baked",
    )


def _from_declared() -> BuildIdentity:
    """Last-resort fallback: the declared/installed package version, no SHA/timestamp."""
    from hexgraph import __version__

    return BuildIdentity(version=__version__, git_sha=None, built_at=None, source="declared")


@lru_cache(maxsize=1)
def resolve_build_identity() -> BuildIdentity:
    """The running code's build identity, resolved once and cached.

    Prefers runtime git (the case where staleness bites) → a baked value (packaged,
    no `.git`) → the declared package version. Never raises.
    """
    return _from_git() or _from_baked() or _from_declared()


def version_string() -> str:
    """`<version> (<sha>)` for human-facing one-liners (CLI / banner). Omits a missing SHA."""
    bi = resolve_build_identity()
    return f"{bi.version} ({bi.git_sha})" if bi.git_sha else bi.version
