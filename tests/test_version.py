"""Build identity (N8): version from pyproject.toml (release-please-managed), SHA from git.

Covers the resolution order (git → baked → declared), the runtime pyproject read that keeps
an editable install current after release-please bumps the version, and the human-facing
`version_string`. Git and pyproject are mocked so the tests are deterministic regardless of
the real repo's checked-out version/SHA.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hexgraph import version as V


# ── _read_pyproject_version: the single source of truth ────────────────────────────


def test_read_pyproject_version(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "hexgraph"\nversion = "0.4.2"\n'
    )
    assert V._read_pyproject_version(tmp_path) == "0.4.2"


def test_read_pyproject_version_missing_file(tmp_path):
    assert V._read_pyproject_version(tmp_path) is None


def test_read_pyproject_version_no_version_key(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "hexgraph"\n')
    assert V._read_pyproject_version(tmp_path) is None


def test_read_pyproject_version_malformed(tmp_path):
    (tmp_path / "pyproject.toml").write_text("this is not = valid toml [[[")
    assert V._read_pyproject_version(tmp_path) is None


# ── _from_git: version from pyproject, SHA/timestamp from git ──────────────────────


def test_from_git_uses_pyproject_version(monkeypatch, tmp_path):
    monkeypatch.setattr(V, "_git_root", lambda: tmp_path)
    monkeypatch.setattr(V, "_read_pyproject_version", lambda root: "1.2.3")

    def fake_git(args, cwd):
        if args[0] == "rev-parse":
            return "abcdef012345"
        if args[0] == "log":
            return "2026-06-04T12:00:00+00:00"
        return None

    monkeypatch.setattr(V, "_git", fake_git)
    bi = V._from_git()
    assert bi is not None
    assert bi.version == "1.2.3"
    assert bi.git_sha == "abcdef012345"
    assert bi.built_at == "2026-06-04T12:00:00+00:00"
    assert bi.source == "git"


def test_from_git_none_when_not_under_git(monkeypatch):
    monkeypatch.setattr(V, "_git_root", lambda: None)
    assert V._from_git() is None


def test_from_git_none_when_pyproject_unreadable(monkeypatch, tmp_path):
    # Git present but no readable pyproject version → fall back, don't crash.
    monkeypatch.setattr(V, "_git_root", lambda: tmp_path)
    monkeypatch.setattr(V, "_read_pyproject_version", lambda root: None)
    assert V._from_git() is None


# ── resolution order: git → baked → declared ──────────────────────────────────────


def _clear_cache():
    V.resolve_build_identity.cache_clear()


def test_resolve_prefers_git(monkeypatch):
    _clear_cache()
    git_bi = V.BuildIdentity(version="0.1.0", git_sha="cafebabe1234",
                             built_at="2026-01-01T00:00:00+00:00", source="git")
    monkeypatch.setattr(V, "_from_git", lambda: git_bi)
    # Baked present but must be shadowed by live git (stale-baked guard).
    monkeypatch.setattr(V, "_from_baked",
                        lambda: V.BuildIdentity("9.9.9", "stale0000000", None, "baked"))
    bi = V.resolve_build_identity()
    assert bi.version == "0.1.0"
    assert bi.source == "git"
    _clear_cache()


def test_resolve_falls_back_to_baked_when_no_git(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(V, "_from_git", lambda: None)
    baked = V.BuildIdentity("0.3.4", "baked0000000", "2026-02-02T00:00:00+00:00", "baked")
    monkeypatch.setattr(V, "_from_baked", lambda: baked)
    bi = V.resolve_build_identity()
    assert bi.version == "0.3.4"
    assert bi.source == "baked"
    assert bi.git_sha == "baked0000000"
    _clear_cache()


def test_resolve_falls_back_to_declared_when_nothing(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(V, "_from_git", lambda: None)
    monkeypatch.setattr(V, "_from_baked", lambda: None)
    bi = V.resolve_build_identity()
    assert bi.source == "declared"
    assert bi.version  # the declared package version, never empty
    assert bi.git_sha is None
    _clear_cache()


def test_as_dict_shape():
    bi = V.BuildIdentity("0.1.0", "abc123", "2026-01-01T00:00:00+00:00", "git")
    d = bi.as_dict()
    assert set(d) == {"version", "git_sha", "built_at"}
    assert "source" not in d  # diagnostic-only, not exposed on /health


def test_version_string_includes_sha(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(
        V, "_from_git",
        lambda: V.BuildIdentity("0.1.0", "cafebabe1234", None, "git"))
    assert V.version_string() == "0.1.0 (cafebabe1234)"
    _clear_cache()


def test_version_string_omits_missing_sha(monkeypatch):
    _clear_cache()
    monkeypatch.setattr(V, "_from_git", lambda: None)
    monkeypatch.setattr(V, "_from_baked", lambda: None)
    monkeypatch.setattr(V, "_from_declared",
                        lambda: V.BuildIdentity("0.0.0+x", None, None, "declared"))
    assert V.version_string() == "0.0.0+x"
    _clear_cache()


# ── never raises, even with a hostile/missing git ─────────────────────────────────


def test_git_helper_swallows_failures(monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise FileNotFoundError("git not installed")

    monkeypatch.setattr(subprocess, "run", boom)
    assert V._git(["rev-parse", "HEAD"], Path(".")) is None


# ── CLI --version ─────────────────────────────────────────────────────────────────


def test_cli_version_flag(capsys, monkeypatch):
    _clear_cache()
    monkeypatch.setattr(
        V, "_from_git",
        lambda: V.BuildIdentity("0.1.0", "deadbeef1234", None, "git"))
    from hexgraph.cli import build_parser

    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "hexgraph" in out
    assert "0.1.0" in out
    assert "deadbeef1234" in out
    _clear_cache()
