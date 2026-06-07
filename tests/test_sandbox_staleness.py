"""Proactive sandbox-image staleness detection (`runner.sandbox_image_staleness` and the
setup-wizard warning that surfaces it).

The gap this closes (seen in the Phase-5 eval): an "up-to-date build" (venv + SPA) can
still run a STALE `hexgraph-sandbox` image that predates a toolchain change — the image
silently lacked FLOSS/YARA and `yara_sweep` returned 0 matches with no error.
`meta_check_features` catches that REACTIVELY (it probes each dep in the image). These tests
cover the PROACTIVE companion: compare the image's build date against the Dockerfile's git
COMMIT time (checkout-independent — not its filesystem mtime) and warn. All Docker/git calls
are mocked — no Docker, no git, no network needed.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from hexgraph.sandbox import runner as R


# ── the core tri-state comparison ────────────────────────────────────────────────────


def _stub_dates(monkeypatch, *, created, src_epoch):
    """Stub the two halves of the comparison directly (no Docker / no git / no filesystem).
    `created`/`src_epoch` are POSIX timestamps or None."""
    monkeypatch.setattr(R, "_image_created_epoch", lambda image: created)
    monkeypatch.setattr(R, "_toolchain_source_epoch", lambda: src_epoch)


def test_staleness_true_when_image_older_than_dockerfile(monkeypatch):
    # image built BEFORE the Dockerfile's last edit → STALE.
    _stub_dates(monkeypatch, created=1000.0, src_epoch=2000.0)
    assert R.sandbox_image_staleness("x:latest") is True


def test_staleness_false_when_image_newer_than_dockerfile(monkeypatch):
    # image built AFTER the Dockerfile → FRESH.
    _stub_dates(monkeypatch, created=2000.0, src_epoch=1000.0)
    assert R.sandbox_image_staleness("x:latest") is False


def test_staleness_false_when_equal(monkeypatch):
    # built at the same instant — not strictly older, so not stale.
    _stub_dates(monkeypatch, created=1500.0, src_epoch=1500.0)
    assert R.sandbox_image_staleness("x:latest") is False


def test_staleness_unknown_when_image_absent(monkeypatch):
    # No image (or docker down / unreadable Created) → UNKNOWN, not a false "stale".
    _stub_dates(monkeypatch, created=None, src_epoch=2000.0)
    assert R.sandbox_image_staleness("x:latest") is None


def test_staleness_unknown_when_dockerfile_absent(monkeypatch):
    # Installed wheel with no source checkout → can't locate the Dockerfile → UNKNOWN.
    _stub_dates(monkeypatch, created=2000.0, src_epoch=None)
    assert R.sandbox_image_staleness("x:latest") is None


def test_staleness_uses_default_image_when_none(monkeypatch):
    # image=None resolves via sandbox_image(); still tri-state.
    monkeypatch.setattr(R, "sandbox_image", lambda: "default:latest")
    seen = {}

    def _created(image):
        seen["image"] = image
        return 1000.0

    monkeypatch.setattr(R, "_image_created_epoch", _created)
    monkeypatch.setattr(R, "_toolchain_source_epoch", lambda: 2000.0)
    assert R.sandbox_image_staleness() is True
    assert seen["image"] == "default:latest"


# ── _image_created_epoch: docker output parsing + robustness ──────────────────────────


def _fake_run(monkeypatch, *, returncode=0, stdout="", raise_exc=None):
    """Stub subprocess.run AND shutil.which('docker') so _image_created_epoch runs offline.
    _image_created_epoch imports shutil locally, so patching the real shutil module covers it;
    subprocess is module-level on the runner."""
    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: "/usr/bin/docker")

    def _run(cmd, *a, **k):
        if raise_exc is not None:
            raise raise_exc
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(R.subprocess, "run", _run)


def test_created_epoch_parses_nanosecond_z_timestamp(monkeypatch):
    # docker emits RFC-3339 with nanoseconds + trailing Z; fromisoformat only takes µs.
    _fake_run(monkeypatch, stdout="2026-06-01T12:34:56.789012345Z\n")
    ts = R._image_created_epoch("x:latest")
    expected = datetime(2026, 6, 1, 12, 34, 56, 789012, tzinfo=timezone.utc).timestamp()
    assert ts == pytest.approx(expected, abs=1.0)


def test_created_epoch_parses_offset_timestamp(monkeypatch):
    # A non-Z explicit offset with fractional seconds also parses.
    _fake_run(monkeypatch, stdout="2026-06-01T12:34:56.500000+02:00\n")
    ts = R._image_created_epoch("x:latest")
    expected = datetime(2026, 6, 1, 12, 34, 56, 500000,
                        tzinfo=timezone(timedelta(hours=2))).timestamp()
    assert ts == pytest.approx(expected, abs=1.0)


def test_created_epoch_none_when_image_missing(monkeypatch):
    # `docker image inspect` on a missing image exits non-zero → None.
    _fake_run(monkeypatch, returncode=1, stdout="")
    assert R._image_created_epoch("x:latest") is None


def test_created_epoch_none_when_unparseable(monkeypatch):
    _fake_run(monkeypatch, stdout="not-a-date\n")
    assert R._image_created_epoch("x:latest") is None


def test_created_epoch_none_on_subprocess_error(monkeypatch):
    _fake_run(monkeypatch, raise_exc=OSError("docker exploded"))
    assert R._image_created_epoch("x:latest") is None


def test_created_epoch_none_without_docker_cli(monkeypatch):
    import shutil as _sh
    monkeypatch.setattr(_sh, "which", lambda name: None)
    assert R._image_created_epoch("x:latest") is None


# ── _toolchain_source_epoch: git COMMIT time (NOT filesystem mtime), Dockerfile only ──
# Using the commit time (via `git log -1 --format=%ct`) is deliberate: a fresh clone /
# worktree / checkout stamps every file's mtime with the checkout time, which would falsely
# read a good image as 'stale'. These tests pin that the helper reads the COMMIT time and
# degrades to None (never a false alarm) when git/source isn't available.


def _stub_git(monkeypatch, tmp_path, *, returncode=0, stdout="", raise_exc=None):
    """Create a real docker/sandbox.Dockerfile under tmp_path (so the is_file() guard passes),
    point repo_root there, and stub `git log -1 --format=%ct` via subprocess.run."""
    dock = tmp_path / "docker"
    dock.mkdir(exist_ok=True)
    (dock / "sandbox.Dockerfile").write_text("FROM scratch\n")
    monkeypatch.setattr("hexgraph.paths.repo_root", lambda: tmp_path)

    def _run(cmd, *a, **k):
        if raise_exc is not None:
            raise raise_exc
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(R.subprocess, "run", _run)


def test_toolchain_epoch_reads_git_commit_time(monkeypatch, tmp_path):
    # The Dockerfile's last-commit epoch (%ct) is returned as a float — NOT its mtime.
    _stub_git(monkeypatch, tmp_path, stdout="1717243200\n")
    assert R._toolchain_source_epoch() == pytest.approx(1717243200.0, abs=1.0)


def test_toolchain_epoch_ignores_filesystem_mtime(monkeypatch, tmp_path):
    # Even if the file's mtime is "now" (the fresh-clone trap), the helper reports the
    # COMMIT time, so a just-checked-out tree doesn't read stale.
    _stub_git(monkeypatch, tmp_path, stdout="1000000000\n")
    import os as _os
    _os.utime(tmp_path / "docker" / "sandbox.Dockerfile", None)  # mtime = now
    assert R._toolchain_source_epoch() == pytest.approx(1000000000.0, abs=1.0)


def test_toolchain_epoch_none_when_dockerfile_missing(monkeypatch, tmp_path):
    # Installed wheel with no source checkout → can't locate the Dockerfile → None.
    monkeypatch.setattr("hexgraph.paths.repo_root", lambda: tmp_path)
    assert R._toolchain_source_epoch() is None


def test_toolchain_epoch_none_when_not_a_git_checkout(monkeypatch, tmp_path):
    # git returns non-zero (not a repo / file untracked) → None, not a false alarm.
    _stub_git(monkeypatch, tmp_path, returncode=128, stdout="")
    assert R._toolchain_source_epoch() is None


def test_toolchain_epoch_none_when_git_output_empty(monkeypatch, tmp_path):
    _stub_git(monkeypatch, tmp_path, returncode=0, stdout="\n")
    assert R._toolchain_source_epoch() is None


def test_toolchain_epoch_never_raises(monkeypatch, tmp_path):
    # A git/subprocess explosion is swallowed → None.
    _stub_git(monkeypatch, tmp_path, raise_exc=OSError("git exploded"))
    assert R._toolchain_source_epoch() is None


def test_toolchain_epoch_never_raises_on_bad_repo_root(monkeypatch):
    def _boom():
        raise RuntimeError("nope")

    monkeypatch.setattr("hexgraph.paths.repo_root", _boom)
    assert R._toolchain_source_epoch() is None
