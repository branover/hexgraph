"""Proactive sandbox-image staleness detection (`runner.sandbox_image_staleness` and the
setup-wizard warning that surfaces it).

The gap this closes (seen in the Phase-5 eval): an "up-to-date build" (venv + SPA) can
still run a STALE `hexgraph-sandbox` image that predates a toolchain change — the image
silently lacked FLOSS/YARA and `yara_sweep` returned 0 matches with no error.
`meta_check_features` catches that REACTIVELY (it probes each dep in the image). These tests
cover the PROACTIVE companion: compare the image's build date against the Dockerfile's mtime
and warn. All Docker calls are mocked — no Docker, no image, no network needed.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone

import pytest

from hexgraph.sandbox import runner as R


# ── the core tri-state comparison ────────────────────────────────────────────────────


def _stub_dates(monkeypatch, *, created, mtime):
    """Stub the two halves of the comparison directly (no Docker / no filesystem).
    `created`/`mtime` are POSIX timestamps or None."""
    monkeypatch.setattr(R, "_image_created_epoch", lambda image: created)
    monkeypatch.setattr(R, "_toolchain_source_mtime", lambda: mtime)


def test_staleness_true_when_image_older_than_dockerfile(monkeypatch):
    # image built BEFORE the Dockerfile's last edit → STALE.
    _stub_dates(monkeypatch, created=1000.0, mtime=2000.0)
    assert R.sandbox_image_staleness("x:latest") is True


def test_staleness_false_when_image_newer_than_dockerfile(monkeypatch):
    # image built AFTER the Dockerfile → FRESH.
    _stub_dates(monkeypatch, created=2000.0, mtime=1000.0)
    assert R.sandbox_image_staleness("x:latest") is False


def test_staleness_false_when_equal(monkeypatch):
    # built at the same instant — not strictly older, so not stale.
    _stub_dates(monkeypatch, created=1500.0, mtime=1500.0)
    assert R.sandbox_image_staleness("x:latest") is False


def test_staleness_unknown_when_image_absent(monkeypatch):
    # No image (or docker down / unreadable Created) → UNKNOWN, not a false "stale".
    _stub_dates(monkeypatch, created=None, mtime=2000.0)
    assert R.sandbox_image_staleness("x:latest") is None


def test_staleness_unknown_when_dockerfile_absent(monkeypatch):
    # Installed wheel with no source checkout → can't locate the Dockerfile → UNKNOWN.
    _stub_dates(monkeypatch, created=2000.0, mtime=None)
    assert R.sandbox_image_staleness("x:latest") is None


def test_staleness_uses_default_image_when_none(monkeypatch):
    # image=None resolves via sandbox_image(); still tri-state.
    monkeypatch.setattr(R, "sandbox_image", lambda: "default:latest")
    seen = {}

    def _created(image):
        seen["image"] = image
        return 1000.0

    monkeypatch.setattr(R, "_image_created_epoch", _created)
    monkeypatch.setattr(R, "_toolchain_source_mtime", lambda: 2000.0)
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


# ── _toolchain_source_mtime: excludes probes, locates the Dockerfile ──────────────────


def test_toolchain_mtime_reads_real_dockerfile():
    # In a source checkout the Dockerfile exists, so the mtime is a real float.
    mt = R._toolchain_source_mtime()
    assert mt is None or isinstance(mt, float)


def test_toolchain_mtime_none_when_dockerfile_missing(monkeypatch, tmp_path):
    # Point repo_root at a dir with no docker/sandbox.Dockerfile → None (the wheel case).
    monkeypatch.setattr("hexgraph.paths.repo_root", lambda: tmp_path)
    assert R._toolchain_source_mtime() is None


def test_toolchain_mtime_reflects_dockerfile_only(monkeypatch, tmp_path):
    # The mtime tracks docker/sandbox.Dockerfile specifically (probes are NOT in the
    # comparison — they're mounted at run time, no rebuild needed).
    dock = tmp_path / "docker"
    dock.mkdir()
    df = dock / "sandbox.Dockerfile"
    df.write_text("FROM scratch\n")
    import os as _os
    _os.utime(df, (4242.0, 4242.0))
    monkeypatch.setattr("hexgraph.paths.repo_root", lambda: tmp_path)
    assert R._toolchain_source_mtime() == pytest.approx(4242.0, abs=1.0)


def test_toolchain_mtime_never_raises(monkeypatch):
    # An exploding repo_root is swallowed → None, never propagates.
    def _boom():
        raise RuntimeError("nope")

    monkeypatch.setattr("hexgraph.paths.repo_root", _boom)
    assert R._toolchain_source_mtime() is None
