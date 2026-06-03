"""The sandbox container runs as a fixed unprivileged uid (1000), but the host process
creates the `/out` bind-mount dir as ITS OWN uid — equal to 1000 only by luck. On any
host whose uid != 1000 (a fresh account, a CI runner, a packaged service) the container
couldn't write `/out` and every extract/exec path died with EACCES. `_ensure_outdir_writable`
makes the host dir writable by uid 1000 without weakening the container. These lock the
three branches of that logic (no Docker needed)."""

import os

import pytest

from hexgraph.sandbox import runner as R


def test_user_flag_uses_the_sandbox_uid_constant():
    # The hardening must still pin the unprivileged 1000:1000 (the constant is just a
    # single source of truth shared with the out-dir fixup) — byte-identical output.
    r = R.SandboxRunner(image="x")
    args = r._hardening_args(allow_network=False, net_container=None,
                             resources=R.ResourceSpec(), secret=False)
    assert "--user" in args and f"{R.SANDBOX_UID}:{R.SANDBOX_GID}" in args
    assert (R.SANDBOX_UID, R.SANDBOX_GID) == (1000, 1000)


def test_noop_when_host_uid_is_the_sandbox_uid(tmp_path, monkeypatch):
    d = tmp_path / "out"
    d.mkdir(mode=0o755)
    monkeypatch.setattr(os, "getuid", lambda: R.SANDBOX_UID, raising=False)
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("should not chown"))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("should not chmod"))
    R._ensure_outdir_writable(d)  # owned by the container uid already → untouched


def test_chowns_to_1000_when_host_is_root(tmp_path, monkeypatch):
    d = tmp_path / "out"
    d.mkdir()
    monkeypatch.setattr(os, "getuid", lambda: 0, raising=False)
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("root must chown, not chmod"))
    R._ensure_outdir_writable(d)
    assert chowned == [(str(d), 1000, 1000)]


def test_widens_mode_when_host_uid_is_neither_root_nor_1000(tmp_path, monkeypatch):
    # The CI-runner / real-user case (uid 1001, 1005, …): can't chown (not root), so open
    # the per-run dir's mode enough for the unmatched container uid (mapped to "other").
    d = tmp_path / "out"
    d.mkdir(mode=0o700)
    monkeypatch.setattr(os, "getuid", lambda: 1001, raising=False)
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("cannot chown as non-root"))
    R._ensure_outdir_writable(d)
    assert (d.stat().st_mode & 0o777) == 0o777
