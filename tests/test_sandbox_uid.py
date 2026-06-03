"""The sandbox container runs as a fixed unprivileged uid (1000), but the host process
creates the `/out` bind-mount dir as ITS OWN uid/gid — equal to 1000 only by luck. On any
host whose uid != 1000 (a fresh account, a CI runner, a packaged service) the container
couldn't write `/out` and every extract/exec path died with EACCES. The fix grants access
by uid/gid WITHOUT opening the dir to other local users: `--group-add <host gid>` on the
container + a 0o770 (group-writable, no "other") out-dir. These lock that logic — no Docker."""

import os

import pytest

from hexgraph.sandbox import runner as R


def _args(monkeypatch, *, euid, egid=4242):
    """`_hardening_args` with the host's effective uid/gid stubbed."""
    monkeypatch.setattr(os, "geteuid", lambda: euid, raising=False)
    monkeypatch.setattr(os, "getegid", lambda: egid, raising=False)
    return R.SandboxRunner(image="x")._hardening_args(
        allow_network=False, net_container=None, resources=R.ResourceSpec(), secret=False)


# ── the container --user + --group-add ──────────────────────────────────────────────

def test_user_flag_always_pins_unprivileged_1000(monkeypatch):
    # Byte-identical hardening: the container is ALWAYS --user 1000:1000, never root,
    # regardless of the host uid. The constant is just a single source of truth.
    for euid in (0, 1000, 1001):
        args = _args(monkeypatch, euid=euid)
        assert "--user" in args and f"{R.SANDBOX_UID}:{R.SANDBOX_GID}" in args
    assert (R.SANDBOX_UID, R.SANDBOX_GID) == (1000, 1000)


def test_group_add_only_for_nonroot_non1000_host(monkeypatch):
    # uid 1000 → owner of /out already, no supplementary group.
    assert "--group-add" not in _args(monkeypatch, euid=1000)
    # root → chowns /out to 1000 instead; must NOT add the root group to the container.
    assert "--group-add" not in _args(monkeypatch, euid=0, egid=0)
    # any other uid (CI runner / real user) → add the host's OWN gid so it can group-write.
    args = _args(monkeypatch, euid=1001, egid=1001)
    assert "--group-add" in args and "1001" in args


# ── the host-side /out dir fixup ────────────────────────────────────────────────────

def test_noop_when_host_uid_is_the_sandbox_uid(tmp_path, monkeypatch):
    d = tmp_path / "out"
    d.mkdir(mode=0o755)
    monkeypatch.setattr(os, "geteuid", lambda: R.SANDBOX_UID, raising=False)
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("should not chown"))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("should not chmod"))
    R._ensure_outdir_writable(d)  # owned by the container uid already → untouched


def test_chowns_to_1000_when_host_is_root(tmp_path, monkeypatch):
    d = tmp_path / "out"
    d.mkdir()
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowned.append((str(p), u, g)))
    monkeypatch.setattr(os, "chmod", lambda *a, **k: pytest.fail("root must chown, not chmod"))
    R._ensure_outdir_writable(d)
    assert chowned == [(str(d), 1000, 1000)]


def test_group_writable_no_other_when_host_uid_is_neither_root_nor_1000(tmp_path, monkeypatch):
    # The CI-runner / real-user case (uid 1001, 1005, …): can't chown (not root), so make
    # the per-run dir group-writable (0o770) — NEVER world-writable (0o777 would expose the
    # extracted firmware / poc / fuzz output, since the real out-dir roots aren't private).
    d = tmp_path / "out"
    d.mkdir(mode=0o700)
    monkeypatch.setattr(os, "geteuid", lambda: 1001, raising=False)
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("cannot chown as non-root"))
    R._ensure_outdir_writable(d)
    mode = d.stat().st_mode & 0o777
    assert mode == 0o770, oct(mode)
    assert not (mode & 0o007), "the out-dir must not be accessible to 'other'"
