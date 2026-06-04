"""Unit tests for the persistent Ghidra project cache (engine.ghidra_project) + the
analyze-once / reuse decision in GhidraDecompiler. No Docker / no real Ghidra: the cache
logic is pure filesystem, and the cold-vs-warm probe invocation is checked with a fake
executor that records its argv.

What's asserted:
  * key derivation = content_hash + ghidra version (different binary OR version ⇒ different key)
  * reuse-vs-create: a slot is a MISS until a cold run persists a project, then a HIT
  * the probe gets the project mount on a cold call and reuses it on the warm call; the
    PROBE itself (run separately, see test_ghidra) chooses -import vs -process from the mount
  * bounded LRU eviction drops the oldest projects to stay under the cap and logs it
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hexgraph.engine import ghidra_project as gp


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_content_hash_matches_sha256(tmp_path):
    import hashlib

    f = _write(tmp_path / "bin", b"hello world")
    assert gp.content_hash(f) == hashlib.sha256(b"hello world").hexdigest()


def test_cache_key_depends_on_content_and_version(tmp_path):
    a = _write(tmp_path / "a", b"AAAA")
    b = _write(tmp_path / "b", b"BBBB")
    sha_a, sha_b = gp.content_hash(a), gp.content_hash(b)
    # Different binary ⇒ different key.
    assert gp.cache_key(sha_a, "12.1") != gp.cache_key(sha_b, "12.1")
    # Same binary, different Ghidra version ⇒ different key (a toolchain upgrade re-analyzes).
    assert gp.cache_key(sha_a, "12.1") != gp.cache_key(sha_a, "11.1.2")
    # Same binary + same version ⇒ stable, reusable key.
    assert gp.cache_key(sha_a, "12.1") == gp.cache_key(sha_a, "12.1")
    # The key embeds both halves.
    assert sha_a in gp.cache_key(sha_a, "12.1")
    assert "12.1" in gp.cache_key(sha_a, "12.1")


def test_unknown_version_is_safe_token(tmp_path):
    sha = gp.content_hash(_write(tmp_path / "a", b"X"))
    assert gp.cache_key(sha, None).endswith("__unknown")
    # A slash in a (hypothetical) version string never escapes the dir name.
    assert "/" not in gp.cache_key(sha, "a/b")


def test_resolve_miss_then_hit(tmp_path):
    """A fresh slot is a MISS; after a (simulated) cold run persists a project + meta it's a HIT."""
    data_dir = tmp_path / "proj"
    sha = gp.content_hash(_write(tmp_path / "a", b"DEADBEEF"))
    slot = gp.resolve(data_dir, sha, "12.1")
    assert not slot.exists()  # nothing analyzed yet
    slot.prepare()
    assert not slot.exists()  # an empty project dir is still a miss (half-written cold run)
    # Simulate the probe persisting an imported project, then the decompiler writing the marker.
    (slot.project_dir / "hexgraph.rep").mkdir(parents=True)
    (slot.project_dir / "hexgraph.gpr").write_text("project")
    slot.write_meta()
    assert slot.exists()  # now a HIT — subsequent calls reuse via -process
    meta = json.loads(slot.meta_path.read_text())
    assert meta["content_hash"] == sha and meta["program_name"] == gp.PROGRAM_NAME


def test_different_binary_gets_its_own_project(tmp_path):
    data_dir = tmp_path / "proj"
    sha_a = gp.content_hash(_write(tmp_path / "a", b"AAAA"))
    sha_b = gp.content_hash(_write(tmp_path / "b", b"BBBB"))
    sa = gp.resolve(data_dir, sha_a, "12.1")
    sb = gp.resolve(data_dir, sha_b, "12.1")
    assert sa.root != sb.root
    sa.prepare(); sb.prepare()
    assert sa.root.is_dir() and sb.root.is_dir() and sa.root.parent == sb.root.parent


def _make_project(root: Path, key: str, size_bytes: int, mtime: float) -> Path:
    d = root / key / "project"
    d.mkdir(parents=True)
    (d / "blob").write_bytes(b"\0" * size_bytes)
    os.utime(root / key, (mtime, mtime))
    return root / key


def test_eviction_drops_oldest_to_cap(tmp_path, caplog):
    data_dir = tmp_path / "proj"
    root = gp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    # Three projects of ~1 MiB each, increasing mtime (old → new).
    _make_project(root, "old__v", mb, mtime=1000)
    _make_project(root, "mid__v", mb, mtime=2000)
    _make_project(root, "new__v", mb, mtime=3000)
    # Cap at 2 MiB ⇒ must evict the single oldest to get under 2 MiB (3→2).
    with caplog.at_level("INFO"):
        evicted = gp.evict_to_cap(data_dir, cap_mb=2)
    assert evicted == ["old__v"]
    assert not (root / "old__v").exists()
    assert (root / "mid__v").exists() and (root / "new__v").exists()
    assert any("evicted old__v" in r.message for r in caplog.records)


def test_eviction_never_drops_kept_slot(tmp_path):
    data_dir = tmp_path / "proj"
    root = gp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    _make_project(root, "old__v", mb, mtime=1000)   # oldest, but it's the one we're using
    _make_project(root, "new__v", mb, mtime=3000)
    evicted = gp.evict_to_cap(data_dir, cap_mb=1, keep="old__v")
    # Over cap, oldest is old__v — but it's kept, so new__v goes instead.
    assert evicted == ["new__v"]
    assert (root / "old__v").exists()


def test_eviction_disabled_when_cap_nonpositive(tmp_path):
    data_dir = tmp_path / "proj"
    root = gp.cache_root(data_dir)
    root.mkdir(parents=True)
    _make_project(root, "a__v", 4 * 1024 * 1024, mtime=1000)
    assert gp.evict_to_cap(data_dir, cap_mb=0) == []
    assert (root / "a__v").exists()


def test_no_eviction_when_under_cap(tmp_path):
    data_dir = tmp_path / "proj"
    root = gp.cache_root(data_dir)
    root.mkdir(parents=True)
    _make_project(root, "a__v", 512 * 1024, mtime=1000)
    assert gp.evict_to_cap(data_dir, cap_mb=10) == []
    assert (root / "a__v").exists()


# --- the decompiler's cold-vs-warm decision (probe argv) ----------------------------------

class _RecordingExecutor:
    """Records project_mount per call and returns a canned payload (no Docker)."""
    def __init__(self):
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, project_mount=None):
        self.calls.append({"probe": probe, "extra_args": extra_args, "project_mount": project_mount})
        return {"tool": "ghidra_probe", "functions": ["main", "other"], "focus": None}


class _Project:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)


def test_decompiler_threads_project_mount_and_persists_marker(tmp_path, monkeypatch):
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    # Force version resolution offline + deterministic (no Docker --check).
    monkeypatch.setattr(gp, "ghidra_version_for_image", lambda *a, **k: "12.1")

    artifact = _write(tmp_path / "bin", b"a real-ish binary")
    project = _Project(tmp_path / "data")
    fake = _RecordingExecutor()
    dec = GhidraDecompiler(runner=fake)

    # COLD call (function A): the mount is threaded to the probe, and afterward the slot's
    # marker exists so the NEXT call is recognized as warm.
    dec.decompile(str(artifact), "funcA", project=project)
    assert len(fake.calls) == 1
    mount = fake.calls[0]["project_mount"]
    assert mount is not None and Path(mount).is_dir()
    assert fake.calls[0]["extra_args"] == ["funcA"]
    sha = gp.content_hash(artifact)
    slot = gp.resolve(project.data_dir, sha, "12.1")
    assert slot.meta_path.is_file()  # marker recorded → reuse on the next call

    # WARM call (DIFFERENT function B): same artifact ⇒ SAME mount reused (analyze once).
    dec.decompile(str(artifact), "funcB", project=project)
    assert len(fake.calls) == 2
    assert fake.calls[1]["project_mount"] == mount
    assert fake.calls[1]["extra_args"] == ["funcB"]


def test_decompiler_no_project_no_mount(tmp_path):
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    fake = _RecordingExecutor()
    GhidraDecompiler(runner=fake).decompile(str(_write(tmp_path / "b", b"x")), "main")
    assert fake.calls[0]["project_mount"] is None  # no project ⇒ throwaway path


@pytest.mark.parametrize("version", ["12.1", "11.1.2"])
def test_decompiler_version_partitions_cache(tmp_path, monkeypatch, version):
    """A Ghidra version change routes to a DIFFERENT mount (so an upgrade re-analyzes)."""
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    monkeypatch.setattr(gp, "ghidra_version_for_image", lambda *a, **k: version)
    artifact = _write(tmp_path / "bin", b"same bytes")
    project = _Project(tmp_path / "data")
    fake = _RecordingExecutor()
    GhidraDecompiler(runner=fake).decompile(str(artifact), "f", project=project)
    assert version.replace(".", ".") in fake.calls[0]["project_mount"]
