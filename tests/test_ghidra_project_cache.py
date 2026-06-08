"""Unit tests for the persistent Ghidra project cache (engine.re.ghidra_project) + the
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
import time
from pathlib import Path

import pytest

from hexgraph.engine.re import ghidra_project as gp


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


def test_eviction_skips_in_use_locked_slot(tmp_path):
    """A slot another process holds the lock on (mid-analysis) must NOT be evicted, even when it
    is the over-cap LRU victim — rmtree'ing it would corrupt the in-flight Ghidra project and
    unlink the lock file out from under the holder (the cross-process corruption the lock prevents).
    Held cross-PROCESS so it's a genuine flock contention, not just a same-process advisory lock."""
    import subprocess
    import sys
    import textwrap

    data_dir = tmp_path / "proj"
    root = gp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    victim = gp.resolve(data_dir, "aaaa", "v"); victim.prepare()
    (victim.project_dir / "blob").write_bytes(b"\0" * mb)
    os.utime(victim.root, (1000, 1000))  # oldest ⇒ would be the LRU victim
    keeper = gp.resolve(data_dir, "bbbb", "v"); keeper.prepare()
    (keeper.project_dir / "blob").write_bytes(b"\0" * mb)
    os.utime(keeper.root, (3000, 3000))

    # Hold the victim's lock in a separate PROCESS while we evict.
    holder_src = textwrap.dedent(f"""
        import fcntl, os, time
        fd = os.open({str(victim.lock_path)!r}, os.O_CREAT | os.O_RDWR, 0o666)
        fcntl.flock(fd, fcntl.LOCK_EX)
        print("locked", flush=True)
        time.sleep(5)
    """)
    holder = subprocess.Popen([sys.executable, "-c", holder_src],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        # Cap at 1 MiB, keep the keeper: the only evictable-by-LRU slot is the locked victim.
        evicted = gp.evict_to_cap(data_dir, cap_mb=1, keep=keeper.root.name)
        assert evicted == []                       # the in-use slot was spared
        assert victim.root.exists()                # NOT wiped
        assert victim.lock_path.exists()           # lock file intact for the holder
    finally:
        holder.terminate()
        holder.wait(timeout=10)


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
    """Records project_mount per call and returns a canned payload (no Docker). When a mount is
    threaded it SIMULATES THE PROBE committing the warm marker on the cold run (the probe owns the
    marker now, not the host) so a subsequent call resolves as warm."""
    def __init__(self):
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, project_mount=None):
        warm = False
        if project_mount is not None:
            proj_dir = Path(project_mount) / "project"
            marker = Path(project_mount) / "meta.json"
            warm = marker.is_file() and proj_dir.is_dir() and any(proj_dir.iterdir())
            if not warm:
                # Simulate a successful COLD import: a non-empty project + the committed marker
                # written as the last step (mirrors ghidra_probe._commit_marker).
                proj_dir.mkdir(parents=True, exist_ok=True)
                (proj_dir / "hexgraph.gpr").write_text("project")
                marker.write_text(json.dumps({"program_name": "hexgraph"}))
        self.calls.append({"probe": probe, "extra_args": extra_args,
                           "project_mount": project_mount, "cached": warm})
        return {"tool": "ghidra_probe", "functions": ["main", "other"], "focus": None,
                "cached": warm}


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

    # COLD call (function A): the mount is threaded to the probe, the probe commits the marker,
    # and afterward the slot's marker exists so the NEXT call is recognized as warm.
    out_cold = dec.decompile(str(artifact), "funcA", project=project)
    assert len(fake.calls) == 1
    mount = fake.calls[0]["project_mount"]
    assert mount is not None and Path(mount).is_dir()
    assert fake.calls[0]["extra_args"] == ["funcA"]
    assert out_cold["cached"] is False  # cold run, freshly imported
    sha = gp.content_hash(artifact)
    slot = gp.resolve(project.data_dir, sha, "12.1")
    assert slot.meta_path.is_file()  # marker committed by the probe → reuse on the next call
    assert slot.exists()             # the authoritative warm signal is now true

    # WARM call (DIFFERENT function B): same artifact ⇒ SAME mount reused (analyze once).
    out_warm = dec.decompile(str(artifact), "funcB", project=project)
    assert len(fake.calls) == 2
    assert fake.calls[1]["project_mount"] == mount
    assert fake.calls[1]["extra_args"] == ["funcB"]
    assert out_warm["cached"] is True  # reused the persistent project (-process, no re-analysis)


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


# --- the atomic warm/cold marker (BLOCKING #2 / SHOULD-FIX #3) -----------------------------

def test_exists_requires_committed_marker(tmp_path):
    """exists() is the single authoritative warm signal: a non-empty project dir WITHOUT a
    committed meta.json reads as a MISS (half-written cold run), with it reads as a HIT."""
    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    # A non-empty project dir but no marker = a crashed cold import → still cold.
    (slot.project_dir / "hexgraph.gpr").write_text("partial")
    assert not slot.exists()
    # Commit the marker → now warm.
    slot.write_meta()
    assert slot.exists()


def test_exists_rejects_corrupt_marker(tmp_path):
    """A truncated/corrupt marker (a crash mid-write, were it not atomic) ⇒ cold."""
    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    (slot.project_dir / "hexgraph.gpr").write_text("x")
    slot.meta_path.write_text("{ not valid json")
    assert not slot.exists()


def test_write_meta_is_atomic_no_tmp_left(tmp_path):
    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    slot.write_meta()
    assert slot.meta_path.is_file()
    assert not slot.meta_path.with_suffix(".json.tmp").exists()  # tmp renamed away


def test_clear_project_wipes_partial_slot(tmp_path):
    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    (slot.project_dir / "hexgraph.gpr").write_text("partial")
    slot.meta_path.write_text("stale")
    slot.clear_project()
    assert slot.project_dir.is_dir()
    assert not any(slot.project_dir.iterdir())  # emptied
    assert not slot.meta_path.exists()           # stale marker dropped


def test_decompiler_redoes_cold_on_partial_slot(tmp_path, monkeypatch):
    """A non-empty slot with NO committed marker must NOT be opened warm — the decompiler clears
    it and the (faked) probe re-imports cold, then commits the marker so the next call is warm."""
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    monkeypatch.setattr(gp, "ghidra_version_for_image", lambda *a, **k: "12.1")
    artifact = _write(tmp_path / "bin", b"a binary")
    project = _Project(tmp_path / "data")
    sha = gp.content_hash(artifact)
    slot = gp.resolve(project.data_dir, sha, "12.1")
    slot.prepare()
    # Pre-seed a HALF-WRITTEN slot: non-empty project, no marker.
    (slot.project_dir / "leftover").write_text("from a crashed import")
    assert not slot.exists()

    fake = _RecordingExecutor()
    out = GhidraDecompiler(runner=fake).decompile(str(artifact), "f", project=project)
    assert out["cached"] is False               # treated as COLD, not warm
    assert slot.exists()                         # now committed → warm next time
    assert not (slot.project_dir / "leftover").exists()  # the partial was wiped


# --- the cross-process slot lock (BLOCKING #1) --------------------------------------------

def test_lock_serializes_concurrent_holders(tmp_path):
    """Two threads contending on one slot's lock never overlap inside the critical section."""
    import threading

    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    inside = 0
    max_concurrent = 0
    overlaps = 0
    lk = threading.Lock()
    barrier = threading.Barrier(2)

    def worker():
        nonlocal inside, max_concurrent, overlaps
        barrier.wait()
        with slot.lock(timeout=10) as ok:
            assert ok
            with lk:
                inside += 1
                max_concurrent = max(max_concurrent, inside)
                if inside > 1:
                    overlaps += 1
            time.sleep(0.2)
            with lk:
                inside -= 1

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert overlaps == 0
    assert max_concurrent == 1


def test_lock_different_slots_run_concurrently(tmp_path):
    """Two DIFFERENT slots have different lock files → no serialization (they overlap)."""
    import threading

    a = gp.resolve(tmp_path / "data", "aaaa", "12.1"); a.prepare()
    b = gp.resolve(tmp_path / "data", "bbbb", "12.1"); b.prepare()
    inside = 0
    max_concurrent = 0
    lk = threading.Lock()
    barrier = threading.Barrier(2)

    def worker(slot):
        nonlocal inside, max_concurrent
        barrier.wait()
        with slot.lock(timeout=10) as ok:
            assert ok
            with lk:
                inside += 1
                max_concurrent = max(max_concurrent, inside)
            time.sleep(0.3)
            with lk:
                inside -= 1

    ta = threading.Thread(target=worker, args=(a,))
    tb = threading.Thread(target=worker, args=(b,))
    ta.start(); tb.start(); ta.join(); tb.join()
    assert max_concurrent == 2  # different locks → ran at the same time


def test_lock_timeout_yields_false(tmp_path):
    """When the slot is already locked by ANOTHER PROCESS, a contender times out and yields
    False (the caller then falls back to a throwaway project)."""
    import subprocess
    import sys
    import textwrap

    slot = gp.resolve(tmp_path / "data", "deadbeef", "12.1")
    slot.prepare()
    # Hold the lock in a separate PROCESS (cross-process, not just cross-thread) for 5s.
    holder_src = textwrap.dedent(f"""
        import fcntl, os, sys, time
        fd = os.open({str(slot.lock_path)!r}, os.O_CREAT | os.O_RDWR, 0o666)
        fcntl.flock(fd, fcntl.LOCK_EX)
        print("locked", flush=True)
        time.sleep(5)
    """)
    holder = subprocess.Popen([sys.executable, "-c", holder_src],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"  # wait until it holds the lock
        t0 = time.monotonic()
        with slot.lock(timeout=0.5, poll=0.05) as ok:
            assert ok is False  # timed out — fall back to throwaway
        assert time.monotonic() - t0 >= 0.5  # actually waited the timeout
    finally:
        holder.terminate()
        holder.wait(timeout=10)


def test_decompiler_falls_back_to_throwaway_on_lock_timeout(tmp_path, monkeypatch):
    """On a lock-acquire timeout the decompiler runs an UNCACHED throwaway probe (no mount) and
    does NOT touch the cached slot."""
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    monkeypatch.setattr(gp, "ghidra_version_for_image", lambda *a, **k: "12.1")
    artifact = _write(tmp_path / "bin", b"a binary")
    project = _Project(tmp_path / "data")

    # Force the lock to "time out" by patching the slot's lock() to yield False.
    import contextlib

    @contextlib.contextmanager
    def _never_acquire(*a, **k):
        yield False

    monkeypatch.setattr(gp.GhidraProject, "lock", _never_acquire)
    fake = _RecordingExecutor()
    out = GhidraDecompiler(runner=fake).decompile(str(artifact), "f", project=project)
    # Ran the throwaway path: NO project_mount threaded.
    assert fake.calls[0]["project_mount"] is None
    assert out["cached"] is False
    # The cached slot was left untouched (no marker committed).
    sha = gp.content_hash(artifact)
    assert not gp.resolve(project.data_dir, sha, "12.1").exists()
