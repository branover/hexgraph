"""Unit tests for the persistent radare2 project cache (engine.re.r2_project) + the analyze-once /
reuse decision in R2Decompiler. No Docker / no real r2: the cache logic is pure filesystem, and the
cold-vs-warm probe invocation is checked with a fake executor that records its argv and SIMULATES
the r2 probe committing the warm marker on a cold run. The real end-to-end save/reload through the
sandbox is exercised separately (a manual sandbox run during development, and by the live-tests CI).

Mirrors tests/test_ghidra_project_cache.py — r2_project deliberately carries its own copy of the
slot / lock / eviction machinery, so it gets its own coverage.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from hexgraph.engine.re import ghidra_project as gp
from hexgraph.engine.re import r2_project as rp


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_content_hash_is_reused_from_ghidra(tmp_path):
    """r2_project reuses the (memoized) sha256 hasher from ghidra_project — one source of truth."""
    import hashlib

    f = _write(tmp_path / "bin", b"hello world")
    assert rp.content_hash is gp.content_hash
    assert rp.content_hash(f) == hashlib.sha256(b"hello world").hexdigest()


def test_cache_key_depends_on_content_and_version(tmp_path):
    a = _write(tmp_path / "a", b"AAAA")
    b = _write(tmp_path / "b", b"BBBB")
    sha_a, sha_b = rp.content_hash(a), rp.content_hash(b)
    assert rp.cache_key(sha_a, "6.1.4") != rp.cache_key(sha_b, "6.1.4")   # different binary
    assert rp.cache_key(sha_a, "6.1.4") != rp.cache_key(sha_a, "6.0.0")   # r2 upgrade re-analyzes
    assert rp.cache_key(sha_a, "6.1.4") == rp.cache_key(sha_a, "6.1.4")   # stable, reusable
    assert sha_a in rp.cache_key(sha_a, "6.1.4") and "6.1.4" in rp.cache_key(sha_a, "6.1.4")


def test_unknown_version_is_safe_token(tmp_path):
    sha = rp.content_hash(_write(tmp_path / "a", b"X"))
    assert rp.cache_key(sha, None).endswith("__unknown")
    assert "/" not in rp.cache_key(sha, "a/b")   # a slash never escapes the dir name


def test_resolve_miss_then_hit(tmp_path):
    """A fresh slot is a MISS; after a (simulated) cold run persists the NAMED project + marker
    it's a HIT. exists() keys on the named-project dir (project/hexgraph), not the parent."""
    data_dir = tmp_path / "proj"
    sha = rp.content_hash(_write(tmp_path / "a", b"DEADBEEF"))
    slot = rp.resolve(data_dir, sha, "6.1.4")
    assert not slot.exists()
    slot.prepare()
    assert not slot.exists()   # empty project dir is still a miss
    # An empty dir.projects (no named project yet) is still a miss even with a marker.
    slot.named_project_dir.mkdir(parents=True)
    (slot.named_project_dir / "rc.r2").write_text("project")
    slot.write_meta()
    assert slot.exists()
    meta = json.loads(slot.meta_path.read_text())
    assert meta["content_hash"] == sha and meta["program_name"] == rp.PROJECT_NAME


def test_exists_requires_named_project_not_just_marker(tmp_path):
    """A committed marker with an EMPTY named-project dir (a save that wrote the marker but no
    project — can't happen in practice, but exists() must be strict) reads as a MISS."""
    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
    slot.prepare()
    slot.write_meta()                       # marker but no named project
    assert not slot.exists()
    slot.named_project_dir.mkdir(parents=True)
    (slot.named_project_dir / "rc.r2").write_text("x")
    assert slot.exists()


def test_exists_rejects_corrupt_marker(tmp_path):
    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
    slot.prepare()
    slot.named_project_dir.mkdir(parents=True)
    (slot.named_project_dir / "rc.r2").write_text("x")
    slot.meta_path.write_text("{ not valid json")
    assert not slot.exists()


def test_write_meta_is_atomic_no_tmp_left(tmp_path):
    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
    slot.prepare()
    slot.write_meta()
    assert slot.meta_path.is_file()
    assert not slot.meta_path.with_suffix(".json.tmp").exists()


def test_clear_project_wipes_partial_slot(tmp_path):
    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
    slot.prepare()
    slot.named_project_dir.mkdir(parents=True)
    (slot.named_project_dir / "rc.r2").write_text("partial")
    slot.meta_path.write_text("stale")
    slot.clear_project()
    assert slot.project_dir.is_dir() and not any(slot.project_dir.iterdir())
    assert not slot.meta_path.exists()


# --- eviction (explicit-only, mirrors ghidra_project) --------------------------------------

def _make_project(root: Path, key: str, size_bytes: int, mtime: float) -> Path:
    d = root / key / "project" / "hexgraph"
    d.mkdir(parents=True)
    (d / "rc.r2").write_bytes(b"\0" * size_bytes)
    os.utime(root / key, (mtime, mtime))
    return root / key


def test_eviction_drops_oldest_to_cap(tmp_path, caplog):
    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    _make_project(root, "old__v", mb, mtime=1000)
    _make_project(root, "mid__v", mb, mtime=2000)
    _make_project(root, "new__v", mb, mtime=3000)
    with caplog.at_level("INFO"):
        evicted = rp.evict_to_cap(data_dir, cap_mb=2)
    assert evicted == ["old__v"]
    assert not (root / "old__v").exists()
    assert (root / "mid__v").exists() and (root / "new__v").exists()
    assert any("evicted old__v" in r.message for r in caplog.records)


def test_eviction_never_drops_kept_slot(tmp_path):
    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    _make_project(root, "old__v", mb, mtime=1000)   # oldest, but the one in use
    _make_project(root, "new__v", mb, mtime=3000)
    assert rp.evict_to_cap(data_dir, cap_mb=1, keep="old__v") == ["new__v"]
    assert (root / "old__v").exists()


def test_eviction_disabled_when_cap_nonpositive(tmp_path):
    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    _make_project(root, "a__v", 4 * 1024 * 1024, mtime=1000)
    assert rp.evict_to_cap(data_dir, cap_mb=0) == []
    assert (root / "a__v").exists()


def test_no_eviction_when_under_cap(tmp_path):
    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    _make_project(root, "a__v", 512 * 1024, mtime=1000)
    assert rp.evict_to_cap(data_dir, cap_mb=10) == []
    assert (root / "a__v").exists()


def test_eviction_skips_in_use_locked_slot(tmp_path):
    """A slot another PROCESS holds the lock on (mid-analysis) is spared even as the LRU victim."""
    import subprocess
    import sys
    import textwrap

    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    mb = 1024 * 1024
    victim = rp.resolve(data_dir, "aaaa", "v"); victim.prepare()
    (victim.project_dir / "blob").write_bytes(b"\0" * mb)
    os.utime(victim.root, (1000, 1000))
    keeper = rp.resolve(data_dir, "bbbb", "v"); keeper.prepare()
    (keeper.project_dir / "blob").write_bytes(b"\0" * mb)
    os.utime(keeper.root, (3000, 3000))

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
        assert rp.evict_to_cap(data_dir, cap_mb=1, keep=keeper.root.name) == []
        assert victim.root.exists() and victim.lock_path.exists()
    finally:
        holder.terminate()
        holder.wait(timeout=10)


def test_cache_size_mb_reports_total(tmp_path):
    data_dir = tmp_path / "proj"
    root = rp.cache_root(data_dir)
    root.mkdir(parents=True)
    _make_project(root, "a__v", 3 * 1024 * 1024, mtime=1000)
    _make_project(root, "b__v", 2 * 1024 * 1024, mtime=2000)
    assert rp.cache_size_mb(data_dir) == 5
    assert rp.cache_size_mb(tmp_path / "empty") == 0


# --- the decompiler's cold-vs-warm decision (probe argv + mount) ---------------------------

class _RecordingExecutor:
    """Records project_mount per call, returns a canned payload (no Docker). When a mount is
    threaded it SIMULATES the r2 probe committing the warm marker + named project on the cold run
    (the probe owns the marker), so a subsequent call resolves as warm."""
    def __init__(self):
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, project_mount=None):
        warm = False
        if project_mount is not None:
            named = Path(project_mount) / "project" / "hexgraph"
            marker = Path(project_mount) / "meta.json"
            warm = marker.is_file() and named.is_dir() and any(named.iterdir())
            if not warm:
                named.mkdir(parents=True, exist_ok=True)
                (named / "rc.r2").write_text("project")
                marker.write_text(json.dumps({"program_name": "hexgraph"}))
        self.calls.append({"probe": probe, "extra_args": extra_args,
                           "project_mount": project_mount, "cached": warm})
        fn = (extra_args or [None])[0]
        focus = None
        if fn and not str(fn).startswith("--"):
            focus = {"name": fn, "address": "0x1000", "pseudocode": "x"}
        return {"tool": "decompile_probe", "functions": ["main", "other"],
                "focus": focus, "cached": warm}


class _Project:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)


def _r2dec(monkeypatch, runner):
    from hexgraph.sandbox.decompiler import R2Decompiler

    monkeypatch.setattr(rp, "r2_version_for_image", lambda *a, **k: "6.1.4")
    return R2Decompiler(runner=runner)


def test_decompiler_threads_project_mount_and_persists_marker(tmp_path, monkeypatch):
    artifact = _write(tmp_path / "bin", b"a real-ish binary")
    project = _Project(tmp_path / "data")
    fake = _RecordingExecutor()
    dec = _r2dec(monkeypatch, fake)

    # COLD (function A): the mount is threaded; the probe commits the marker; the slot is now warm.
    out_cold = dec.decompile(str(artifact), "funcA", project=project)
    assert len(fake.calls) == 1
    mount = fake.calls[0]["project_mount"]
    assert mount is not None and Path(mount).is_dir()
    assert fake.calls[0]["extra_args"] == ["funcA"]
    assert out_cold["cached"] is False
    sha = rp.content_hash(artifact)
    slot = rp.resolve(project.data_dir, sha, "6.1.4")
    assert slot.exists()

    # WARM (DIFFERENT function B): SAME mount reused, no re-analysis.
    out_warm = dec.decompile(str(artifact), "funcB", project=project)
    assert len(fake.calls) == 2
    assert fake.calls[1]["project_mount"] == mount
    assert fake.calls[1]["extra_args"] == ["funcB"]
    assert out_warm["cached"] is True


def test_decompiler_no_project_no_mount(tmp_path, monkeypatch):
    fake = _RecordingExecutor()
    _r2dec(monkeypatch, fake).decompile(str(_write(tmp_path / "b", b"x")), "main")
    assert fake.calls[0]["project_mount"] is None   # no project ⇒ throwaway aaa-per-call


def test_decompiler_reanalyze_forces_cold(tmp_path, monkeypatch):
    """After a warm slot exists, reanalyze=True drops it (force_cold) so the run re-analyzes cold
    (and passes --reanalyze to the probe for the deeper aaaa pass)."""
    artifact = _write(tmp_path / "bin", b"bytes")
    project = _Project(tmp_path / "data")
    fake = _RecordingExecutor()
    dec = _r2dec(monkeypatch, fake)

    dec.decompile(str(artifact), "f", project=project)                       # cold → warm
    assert fake.calls[-1]["cached"] is False
    assert dec.decompile(str(artifact), "f", project=project)["cached"] is True   # warm
    out = dec.decompile(str(artifact), "f", project=project, reanalyze=True)      # forced cold
    assert out["cached"] is False
    assert "--reanalyze" in fake.calls[-1]["extra_args"]


def test_decompiler_never_auto_evicts(tmp_path, monkeypatch):
    """Resolving/using a slot for a decompile must NEVER trigger eviction — a persisted analysis
    is durable and reclaimed only via `hexgraph prune --r2-cache-mb`."""
    evicts: list = []
    monkeypatch.setattr(rp, "evict_to_cap", lambda *a, **k: evicts.append((a, k)) or [])
    artifact = _write(tmp_path / "bin", b"durable bytes")
    project = _Project(tmp_path / "data")
    _r2dec(monkeypatch, _RecordingExecutor()).decompile(str(artifact), "f", project=project)
    assert evicts == []


def test_decompiler_redoes_cold_on_partial_slot(tmp_path, monkeypatch):
    """A non-empty slot with NO committed marker must NOT be opened warm — the decompiler clears it
    and the (faked) probe re-analyzes cold, then commits the marker."""
    artifact = _write(tmp_path / "bin", b"a binary")
    project = _Project(tmp_path / "data")
    sha = rp.content_hash(artifact)
    slot = rp.resolve(project.data_dir, sha, "6.1.4")
    slot.prepare()
    (slot.project_dir / "leftover").write_text("from a crashed save")
    assert not slot.exists()

    fake = _RecordingExecutor()
    out = _r2dec(monkeypatch, fake).decompile(str(artifact), "f", project=project)
    assert out["cached"] is False
    assert slot.exists()
    assert not (slot.project_dir / "leftover").exists()   # partial wiped


def test_decompiler_version_partitions_cache(tmp_path, monkeypatch):
    """An r2 version change routes to a DIFFERENT mount (an upgrade re-analyzes)."""
    from hexgraph.sandbox.decompiler import R2Decompiler

    artifact = _write(tmp_path / "bin", b"same bytes")
    project = _Project(tmp_path / "data")
    fake = _RecordingExecutor()
    monkeypatch.setattr(rp, "r2_version_for_image", lambda *a, **k: "6.0.0")
    R2Decompiler(runner=fake).decompile(str(artifact), "f", project=project)
    assert "6.0.0" in fake.calls[0]["project_mount"]


def test_decompiler_falls_back_to_throwaway_on_lock_timeout(tmp_path, monkeypatch):
    """On a lock-acquire timeout the decompiler runs an UNCACHED throwaway probe (no mount) and
    does NOT touch the cached slot."""
    import contextlib

    artifact = _write(tmp_path / "bin", b"a binary")
    project = _Project(tmp_path / "data")

    @contextlib.contextmanager
    def _never_acquire(*a, **k):
        yield False

    monkeypatch.setattr(rp.R2Project, "lock", _never_acquire)
    fake = _RecordingExecutor()
    out = _r2dec(monkeypatch, fake).decompile(str(artifact), "f", project=project)
    assert fake.calls[0]["project_mount"] is None and out["cached"] is False
    sha = rp.content_hash(artifact)
    assert not rp.resolve(project.data_dir, sha, "6.1.4").exists()


def test_disassemble_func_never_uses_project(tmp_path, monkeypatch):
    """Targeted disassembly (`--disasm`) is already cheap (`af`) and must run project-less — no
    mount, so it never pays or touches the whole-binary persistent project."""
    fake = _RecordingExecutor()
    _r2dec(monkeypatch, fake).disassemble_func(str(_write(tmp_path / "b", b"x")), "0x1200")
    assert fake.calls[0]["project_mount"] is None
    assert fake.calls[0]["extra_args"] == ["--disasm", "0x1200"]


# --- the cross-process slot lock (r2's own copy) -------------------------------------------

def test_lock_serializes_concurrent_holders(tmp_path):
    import threading

    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
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
    assert overlaps == 0 and max_concurrent == 1


def test_lock_timeout_yields_false(tmp_path):
    import subprocess
    import sys
    import textwrap

    slot = rp.resolve(tmp_path / "data", "deadbeef", "6.1.4")
    slot.prepare()
    holder_src = textwrap.dedent(f"""
        import fcntl, os, time
        fd = os.open({str(slot.lock_path)!r}, os.O_CREAT | os.O_RDWR, 0o666)
        fcntl.flock(fd, fcntl.LOCK_EX)
        print("locked", flush=True)
        time.sleep(5)
    """)
    holder = subprocess.Popen([sys.executable, "-c", holder_src],
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "locked"
        t0 = time.monotonic()
        with slot.lock(timeout=0.5, poll=0.05) as ok:
            assert ok is False
        assert time.monotonic() - t0 >= 0.5
    finally:
        holder.terminate()
        holder.wait(timeout=10)


# --- CLI: prune reclaims the r2 cache ONLY when asked --------------------------------------

def test_cmd_prune_r2_cache_is_explicit_only(hg_home):
    import argparse

    from hexgraph.cli import _cmd_prune
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project

    with session_scope() as s:
        p = create_project(s, name="prune-r2-test")
        pid, data_dir = p.id, p.data_dir

    root = rp.cache_root(data_dir)
    root.mkdir(parents=True, exist_ok=True)
    mb = 1024 * 1024
    _make_project(root, "old__v", 2 * mb, mtime=1000)
    _make_project(root, "new__v", 2 * mb, mtime=2000)

    # No flag → report only; delete NOTHING.
    assert _cmd_prune(argparse.Namespace(project=pid, ghidra_cache_mb=None, r2_cache_mb=None)) == 0
    assert (root / "old__v").exists() and (root / "new__v").exists()

    # Explicit --r2-cache-mb 2 → evict the oldest r2 project to get under 2 MiB.
    assert _cmd_prune(argparse.Namespace(project=pid, ghidra_cache_mb=None, r2_cache_mb=2)) == 0
    assert not (root / "old__v").exists() and (root / "new__v").exists()
