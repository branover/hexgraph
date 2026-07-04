"""Persistent Ghidra project cache — analyze once, reuse forever (design §5.1 / §7 Phase 1).

Today `ghidra_probe.py` runs `analyzeHeadless -import <artifact> -postScript … -deleteProject`
in the ephemeral `/scratch` tmpfs on EVERY call, so a full re-import + auto-analysis happens
per `decompile_function` / `list_functions`. On real firmware that is crippling.

This module owns the *host-side* cache of imported+analyzed Ghidra projects:

  <project.data_dir>/ghidra/<sha256-of-artifact>__<ghidra-version>/
      project/        ← the .gpr / .rep Ghidra project (bind-mounted writable into the sandbox)
      meta.json       ← {content_hash, ghidra_version, program_name, created_at}

Keyed by the artifact's content hash AND the toolchain (Ghidra) version, so a different binary
OR a Ghidra upgrade gets a fresh project; reuse only on an exact match. The FIRST decompile of a
given artifact imports + analyzes + persists; SUBSEQUENT decompiles open the existing project and
re-run the postScript over the already-imported program with `-process` (no `-import`, no
re-analysis).

Only HexGraph's own project bytes live here — never the target. The target artifact still enters
the sandbox read-only at `/artifact`; this directory is a bounded writable volume (analogous to the
`/out` bind-mount), and the rest of the hardening (`--read-only` rootfs, `--network none`,
`--cap-drop ALL`, `--no-new-privileges`, `--user 1000:1000`) is untouched.

A persisted analysis is DURABLE researcher knowledge and is NEVER auto-deleted to reclaim space
(an operator lost a 24-hour analysis when an earlier LRU cap silently evicted a project larger than
the cap). Reclaiming the cache is an EXPLICIT, opt-in act only: `hexgraph prune <project>
--ghidra-cache-mb N` calls `evict_to_cap` deliberately. `features.ghidra.project_cache_mb` is the
suggested cap for that command, NOT an automatic ceiling.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl  # POSIX advisory locks (host-side; not available on Windows)
except ImportError:  # pragma: no cover — non-POSIX host
    fcntl = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# Inside the sandbox container, the persistent project is bind-mounted here (writable).
# The probe creates `project/` under it for the Ghidra .gpr/.rep and uses the same dir for
# its meta marker. Distinct from /scratch (tmpfs: HOME/TMPDIR/user-settings) and /out.
CONTAINER_PROJECT_DIR = "/ghidra-project"

# Fixed Ghidra project name inside the cache dir — re-used verbatim by `-process` on warm calls.
PROGRAM_NAME = "hexgraph"

# The committed-marker filename (engine.re.ghidra_project.GhidraProject.meta_path basename). The
# probe writes it as the LAST step of a fully successful cold import+analyze, so its presence is
# the AUTHORITATIVE "this slot is a valid warm project" signal — a half-written / crashed cold
# run leaves the project dir non-empty but WITHOUT a committed marker, and is re-done as cold.
META_NAME = "meta.json"

# The per-slot advisory-lock filename. A cross-process `fcntl.flock` is held on it (by the HOST
# runner/decompiler) for the WHOLE use of a slot, so two processes (the web app + an agent's MCP
# server) can never open one Ghidra project — which is NOT concurrency-safe — at once.
LOCK_NAME = ".hglock"

# Default time a same-target decompile waits for an in-flight one before falling back to a
# throwaway ephemeral project (correct, just uncached). Long enough for a warm reuse to finish;
# the cold importer holds the lock for the whole analysis, so a contender for a COLD slot may
# instead time out and run its own throwaway analysis (still correct).
DEFAULT_LOCK_TIMEOUT = 600.0

# How many bytes the chunked sha256 reads at a time.
_HASH_CHUNK = 1024 * 1024

# Memoized Ghidra version per sandbox image (so the cache-key/toolchain digest doesn't cost a
# container `--check` on every decompile). Keyed by image tag.
_VERSION_CACHE: dict[str, str] = {}


def content_hash(artifact: str | Path) -> str:
    """sha256 of the artifact bytes — the content half of the cache key."""
    h = hashlib.sha256()
    with open(artifact, "rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_version(version: str | None) -> str:
    """A filesystem-safe toolchain token for the cache-dir name. Unknown → 'unknown'."""
    v = (version or "unknown").strip() or "unknown"
    return "".join(c if (c.isalnum() or c in ".-_") else "_" for c in v)


def cache_key(content_sha: str, ghidra_version: str | None) -> str:
    """The cache-dir basename: `<sha256>__<ghidra-version>`. A different binary OR a Ghidra
    upgrade yields a different key, so a stale project is never reused across either change."""
    return f"{content_sha}__{_safe_version(ghidra_version)}"


def cache_root(data_dir: str | Path) -> Path:
    """`<data_dir>/ghidra` — the per-project root that holds every cached Ghidra project."""
    return Path(data_dir) / "ghidra"


@dataclass
class GhidraProject:
    """A resolved cache slot for one (artifact, ghidra-version) pair."""
    root: Path           # <data_dir>/ghidra/<key>
    project_dir: Path    # <root>/project  — the dir Ghidra writes its .gpr/.rep into
    meta_path: Path      # <root>/meta.json  — the COMMITTED warm marker (last step of cold)
    content_sha: str
    ghidra_version: str | None
    program_name: str = PROGRAM_NAME

    @property
    def lock_path(self) -> Path:
        """`<root>/.hglock` — the per-slot advisory-lock file (`fcntl.flock`)."""
        return self.root / LOCK_NAME

    def exists(self) -> bool:
        """The SINGLE authoritative "is this a valid warm project?" signal. True iff a previous
        COLD run COMMITTED its marker (`meta.json`, written only as the LAST step of a fully
        successful import+analyze) AND the project dir is non-empty. A half-written / crashed /
        timed-out cold run leaves a non-empty project dir but NO committed marker, so it reads as
        a miss and is re-done as cold rather than opened with `-process` against an incomplete
        program. Used everywhere the warm/cold decision is made (host and, via the same marker,
        the probe)."""
        if not self.meta_path.is_file():
            return False
        try:
            json.loads(self.meta_path.read_text())
        except (OSError, ValueError):
            return False
        return self.project_dir.is_dir() and any(self.project_dir.iterdir())

    def prepare(self) -> None:
        """Make the host-side slot dir before a run. Created world-writable (0o777) so the
        `--user 1000:1000` container can write the project regardless of the host process's own
        uid — mirrors how the runner makes the `/out` bind-mount writable. (This is HexGraph's
        own data dir, not target bytes.)"""
        self.project_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o777)
            os.chmod(self.project_dir, 0o777)
        except OSError:
            pass  # best-effort; on a uid==1000 host the default perms already suffice

    def clear_project(self) -> None:
        """Wipe a partially-written project dir so the cold path re-imports cleanly. Called when
        the slot is NOT a valid warm project (no committed marker) but the dir is non-empty — i.e.
        a prior cold run died mid-import. Removes the stale marker too. Best-effort; leaves the
        slot dir itself (and the lock) in place."""
        try:
            if self.meta_path.exists():
                self.meta_path.unlink()
        except OSError:
            pass
        try:
            if self.project_dir.exists():
                shutil.rmtree(self.project_dir)
        except OSError:
            pass
        self.project_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.project_dir, 0o777)
        except OSError:
            pass

    def write_meta(self) -> None:
        """COMMIT the warm marker — the LAST step of a successful cold import+analyze, and the
        only thing `exists()` keys on. Written atomically (tmp + `os.replace`) so a crash never
        leaves a half-written marker that would falsely read as warm. Touches mtime, which is what
        LRU eviction orders by."""
        payload = json.dumps({
            "content_hash": self.content_sha,
            "ghidra_version": self.ghidra_version,
            "program_name": self.program_name,
            "created_at": time.time(),
        })
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(payload)
        os.replace(tmp, self.meta_path)

    def touch(self) -> None:
        """Mark this project most-recently-used (warm hit) so LRU eviction spares it."""
        now = time.time()
        try:
            os.utime(self.root, (now, now))
            if self.meta_path.is_file():
                os.utime(self.meta_path, (now, now))
        except OSError:
            pass

    @contextlib.contextmanager
    def lock(self, *, timeout: float = DEFAULT_LOCK_TIMEOUT, poll: float = 0.25):
        """Hold a CROSS-PROCESS advisory lock (`fcntl.flock`, exclusive) on `<root>/.hglock` for
        the WHOLE use of this slot, so two OS processes (the web app + an agent's MCP server)
        sharing the data dir can never open the same non-concurrency-safe Ghidra project at once.

        Acquire is lock-and-wait with a timeout: a concurrent same-target decompile blocks until
        the in-flight one finishes (then proceeds warm). On timeout it yields ``False`` instead of
        raising, so the caller can fall back to a throwaway ephemeral project (correct, uncached)
        rather than block forever or corrupt the slot. On success it yields ``True``.

        Different targets resolve to different slots → different lock files → still fully
        concurrent. On a non-POSIX host (no `fcntl`) it degrades to a no-op that yields ``True``
        (single-process dev only)."""
        if fcntl is None:  # pragma: no cover — non-POSIX host
            yield True
            return
        self.root.mkdir(parents=True, exist_ok=True)
        # 0o666 so a different host uid (or the container's uid, were it ever to open it) can lock.
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o666)
        acquired = False
        try:
            deadline = time.monotonic() + max(0.0, timeout)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    if time.monotonic() >= deadline:
                        log.warning(
                            "ghidra project cache: timed out after %.0fs waiting for the slot "
                            "lock on %s — falling back to a throwaway project (uncached)",
                            timeout, self.root.name)
                        break
                    time.sleep(poll)
            yield acquired
        finally:
            if acquired:
                with contextlib.suppress(OSError):
                    fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)


def resolve(data_dir: str | Path, content_sha: str, ghidra_version: str | None) -> GhidraProject:
    """Resolve (don't create) the cache slot for an artifact hash + Ghidra version."""
    root = cache_root(data_dir) / cache_key(content_sha, ghidra_version)
    return GhidraProject(
        root=root,
        project_dir=root / "project",
        meta_path=root / "meta.json",
        content_sha=content_sha,
        ghidra_version=ghidra_version,
    )


def _evict_slot_locked(slot_root: Path) -> bool:
    """Evict a cache slot ONLY while holding its `.hglock`, returning True if evicted and
    False if another holder has it (skip). Holding the lock ACROSS the rmtree is what makes
    this safe: probing the lock and then releasing it before deleting would leave a TOCTOU
    window in which a holder could acquire the slot and start an analysis we then rmtree out
    from under them — the very cross-process corruption the per-slot lock exists to prevent.
    Deleting the locked `.hglock` is safe on POSIX: our fd stays valid (unlinked-but-open),
    and a later opener re-creates a fresh slot + new lock inode — a cache miss, never a
    shared-project race. On a non-POSIX host (no `fcntl`) there is no cross-process holder to
    race, so just delete. rmtree failures propagate to the caller."""
    if fcntl is None:  # pragma: no cover — non-POSIX host
        shutil.rmtree(slot_root)
        return True
    lock_path = slot_root / LOCK_NAME
    fd = None
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o666)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False  # a holder is mid-analysis → do NOT evict
            raise
        shutil.rmtree(slot_root)  # deletes the now-unlinked .hglock too; our fd stays valid
        return True
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(fd)


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file() and not p.is_symlink():
                total += p.stat().st_size
        except OSError:
            pass
    return total


def evict_to_cap(data_dir: str | Path, cap_mb: int, *, keep: str | None = None) -> list[str]:
    """EXPLICIT LRU eviction: drop whole cached projects (oldest mtime first) until the total
    size under `<data_dir>/ghidra` is within `cap_mb`. Called ONLY on an explicit user request
    (`hexgraph prune --ghidra-cache-mb`) — NEVER automatically, since a persisted analysis is
    durable and must not be deleted to reclaim space without the user asking. `keep` is a cache-key
    basename never evicted; an in-use (locked) slot is skipped even here. Logs every eviction — no
    silent deletion. Returns the list of evicted keys. cap_mb <= 0 is a no-op (unbounded)."""
    if cap_mb <= 0:
        return []
    root = cache_root(data_dir)
    if not root.is_dir():
        return []
    cap_bytes = cap_mb * 1024 * 1024
    # Size each child ONCE and sum to the total — no separate full-tree rglob of `root`. The
    # kept slot (the one we're about to use) is counted toward the total but never evicted.
    slots = []
    total = 0
    for child in root.iterdir():
        if not child.is_dir():
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError:
            continue
        size = _dir_size(child)
        total += size
        if child.name != keep:
            slots.append((mtime, child, size))
    # Common path: already within the cap → return WITHOUT sorting or any further work.
    if total <= cap_bytes:
        return []
    slots.sort(key=lambda s: s[0])  # oldest first
    evicted: list[str] = []
    for _mtime, child, size in slots:
        if total <= cap_bytes:
            break
        try:
            evicted_ok = _evict_slot_locked(child)
        except OSError as exc:
            log.warning("ghidra project cache: failed to evict %s: %s", child.name, exc)
            continue
        if not evicted_ok:
            # Another process holds this slot's `.hglock` (mid-analysis). Skip it; a later
            # eviction (or the holder finishing) reclaims the space.
            log.info("ghidra project cache: skipping eviction of in-use slot %s", child.name)
            continue
        total -= size
        evicted.append(child.name)
        log.info("ghidra project cache: evicted %s (%.1f MiB) to stay within %d MiB cap",
                 child.name, size / (1024 * 1024), cap_mb)
    if total > cap_bytes:
        log.warning("ghidra project cache: still %.1f MiB over the %d MiB cap after evicting "
                    "%d project(s) — the live/kept project alone exceeds the cap; consider "
                    "raising features.ghidra.project_cache_mb",
                    (total - cap_bytes) / (1024 * 1024), cap_mb, len(evicted))
    return evicted


def cache_size_mb(data_dir: str | Path) -> int:
    """Total size (MiB) of the persisted Ghidra project cache under `<data_dir>/ghidra` — for the
    `hexgraph prune` report, so the operator sees what they're keeping before choosing to reclaim."""
    root = cache_root(data_dir)
    return _dir_size(root) // (1024 * 1024) if root.is_dir() else 0


def project_cache_mb() -> int:
    """The configured cache cap in MiB (settings layer). Defaults sensibly; <=0 means
    unbounded. Never raises — a config problem must not break decompilation."""
    try:
        from hexgraph import settings as st

        return int(st.resolved()["features"]["ghidra"].get("project_cache_mb", 4096))
    except Exception:  # noqa: BLE001
        return 4096


def ghidra_version_for_image(image: str, *, runner=None) -> str | None:
    """The Ghidra version of `image`, memoized per image (one `--check` container run, reused
    for the toolchain half of the cache key). Returns None if Ghidra/Docker is unavailable —
    callers then fall back to an 'unknown' toolchain token (cold path still works; reuse simply
    waits until a version is known). Never raises."""
    if image in _VERSION_CACHE:
        return _VERSION_CACHE[image] or None
    try:
        from hexgraph.sandbox.runner import docker_available

        if not docker_available():
            return None
        from hexgraph.sandbox.executor import get_executor

        rn = runner or get_executor()
        out = rn.run_json_probe("ghidra_probe.py", None, extra_args=["--check"])
        version = out.get("version") if isinstance(out, dict) else None
    except Exception:  # noqa: BLE001 — version probing is best-effort
        version = None
    _VERSION_CACHE[image] = version or ""
    return version
