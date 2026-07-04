"""Persistent radare2 project cache — analyze once, reuse forever (the r2 half of the
analyze/decompile split; the Ghidra half is `engine.re.ghidra_project`).

Today the radare2 probes run a full `aaa` on EVERY call (decompile a function, list functions,
map xrefs), which is crippling on real firmware — an operator hit multi-hour `aaa` passes on a
481 MB binary. radare2 CAN persist an analyzed program as a **project** and reload it with no
re-analysis; this module owns the host-side cache of those projects, keyed exactly like the
Ghidra one:

  <project.data_dir>/r2/<sha256-of-artifact>__<r2-version>/
      project/        ← the writable dir bind-mounted into the sandbox as `dir.projects`;
                        radare2 writes its git-backed named project (`hexgraph/`) under it
      meta.json       ← {content_hash, r2_version, program_name, created_at} — the COMMITTED
                        warm marker, written as the LAST step of a successful cold save

**CRITICAL r2 gotcha (verified on r2 6.1.4):** a project MUST be saved by NAME into a configured
`dir.projects` — `Ps <name>` — NOT by absolute path (`Ps /abs/path` SEGFAULTS on reload across
every r2 version tested). The probe sets `-e dir.projects=<mount>/project` and saves `Ps hexgraph`
(cold) / reloads `-p hexgraph` (warm, no `aaa`). radare2 projects are git-backed, so the probe
sets `GIT_AUTHOR_*`/`GIT_COMMITTER_*` to avoid a git-identity prompt.

Only HexGraph's own project bytes live here — never the target. The target still enters the sandbox
read-only at `/artifact`; this is a bounded writable volume, and the rest of the hardening
(`--read-only`, `--network none`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000:1000`) is
untouched. A persisted analysis is DURABLE researcher knowledge and is NEVER auto-deleted to
reclaim space (mirroring `ghidra_project.py` after an operator lost a 24-hour analysis to an LRU
cap). Reclaiming the cache is an EXPLICIT, opt-in act only — `hexgraph prune <project>
--r2-cache-mb N` calls `evict_to_cap`; `features.re.r2_project_cache_mb` is the suggested cap for
that command, NOT an automatic ceiling.

NOTE: the slot / cross-process-lock / eviction machinery here mirrors `ghidra_project.py`. That is
deliberate for this PR — unifying both onto a shared `project_cache` base is a follow-up, kept
separate so this change does not refactor the just-shipped Ghidra warm-slot path.
"""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

# content_hash is genuinely generic (sha256 of the artifact bytes) — reuse it rather than
# re-implement the chunked hash. The rest is r2-specific enough to keep local.
from hexgraph.engine.re.ghidra_project import content_hash

try:
    import fcntl  # POSIX advisory locks (host-side)
except ImportError:  # pragma: no cover — non-POSIX host
    fcntl = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

# Inside the container the persistent project is bind-mounted at the runner's project mount point
# (runner.CONTAINER_PROJECT_DIR); radare2's `dir.projects` points at `project/` under it. The mount
# point name is Ghidra-flavored (`/ghidra-project`) but it is just a generic writable HexGraph dir;
# renaming it generically is a cosmetic follow-up.
PROJECT_SUBDIR = "project"

# Fixed radare2 project NAME saved under dir.projects — reused verbatim by `-p` on warm reloads.
# MUST be a bare name, never a path (an absolute-path project segfaults r2 on reload).
PROJECT_NAME = "hexgraph"

# The committed-marker filename. Written as the LAST step of a successful cold save, so its
# presence is the AUTHORITATIVE "this slot is a valid warm project" signal — a crashed/timed-out
# cold save leaves the project dir non-empty but WITHOUT a marker and is re-done as cold.
META_NAME = "meta.json"

# Per-slot advisory-lock filename (cross-process `fcntl.flock`, held by the HOST for the whole use
# of a slot). radare2 opening one project dir from two processes is not safe; the lock serializes.
LOCK_NAME = ".hglock"

DEFAULT_LOCK_TIMEOUT = 600.0

_VERSION_CACHE: dict[str, str] = {}


def _safe_version(version: str | None) -> str:
    v = (version or "unknown").strip() or "unknown"
    return "".join(c if (c.isalnum() or c in ".-_") else "_" for c in v)


def cache_key(content_sha: str, r2_version: str | None) -> str:
    """`<sha256>__<r2-version>` — a different binary OR an r2 upgrade yields a different key, so a
    stale project (whose git-backed format may not load on a newer r2) is never reused."""
    return f"{content_sha}__{_safe_version(r2_version)}"


def cache_root(data_dir: str | Path) -> Path:
    return Path(data_dir) / "r2"


@dataclass
class R2Project:
    """A resolved cache slot for one (artifact, r2-version) pair."""
    root: Path            # <data_dir>/r2/<key>
    project_dir: Path     # <root>/project  — radare2's dir.projects (holds the named project)
    meta_path: Path       # <root>/meta.json — the COMMITTED warm marker
    content_sha: str
    r2_version: str | None
    program_name: str = PROJECT_NAME

    @property
    def lock_path(self) -> Path:
        return self.root / LOCK_NAME

    @property
    def named_project_dir(self) -> Path:
        """`<project_dir>/<name>` — where radare2 writes the git-backed project for `Ps <name>`."""
        return self.project_dir / self.program_name

    def exists(self) -> bool:
        """The SINGLE authoritative "is this a valid warm project?" signal: a committed marker AND
        a non-empty named-project dir. A half-written/crashed cold save reads as a miss (re-done
        cold) rather than a `-p` load against an incomplete project."""
        if not self.meta_path.is_file():
            return False
        try:
            json.loads(self.meta_path.read_text())
        except (OSError, ValueError):
            return False
        return self.named_project_dir.is_dir() and any(self.named_project_dir.iterdir())

    def prepare(self) -> None:
        """Create the host-side slot dir, world-writable so the `--user 1000:1000` container can
        write the project regardless of the host uid (mirrors the `/out` bind-mount)."""
        self.project_dir.mkdir(parents=True, exist_ok=True)
        for p in (self.root, self.project_dir):
            try:
                os.chmod(p, 0o777)
            except OSError:
                pass

    def clear_project(self) -> None:
        """Wipe a partially-written project so the cold path re-saves cleanly. Removes the stale
        marker + the project dir; best-effort."""
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
        """COMMIT the warm marker atomically (tmp + os.replace) — the LAST step of a successful
        cold save, and the only thing `exists()` keys on."""
        payload = json.dumps({
            "content_hash": self.content_sha,
            "r2_version": self.r2_version,
            "program_name": self.program_name,
            "created_at": time.time(),
        })
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(payload)
        os.replace(tmp, self.meta_path)

    def touch(self) -> None:
        """Mark most-recently-used (warm hit) so LRU eviction spares it."""
        now = time.time()
        try:
            os.utime(self.root, (now, now))
            if self.meta_path.is_file():
                os.utime(self.meta_path, (now, now))
        except OSError:
            pass

    @contextlib.contextmanager
    def lock(self, *, timeout: float = DEFAULT_LOCK_TIMEOUT, poll: float = 0.25):
        """Cross-process advisory lock (`fcntl.flock`, exclusive) on `<root>/.hglock`, held for the
        whole use of the slot. Lock-and-wait with a timeout: yields True on acquire, False on
        timeout (caller falls back to a throwaway uncached run) — never blocks forever. Different
        targets → different slots → still concurrent. No-op yielding True on a non-POSIX host."""
        if fcntl is None:  # pragma: no cover — non-POSIX host
            yield True
            return
        self.root.mkdir(parents=True, exist_ok=True)
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
                        log.warning("r2 project cache: timed out after %.0fs waiting for the slot "
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


def resolve(data_dir: str | Path, content_sha: str, r2_version: str | None) -> R2Project:
    """Resolve (don't create) the cache slot for an artifact hash + r2 version."""
    root = cache_root(data_dir) / cache_key(content_sha, r2_version)
    return R2Project(
        root=root,
        project_dir=root / PROJECT_SUBDIR,
        meta_path=root / META_NAME,
        content_sha=content_sha,
        r2_version=r2_version,
    )


def _evict_slot_locked(slot_root: Path) -> bool:
    """Evict a slot ONLY while holding its `.hglock` (returns False if another holder has it, to
    skip). Holding the lock across the rmtree avoids the TOCTOU race the per-slot lock exists to
    prevent. Deleting the locked `.hglock` is safe on POSIX (our fd stays valid)."""
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
                return False
            raise
        shutil.rmtree(slot_root)
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
    """EXPLICIT LRU eviction: drop whole cached r2 projects (oldest mtime first) until the total
    size under `<data_dir>/r2` is within `cap_mb`. Called ONLY on an explicit user request
    (`hexgraph prune --r2-cache-mb`) — NEVER automatically, since a persisted analysis is durable
    and must not be deleted to reclaim space without the user asking. `keep` is a cache-key basename
    never evicted (the project we're about to use); an in-use (locked) slot is skipped even here.
    Logs every eviction — no silent deletion. Returns the evicted keys. cap_mb <= 0 is a no-op."""
    if cap_mb <= 0:
        return []
    root = cache_root(data_dir)
    if not root.is_dir():
        return []
    cap_bytes = cap_mb * 1024 * 1024
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
    if total <= cap_bytes:
        return []
    slots.sort(key=lambda s: s[0])
    evicted: list[str] = []
    for _mtime, child, size in slots:
        if total <= cap_bytes:
            break
        try:
            ok = _evict_slot_locked(child)
        except OSError as exc:
            log.warning("r2 project cache: failed to evict %s: %s", child.name, exc)
            continue
        if not ok:
            log.info("r2 project cache: skipping eviction of in-use slot %s", child.name)
            continue
        total -= size
        evicted.append(child.name)
        log.info("r2 project cache: evicted %s (%.1f MiB) to stay within %d MiB cap",
                 child.name, size / (1024 * 1024), cap_mb)
    if total > cap_bytes:
        log.warning("r2 project cache: still %.1f MiB over the %d MiB cap after evicting %d "
                    "project(s) — the kept project alone exceeds the cap; consider raising "
                    "features.re.r2_project_cache_mb", (total - cap_bytes) / (1024 * 1024),
                    cap_mb, len(evicted))
    return evicted


def project_cache_mb() -> int:
    """The SUGGESTED r2 project-cache cap in MiB for `hexgraph prune --r2-cache-mb` (settings;
    <=0 = unbounded). NOT an automatic ceiling — eviction only ever runs on that explicit command.
    Never raises — a config problem must not break decompilation."""
    try:
        from hexgraph import settings as st

        return int((st.resolved().get("features", {}).get("re", {}) or {})
                   .get("r2_project_cache_mb", 4096))
    except Exception:  # noqa: BLE001
        return 4096


def cache_size_mb(data_dir: str | Path) -> int:
    """Total size (MiB) of the persisted r2 project cache under `<data_dir>/r2` — for the
    `hexgraph prune` report, so the operator sees what they're keeping before choosing to reclaim."""
    root = cache_root(data_dir)
    return _dir_size(root) // (1024 * 1024) if root.is_dir() else 0


def r2_version_for_image(image: str, *, runner=None) -> str | None:
    """The radare2 version of `image`, memoized per image (the toolchain half of the cache key).
    Reads it from `binutils_probe.py --r2-version` (a no-target run). None if unavailable — the
    caller then uses an 'unknown' token (cold path still works). Never raises."""
    if image in _VERSION_CACHE:
        return _VERSION_CACHE[image] or None
    version = None
    try:
        from hexgraph.sandbox.runner import docker_available

        if docker_available():
            from hexgraph.sandbox.executor import get_executor

            rn = runner or get_executor()
            out = rn.run_json_probe("decompile_probe.py", None, extra_args=["--r2-version"])
            version = out.get("r2_version") if isinstance(out, dict) else None
    except Exception:  # noqa: BLE001 — version probing is best-effort
        version = None
    _VERSION_CACHE[image] = version or ""
    return version
