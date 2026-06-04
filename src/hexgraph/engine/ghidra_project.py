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

Bounded eviction: the total size under `<data_dir>/ghidra` is capped
(`features.ghidra.project_cache_mb`, default 4096 MiB); when a new project would exceed the cap we
evict whole projects LRU (by mtime) and LOG each eviction — no silent cap (repo discipline).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Inside the sandbox container, the persistent project is bind-mounted here (writable).
# The probe creates `project/` under it for the Ghidra .gpr/.rep and uses the same dir for
# its meta marker. Distinct from /scratch (tmpfs: HOME/TMPDIR/user-settings) and /out.
CONTAINER_PROJECT_DIR = "/ghidra-project"

# Fixed Ghidra project name inside the cache dir — re-used verbatim by `-process` on warm calls.
PROGRAM_NAME = "hexgraph"

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
    meta_path: Path      # <root>/meta.json
    content_sha: str
    ghidra_version: str | None
    program_name: str = PROGRAM_NAME

    def exists(self) -> bool:
        """True iff a previous COLD run completed and persisted a usable project. We require
        both the meta marker (written only after analyzeHeadless produced output) AND a
        non-empty project dir, so a half-written/crashed cold run is treated as a miss and
        re-analyzed rather than opened with `-process` against nothing."""
        if not self.meta_path.is_file():
            return False
        try:
            json.loads(self.meta_path.read_text())
        except (OSError, ValueError):
            return False
        return self.project_dir.is_dir() and any(self.project_dir.iterdir())

    def prepare(self) -> None:
        """Make the host-side project dir before the cold run. Created world-writable (0o777)
        so the `--user 1000:1000` container can write the project regardless of the host
        process's own uid — mirrors how the runner makes the `/out` bind-mount writable.
        (This is HexGraph's own data dir, not target bytes.)"""
        self.project_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o777)
            os.chmod(self.project_dir, 0o777)
        except OSError:
            pass  # best-effort; on a uid==1000 host the default perms already suffice

    def write_meta(self) -> None:
        """Record the cold-run marker (also the file `exists()` keys on). Touches mtime, which
        is what LRU eviction orders by."""
        self.meta_path.write_text(json.dumps({
            "content_hash": self.content_sha,
            "ghidra_version": self.ghidra_version,
            "program_name": self.program_name,
            "created_at": time.time(),
        }))

    def touch(self) -> None:
        """Mark this project most-recently-used (warm hit) so LRU eviction spares it."""
        now = time.time()
        try:
            os.utime(self.root, (now, now))
            if self.meta_path.is_file():
                os.utime(self.meta_path, (now, now))
        except OSError:
            pass


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
    """Bounded LRU eviction: drop whole cached projects (oldest mtime first) until the total
    size under `<data_dir>/ghidra` is within `cap_mb`. `keep` is a cache-key basename never
    evicted (the project we're about to use). Logs every eviction — no silent cap. Returns the
    list of evicted keys. cap_mb <= 0 disables eviction (unbounded)."""
    if cap_mb <= 0:
        return []
    root = cache_root(data_dir)
    if not root.is_dir():
        return []
    cap_bytes = cap_mb * 1024 * 1024
    slots = []
    for child in root.iterdir():
        if not child.is_dir() or child.name == keep:
            continue
        try:
            mtime = child.stat().st_mtime
        except OSError:
            continue
        slots.append((mtime, child, _dir_size(child)))
    total = _dir_size(root)
    if total <= cap_bytes:
        return []
    slots.sort(key=lambda s: s[0])  # oldest first
    evicted: list[str] = []
    for _mtime, child, size in slots:
        if total <= cap_bytes:
            break
        try:
            shutil.rmtree(child)
        except OSError as exc:
            log.warning("ghidra project cache: failed to evict %s: %s", child.name, exc)
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
