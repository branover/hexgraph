"""The Decompiler seam (SPEC §3).

radare2 (`R2Decompiler`) is the always-available default. Ghidra is an optional
upgrade, selected when enabled in Settings — `GhidraDecompiler` (headless, in the
sandbox image) and `GhidraBridgeDecompiler` (a Ghidra you have open). Task code
asks for `get_decompiler()` and never names a tool, so swapping is transparent.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod

from hexgraph.sandbox.executor import Executor, get_executor


class Decompiler(ABC):
    name: str

    @abstractmethod
    def decompile(self, artifact: str, function: str | None = None, *, project=None) -> dict:
        """Return {functions: [...], focus: {name, pseudocode, disasm}|null}.

        `project` (a `Project`, optional) lets a decompiler that supports it cache its analysis
        on that project's data dir (the persistent Ghidra project — analyze once, reuse). It is
        ignored by decompilers without a persistent project (radare2)."""
        ...


class R2Decompiler(Decompiler):
    name = "radare2"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None, *, project=None) -> dict:
        # radare2 has no persistent project; `project` is accepted for seam parity, ignored.
        args = [function] if function else None
        return self.runner.run_json_probe("decompile_probe.py", artifact, extra_args=args)


class GhidraDecompiler(Decompiler):
    """Headless Ghidra (`analyzeHeadless`) running in the sandbox image. Emits the
    same {functions, focus} contract (plus calls/structs used by enriched recon).

    When a `project` is supplied, the imported+analyzed Ghidra project is PERSISTED on that
    project's data dir and reused across calls (engine.ghidra_project) — the first decompile
    of an artifact pays the full analysis cost; later decompiles of OTHER functions reuse it.
    Without a `project` it runs the old throwaway-project path (correct, just slower)."""

    name = "ghidra"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None, *, project=None) -> dict:
        args = [function] if function else None
        slot = self._resolve_slot(artifact, project)
        out = self.runner.run_json_probe(
            "ghidra_probe.py", artifact, extra_args=args,
            project_mount=(str(slot.root) if slot is not None else None))
        if slot is not None:
            # The cold run just persisted the project; record the marker (what exists() keys
            # on) and touch the slot so LRU eviction spares the most-recently-used project.
            try:
                slot.write_meta()
                slot.touch()
            except Exception:  # noqa: BLE001 — bookkeeping must not fail a good decompile
                pass
        return out

    def _resolve_slot(self, artifact: str, project):
        """Resolve, prepare, and make room for the persistent-project slot for this artifact —
        or None if caching isn't possible (no project / no data dir / any error). Best-effort:
        a failure falls back to the throwaway path rather than breaking decompilation."""
        if project is None or not getattr(project, "data_dir", None):
            return None
        try:
            from hexgraph.engine import ghidra_project as gp
            from hexgraph.sandbox.runner import sandbox_image

            sha = gp.content_hash(artifact)
            version = gp.ghidra_version_for_image(sandbox_image(), runner=self.runner)
            slot = gp.resolve(project.data_dir, sha, version)
            slot.prepare()
            # Evict BEFORE the run so a cold analysis lands within the cap; never evict the
            # slot we're about to (re)use.
            gp.evict_to_cap(project.data_dir, gp.project_cache_mb(), keep=slot.root.name)
            return slot
        except Exception:  # noqa: BLE001 — caching is an optimization, never load-bearing
            return None


def _resolve_name(explicit: str | None) -> str:
    """Pick the decompiler: explicit arg → env override → Settings → radare2.
    Never raises on config — an unavailable Ghidra is handled by the caller's
    best-effort fallback, so analysis always proceeds."""
    if explicit:
        return explicit.lower()
    env = os.environ.get("HEXGRAPH_DECOMPILER")
    if env:
        return env.lower()
    try:
        from hexgraph.engine.ghidra import ghidra_config

        g = ghidra_config()
        if g.get("enabled"):
            return "ghidra_bridge" if g.get("mode") == "bridge" else "ghidra"
    except Exception:  # noqa: BLE001 — config problems must not break decompilation
        pass
    return "radare2"


def get_decompiler(name: str | None = None) -> Decompiler:
    resolved = _resolve_name(name)
    if resolved in ("radare2", "r2"):
        return R2Decompiler()
    if resolved == "ghidra":
        return GhidraDecompiler()
    if resolved in ("ghidra_bridge", "bridge"):
        from hexgraph.engine.ghidra_bridge import GhidraBridgeDecompiler

        return GhidraBridgeDecompiler()
    raise ValueError(f"unknown decompiler {resolved!r}")
