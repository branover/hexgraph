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
    def decompile(self, artifact: str, function: str | None = None) -> dict:
        """Return {functions: [...], focus: {name, pseudocode, disasm}|null}."""
        ...


class R2Decompiler(Decompiler):
    name = "radare2"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None) -> dict:
        args = [function] if function else None
        return self.runner.run_json_probe("decompile_probe.py", artifact, extra_args=args)


class GhidraDecompiler(Decompiler):
    """Headless Ghidra (`analyzeHeadless`) running in the sandbox image. Emits the
    same {functions, focus} contract (plus calls/structs used by enriched recon)."""

    name = "ghidra"

    def __init__(self, runner: Executor | None = None) -> None:
        self.runner = runner or get_executor()

    def decompile(self, artifact: str, function: str | None = None) -> dict:
        args = [function] if function else None
        return self.runner.run_json_probe("ghidra_probe.py", artifact, extra_args=args)


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
