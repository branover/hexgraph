"""The Decompiler seam (SPEC §3).

radare2 (`R2Decompiler`) is the v1 workhorse. Ghidra headless can drop in later
as another `Decompiler` implementation — task code asks for `get_decompiler()`
and never names a specific tool, so swapping is one new class + a build arg.
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


def get_decompiler(name: str | None = None) -> Decompiler:
    name = (name or os.environ.get("HEXGRAPH_DECOMPILER") or "radare2").lower()
    if name in ("radare2", "r2"):
        return R2Decompiler()
    if name == "ghidra":
        raise NotImplementedError(
            "Ghidra decompiler is opt-in and not wired yet; build the sandbox with WITH_GHIDRA=1 "
            "and add a GhidraDecompiler. radare2 is the v1 default."
        )
    raise ValueError(f"unknown decompiler {name!r}")
