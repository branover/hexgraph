"""Connect to a running Ghidra over loopback (the `ghidra_bridge` server).

Lets a researcher who already has Ghidra open import its programs as HexGraph
targets and pull decompilation from their live analysis — bytes never leave the
machine (loopback only). This is distinct from headless mode (which runs Ghidra
in the sandbox).

The actual remote-Ghidra calls live in `_RemoteOps` (version-dependent, exercised
only against a live Ghidra). Everything else takes an injectable `ops` object so
the import flow and the Decompiler wrapper are unit-testable with a fake.
"""

from __future__ import annotations

import re
from typing import Protocol

from hexgraph.engine.ghidra import ghidra_config
from hexgraph.sandbox.decompiler import Decompiler

# A symbol name we're willing to interpolate into a remote_eval string. Mirrors
# decompile_probe._SAFE_NAME: only the characters that occur in real symbol names,
# so a caller-supplied function name can never carry Python/string-breakout syntax.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@$:]+$")


class BridgeUnavailable(RuntimeError):
    """The Ghidra Bridge client isn't installed or no server is reachable."""


class BridgeOps(Protocol):
    def list_programs(self) -> list[dict]: ...
    def executable_path(self, program: str) -> str | None: ...
    def decompile(self, program: str | None, function: str | None) -> dict: ...


class _RemoteOps:
    """Real ops backed by a live `ghidra_bridge` connection (untested offline)."""

    def __init__(self, bridge) -> None:
        self.b = bridge

    def list_programs(self) -> list[dict]:
        rows = self.b.remote_eval(
            "[(p.getName(), p.getExecutablePath(), "
            "p.getLanguageID().getIdAsString(), p.getFunctionManager().getFunctionCount()) "
            "for p in state.getTool().getService("
            "ghidra.app.services.ProgramManager).getAllOpenPrograms()]"
        )
        return [{"name": n, "path": pth, "language": lang, "functions": fc} for (n, pth, lang, fc) in rows]

    def executable_path(self, program: str) -> str | None:
        for p in self.list_programs():
            if p["name"] == program:
                return p.get("path")
        return None

    def decompile(self, program: str | None, function: str | None) -> dict:
        # Operate on the currently-active program in Ghidra.
        names = self.b.remote_eval(
            "[f.getName() for f in currentProgram.getFunctionManager().getFunctions(True)]"
        )
        focus = None
        if function:
            pseudo = self._decompile_one(function)
            focus = {"name": function, "resolved": function, "pseudocode": pseudo, "disasm": "", "callees": []}
        return {"functions": names[:400], "focus": focus, "tool": "ghidra_bridge"}

    def _decompile_one(self, function: str) -> str:
        # Never build eval'd code by interpolating a caller-supplied name. Validate it
        # against the strict symbol-name allowlist, then pass it as a BOUND variable
        # (`fn` in the bridge eval namespace) so it's data, not code.
        if not _SAFE_NAME.match(function or ""):
            raise BridgeUnavailable(f"unsafe Ghidra function name: {function!r}")
        return self.b.remote_eval(
            "(lambda di: (di.openProgram(currentProgram), "
            "di.decompileFunction([f for f in currentProgram.getFunctionManager().getFunctions(True) "
            "if f.getName()==fn][0], 60, __import__('ghidra.util.task', fromlist=['ConsoleTaskMonitor'])"
            ".ConsoleTaskMonitor()).getDecompiledFunction().getC())[1])("
            "__import__('ghidra.app.decompiler', fromlist=['DecompInterface']).DecompInterface())",
            fn=function,
        )


def connect_ops(host: str | None = None, port: int | None = None) -> BridgeOps:
    g = ghidra_config()
    host = host or g["bridge"]["host"]
    port = port or g["bridge"]["port"]
    try:
        import ghidra_bridge
    except Exception as exc:  # noqa: BLE001
        raise BridgeUnavailable("Ghidra Bridge client not installed (pip install ghidra_bridge)") from exc
    try:
        bridge = ghidra_bridge.GhidraBridge(connect_to_host=host, connect_to_port=port, namespace={})
    except Exception as exc:  # noqa: BLE001
        raise BridgeUnavailable(f"no Ghidra Bridge server at {host}:{port} (run ghidra_bridge_server.py in Ghidra)") from exc
    return _RemoteOps(bridge)


class GhidraBridgeDecompiler(Decompiler):
    name = "ghidra_bridge"

    def __init__(self, ops: BridgeOps | None = None) -> None:
        self._ops = ops

    def _resolve(self) -> BridgeOps:
        return self._ops if self._ops is not None else connect_ops()

    def decompile(self, artifact: str, function: str | None = None, *, project=None) -> dict:
        # The bridge talks to a Ghidra you already have open (your project IS the cache);
        # `project` is accepted for seam parity and ignored.
        return self._resolve().decompile(program=None, function=function)


def list_open_programs(ops: BridgeOps | None = None) -> list[dict]:
    return (ops or connect_ops()).list_programs()


def import_program(session, project, *, path: str, name: str | None = None, ops: BridgeOps | None = None):
    """Ingest a program Ghidra has open as a target, using its real on-disk bytes
    (Ghidra runs on the same machine — loopback). Recon then populates the facts,
    so the 'targets only from real bytes' invariant holds."""
    import os

    from hexgraph.engine.pipeline import analyze_target
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.unpack import build_links_against
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import docker_available

    if not path or not os.path.isfile(path):
        raise BridgeUnavailable(f"Ghidra program path not readable on this host: {path!r}")
    target = ingest_file(session, project, path, name=name or os.path.basename(path))
    result = {"target_id": target.id, "name": target.name}
    if docker_available():
        analyze_target(session, project, target, get_executor())
        build_links_against(session, project)
        result["recon"] = True
    else:
        result["recon"] = False
    return result
