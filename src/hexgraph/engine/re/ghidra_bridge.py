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

from hexgraph.engine.re.ghidra import ghidra_config
from hexgraph.sandbox.decompiler import Decompiler

# A symbol name we're willing to interpolate into a remote_eval string. Mirrors
# decompile_probe._SAFE_NAME: only the characters that occur in real symbol names,
# so a caller-supplied function name can never carry Python/string-breakout syntax.
# (Notably excludes quotes and backslashes, so inlining a validated name as a "..."
# literal in the eval string can't break out of the string.)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@$:]+$")
# A focus given as a strict hex address resolves to the function CONTAINING it
# (analyze-at-address), mirroring the headless probe; otherwise the focus is a name.
_ADDR = re.compile(r"^0x[0-9a-fA-F]+$")


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

    # Project one program tuple — (name, path, language, function_count) — for the row shape.
    _PROG_TUPLE = ("(p.getName(), p.getExecutablePath(), p.getLanguageID().getIdAsString(), "
                   "p.getFunctionManager().getFunctionCount())")

    def list_programs(self) -> list[dict]:
        # The GUI path enumerates every open program via the ProgramManager service — but that
        # service exists only when Ghidra is open in the GUI. Under a HEADLESS bridge server
        # (analyzeHeadless -postScript ghidra_bridge_server.py) state.getTool()/the service is
        # absent and this raises remotely, so fall back to the single active currentProgram (the
        # one the headless server loaded), which is also what decompile() operates on.
        try:
            rows = self.b.remote_eval(
                "[%s for p in state.getTool().getService("
                "ghidra.app.services.ProgramManager).getAllOpenPrograms()]" % self._PROG_TUPLE
            )
        except Exception:  # noqa: BLE001 — GUI-only service missing under a headless bridge server
            rows = self.b.remote_eval("[%s for p in [currentProgram]]" % self._PROG_TUPLE)
        # Defensive: index rather than destructure, skipping any row that isn't the 4-tuple shape,
        # so an unexpected remote shape can't raise an opaque ValueError.
        return [{"name": r[0], "path": r[1], "language": r[2], "functions": r[3]}
                for r in rows if len(r) == 4]

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
            resolved, pseudo = self._decompile_one(function)
            # Empty resolved name = the focus wasn't found in the live program (a missing name or
            # an address not inside a function) -> no focus, mirroring the headless probe.
            if resolved:
                focus = {"name": resolved, "resolved": resolved, "pseudocode": pseudo,
                         "disasm": "", "callees": []}
        return {"functions": names[:400], "focus": focus, "tool": "ghidra_bridge"}

    def _decompile_one(self, focus: str) -> tuple[str, str]:
        """Decompile the function identified by `focus` over the bridge — an exact NAME, or a
        hex ADDRESS resolved to the function CONTAINING it (analyze-at-address, mirroring the
        headless probe). Returns (resolved_name, pseudocode).

        Two scoping rules drive the shape of this eval, both learned the hard way:
        - The validated focus token is INLINED as a "..." string literal (`_SAFE_NAME`/`_ADDR`
          exclude quotes and backslashes, so it can't break out of the literal).
        - The resolved function is computed at the eval's TOP LEVEL and passed into the worker
          as a bound lambda PARAMETER (`fn`). A bound `remote_eval` KWARG does NOT work: jfx_bridge
          injects kwargs into the eval's LOCALS, which a nested lambda/comprehension can't close
          over (free vars resolve via globals), so the old `fn=` kwarg raised NameError every call.
        """
        if _ADDR.match(focus or ""):
            # getFunctionContaining returns None when the address isn't inside any function.
            target_expr = ("currentProgram.getFunctionManager().getFunctionContaining("
                           'currentProgram.getAddressFactory().getAddress("%s"))' % focus)
        elif _SAFE_NAME.match(focus or ""):
            # `or [None]` so an unknown name yields None, not an IndexError on the [0].
            target_expr = ("([f for f in currentProgram.getFunctionManager().getFunctions(True) "
                           'if f.getName()=="%s"] or [None])[0]' % focus)
        else:
            raise BridgeUnavailable(f"unsafe Ghidra focus: {focus!r}")
        # Guard every step the headless probe guards, so a not-found name / not-in-a-function
        # address / failed-or-timed-out decompile returns a clean sentinel instead of a raw
        # remote exception: fn is None -> ('', ''); a function that doesn't decompile ->
        # (name, ''); otherwise (name, C). The resolved function rides in as a bound lambda PARAM.
        return self.b.remote_eval(
            "(lambda di, fn: ('', '') if fn is None else "
            "(lambda res: (fn.getName(), res.getDecompiledFunction().getC()) "
            "if (res is not None and res.decompileCompleted() "
            "and res.getDecompiledFunction() is not None) else (fn.getName(), ''))"
            "((di.openProgram(currentProgram), di.decompileFunction(fn, 60, "
            "__import__('ghidra.util.task', fromlist=['ConsoleTaskMonitor']).ConsoleTaskMonitor()))[1])"
            ")("
            "__import__('ghidra.app.decompiler', fromlist=['DecompInterface']).DecompInterface(), "
            + target_expr + ")"
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


class _ManagedOps:
    """Ops backed by HexGraph's OWN managed resident bridge (engine.re.bridge) — a pyghidra process
    holding the target's warm project open behind a plain line-delimited JSON RPC over TCP.

    DISTINCT from `_RemoteOps` (which drives a researcher's live Ghidra via ghidra_bridge/jfx_bridge
    remote_eval): here HexGraph controls both ends, so the wire is a small vetted protocol — the
    client sends a structured request, the resident server runs the matching `pyghidra_lib` core and
    returns JSON. No client library, no remote code eval. Serves every Ghidra op the headless path
    does — decompile, list, xrefs, taint, emulate, and rename (the one write, persisted server-side
    into the resident project)."""

    def __init__(self, host: str, port: int, timeout: float = 600.0) -> None:
        self.host, self.port, self.timeout = host, port, timeout

    def _rpc(self, req: dict) -> dict:
        import json
        import socket

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
                line = sock.makefile("rb").readline()
        except OSError as exc:
            raise BridgeUnavailable(
                f"managed Ghidra bridge at {self.host}:{self.port} unreachable: {exc}") from exc
        if not line:
            raise BridgeUnavailable("managed Ghidra bridge closed the connection with no response")
        return json.loads(line.decode("utf-8"))

    def list_programs(self) -> list[dict]:
        # One resident program; shape the row like _RemoteOps for a uniform caller.
        resp = self._rpc({"op": "ping"})
        return [{"name": "artifact", "path": None, "language": None,
                 "functions": resp.get("functions_total")}]

    def executable_path(self, program: str) -> str | None:
        return None

    def decompile(self, program: str | None, function: str | None) -> dict:
        req: dict = {"op": "decompile"}
        if function:
            req["focus"] = function
        resp = self._rpc(req)
        # An error / not-found focus reads as no focus, mirroring the headless probe.
        focus = None if resp.get("error") else resp.get("focus")
        return {"functions": (resp.get("functions") or [])[:400], "focus": focus,
                "tool": "ghidra_bridge"}

    # The remaining Ghidra ops, each a single RPC to the resident program (the server runs the
    # matching core and returns the SAME JSON the headless probe would). Payloads mirror the
    # `ghidra_probe.py` argv: xrefs (mode, subject) · taint · emulate (focus) · rename (addr, name).
    def xrefs(self, mode: str, subject: str | None) -> dict:
        return self._rpc({"op": "xrefs", "mode": mode, "subject": subject})

    def run_taint(self) -> dict:
        return self._rpc({"op": "taint"})

    def run_emulate(self, function: str | None) -> dict:
        return self._rpc({"op": "emulate", "focus": function})

    def rename_function(self, address: str, new_name: str) -> dict:
        return self._rpc({"op": "rename", "address": address, "new_name": new_name})

    def search_bytes(self, bytes_pattern, immediate) -> dict:
        return self._rpc({"op": "search", "bytes_pattern": bytes_pattern, "immediate": immediate})


def connect_managed(host: str, port: int) -> BridgeOps:
    """Ops for HexGraph's managed resident bridge (custom JSON RPC). Unlike `connect_ops`, needs NO
    client library — HexGraph controls both ends. Used by decompiler routing for a live bridge."""
    return _ManagedOps(host, port)


class GhidraBridgeDecompiler(Decompiler):
    name = "ghidra_bridge"

    def __init__(self, ops: BridgeOps | None = None) -> None:
        self._ops = ops

    def _resolve(self) -> BridgeOps:
        return self._ops if self._ops is not None else connect_ops()

    def decompile(self, artifact: str, function: str | None = None, *,
                  address: str | None = None, reanalyze: bool = False, project=None) -> dict:
        # The bridge talks to a Ghidra you already have open (your project IS the cache);
        # `project` is accepted for seam parity and ignored. An address focus is passed through
        # for the bridge to resolve.
        if reanalyze:
            # A resident bridge holds the project; re-analysis is a COLD re-import that can't run
            # over the bridge (and would conflict with a headless re-import). Surface it rather than
            # silently no-op the reanalyze — the caller (re_reanalyze) sees the actionable error.
            return {"functions": [], "focus": None,
                    "error": "a resident Ghidra bridge holds this target — re_bridge_stop first to "
                             "re-analyze (a cold re-import), then restart the bridge"}
        return self._resolve().decompile(program=None, function=function or address)

    # The rest of the Ghidra op surface, served by the MANAGED bridge (routed via
    # `sandbox.decompiler.ghidra_op_backend`). Same signatures as `GhidraDecompiler`'s so a call site
    # can ask either backend identically; `project` is accepted for seam parity and ignored (a live
    # bridge IS the warm project).
    def _managed(self) -> "_ManagedOps":
        """These ops are served ONLY by the managed per-target bridge; a bare
        GhidraBridgeDecompiler() in researcher-`bridge` mode drives the jfx `_RemoteOps`, which has no
        such methods. Guard with a clear error rather than an opaque AttributeError. Not reachable
        today — every call site routes via `ghidra_op_backend`, which only builds it with a
        `connect_managed` ops — but keeps the seam honest if that changes."""
        ops = self._resolve()
        if not isinstance(ops, _ManagedOps):
            raise BridgeUnavailable(
                "this Ghidra op is served only by a managed per-target bridge (re_bridge_start); "
                "the researcher-Ghidra bridge is decompile-only")
        return ops

    def xrefs(self, artifact: str, *, mode: str, subject: str | None = None, project=None) -> dict:
        return self._managed().xrefs(mode, subject)

    def run_taint(self, artifact: str, *, project=None) -> dict:
        return self._managed().run_taint()

    def run_emulate(self, artifact: str, function: str, *, project=None) -> dict:
        return self._managed().run_emulate(function)

    def rename_function(self, artifact: str, *, address: str, new_name: str, project=None) -> dict:
        return self._managed().rename_function(address, new_name)

    def search_bytes(self, artifact: str, *, bytes_pattern: str | None = None,
                     immediate: str | None = None, project=None) -> dict:
        return self._managed().search_bytes(bytes_pattern, immediate)


def list_open_programs(ops: BridgeOps | None = None) -> list[dict]:
    return (ops or connect_ops()).list_programs()


def import_program(session, project, *, path: str, name: str | None = None, ops: BridgeOps | None = None):
    """Ingest a program Ghidra has open as a target, using its real on-disk bytes
    (Ghidra runs on the same machine — loopback). Recon then populates the facts,
    so the 'targets only from real bytes' invariant holds."""
    import os

    from hexgraph.engine.pipeline import analyze_target
    from hexgraph.engine.targets.ingest import ingest_file
    from hexgraph.engine.targets.unpack import build_links_against
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
