#!/usr/bin/env python3
"""Entrypoint for a persistent Ghidra bridge container (engine.re.bridge) — PyGhidra edition.

`start_detached` runs this as `python3 /opt/hexgraph/ghidra_bridge_probe.py /artifact` in a
long-lived (`docker run -d`) container. It opens the target's WARM Ghidra slot ONCE via pyghidra
(no re-analysis) and keeps it resident behind a plain line-delimited JSON RPC server
(`pyghidra_lib.serve_bridge`) — so repeated re_decompile for the target skip the per-call project
open (~15s on a 6GB project) that the headless path pays every time.

Replaces the Jython `analyzeHeadless -postScript ghidra_bridge_serve.py` + jfx_bridge harness: the
server is now HexGraph's OWN stdlib-socket RPC calling the SAME in-process cores as `ghidra_probe`,
so no ghidra_bridge/jfx_bridge is baked into the image. Binds 0.0.0.0 so the container's private
bridge IP is reachable from the host (the host connects to <container-ip>:GHIDRA_BRIDGE_PORT). MUST
run from /opt/hexgraph (a read-only mount) — pyghidra's namespace finder recurses on a writable
sys.path[0]; the runner invokes `python3 /opt/hexgraph/ghidra_bridge_probe.py`, so that holds."""
import os
import sys

try:  # bare import when RUN from /opt/hexgraph; package path when IMPORTED as a module (tests)
    import pyghidra_lib as L
except ModuleNotFoundError:  # pragma: no cover
    from hexgraph.sandbox.probes import pyghidra_lib as L

PORT = int(os.environ.get("GHIDRA_BRIDGE_PORT", "4768"))


def main() -> int:
    artifact = sys.argv[1] if len(sys.argv) > 1 else "/artifact"
    try:
        L.start()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"ghidra_bridge_probe: pyghidra failed to start: {exc}\n")
        return 3
    try:
        # WARM open REQUIRED (start_bridge gates on slot.exists()); cold_analyze=False so a missing
        # slot fails fast here rather than silently kicking off a huge cold analysis in the bridge.
        with L.open_target(artifact, cold_analyze=False) as (program, flat, cached):
            from ghidra.util.task import ConsoleTaskMonitor

            sys.stderr.write(f"ghidra_bridge_probe: project resident (cached={cached}); "
                             f"serving JSON RPC on 0.0.0.0:{PORT}\n")
            sys.stderr.flush()
            # Pass the CLASS (a per-request monitor factory), not an instance: serve_bridge mints a
            # fresh ConsoleTaskMonitor per request so a decompile timeout — which cancels the monitor
            # it's handed, permanently for a ConsoleTaskMonitor — can't poison later decompiles into
            # empty bodies. See pyghidra_lib._serve_one.
            L.serve_bridge("0.0.0.0", PORT, program, flat, ConsoleTaskMonitor)  # blocks forever
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"ghidra_bridge_probe: {exc}\n")
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
