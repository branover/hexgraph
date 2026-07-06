# -*- coding: utf-8 -*-
# NOTE: this runs inside Ghidra's Jython (Python 2.7) -- keep it ASCII-only (Jython aborts a
# script with a SyntaxError on a non-ASCII byte without an encoding cookie).
"""Ghidra Bridge server harness -- an analyzeHeadless postScript that keeps a project resident.

engine/re/bridge.py launches this in a long-lived, detached sandbox container:

    analyzeHeadless <proj> hexgraph -process artifact -noanalysis \
        -scriptPath /opt/hexgraph -postScript ghidra_bridge_serve.py

Because -process opens the ALREADY-analyzed warm slot (no -import, no re-analysis) and this script
BLOCKS (background=False -> server.run() runs in this thread), the JVM and the opened program stay
resident to serve ghidra_bridge RPC calls -- so repeated re_decompile/re_xrefs/... for the target
skip the per-call project open (~15s on a 6GB project) that the headless path pays every time.

The server binds 0.0.0.0 so the container's bridge IP is reachable from the HexGraph host (a
docker-proxy published port does NOT work -- jfx_bridge is bidirectional and the host->container
proxy drops the server's callbacks). The host connects to <container-ip>:GHIDRA_BRIDGE_PORT.

The ghidra_bridge server scripts + jfx_bridge are baked into the image at /opt/ghidra-bridge (NOT
the mounted probes dir, which is overlaid at runtime); add that to the Jython path.
"""
import os
import sys

sys.path.insert(0, os.environ.get("GHIDRA_BRIDGE_SCRIPTS", "/opt/ghidra-bridge"))

from ghidra_bridge_server import GhidraBridgeServer  # noqa: E402  (path set above)

GhidraBridgeServer.run_server(
    server_host="0.0.0.0",
    server_port=int(os.environ.get("GHIDRA_BRIDGE_PORT", "4768")),
    background=False,  # run() in THIS thread -> blocks -> keeps analyzeHeadless (JVM + program) alive
)
