"""Ghidra integration — optional, behind settings.

Three ways HexGraph can use Ghidra, all opt-in via Settings (`features.ghidra`):

- **headless** — `analyzeHeadless` runs inside the existing `--network none`
  sandbox image (built with `WITH_GHIDRA=1`). The natural fit: Ghidra is just
  another tool over the target's bytes, and the target is never executed.
- **bridge** — connect over loopback to a Ghidra you already have open (the
  `ghidra_bridge` server). HexGraph pulls decompilation / programs from your
  live analysis; bytes never leave your machine.
- **enrich_recon** — materialize Ghidra's function inventory / call graph /
  recovered structs into the typed graph (builds on headless).

Everything degrades gracefully: when Ghidra is disabled or unavailable, callers
fall back to radare2 and recon proceeds unchanged.
"""

from __future__ import annotations

import socket

from hexgraph import settings as st


def ghidra_config() -> dict:
    return st.resolved()["features"]["ghidra"]


def bridge_reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_ghidra() -> dict:
    """Best-effort status of the configured Ghidra integration (no target needed).
    Returns {enabled, mode, ok, detail, ...} for the Settings 'Test' button."""
    g = ghidra_config()
    if not g["enabled"]:
        return {"enabled": False, "ok": False, "detail": "Ghidra is disabled in Settings."}

    mode = g["mode"]
    if mode == "bridge":
        host, port = g["bridge"]["host"], g["bridge"]["port"]
        try:
            import ghidra_bridge  # noqa: F401

            installed = True
        except Exception:  # noqa: BLE001
            installed = False
        reachable = bridge_reachable(host, port)
        ok = installed and reachable
        if not installed:
            detail = "Install the bridge client: pip install ghidra_bridge (and run the server script in Ghidra)."
        elif not reachable:
            detail = f"No Ghidra Bridge listening at {host}:{port}. In Ghidra, run ghidra_bridge_server.py."
        else:
            detail = f"Connected to Ghidra Bridge at {host}:{port}."
        return {"enabled": True, "mode": mode, "ok": ok, "detail": detail,
                "bridge_client_installed": installed, "reachable": reachable, "host": host, "port": port}

    # headless: Ghidra must be present in the sandbox image (WITH_GHIDRA=1).
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return {"enabled": True, "mode": mode, "ok": False,
                "detail": "Docker is not running; headless Ghidra runs inside the sandbox image."}
    probe = _probe_ghidra_present()
    return {"enabled": True, "mode": mode, "ok": probe["present"], "detail": probe["detail"],
            "ghidra_version": probe.get("version")}


def _probe_ghidra_present() -> dict:
    """Ask the sandbox image whether analyzeHeadless is installed (no target run)."""
    from hexgraph.sandbox.executor import get_executor
    from hexgraph.sandbox.runner import SandboxError

    try:
        # The probe accepts --check and reports Ghidra presence without a target.
        out = get_executor().run_json_probe("ghidra_probe.py", _self_artifact(), extra_args=["--check"])
    except SandboxError as exc:
        return {"present": False, "detail": f"Ghidra not found in sandbox image (build with WITH_GHIDRA=1): {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"present": False, "detail": f"Could not check the sandbox image: {exc}"}
    if out.get("present"):
        return {"present": True, "detail": f"Ghidra {out.get('version', '?')} available in the sandbox.",
                "version": out.get("version")}
    return {"present": False, "detail": out.get("detail", "Ghidra is not installed in the sandbox image.")}


def enrich_enabled() -> bool:
    g = ghidra_config()
    return bool(g["enabled"] and g.get("enrich_recon") and g["mode"] == "headless")


def enrich_target(session, project, target) -> dict:
    """Materialize Ghidra's function inventory, call graph, and recovered structs
    into the typed graph (best-effort). Bounded so it never floods the graph.
    Returns a summary; raises only on a hard sandbox failure (caller guards)."""
    from hexgraph.db.models import EdgeType, NodeType
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.nodes import get_or_create_node, materialize_function
    from hexgraph.sandbox.executor import get_executor

    data = get_executor().run_json_probe("ghidra_probe.py", target.path)
    if "error" in data:
        return {"ok": False, "detail": data["error"]}

    fn_nodes: dict[str, str] = {}
    for name in (data.get("functions") or [])[:200]:
        node = materialize_function(session, project_id=project.id, target_id=target.id,
                                    name=name, created_by="ghidra")
        fn_nodes[name] = node.id

    edges = 0
    for caller, callee in (data.get("calls") or [])[:1000]:
        if caller not in fn_nodes or callee not in fn_nodes:
            continue
        add_edge(session, project_id=project.id, src=("node", fn_nodes[caller]),
                 dst=("node", fn_nodes[callee]), type=EdgeType.calls, origin="ghidra", confidence=0.9)
        edges += 1

    structs = 0
    for st_ in (data.get("structs") or [])[:100]:
        get_or_create_node(session, project_id=project.id, node_type=NodeType.struct,
                           name=st_.get("name", "struct"), target_id=target.id,
                           attrs={"size": st_.get("size"), "fields": st_.get("fields", [])},
                           created_by="ghidra")
        structs += 1

    return {"ok": True, "functions": len(fn_nodes), "calls": edges, "structs": structs}


def _self_artifact() -> str:
    """A throwaway file to satisfy the probe's read-only artifact mount during a
    --check (the probe ignores it when --check is passed)."""
    import tempfile

    fd, path = tempfile.mkstemp(prefix="hexgraph-ghidra-check-")
    import os

    os.close(fd)
    return path
