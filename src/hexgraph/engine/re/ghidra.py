"""Ghidra integration — optional, behind settings.

Three ways HexGraph can use Ghidra, all opt-in via Settings (`features.ghidra`):

- **headless** — `analyzeHeadless` runs inside the existing `--network none`
  sandbox image (built with `WITH_GHIDRA=1`). The natural fit: Ghidra is just
  another tool over the target's bytes, and the target is never executed.
- **bridge** — connect over loopback to a Ghidra you already have open (the
  `ghidra_bridge` server). HexGraph pulls decompilation / programs from your
  live analysis; bytes never leave your machine.
- **enrich_recon** — record Ghidra's function inventory / call graph / recovered
  structs into the SUBSTRATE (the Observation store), so they become queryable and
  ENRICH already-curated nodes without flooding the graph (builds on headless;
  design §5.3).

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


def _bridge_smoke_decompile(host: str, port: int) -> tuple[bool, str, str | None]:
    """Prove the bridge can actually DECOMPILE, not just that its socket is open: connect, list
    the active program's functions, and decompile the first one. Returns (ok, detail, fn_name).
    An active program with no functions still counts as ok (nothing to test) so an empty target
    doesn't read as broken. Any failure → (False, "<Error>: …", None)."""
    try:
        from hexgraph.engine.re.ghidra_bridge import connect_ops

        ops = connect_ops(host, port)
        names = (ops.decompile(None, None).get("functions")) or []
        if not names:
            return True, "no functions", None
        ops.decompile(None, names[0])  # exercises the real remote decompile path
        return True, "ok", names[0]
    except Exception as exc:  # noqa: BLE001 — a smoke failure means bridge decompile is broken
        return False, f"{type(exc).__name__}: {exc}", None


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
        result = {"enabled": True, "mode": mode, "host": host, "port": port,
                  "bridge_client_installed": installed, "reachable": reachable}
        if not installed:
            return {**result, "ok": False,
                    "detail": "Install the bridge client: pip install ghidra_bridge (and run the server script in Ghidra)."}
        if not reachable:
            return {**result, "ok": False,
                    "detail": f"No Ghidra Bridge listening at {host}:{port}. In Ghidra, run ghidra_bridge_server.py."}
        # Reachable + client present is NOT enough: a socket check alone reports green while
        # decompilation throws. Prove a real decompile works (the honest signal).
        smoke_ok, smoke_detail, fn = _bridge_smoke_decompile(host, port)
        if smoke_ok:
            detail = (f"Connected to Ghidra Bridge at {host}:{port}; decompiled {fn} as a smoke test."
                      if fn else
                      f"Connected to Ghidra Bridge at {host}:{port} (no functions in the active program to smoke-test).")
        else:
            detail = f"Connected to Ghidra Bridge at {host}:{port}, but a test decompile failed: {smoke_detail}"
        return {**result, "ok": smoke_ok, "detail": detail}

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
    """Run Ghidra's full-inventory analysis and record it into the SUBSTRATE — the
    Observation store (design §5.3) — NOT as bulk graph nodes.

    Ghidra computes the whole function inventory, the call graph, and the recovered
    structs; dumping all of that straight into the typed graph was a graph-explosion
    source (≤200 functions + ≤1000 call edges + ≤100 structs, ELF/libc struct noise
    included). Instead we record each as an Observation: the extract-at-write machinery
    distills the always-welcome facts (prototypes, addresses, `A calls B` relationships,
    real-struct layouts) into the enrichment index, so they ENRICH any function/struct
    already curated and self-wire `calls` edges among already-promoted functions — but
    create no new bulk nodes. Built-in ELF/libc structs live in the queryable catalog,
    filtered by the extractor, and never reach the graph.

    Returns a summary of what was recorded; raises only on a hard sandbox failure
    (caller guards)."""
    from hexgraph.engine import observations as O
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    # Route through the decompiler seam (passing `project`) so the full-inventory analysis
    # PERSISTS to the project's Ghidra-project cache and is reused by later decompiles — same
    # JSON contract (functions/calls/structs), analyze-once.
    data = GhidraDecompiler().decompile(target.path, project=project)
    if "error" in data:
        return {"ok": False, "detail": data["error"]}

    chash = O.content_hash_for(target)
    functions = list(data.get("functions") or [])
    calls = list(data.get("calls") or [])
    structs = list(data.get("structs") or [])

    def _record(tool, result_kind, payload, summary):
        # content_hash scopes the facts to the exact bytes (extract-at-write + passive
        # invalidation). Recording creates ZERO graph nodes.
        O.record_observation(
            session, project_id=project.id, target_id=target.id, source="ghidra-enrich",
            tool=tool, args={}, result_kind=result_kind, payload=payload,
            summary=summary, content_hash=chash)

    # Function inventory + recovered prototypes/addresses → function_list facts.
    _record("enrich_recon", "function_list",
            {"functions": [f if isinstance(f, dict) else {"name": f} for f in functions]},
            f"{len(functions)} functions")
    # Call graph → `A calls B` relationship facts (edges self-wire among promoted fns).
    _record("enrich_recon", "call_graph",
            {"functions": _call_graph_records(calls)}, f"{len(calls)} call edges")
    # Recovered structs → real-layout facts (the extractor drops built-ins).
    _record("enrich_recon", "structs", {"structs": structs}, f"{len(structs)} structs")

    return {"ok": True, "recorded": True, "functions": len(functions),
            "calls": len(calls), "structs": len(structs)}


# A function rename propagated into Ghidra: the address it lives at (validated before any
# probe interpolation) and the new name (a plausible identifier — Ghidra's setName takes it
# as a Java arg, not a shell command, so this guards against garbage, not injection).
import re as _re

_RENAME_ADDR = _re.compile(r"^0x[0-9a-fA-F]+$")
_RENAME_IDENT = _re.compile(r"^[A-Za-z_][A-Za-z0-9_:.$]*$")


def propagate_function_rename(session, node, new_name: str) -> dict:
    """Phase 3 rename round-trip: when Ghidra is the active backend, write a confirmed
    function rename INTO the persistent Ghidra project and re-decompile, so the analyst's
    rename sticks for every future decompile and the graph reflects the fresh result.

    Best-effort and never raises into the caller — the graph rename has already succeeded;
    this only adds Ghidra propagation when it's possible. Returns a status dict.

    Cache-coherence: the re-decompile is recorded under args={"function": new_name}, which is
    a DISTINCT Observation from the pre-rename one (the dedup key includes args), so it never
    serves the stale decompile — the new name IS the cache-bust dimension, no epoch needed."""
    if node.node_type != "function" or not node.address:
        return {"propagated": False, "reason": "not an addressed function node"}
    gcfg = ghidra_config()
    if not gcfg.get("enabled") or gcfg.get("mode") != "headless":
        return {"propagated": False, "reason": "headless Ghidra is not the active backend"}
    if not (_RENAME_ADDR.match(str(node.address)) and _RENAME_IDENT.match(new_name)):
        return {"propagated": False, "reason": "address or name failed validation"}

    from hexgraph.db.models import Project, Target
    from hexgraph.sandbox.runner import docker_available

    target = session.get(Target, node.target_id)
    project = session.get(Project, node.project_id)
    if target is None or project is None or not getattr(target, "path", None):
        return {"propagated": False, "reason": "no target path"}
    if not docker_available():
        return {"propagated": False, "reason": "Docker/sandbox not running"}

    from hexgraph.sandbox.decompiler import GhidraDecompiler

    try:
        out = GhidraDecompiler().rename_function(
            target.path, address=str(node.address), new_name=new_name, project=project)
    except Exception as exc:  # noqa: BLE001 — propagation must never break the graph rename
        return {"propagated": False, "reason": f"rename probe failed: {exc}"}
    if not isinstance(out, dict) or out.get("error"):
        return {"propagated": False, "reason": (out or {}).get("error", "no result")}
    focus = out.get("focus")
    if not isinstance(focus, dict):
        return {"propagated": False, "reason": "rename produced no focus (function not found?)"}

    # Record the fresh decompile (distinct args → no stale-cache hit) so the renamed function's
    # recovered facts re-index and enrich the node (whose name is already new_name). Also refresh
    # the node's stored pseudocode so its body reflects the rename, not just its attrs.
    from hexgraph.engine import observations as O

    O.record_observation(
        session, project_id=project.id, target_id=target.id, source="annotate-rename",
        tool="decompile_function", args={"function": new_name}, result_kind="decompilation",
        payload=out, summary=f"re-decompiled {new_name} after rename",
        content_hash=O.content_hash_for(target), node_refs=[new_name])
    if focus.get("pseudocode"):
        attrs = dict(node.attrs_json or {})
        attrs["pseudocode"] = focus["pseudocode"]
        node.attrs_json = attrs
    return {"propagated": True, "function": new_name}


def _call_graph_records(calls) -> list[dict]:
    """Reshape a Ghidra call-graph (list of [caller, callee] pairs) into per-caller
    function records with a `callees` list, the shape the function/call extractor reads."""
    by_caller: dict[str, list[str]] = {}
    for pair in calls:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        caller, callee = pair
        if caller and callee:
            by_caller.setdefault(caller, []).append(callee)
    return [{"name": c, "callees": cs} for c, cs in by_caller.items()]


def _self_artifact() -> str:
    """A throwaway file to satisfy the probe's read-only artifact mount during a
    --check (the probe ignores it when --check is passed)."""
    import tempfile

    fd, path = tempfile.mkstemp(prefix="hexgraph-ghidra-check-")
    import os

    os.close(fd)
    return path
