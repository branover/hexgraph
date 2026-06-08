"""The TaintAnalyzer seam (design §7 Phase 4) — grounded source→sink data-flow taint.

Computed from REAL P-Code (Ghidra `HighFunction`), never the LLM. `GhidraTaintAnalyzer`
runs the sandboxed `--taint` pass (reusing the persistent Ghidra project, so taint after a
prior decompile pays no re-analysis cost); when Ghidra isn't the active backend the seam
degrades to `NullTaintAnalyzer` — taint is simply unavailable and nothing is fabricated.
angr-backed input→sink solving slots in behind this same seam later (Phase 5 Tier B).

`analyze_taint` runs the analyzer over a target, records a `taint` Observation (the full
flow list lives in the substrate — NOT bulk graph nodes), and PROMOTES only the grounded
few nodes/edges on each supporting path: the source function, a `sink` node for the
dangerous call, and a `taints` edge between them that `engine.findings.reachability` already walks.
Its graph footprint is bounded by the flows it finds, never the program (design §5.1/§5.3).
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.orm import Session

log = logging.getLogger(__name__)


class TaintAnalyzer(ABC):
    """Grounded source→sink taint over a target's real code. Implementations run in the
    sandbox and never expose raw bytes to the LLM — only the structured flow list."""

    name: str
    available: bool = True

    @abstractmethod
    def analyze(self, artifact: str, *, project: Any = None) -> dict:
        """Return ``{available, flows, analyzed, error}``. Each flow is
        ``{function, function_addr, source:{kind,detail},
            sink:{func,category,call_addr,arg_index}, sanitized:[...]}``."""
        ...


class NullTaintAnalyzer(TaintAnalyzer):
    """No grounded taint backend (Ghidra not enabled). The deterministic core emits no taint
    findings rather than fabricating one — taint just reports unavailable."""

    name = "none"
    available = False

    def analyze(self, artifact: str, *, project: Any = None) -> dict:
        return {"available": False, "flows": [], "analyzed": 0, "error": None}


class GhidraTaintAnalyzer(TaintAnalyzer):
    """Ghidra `HighFunction` P-Code taint, run headless in the sandbox over the persistent
    project (via `GhidraDecompiler.run_taint`)."""

    name = "ghidra"
    available = True

    def __init__(self, decompiler: Any = None) -> None:
        self._decompiler = decompiler

    def analyze(self, artifact: str, *, project: Any = None) -> dict:
        deco = self._decompiler
        if deco is None:
            from hexgraph.sandbox.decompiler import GhidraDecompiler

            deco = GhidraDecompiler()
        run_taint = getattr(deco, "run_taint", None)
        if run_taint is None:
            return {"available": False, "flows": [], "analyzed": 0,
                    "error": "active decompiler has no taint backend"}
        try:
            out = run_taint(artifact, project=project) or {}
        except Exception as exc:  # noqa: BLE001 — a sandbox/Ghidra failure DEGRADES (no flows,
            # an error note), it never aborts the analysis task. Honors the graceful-degrade
            # contract analyze_taint documents, so a future static_analysis caller need not guard.
            log.warning("taint analysis failed (%s): %s", type(exc).__name__, exc)
            return {"available": True, "flows": [], "analyzed": 0, "error": str(exc)}
        taint = out.get("taint") or {}
        return {"available": True, "flows": taint.get("flows", []),
                "analyzed": taint.get("analyzed", 0), "error": out.get("error")}


def get_taint_analyzer() -> TaintAnalyzer:
    """Pick the taint analyzer the way `get_decompiler()` picks a decompiler — Ghidra (headless)
    when it's enabled in Settings, else `NullTaintAnalyzer`. Core code asks the seam and never
    names a tool; an unavailable analyzer degrades gracefully (no taint findings, none faked)."""
    try:
        from hexgraph import settings as st

        ghidra = (st.resolved().get("features", {}) or {}).get("ghidra", {}) or {}
        if ghidra.get("enabled") and (ghidra.get("mode") or "headless") == "headless":
            return GhidraTaintAnalyzer()
    except Exception:  # noqa: BLE001 — a settings hiccup must never crash analysis selection
        log.debug("taint analyzer selection failed; using NullTaintAnalyzer", exc_info=True)
    return NullTaintAnalyzer()


def _source_label(source: dict) -> str:
    """A short human label for a flow's source (`param host`, `call_return getenv`, …)."""
    kind = (source or {}).get("kind") or "unknown"
    detail = (source or {}).get("detail") or ""
    return ("%s %s" % (kind, detail)).strip()


def analyze_taint(session: Session, project: Any, target: Any, *,
                  source: str = "agent", analyzer: TaintAnalyzer | None = None) -> dict:
    """Run grounded P-Code taint over `target`, record a `taint` Observation, and promote the
    grounded few nodes/edges on each flow: the source `function` node, a `sink` node for the
    dangerous call, and a `taints` edge between them (which `engine.findings.reachability` walks).

    Returns ``{available, flows, analyzed, promoted:{functions,sinks,edges},
    observation_id, cached, error}``. When no analyzer is available, returns availability
    False and promotes nothing — never fabricates a flow."""
    from hexgraph.engine import observations as obs
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.graph.nodes import get_or_create_node

    analyzer = analyzer or get_taint_analyzer()
    path = getattr(target, "path", None)
    promoted = {"functions": 0, "sinks": 0, "edges": 0}
    if not analyzer.available or not path:
        return {"available": False, "flows": [], "analyzed": 0,
                "promoted": promoted, "observation_id": None, "cached": False, "error": None}

    result = analyzer.analyze(path, project=project)
    flows = result.get("flows") or []
    status = "error" if result.get("error") else "ok"

    n_exec = sum(1 for f in flows if (f.get("sink") or {}).get("category") == "command_exec")
    n_overflow = sum(1 for f in flows if (f.get("sink") or {}).get("category") == "buffer_overflow")
    summary = ("taint: %d flow(s) (%d command-exec, %d overflow) across %d function(s)"
               % (len(flows), n_exec, n_overflow, result.get("analyzed", 0)))
    observation, cached = obs.record_observation(
        session, project_id=project.id, target_id=target.id, source=source,
        tool="taint_analysis", args=None, result_kind="taint", payload=result,
        summary=summary, status=status, content_hash=obs.content_hash_for(target),
    )

    seen_edges = set()
    for flow in flows:
        sink = flow.get("sink") or {}
        fn_name = flow.get("function")
        sink_func = sink.get("func")
        if not fn_name or not sink_func:
            continue
        fnode = get_or_create_node(
            session, project_id=project.id, node_type="function", name=fn_name,
            target_id=target.id, address=flow.get("function_addr"), created_by="taint",
        )
        promoted["functions"] += 1
        sink_name = "%s@%s" % (sink_func, sink.get("call_addr") or "?")
        snode = get_or_create_node(
            session, project_id=project.id, node_type="sink", name=sink_name,
            target_id=target.id, address=sink.get("call_addr"), created_by="taint",
            attrs={"is_sink": True, "sink_func": sink_func, "category": sink.get("category")},
        )
        promoted["sinks"] += 1
        key = (fnode.id, snode.id)
        if key in seen_edges:
            continue
        seen_edges.add(key)
        add_edge(
            session, project_id=project.id, src=("node", fnode.id), dst=("node", snode.id),
            type="taints", origin="tool", confidence=0.9, created_by_tool="taint_analysis",
            attrs={
                "source": _source_label(flow.get("source") or {}),
                "via_param": str(sink.get("arg_index")) if sink.get("arg_index") is not None else None,
                "sanitized": ", ".join(flow.get("sanitized") or []) or "none",
                "category": sink.get("category"),
            },
            merge=True,
        )
        promoted["edges"] += 1

    return {"available": True, "flows": flows, "analyzed": result.get("analyzed", 0),
            "promoted": promoted, "observation_id": observation.id, "cached": cached,
            "error": result.get("error")}
