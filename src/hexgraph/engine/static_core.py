"""The deterministic static-analysis core (design §6, Phase 4).

`static_analysis` is split into two layers. THIS layer always runs and is
backend-independent: it computes grounded source→sink taint
(`engine.taint.analyze_taint`) and emits a finding for each flow that is DERIVED FROM THE
REAL BYTES — "a <source> reaches <sink> via taint path X" — never an LLM guess. The LLM
synthesis layer (the agent loop in `engine.llm_tasks`) runs on top, reasoning over the
now-grounded graph; under the mock backend with no explicit scenario it contributes
nothing (`llm.mock._resolve_scenario` defaults `static_analysis` to `no_findings`), so the
grounded results stand alone instead of a fabricated, binary-agnostic vuln.

The core's graph footprint is bounded by the flows it finds — `analyze_taint` promotes only
the source function + sink node + `taints` edge per flow — never the whole program.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from hexgraph.models.finding import Evidence, Finding

log = logging.getLogger(__name__)

# Taint sink category → the frozen Finding schema's category.
_CATEGORY = {"command_exec": "command-injection", "buffer_overflow": "memory-safety"}


def _grounded_finding(flow: dict) -> Finding | None:
    """Turn one grounded taint flow into a schema-shaped Finding, or None if it isn't a
    category we surface. High confidence (it's computed from real P-Code), dropped to medium
    when an incomplete sanitizer sits on the path (present but not proven sufficient)."""
    sink = flow.get("sink") or {}
    category = _CATEGORY.get(sink.get("category"))
    fn = flow.get("function")
    sink_func = sink.get("func")
    if not (category and fn and sink_func):
        return None

    src = flow.get("source") or {}
    source_label = ("%s %s" % (src.get("kind", ""), src.get("detail", ""))).strip() or "untrusted input"
    sanitized = flow.get("sanitized") or []
    confidence = "high"
    san_note = ""
    if sanitized:
        confidence = "medium"  # a partial mitigation exists — flag for triage, don't over-claim
        san_note = (" An incomplete sanitizer (%s) is applied on the path but does not fully "
                    "neutralize the value." % ", ".join(sanitized))

    if sink.get("category") == "command_exec":
        title = "Tainted input reaches %s() — command injection" % sink_func
        summary = ("A %s value flows into %s() in %s without adequate sanitization, allowing "
                   "command injection." % (source_label, sink_func, fn))
    else:
        title = "Tainted input reaches %s() — buffer overflow" % sink_func
        summary = ("A %s value flows into the unbounded %s() in %s, overflowing the destination "
                   "buffer." % (source_label, sink_func, fn))

    reasoning = ("Grounded P-Code data-flow taint (computed from the decompiled bytes, not "
                 "inferred): in %s (%s), the %s reaches %s() at %s as argument %s.%s"
                 % (fn, flow.get("function_addr"), source_label, sink_func,
                    sink.get("call_addr"), sink.get("arg_index"), san_note))

    return Finding(
        title=title[:200], severity="high", confidence=confidence, category=category,
        summary=summary[:600], reasoning=reasoning,
        evidence=Evidence(
            function=fn, address=flow.get("function_addr"), sink=sink_func,
            extra={"grounded": True, "taint": {
                "source": source_label, "category": sink.get("category"),
                "call_addr": sink.get("call_addr"), "arg_index": sink.get("arg_index"),
                "sanitized": sanitized, "function_addr": flow.get("function_addr")}},
        ),
    )


def run_static_core(session: Session, project: Any, target: Any, *, task: Any = None) -> list[str]:
    """Run grounded taint over `target` and persist a finding per source→sink flow. Returns the
    persisted finding ids (the caller folds them into its reachability / record_run pass).
    `analyze_taint` promotes the grounded nodes/edges; we additionally wire each finding
    `about`→ its sink node so reachability can argue input→sink across the call graph.

    Best-effort and honest: with no Ghidra backend `analyze_taint` reports unavailable and this
    returns no findings — nothing is fabricated."""
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.nodes import get_or_create_node
    from hexgraph.engine.taint import analyze_taint

    result = analyze_taint(session, project, target, source="static_core")
    if not result.get("available"):
        return []

    task_id = getattr(task, "id", None)
    ids: list[str] = []
    for flow in result.get("flows", []):
        finding = _grounded_finding(flow)
        if finding is None:
            continue
        row = persist_finding(session, project_id=project.id, target_id=target.id,
                              task_id=task_id, finding=finding, finding_type="vulnerability")
        ids.append(row.id)
        # persist_finding wires about→ the FUNCTION node; also wire about→ the SINK node that
        # analyze_taint promoted, so engine.reachability has the sink candidate to argue from.
        sink = flow.get("sink") or {}
        snode = get_or_create_node(
            session, project_id=project.id, node_type="sink",
            name="%s@%s" % (sink.get("func"), sink.get("call_addr") or "?"),
            target_id=target.id, address=sink.get("call_addr"), created_by="taint",
        )
        add_edge(session, project_id=project.id, src=("finding", row.id), dst=("node", snode.id),
                 type="about", origin="tool", created_by_task_id=task_id,
                 attrs={"role": "sink"}, merge=True)

    if ids:
        log.info("static core: %d grounded taint finding(s) on target %s", len(ids), target.id)
    return ids
