"""The deterministic static-analysis core (design §6, Phase 4).

`static_analysis` is split into two layers. THIS layer always runs and is
backend-independent: it computes grounded source→sink taint
(`engine.re.taint.analyze_taint`) and emits a finding for each flow that is DERIVED FROM THE
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

# Taint source kinds (from `engine.re.taint` / the Ghidra probe) where the untrusted input ENTERS
# WITHIN the analyzed function itself — a self-contained, fully-grounded source→sink flow:
#   * `libc_input`  — a buffer-filling input call (fgets/read/recv/...) landed untrusted bytes here
#   * `call_return` — an attacker-influenced library return (getenv/getchar/fgetc)
# For these the intra-procedural taint analysis sees the WHOLE flow (input boundary → sink in one
# function), so high confidence is warranted. A `param` source, by contrast, only establishes the
# flow IF the parameter is attacker-controlled — which the call graph (engine.findings.reachability)
# decides, not this intra-procedural pass — so it earns at most medium until reachability argues it.
_SELF_CONTAINED_SOURCES = frozenset({"libc_input", "call_return"})


def _grounded_finding(flow: dict) -> Finding | None:
    """Turn one grounded taint flow into a schema-shaped Finding, or None if it isn't a
    category we surface.

    Confidence is calibrated to how strong the flow actually is, so the deterministic core never
    over-claims a confident false positive (the whole point of grounding it in real P-Code):

      * `high`   — a SELF-CONTAINED flow: the untrusted input both ENTERS (a libc input call /
                   source return) and reaches the sink WITHIN this one function, so the
                   intra-procedural taint pass observed the entire path. Genuine and complete.
      * `medium` — a PARAMETER-sourced flow (the input arrives from a caller): real, but whether
                   that parameter is actually attacker-controlled depends on the call graph, which
                   reachability (engine.findings.reachability), not this intra-procedural pass,
                   establishes. We must NOT claim high until reach is argued.
      * `low`    — the source is UNATTRIBUTED (`unknown`/missing): taint reached the sink but could
                   not be tied to any real input boundary. This is the over-broad / input-
                   independent case; we record it (tagged distinctly) for triage but never confidently.

    A present-but-unverified sanitizer on the path caps the result at medium (never high)."""
    sink = flow.get("sink") or {}
    category = _CATEGORY.get(sink.get("category"))
    fn = flow.get("function")
    sink_func = sink.get("func")
    if not (category and fn and sink_func):
        return None

    src = flow.get("source") or {}
    src_kind = (src.get("kind") or "").strip()
    source_label = ("%s %s" % (src_kind, src.get("detail", ""))).strip() or "untrusted input"
    sanitized = flow.get("sanitized") or []

    # Calibrate confidence by how well the source is attributed (see the docstring). An
    # unattributed source is the over-broad / input-independent case the prior code over-promoted.
    input_attributed = src_kind in _SELF_CONTAINED_SOURCES or src_kind == "param"
    if src_kind in _SELF_CONTAINED_SOURCES:
        confidence = "high"
        prov_note = ""
    elif src_kind == "param":
        confidence = "medium"  # intra-procedural only — reachability must argue the param is controlled
        prov_note = (" The source is a function parameter, so this flow holds only if the parameter "
                     "is attacker-controlled; reachability across the call graph (not this "
                     "intra-procedural pass) must establish that — confidence is medium until it does.")
    else:
        confidence = "low"  # unattributed source — taint reached the sink but no input boundary
        prov_note = (" The tainted value could NOT be tied to a concrete input source (it is "
                     "input-independent / unattributed), so this is reported at low confidence and "
                     "must be triaged before it is treated as a real input-driven flow.")

    san_note = ""
    if sanitized:
        # A partial mitigation exists — flag for triage, don't over-claim. Cap at medium (never
        # high), but never RAISE a flow already below medium (an unattributed low stays low).
        if confidence == "high":
            confidence = "medium"
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
                 "inferred): in %s (%s), the %s reaches %s() at %s as argument %s.%s%s"
                 % (fn, flow.get("function_addr"), source_label, sink_func,
                    sink.get("call_addr"), sink.get("arg_index"), san_note, prov_note))

    return Finding(
        title=title[:200], severity="high", confidence=confidence, category=category,
        summary=summary[:600], reasoning=reasoning,
        evidence=Evidence(
            function=fn, address=flow.get("function_addr"), sink=sink_func,
            extra={"grounded": True, "taint": {
                "source": source_label, "source_kind": src_kind or None,
                "input_attributed": input_attributed, "category": sink.get("category"),
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
    from hexgraph.engine.graph.edges import add_edge
    from hexgraph.engine.findings.findings import persist_finding
    from hexgraph.engine.graph.nodes import get_or_create_node
    from hexgraph.engine.re.taint import analyze_taint

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
        # analyze_taint promoted, so engine.findings.reachability has the sink candidate to argue from.
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
