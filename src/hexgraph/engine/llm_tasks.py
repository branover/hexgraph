"""Execute LLM-backed tasks behind the backend seam (SPEC §5, §6).

`static_analysis`, `reverse_engineering`, `pattern_sweep`, `harness_generation`
all flow through here: gather deterministic facts from the target's recon
metadata (and, for static analysis, decompilation in M3-T5), build a prompt,
ask the selected `LLMBackend` to reason, and persist the resulting findings.

**Backend-agnostic by construction**: this code never branches on which backend
it is — it calls `run_findings(get_backend(...))`. The mock returns canned,
schema-valid findings; real backends return live ones; the path is identical.
Findings' `related_target_refs` become `related_to` edges and
`suggested_followups` are stored for one-click spawning (M4).
"""

from __future__ import annotations

import logging
import os

from sqlalchemy.orm import Session

from hexgraph.db.models import EdgeType, Project, Target, TargetKind, Task, TaskStatus
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.engine.re.recon import RISKY_SINKS
from hexgraph.engine.graph.refs import pick_sibling, resolve_target_ref
from hexgraph.engine.tasks import write_trace
from hexgraph.llm.registry import get_backend
from hexgraph.llm.runner import run_findings_agentic
from hexgraph.tasks.base import TaskContext

log = logging.getLogger(__name__)

LLM_TASK_TYPES = {"static_analysis", "reverse_engineering", "pattern_sweep", "harness_generation"}
_DECOMPILE_TYPES = {"static_analysis", "reverse_engineering"}
_DECOMPILABLE_KINDS = {TargetKind.executable, TargetKind.shared_library}


def _gather_decompilation(target: Target, ctx: TaskContext, project: Project | None = None) -> dict | None:
    """Best-effort decompilation to enrich the prompt (real backends use it; the
    mock ignores it). Gated on the environment — never on the backend identity —
    so the backend seam stays clean. Silently skipped if the sandbox is absent."""
    if os.environ.get("HEXGRAPH_DISABLE_DECOMPILE") == "1":
        return None
    if ctx.task_type not in _DECOMPILE_TYPES or target.kind not in _DECOMPILABLE_KINDS:
        return None
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None
    try:
        from hexgraph.sandbox.decompiler import get_decompiler

        return get_decompiler().decompile(target.path, ctx.function, project=project)
    except Exception:  # noqa: BLE001 — decompilation is best-effort enrichment
        return None


def _build_prompt(target: Target, ctx: TaskContext, decomp: dict | None = None) -> str:
    """A deterministic prompt from recon facts + decompilation. The mock ignores
    it; real backends reason over it. The LLM only ever sees tool output here,
    never raw target bytes."""
    meta = target.metadata_json or {}
    lines = [
        f"Target: {target.name} ({target.format} {target.arch}, {target.kind.value})",
        f"Imports: {', '.join(meta.get('imports', [])[:30])}",
        f"Mitigations: {meta.get('mitigations', {})}",
    ]
    if ctx.objective:
        lines.append(f"Objective: {ctx.objective}")
    if ctx.function:
        lines.append(f"Focus function: {ctx.function}")
    if decomp:
        focus = decomp.get("focus")
        if focus and focus.get("pseudocode"):
            lines.append(f"Decompiled {focus['name']}:\n{focus['pseudocode']}")
        elif decomp.get("functions"):
            lines.append(f"Functions: {', '.join(decomp['functions'][:40])}")
    lines.append(
        f"Emit findings as JSON ({ctx.task_type}). Each finding must match the HexGraph finding schema."
    )
    return "\n".join(lines)


def _build_context(session: Session, project: Project, target: Target, task: Task) -> TaskContext:
    params = task.params_json or {}
    meta = target.metadata_json or {}
    risky = sorted(set(meta.get("imports", [])) & RISKY_SINKS)

    sibling = pick_sibling(session, project.id, target)
    # Edge-anchored task: prefer the edge's other endpoint as the sibling/context,
    # and surface the relationship in the objective (design §5 relational tasks).
    if task.anchor_kind == "edge" and task.anchor_id:
        from hexgraph.db.models import Edge

        edge = session.get(Edge, task.anchor_id)
        if edge is not None:
            other_kind, other_id = (
                (edge.dst_kind, edge.dst_id) if edge.src_id == target.id else (edge.src_kind, edge.src_id)
            )
            if other_kind == "target":
                other = session.get(Target, other_id)
                if other is not None:
                    sibling = other
    return TaskContext(
        task_id=task.id,
        task_type=task.type,
        project_id=project.id,
        target_id=target.id,
        target_name=target.name,
        objective=task.objective_text,
        function=params.get("function"),
        sink=params.get("sink") or (risky[0] if risky else None),
        sibling_target_id=sibling.id if sibling else None,
        sibling_name=sibling.name if sibling else None,
        target_format=target.format,
        arch=target.arch,
        model=task.model,
        mock_scenario=params.get("mock_scenario"),
    )


def preview_context(session: Session, project: Project, target: Target, *, task_type: str,
                    objective: str | None = None, params: dict | None = None) -> dict:
    """Build a transient TaskContext from request params (no Task row) and assemble
    the bundle for a pre-flight launch preview. Decompilation is omitted (added at
    run time) to keep the preview fast/offline."""
    from hexgraph.engine.context import preview_context as assemble

    params = params or {}
    meta = target.metadata_json or {}
    risky = sorted(set(meta.get("imports", [])) & RISKY_SINKS)
    sibling = pick_sibling(session, project.id, target)
    ctx = TaskContext(
        task_id="preview", task_type=task_type, project_id=project.id, target_id=target.id,
        target_name=target.name, objective=objective, function=params.get("function"),
        sink=params.get("sink") or (risky[0] if risky else None),
        sibling_target_id=sibling.id if sibling else None,
        sibling_name=sibling.name if sibling else None,
        target_format=target.format, arch=target.arch, mock_scenario=params.get("mock_scenario"),
    )
    return assemble(session, project, target, ctx)


def _compile_harnesses(findings) -> None:
    """For harness_generation findings, actually build the emitted source in the
    sandbox and record the real result. Best-effort + env/docker-gated."""
    if os.environ.get("HEXGRAPH_DISABLE_SANDBOX_BUILD") == "1":
        return
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return
    from hexgraph.engine.harness import compile_harness_source

    for finding in findings:
        source = finding.evidence.decompiled_snippet
        if not source:
            continue
        try:
            build = compile_harness_source(source)
        except Exception:  # noqa: BLE001 — best-effort enrichment
            continue
        extra = dict(finding.evidence.extra or {})
        extra["build"] = build
        finding.evidence.extra = extra


def _materialize_decomp_graph(session: Session, project_id: str, target_id: str, decomp: dict) -> None:
    """Promote the decompiled FOCUS function into the graph (the deliberate curation
    act of decompiling THIS function) and record the decompilation as a durable
    Observation, mirroring the agent-tool PROMOTE path (design §5.3). The single-pass
    path obeys the SAME curation contract: callees are NOT mass-minted — `calls` edges
    self-wire only to callees ALREADY curated (the both-endpoints-exist rule, handled by
    the enrichment relationship-materializer the recorded Observation drives). Without
    this, decompiling one focus would bulk-spawn every callee as a node — the graph
    explosion this Phase exists to stop."""
    focus = decomp.get("focus")
    if not focus or not focus.get("name"):
        return
    from hexgraph.engine import observations as O

    target = session.get(Target, target_id)
    # Record first so extract-at-write indexes the focus's facts + the `A calls B`
    # relationship facts under the target's content_hash; the edge to any callee that
    # is already a node self-wires, new callees do not get minted. Best-effort — a
    # store hiccup must never break task execution.
    if target is not None:
        try:
            O.record_observation(
                session, project_id=project_id, target_id=target_id, source="decompile",
                tool="decompile_function", args={"function": focus["name"]},
                result_kind="decompilation", payload=decomp,
                summary=f"decompiled {focus['name']}",
                content_hash=O.content_hash_for(target),
                node_refs=[focus["name"]],
            )
        except Exception:  # noqa: BLE001 — discoverability is best-effort, never load-bearing
            pass
    # Promote ONLY the focus. get_or_create_node pulls the just-indexed prototype/
    # address facts at create, and self-wires `calls` edges to callees already curated.
    materialize_function(
        session, project_id=project_id, target_id=target_id, name=focus["name"],
        address=focus.get("address"), pseudocode=focus.get("pseudocode") or None,
        created_by="decompile",
    )


def execute_llm_task(session: Session, project: Project, target: Target, task: Task) -> int:
    """Run an LLM-backed task to findings. Returns the number of findings emitted.

    Sets the task status to needs_triage if any finding has low confidence.
    """
    ctx = _build_context(session, project, target, task)
    decomp = _gather_decompilation(target, ctx, project)
    if decomp:
        ctx.tool_outputs["decompilation"] = decomp
        _materialize_decomp_graph(session, project.id, target.id, decomp)

    # Phase 4 deterministic core (design §6): for static_analysis, compute grounded source→sink
    # taint and emit a finding per flow BEFORE the LLM synthesizes — so the model reasons over a
    # graph that already carries real taint/sink truth. Backend-independent + always-on; degrades
    # to nothing when Ghidra is off (no fabrication). Best-effort: never fail the task over it.
    # NOTE: these grounded findings are persisted up front and are DELIBERATELY kept even if the
    # later LLM synthesis layer errors and the task is marked failed — they're derived from the
    # real bytes, so they stand on their own (the two layers are independent by design).
    core_finding_ids: list[str] = []
    if task.type == "static_analysis":
        try:
            from hexgraph.engine.re.static_core import run_static_core

            core_finding_ids = run_static_core(session, project, target, task=task)
        except Exception:  # noqa: BLE001 — the deterministic core is best-effort
            log.warning("deterministic static core failed", exc_info=True)

    # Assemble the content bundle (the frozen, content-addressed input).
    from hexgraph.engine.context import build_context_bundle, estimate_tokens
    from hexgraph.llm.cassette import maybe_wrap_cassette
    from hexgraph.llm.prompting import system_prompt

    bundle = build_context_bundle(session, project, target, task, ctx)
    task.context_bundle_id = bundle.row.id

    backend = get_backend(task.backend if task.backend not in (None, "none") else None)
    backend = maybe_wrap_cassette(backend, project)
    req = ctx.build_request(prompt=bundle.prompt)
    req.cache_key = bundle.row.bundle_sha

    # Agent loop: advertise the sandboxed tools and let the model investigate
    # (decompile/strings/imports/…, fuzz when enabled) before concluding. Strict
    # superset of a single pass — a backend that answers immediately is unchanged.
    from hexgraph.agent.agent_tools import ToolContext, available_tools, run_tool

    toolctx = ToolContext(session=session, project=project, target=target)
    tools = available_tools(toolctx)
    findings, usage, transcript = run_findings_agentic(
        backend, req, tools=tools, tool_runner=lambda c: run_tool(toolctx, c.name, c.input),
    )

    if task.type == "harness_generation":
        _compile_harnesses(findings)

    # Metering seam: log usage per task (BYOK = user's own spend; the hook a future
    # credits sink uses). No-op-ish locally.
    from hexgraph.metering import record_usage

    record_usage(f"task.{task.type}", usage, task_id=task.id)

    write_trace(task, "prompt.txt", bundle.prompt)
    write_trace(task, "system.txt", system_prompt(task.type))
    if transcript:
        write_trace(task, "agent_trace.json", {"steps": transcript})
    write_trace(task, "bundle.json", {
        "bundle_sha": bundle.row.bundle_sha, "token_estimate": bundle.row.token_estimate,
        "token_budget": bundle.row.token_budget, "dropped": [d.kind for d in bundle.dropped],
        "items": [{"kind": it.kind, "est_tokens": estimate_tokens(it.text)} for it in bundle.included],
    })
    write_trace(task, "response.json", {
        "findings": [f.to_payload() for f in findings],
        "usage": {"input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
                  "cost_source": usage.cost_source, "cost_usd": usage.cost_usd},
    })
    write_trace(task, "usage.json", {
        "input_tokens": usage.input_tokens, "output_tokens": usage.output_tokens,
        "cost_source": usage.cost_source, "cost_usd": usage.cost_usd,
    })
    task.cost_estimate = usage.cost_usd
    task.backend = backend.name

    low_confidence = False
    persisted_ids: list[str] = []
    for finding in findings:
        resolved_refs = [
            r for r in (resolve_target_ref(session, project.id, ref) for ref in finding.related_target_refs or [])
            if r is not None and r.id != target.id
        ]
        # pattern_sweep reports a sibling's issue: home the finding ON that sibling
        # (the graph payoff), while still drawing the seed -> sibling related_to edge.
        home = resolved_refs[0] if (task.type == "pattern_sweep" and resolved_refs) else target
        row = persist_finding(
            session,
            project_id=project.id,
            target_id=home.id,
            task_id=task.id,
            finding=finding,
        )
        persisted_ids.append(row.id)
        if finding.confidence == "low":
            low_confidence = True
        edge_type = EdgeType.instance_of_pattern if task.type == "pattern_sweep" else EdgeType.related_to
        for dst in resolved_refs:
            add_edge(
                session, project_id=project.id,
                src=("target", target.id), dst=("target", dst.id),
                type=edge_type, origin="llm", confidence=finding.confidence,
                created_by_task_id=task.id,
                # One edge per (src,dst,type): repeats fold in, accumulating finding ids
                # instead of drawing parallel duplicates (graph stays readable).
                merge=True,
                attrs={
                    "finding_id": row.id,
                    # B3: link the match back to the seed finding that triggered the sweep.
                    "matched_from_finding_id": task.parent_finding_id or row.id,
                },
            )

    if findings and low_confidence:
        task.status = TaskStatus.needs_triage

    # Promote any harness this task produced to a managed source_file + harness node
    # (design §4.3): the transient evidence.decompiled_snippet stays for back-compat,
    # but going forward a harness is navigable source in the graph. Best-effort —
    # never fail the task over it (the findings are already persisted).
    if task.type == "harness_generation" and persisted_ids:
        from hexgraph.db.models import Finding as _Finding
        from hexgraph.engine.harness_promote import promote_harness

        for fid in persisted_ids:
            f = session.get(_Finding, fid)
            ev = (f.evidence_json or {}) if f else {}
            if ev.get("decompiled_snippet"):
                try:
                    promote_harness(session, project, f.target_id, ev["decompiled_snippet"],
                                    function=ev.get("function"), finding_id=f.id)
                except Exception:  # noqa: BLE001 — promotion is best-effort
                    pass

    # Fold any duplicate function/symbol nodes this task introduced (e.g. a
    # decompiler `sym.foo` colliding with an agent's `foo`) into one node.
    from hexgraph.engine.graph.nodemerge import merge_duplicate_nodes

    merge_duplicate_nodes(session, project.id)

    # Standard B, static (docs/design/design-verification-oracles.md Phase 4): now that the agent has
    # built the graph (input/sink nodes + taints/calls dataflow) and dupes are folded, try to
    # ARGUE static input-reachability for each finding whose cited sink has a source→sink path.
    # Best-effort + envelope-only: it only UPGRADES a code_present/static floor (never downgrades a
    # dynamic claim), so a stronger assurance the agent recorded is untouched. A failure here must
    # not fail the task (the findings are already persisted).
    all_finding_ids = core_finding_ids + persisted_ids
    if all_finding_ids:
        from hexgraph.engine.findings.reachability import argue_reachability_for_finding

        for fid in all_finding_ids:
            try:
                argue_reachability_for_finding(session, fid)
            except Exception:  # noqa: BLE001 — reachability is advisory, never fatal
                pass

    # Discipline loop, Layer 1 (design-working-memory.md §6): auto-draft the closing
    # AGENT journal entry from the tool-call trace + the findings, so journaling is a
    # STRUCTURAL step of finishing a task — deterministic, never dependent on the model
    # remembering to call a tool, and offline/mock-safe (zero-token). Best-effort: a
    # failure here must never fail the task (the findings are already persisted).
    from hexgraph.engine import journal as _journal
    from hexgraph.db.models import Finding as _FindingRow

    finding_titles = [f.title for f in findings]
    for fid in core_finding_ids:
        row = session.get(_FindingRow, fid)
        if row is not None:
            finding_titles.append(row.title)
    _journal.auto_log_task(
        session, project, task_id=task.id, task_type=task.type, target_name=target.name,
        transcript=transcript, finding_titles=finding_titles,
    )

    # Group this execution as an analysis_run for run-to-run comparison.
    from hexgraph.engine.runs import record_run

    record_run(
        session, project_id=project.id, anchor_kind="target", anchor_id=target.id,
        task=task, bundle_sha=bundle.row.bundle_sha,
        finding_count=len(findings) + len(core_finding_ids),
    )
    return len(findings) + len(core_finding_ids)
