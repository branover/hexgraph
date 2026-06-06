"""angr solving orchestration (design §3.5 / Phase 5C, PRs 5C-3 + 5C-4).

The `get_solver()` seam (`engine/solver.py`) runs the bounded symbolic exploration in the
dedicated angr image and returns a pure `SolverResult`. THIS module is the engine layer that
turns that result into durable HexGraph state, exactly the way `engine/static_core` consumes
the taint seam and `engine/emulation` consumes the decompiler seam:

  * `solve_reaching_input` — solve for a concrete input that REACHES a sink, record a `solver`
    Observation, promote the few GROUNDED path nodes/edges (the sink + the enclosing function +
    the `calls` edge — never a flood), and emit a high-confidence `vulnerability` finding that
    carries the concrete reaching input in its envelope (`evidence.reproducer` + the solver
    detail under `evidence.extra.solver`). The assurance is `input_reachable / static`: angr
    PROVED an input exists reaching the sink (and produced it), but the target was never run —
    the strongest static claim short of a live PoC.
  * `solve_constraint` — recover the value that SATISFIES a single check, record a `solver`
    Observation, and annotate the function node with the recovered value (the angr analogue of
    `engine/emulation`'s constant recovery). Single-check solving only — NOT whole-program
    exploration (design §7).

Opt-in + gated. Both consult `features.angr` (the seam selects `NullSolver` when off, and the
probe boundary asserts `policy.assert_allows_solver()` too). Nothing is ever fabricated: when
the solver finds nothing it returns `None`, and these functions record an honest unsolved
result and emit NO finding.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from hexgraph.db.models import EdgeType, NodeType, Project, Target
from hexgraph.engine import observations as O
from hexgraph.engine.solver import (
    ConstraintRef,
    SinkRef,
    SolverResult,
    get_solver,
    solver_enabled,
)

log = logging.getLogger(__name__)

RESULT_KIND = "solver"

_DISABLED_MSG = (
    "angr symbolic execution is not enabled (set features.angr.enabled in Settings to solve "
    "for an input that reaches a sink, or a value that satisfies a check, in the sandbox). It "
    "is opt-in heavy compute, bounded by the sandbox ResourceSpec + a step/time cap; it relaxes "
    "no sandbox boundary (angr symbolically executes, it never runs the target natively)."
)

_REUSE_HINT = (
    "Solver results persist as a `solver` Observation on this target (scoped to the analyzed "
    "bytes); check list_observations(target_id, kind='solver') before re-running — angr is slow. "
    "A solved reaching-input promotes a high-confidence `vulnerability` finding carrying the "
    "concrete input; a solved constraint annotates the function node with the recovered value."
)


def _serialize(result: SolverResult | None) -> dict:
    """A JSON-able view of a SolverResult (or the unsolved sentinel) for the Observation."""
    if result is None:
        return {"solved": False}
    return {
        "solved": True,
        "kind": result.kind,
        "concrete_input": result.concrete_input,
        "recovered_value": result.recovered_value,
        "recovered_value_hex": result.recovered_value_hex,
        "path_addrs": list(result.path_addrs or []),
        "constraints": list(result.constraints or []),
        "provenance": dict(result.provenance or {}),
    }


def _resolve_solver(solver, target):
    """The Solver to use + an optional early error string. Honours an injected `solver` (tests
    pass a fake returning a canned SolverResult); otherwise checks the feature gate + Docker and
    returns `get_solver()`. Fails closed: an off gate / a path-less surface / no Docker each
    yield a clean error rather than a fabricated solve."""
    if solver is not None:
        return solver, None
    if not solver_enabled():
        return None, _DISABLED_MSG
    if not str(getattr(target, "path", "") or "").strip():
        return None, ("this target has no byte artifact to solve over (a Channel-reached surface "
                      "has no file); the solver explores bytes.")
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return None, "angr solver unavailable (Docker/sandbox not running)"
    return get_solver(), None


def _record(session: Session, project: Project, target: Target, *, source: str,
            tool: str, args: dict, result: SolverResult | None, summary: str):
    """Record the `solver` Observation (scoped to the analyzed bytes). Returns (obs, cached)."""
    return O.record_observation(
        session, project_id=project.id, target_id=target.id, source=source,
        tool=tool, args={k: v for k, v in args.items() if v is not None},
        result_kind=RESULT_KIND, payload=_serialize(result), summary=summary,
        content_hash=O.content_hash_for(target),
    )


# ── 5C-3: input → sink solving + the grounded vulnerability finding ───────────────────────


def solve_reaching_input(
    session: Session,
    project: Project,
    target: Target,
    *,
    sink_func: str | None = None,
    sink_addr: str | None = None,
    function: str | None = None,
    function_addr: str | None = None,
    arg_index: int | None = None,
    budget: str | None = None,
    source: str = "agent",
    solver: Any = None,
) -> dict:
    """Solve for a concrete input that drives execution to a sink; on success record a `solver`
    Observation, promote the grounded path, and emit a `vulnerability` finding carrying the input.

    `sink_func` (e.g. "system") is the validated agent selector; `sink_addr`/`function`/
    `function_addr`/`arg_index` are optional graph references that sharpen it. `budget` is a coarse
    tier (quick|default|deep). Returns a dict with `solved`, the `observation_id`, the
    `finding_id` (when solved), the `concrete_input` (hex), and the reuse hint — or `{"error": …}`
    when the feature is off / Docker is down / the artifact isn't analyzable."""
    if not (sink_func or sink_addr):
        return {"error": "a sink selector is required (sink_func, e.g. 'system', or sink_addr)"}

    use_solver, err = _resolve_solver(solver, target)
    if err:
        return {"error": err}

    sink = SinkRef(func=sink_func, call_addr=sink_addr, function=function,
                   function_addr=function_addr, arg_index=arg_index)
    from hexgraph.policy import PolicyViolation
    from hexgraph.sandbox.runner import SandboxError

    try:
        result = use_solver.solve_reaching_input(target.path, sink, project=project, budget=budget)
    except PolicyViolation:
        return {"error": _DISABLED_MSG}
    except SandboxError as exc:
        return {"error": f"angr solve failed: {exc}"}
    except Exception as exc:  # noqa: BLE001 — a sandbox/angr hiccup degrades to an honest error
        return {"error": f"angr solve failed: {exc}"}

    args = {"mode": "reaching-input", "sink_func": sink_func, "sink_addr": sink_addr,
            "function": function, "budget": budget}
    solved = result is not None and result.concrete_input is not None
    summary = (f"angr solved a reaching input for {sink_func or sink_addr} on {target.name}"
               if solved else f"angr found no input reaching {sink_func or sink_addr} within the budget")
    obs, cached = _record(session, project, target, source=source, tool="solve_reaching_input",
                          args=args, result=result if solved else None, summary=summary)

    if not solved:
        return {"solved": False, "observation_id": obs.id if obs else None, "cached": cached,
                "reason": "no input reaching the sink was found within the budget "
                          "(unreachable, unsatisfiable, or the step/time/state cap was hit)",
                "reuse_hint": _REUSE_HINT}

    # A cached Observation means this exact solve already ran and already promoted a finding —
    # don't re-mint a duplicate vulnerability finding on a repeat call (analyze once, reuse).
    if cached:
        return {
            "solved": True, "cached": True, "observation_id": obs.id if obs else None,
            "finding_id": None, "concrete_input": result.concrete_input,
            "concrete_input_repr": (result.provenance or {}).get("input_repr"),
            "path_addrs": list(result.path_addrs or []),
            "note": "this solve was already recorded (an identical prior solve emitted the "
                    "finding); no duplicate finding was created.",
            "reuse_hint": _REUSE_HINT,
        }

    # Finding-level dedup, INDEPENDENT of the Observation cache: the cache keys on the call args
    # (mode, sink, function, budget), so re-solving the SAME sink at a DIFFERENT budget/function
    # writes a fresh Observation and would otherwise mint a SECOND vulnerability finding for the
    # same sink (the Phase-5 determinism check flags that). If a solver-origin finding for this
    # (target, sink) already exists, reuse it instead of minting a duplicate.
    existing = _existing_solver_finding(session, target, sink_func=sink_func, sink_addr=sink_addr)
    if existing is not None:
        return {
            "solved": True, "cached": False, "observation_id": obs.id if obs else None,
            "finding_id": existing.id, "duplicate_finding_suppressed": True,
            "concrete_input": result.concrete_input,
            "concrete_input_repr": (result.provenance or {}).get("input_repr"),
            "path_addrs": list(result.path_addrs or []),
            "note": "a solver-origin vulnerability finding for this sink already exists "
                    "(prior solve); the new observation was recorded but no duplicate finding "
                    "was created.",
            "reuse_hint": _REUSE_HINT,
        }

    finding_id = _promote_and_emit(
        session, project, target, result,
        sink_func=sink_func, sink_addr=sink_addr, function=function,
        function_addr=function_addr, observation_id=obs.id if obs else None,
    )
    return {
        "solved": True,
        "observation_id": obs.id if obs else None,
        "finding_id": finding_id,
        "cached": cached,
        "concrete_input": result.concrete_input,
        "concrete_input_repr": (result.provenance or {}).get("input_repr"),
        "path_addrs": list(result.path_addrs or []),
        "provenance": dict(result.provenance or {}),
        "reuse_hint": _REUSE_HINT,
    }


def _existing_solver_finding(session: Session, target: Target, *, sink_func: str | None,
                             sink_addr: str | None):
    """An existing solver-origin `vulnerability` finding for this `(target, sink)`, or None.

    Identity is the sink the finding was emitted for — its `sink_func`/`sink_addr` recorded under
    `evidence.extra.solver` by `_promote_and_emit`. Used to suppress a duplicate finding when the
    same sink is re-solved at a different budget/function (the Observation cache can't catch that:
    its key includes the budget). Returns the first match (one finding per sink is the invariant)."""
    from hexgraph.db.models import Finding as FindingRow

    rows = (session.query(FindingRow)
            .filter(FindingRow.target_id == target.id,
                    FindingRow.finding_type == "vulnerability")
            .all())
    for r in rows:
        solver = ((r.evidence_json or {}).get("extra") or {}).get("solver") or {}
        if solver.get("backend") != "angr":
            continue
        if solver.get("sink_func") == sink_func and solver.get("sink_addr") == sink_addr:
            return r
    return None


def _promote_and_emit(
    session: Session, project: Project, target: Target, result: SolverResult,
    *, sink_func: str | None, sink_addr: str | None = None, function: str | None,
    function_addr: str | None = None, observation_id: str | None,
) -> str:
    """Promote the GROUNDED path (the sink symbol + the enclosing function + a `calls` edge) and
    emit the high-confidence `vulnerability` finding carrying the concrete reaching input. Returns
    the finding id. Deliberately mints only the few grounded nodes the solve justifies, never the
    whole explored path."""
    from hexgraph.engine.assurance import INPUT_REACHABLE, STATIC, UNSPECIFIED, assurance
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.nodes import materialize_function, materialize_symbol
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding, FollowupSuggestion

    prov = result.provenance or {}
    sink_label = sink_func or "the sink"
    reached_addr = prov.get("reached_addr")

    # Grounded promotion: the sink as an is_sink symbol node; the enclosing function (if named)
    # with a `calls` edge to it. Nothing else from the explored path is minted.
    sink_node = None
    if sink_func:
        sink_node = materialize_symbol(
            session, project_id=project.id, target_id=target.id, name=sink_func,
            is_sink=True, created_by="solver",
        )
        if observation_id:
            attrs = O.add_provenance(dict(sink_node.attrs_json or {}), observation_id)
            sink_node.attrs_json = attrs
            flag_modified(sink_node, "attrs_json")
    if function and sink_node is not None:
        fn_node = materialize_function(
            session, project_id=project.id, target_id=target.id, name=function,
            # The caller's resolved function_addr is authoritative; fall back to the probe's echo.
            address=function_addr or prov.get("function_addr"), created_by="solver",
        )
        add_edge(
            session, project_id=project.id, src=("node", fn_node.id), dst=("node", sink_node.id),
            type=EdgeType.calls, origin="derived", confidence=1.0,
            attrs={"by": "angr-solver",
                   **({"observation_id": observation_id} if observation_id else {})},
            merge=True,
        )

    asr = assurance(
        INPUT_REACHABLE, STATIC, UNSPECIFIED,
        detail=f"angr symbolically solved a concrete input that drives execution to {sink_label}",
    )
    solver_extra = {
        "backend": "angr",
        # The sink identity (func + addr) — the dedup key `_existing_solver_finding` matches on,
        # so a re-solve of the SAME sink at a different budget reuses this finding.
        "sink_func": sink_func,
        "sink_addr": sink_addr,
        "concrete_input_hex": result.concrete_input,
        "concrete_input_repr": prov.get("input_repr"),
        "input_model": prov.get("input_model"),
        "path_addrs": list(result.path_addrs or []),
        "reached_addr": reached_addr,
        "provenance": prov,
        "observation_id": observation_id,
    }
    finding = Finding(
        title=f"Solver-reachable sink: {sink_label} reachable with a crafted input on {target.name}",
        severity="high",
        confidence="high",  # a concrete reaching input is concrete evidence, not a guess
        category="other",
        summary=(f"angr symbolic execution solved a concrete input that drives execution all the "
                 f"way to {sink_label} in {target.name}. A privileged/dangerous sink is reachable, "
                 f"and the exact reaching input has been recovered (recorded as the reproducer)."),
        reasoning=(
            f"angr explored {target.name} symbolically and the SMT solver produced an input that "
            f"satisfies every branch constraint on a path to {sink_label}"
            + (f" (reached at {reached_addr})" if reached_addr else "")
            + ". The input was SOLVED, not guessed or read from the binary — it is a witness that "
            "the sink is genuinely reachable. Assurance: input_reachable / static (proved an input "
            "exists and produced it, but the target was not executed). Verify dynamically with "
            "verify_poc to raise this to input_reachable / dynamic."
        ),
        evidence=Evidence(
            function=function,
            sink=sink_func,
            address=reached_addr,
            reproducer=result.concrete_input,  # the concrete reaching input bytes (hex)
            extra={"solver": solver_extra, "assurance": asr},
        ),
        suggested_followups=[
            FollowupSuggestion(
                task_type="static_analysis",
                label=f"Root-cause the path to {sink_label} and assess the impact",
                params={"function": function or ""},
            )
        ],
    )
    task = create_task(session, project=project, target_id=target.id, type="solve", backend="agent")
    row = persist_finding(
        session, project_id=project.id, target_id=target.id, task_id=task.id,
        finding=finding, finding_type="vulnerability",
    )
    # Leave `origin` at the default ("agent") — the agent directed the solve, exactly as the
    # fuzzing/poc deterministic findings do; the solver detail lives in evidence.extra.solver.
    log.info("solver: emitted vulnerability finding %s (sink=%s) on target %s",
             row.id, sink_label, target.id)
    return row.id


# ── 5C-4: single-check constraint solving → function-node annotation ──────────────────────


def solve_constraint(
    session: Session,
    project: Project,
    target: Target,
    *,
    function: str | None = None,
    check_addr: str | None = None,
    function_addr: str | None = None,
    sink_func: str | None = None,
    budget: str | None = None,
    source: str = "agent",
    solver: Any = None,
) -> dict:
    """Recover a value/input that satisfies a single check; on success record a `solver`
    Observation and annotate the function node with the recovered value (the angr analogue of
    P-Code emulation's constant recovery). Single-check solving only — NOT whole-program
    exploration. `check_addr` pins the comparison/pass block; `sink_func` is an alternative
    selector when the check gates a sink. Returns a dict with `solved`, `observation_id`, the
    recovered value/input, and the reuse hint (or `{"error": …}`)."""
    if not (function or check_addr or sink_func):
        return {"error": "a check selector is required (function, check_addr, or sink_func)"}

    use_solver, err = _resolve_solver(solver, target)
    if err:
        return {"error": err}

    check = ConstraintRef(function=function, function_addr=function_addr, check_addr=check_addr)
    # Thread the optional sink selector through the SinkRef-shaped fields the probe also reads.
    from hexgraph.policy import PolicyViolation
    from hexgraph.sandbox.runner import SandboxError

    try:
        # The constraint probe also accepts a sink selector (a check that gates a sink); the
        # ConstraintRef carries function/check_addr, and we pass sink_func via a SinkRef shim so
        # the seam stays single-typed. Most callers use function + check_addr.
        if sink_func and not check_addr:
            sink = SinkRef(func=sink_func, function=function, function_addr=function_addr)
            result = use_solver.solve_reaching_input(target.path, sink, project=project, budget=budget)
            if result is not None:
                result = SolverResult(
                    kind="constraint_value", concrete_input=result.concrete_input,
                    path_addrs=result.path_addrs, provenance=result.provenance,
                )
        else:
            result = use_solver.solve_constraint(target.path, check, project=project, budget=budget)
    except PolicyViolation:
        return {"error": _DISABLED_MSG}
    except SandboxError as exc:
        return {"error": f"angr constraint solve failed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"angr constraint solve failed: {exc}"}

    solved = result is not None and (result.concrete_input is not None
                                     or result.recovered_value is not None)
    args = {"mode": "constraint", "function": function, "check_addr": check_addr,
            "sink_func": sink_func, "budget": budget}
    summary = (f"angr recovered a value satisfying the check in {function or check_addr or sink_func} "
               f"on {target.name}" if solved
               else f"angr found no satisfying value for {function or check_addr or sink_func}")
    obs, cached = _record(session, project, target, source=source, tool="solve_constraint",
                          args=args, result=result if solved else None, summary=summary)

    if not solved:
        return {"solved": False, "observation_id": obs.id if obs else None, "cached": cached,
                "reason": "no satisfying value was found within the budget",
                "reuse_hint": _REUSE_HINT}

    # Annotate the function node with the recovered value (the emulation precedent), if named.
    annotated = None
    if function:
        from hexgraph.engine.nodes import materialize_function

        node = materialize_function(session, project_id=project.id, target_id=target.id,
                                    name=function, created_by="solver")
        attrs = dict(node.attrs_json or {})
        if result.recovered_value is not None:
            attrs["recovered_value"] = result.recovered_value
            attrs["recovered_value_hex"] = result.recovered_value_hex
        if result.concrete_input is not None:
            attrs["satisfying_input_hex"] = result.concrete_input
        if obs is not None:
            O.add_provenance(attrs, obs.id)
        node.attrs_json = attrs
        flag_modified(node, "attrs_json")
        annotated = node.id

    return {
        "solved": True,
        "observation_id": obs.id if obs else None,
        "function_node_id": annotated,
        "cached": cached,
        "recovered_value": result.recovered_value,
        "recovered_value_hex": result.recovered_value_hex,
        "satisfying_input": result.concrete_input,
        "reuse_hint": _REUSE_HINT,
    }
