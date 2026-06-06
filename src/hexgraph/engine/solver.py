"""The Solver seam (design §3.5 / Phase 5C) — angr symbolic execution behind `get_solver()`.

This is the **flagship** Phase-5 capability and the one genuinely *new* kind of answer in
the council: given a sink, **solve for an input that reaches it**; given a check, **recover
the value that satisfies it**. It composes with what is already built — reachability argues a
*path exists*, taint flags the *flow*, and a solver can argue an *input exists* and even
produce it. It answers the same family of question as `get_taint_analyzer()` (does untrusted
input reach this sink, and under what constraints), so it earns a real seam, and this module
**mirrors `engine/taint.py` precisely**: an ABC, a concrete backend, and a `Null*` that
degrades gracefully and *fabricates nothing*.

**Phase 5C-A (this PR) ships the seam and its Null path only.** The angr dependency, the
`angr_probe`, the sandbox-image rebuild, and the input→sink/constraint solving logic land in
**Phase 5C-B**. So `AngrSolver` is a typed SKELETON whose methods raise a clear
`NotImplementedError("… lands in Phase 5C-B")`; `NullSolver` (the default, gate-off path) is
fully functional today and returns `None` from every method. **angr is never imported at
module load** — it is not installed yet, and even in 5C-B it stays inside the sandbox/probe,
never the host process — so this module imports cleanly offline.

**Gate (mirrors emulation, NOT the exec tier).** angr is policy-gated via
`policy.assert_allows_solver()` (`features.angr`), but it is a *heavy-analysis opt-in modeled
on emulation*: it symbolically executes — it never runs the target natively, opens no socket,
and touches no network — so **it relaxes no sandbox boundary and raises NO execution/egress
tier**. The gate exists only to make symbolic execution opt-in and to bound it with the
existing `ResourceSpec` + a step/time cap in the probe, because it is the one tool here that
can genuinely exhaust memory/time. `get_solver()` consults the gate and degrades to
`NullSolver` when angr is off (the default).
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


# ── The query shapes the agent may pose (validated, bounded — never a raw angr script) ──
#
# These are deliberately small, structured descriptions of WHAT to solve toward, not how:
# the step/state/time caps are HexGraph's, enforced in the probe (5C-B), never the agent's.
# They carry *references into the graph* (a sink node / a function + check), so the agent
# names a validated target, and angr works from the raw artifact behind the sandbox boundary.


@dataclass(frozen=True)
class SinkRef:
    """The sink to solve a reaching input *toward* — a validated reference into the graph,
    resolved by the caller before it reaches the solver. `call_addr` is the address of the
    dangerous call site (the concrete state angr drives toward); `func`/`category`/`arg_index`
    mirror the `sink` node attributes taint already promotes (`engine/taint.py`), so a solver
    run slots naturally after a taint pass nominated the sink. `function`/`function_addr` name
    the enclosing routine to start symbolic execution from."""

    call_addr: str | None = None
    func: str | None = None              # the dangerous callee (e.g. "system", "strcpy")
    category: str | None = None          # e.g. "command_exec", "buffer_overflow"
    arg_index: int | None = None         # which argument the input must control, if known
    function: str | None = None          # the enclosing function to explore from
    function_addr: str | None = None


@dataclass(frozen=True)
class ConstraintRef:
    """A single comparison/check whose satisfying value to recover (e.g. the `secret` in
    `if (strcmp(input, secret))`). Single-check constraint solving is the explicit scope —
    NOT whole-program exploration (§7). `function` names the routine containing the check;
    `check_addr` pins the comparison; `description` is a free-text hint from the caller."""

    function: str | None = None
    function_addr: str | None = None
    check_addr: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class SolverResult:
    """What a solver recovered. `kind` is ``"reaching_input"`` or ``"constraint_value"``.

    For a reaching-input solve, `concrete_input` is the bytes (hex-encoded for transport) that
    drive execution to the sink. For a constraint solve, `recovered_value`/`recovered_value_hex`
    are the value that satisfies the check (fed to the same function-node annotation path as
    `engine/emulation.py`). `path_addrs` is the few grounded basic-block addresses on the
    satisfying path (promotable as nodes/edges, never the whole program). `provenance` records
    HOW it was obtained (backend, step/time budget actually used) so a finding can cite it.

    A solver returns **None** (not an empty `SolverResult`) when it finds nothing — the
    caller treats None as "no solution", and nothing is ever fabricated."""

    kind: str
    concrete_input: str | None = None        # hex-encoded reaching input, when kind=="reaching_input"
    recovered_value: int | str | None = None  # the satisfying value, when kind=="constraint_value"
    recovered_value_hex: str | None = None
    path_addrs: list[str] = field(default_factory=list)
    constraints: list[str] = field(default_factory=list)  # human-readable path constraints, if any
    provenance: dict[str, Any] = field(default_factory=dict)


class Solver(ABC):
    """Symbolic-execution-backed input/constraint solving over a target's real code.
    Implementations run angr inside the sandbox (5C-B) and never expose raw bytes to the LLM —
    only the structured `SolverResult`. A backend that finds nothing returns `None`; an
    unavailable backend is `available = False` and returns `None` from everything."""

    name: str
    available: bool = True

    @abstractmethod
    def solve_reaching_input(self, artifact: str, sink: SinkRef, *,
                             project: Any = None, budget: Any = None) -> SolverResult | None:
        """Given `sink`, solve for a concrete input that drives execution to it. Returns a
        `SolverResult` (``kind="reaching_input"``) carrying the reaching input, or **None** when
        no reaching input is found within the budget (the caller fabricates nothing). `artifact`
        is the sandbox path to the target bytes; `project` is the HexGraph project (for the
        persistent-analysis cache, optional — angr works from the raw artifact); `budget` is a
        coarse, HexGraph-set resource tier (step/state/time caps enforced in the probe, NOT an
        agent-supplied angr script)."""
        ...

    @abstractmethod
    def solve_constraint(self, artifact: str, check: ConstraintRef, *,
                         project: Any = None, budget: Any = None) -> SolverResult | None:
        """Recover a value that satisfies `check` (single-check constraint solving — e.g. the
        secret a `strcmp` compares against). Returns a `SolverResult` (``kind="constraint_value"``)
        carrying the satisfying value, or **None** when none is found within the budget. Same
        `artifact`/`project`/`budget` contract as `solve_reaching_input`. Explicitly NOT
        whole-program symbolic exploration."""
        ...


class NullSolver(Solver):
    """No solver backend (`features.angr` off — the default). The deterministic core solves
    nothing rather than fabricating a result: every method reports unavailable by returning
    `None`. Fully functional today; this is the graceful-degrade precedent from
    `NullTaintAnalyzer`."""

    name = "none"
    available = False

    def solve_reaching_input(self, artifact: str, sink: SinkRef, *,
                             project: Any = None, budget: Any = None) -> SolverResult | None:
        return None

    def solve_constraint(self, artifact: str, check: ConstraintRef, *,
                         project: Any = None, budget: Any = None) -> SolverResult | None:
        return None


class AngrSolver(Solver):
    """angr-backed symbolic execution (the first concrete behind this seam). SKELETON only in
    Phase 5C-A: the class and its method shapes are fixed here so callers (and 5C-B) can build
    against a stable surface, but the solving logic — the angr probe, the sandbox-image
    dependency, and the step/time-bounded exploration — lands in **Phase 5C-B**. Its methods
    therefore raise a clear `NotImplementedError` for now.

    angr is **never imported at module load** (it is not installed yet, and even in 5C-B it
    runs inside the sandbox/probe, not the host). Any future host-side angr import must be
    deferred into the method body so this module always imports cleanly offline."""

    name = "angr"
    available = True

    _NOT_WIRED = "angr solving lands in Phase 5C-B (the angr probe + sandbox-image dependency)"

    def solve_reaching_input(self, artifact: str, sink: SinkRef, *,
                             project: Any = None, budget: Any = None) -> SolverResult | None:
        raise NotImplementedError(self._NOT_WIRED)

    def solve_constraint(self, artifact: str, check: ConstraintRef, *,
                         project: Any = None, budget: Any = None) -> SolverResult | None:
        raise NotImplementedError(self._NOT_WIRED)


def _resolve_name(explicit: str | None) -> str:
    """Pick the solver backend: explicit arg → `HEXGRAPH_SOLVER` env override → the
    `features.angr` gate → `NullSolver`. Mirrors `get_decompiler`'s `HEXGRAPH_DECOMPILER`
    override and `get_taint_analyzer`'s settings-driven selection.

    The env override (``HEXGRAPH_SOLVER=null|angr``) lets a test or operator pin the backend
    regardless of the gate — but selecting ``angr`` this way does NOT bypass the policy gate:
    `get_solver()` still consults `policy.assert_allows_solver()` for the gated default path,
    and the angr backend itself is inert (raises `NotImplementedError`) until 5C-B. A config
    hiccup must never crash selection — it fails closed to ``none`` (the safe, fabricates-nothing
    backend)."""
    if explicit:
        return explicit.lower()
    env = os.environ.get("HEXGRAPH_SOLVER")
    if env:
        return env.lower()
    try:
        from hexgraph import policy

        # The gate is the one place the static-only-analysis posture is consulted for angr.
        # When off (the default) we degrade to NullSolver; the gate raises no tier, so this
        # selection NEVER widens execution/egress.
        policy.assert_allows_solver()
        return "angr"
    except Exception:  # noqa: BLE001 — gate off (PolicyViolation) or any settings hiccup ⇒ degrade
        log.debug("solver gate off / selection failed; using NullSolver", exc_info=True)
    return "none"


def get_solver(name: str | None = None) -> Solver:
    """Pick the solver the way `get_taint_analyzer()` / `get_decompiler()` pick a backend —
    `AngrSolver` when `features.angr` is enabled (and the policy permits), else `NullSolver`.
    Core code asks the seam and never names a tool; an unavailable backend degrades gracefully
    (no solution, nothing fabricated). `name` (or `HEXGRAPH_SOLVER`) forces a specific backend."""
    resolved = _resolve_name(name)
    if resolved in ("none", "null"):
        return NullSolver()
    if resolved == "angr":
        return AngrSolver()
    raise ValueError(f"unknown solver {resolved!r}")
