"""The Solver seam (design §3.5 / Phase 5C) — angr symbolic execution behind `get_solver()`.

This is the **flagship** Phase-5 capability and the one genuinely *new* kind of answer in
the council: given a sink, **solve for an input that reaches it**; given a check, **recover
the value that satisfies it**. It composes with what is already built — reachability argues a
*path exists*, taint flags the *flow*, and a solver can argue an *input exists* and even
produce it. It answers the same family of question as `get_taint_analyzer()` (does untrusted
input reach this sink, and under what constraints), so it earns a real seam, and this module
**mirrors `engine/taint.py` precisely**: an ABC, a concrete backend, and a `Null*` that
degrades gracefully and *fabricates nothing*.

**Phase 5C-A shipped the seam + the Null path; Phase 5C-B (this PR) wires angr end to end.**
`AngrSolver.solve_reaching_input` / `solve_constraint` now run `sandbox/probes/angr_probe.py`
inside the DEDICATED, optional `hexgraph-angr` image (D10 — the heavy angr/z3 stack ships in its
own sibling image, never the base sandbox) and map the probe's JSON to a `SolverResult` (or
`None` when nothing was solved). `NullSolver` (the default, gate-off path) still returns `None`
from every method, fabricating nothing. **angr is never imported in this module** — it lives only
inside the probe, behind the sandbox boundary, so the host process never depends on it and this
module imports cleanly offline (a contract test enforces it). The engine layer that turns a
`SolverResult` into Observations/findings/annotations is `engine/solving.py`.

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
    drive execution to the sink. `concrete_input` is the FULL symbolic buffer (real bytes + any
    unconstrained filler), so `minimal_input` carries just the leading `constrained_len` bytes the
    satisfying path actually constrains — "the part that matters", the faithful reproducer a human
    should copy (both omitted when the probe couldn't introspect the constraints). For a constraint
    solve, `recovered_value`/`recovered_value_hex` are the value that satisfies the check (fed to
    the same function-node annotation path as `engine/emulation.py`). `path_addrs` is the few
    grounded basic-block addresses on the satisfying path (promotable as nodes/edges, never the
    whole program). `provenance` records HOW it was obtained (backend, step/time budget actually
    used) so a finding can cite it.

    A solver returns **None** (not an empty `SolverResult`) when it finds nothing — the
    caller treats None as "no solution", and nothing is ever fabricated."""

    kind: str
    concrete_input: str | None = None        # hex-encoded reaching input, when kind=="reaching_input"
    minimal_input: str | None = None         # hex of the leading constrained-byte prefix ("the part that matters")
    constrained_len: int | None = None       # number of leading input bytes the path constrains
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


# ── The dedicated angr image (D10 — a separate optional image, NOT the base sandbox) ──────
# angr's pip stack is the heaviest dependency in Phase 5 and it is opt-in, so it ships in its
# OWN sibling image (docker/angr.Dockerfile), built by `just angr-build`. The selector honours
# the worktree discipline: set HEXGRAPH_ANGR_IMAGE to a private tag for testing; NEVER clobber
# the shared tag.
DEFAULT_ANGR_IMAGE = "hexgraph-angr:latest"


def angr_image() -> str:
    """The dedicated angr (solver) image tag. `HEXGRAPH_ANGR_IMAGE` (a worktree's private tag)
    overrides the Settings value, which overrides the default — mirrors `fuzz_image()`."""
    img = os.environ.get("HEXGRAPH_ANGR_IMAGE")
    if img:
        return img
    try:
        from hexgraph import settings

        return settings.get("features.angr.image", DEFAULT_ANGR_IMAGE) or DEFAULT_ANGR_IMAGE
    except Exception:  # noqa: BLE001 — a settings hiccup must never break image selection
        return DEFAULT_ANGR_IMAGE


def solver_enabled() -> bool:
    """True iff `features.angr` is on (so the solver seam selects `AngrSolver`). angr IS a
    policy gate (`policy.assert_allows_solver`) — unlike floss/yara — but, like emulation, it
    raises no tier, so this is a plain opt-in read. Fail-closed: any settings hiccup ⇒ off."""
    try:
        from hexgraph import settings

        return bool(settings.get("features.angr.enabled"))
    except Exception:  # noqa: BLE001 — a settings problem must never silently enable it
        return False


# Coarse, HexGraph-set resource/budget tiers (the agent picks a tier name, never raw caps —
# design §2.8). Each maps onto the angr_probe's bounding flags: an INNER wall-clock deadline
# (kept below the container's own timeout so we get a clean "unsolved" instead of a SIGKILL),
# a step cap, an active-state ceiling, and the symbolic input length.
_BUDGETS = {
    "quick":   {"timeout": 45,  "max_steps": 1500, "max_active": 32, "max_input_len": 32},
    "default": {"timeout": 120, "max_steps": 4000, "max_active": 64, "max_input_len": 64},
    "deep":    {"timeout": 240, "max_steps": 12000, "max_active": 128, "max_input_len": 96},
}
_DEFAULT_BUDGET = "default"

# How far below the container's wall-clock cap the probe's INNER deadline must stay. The probe
# checks its deadline cooperatively (between steps) and may run one last z3 query (capped at the
# probe's per-query ceiling, 30s) plus teardown/JSON-flush after the deadline trips, so the
# inner deadline + that tail must finish before the container SIGKILLs. This headroom covers it.
_INNER_DEADLINE_HEADROOM = 45
_MIN_INNER_DEADLINE = 15  # never clamp the inner deadline below this, however small the cap


def _budget_args(budget: Any, *, container_timeout: int | None = None) -> list[str]:
    """Map a coarse budget tier (a name, or None) to the probe's bounding flags. The INNER
    wall-clock deadline is clamped to stay safely below `container_timeout` (the resolved
    `ResourceSpec.timeout`) so a user-lowered sandbox timeout can't invert the ordering — the
    probe always degrades to a clean 'unsolved' before the container SIGKILLs it."""
    tier = budget if isinstance(budget, str) and budget in _BUDGETS else _DEFAULT_BUDGET
    b = _BUDGETS[tier]
    timeout = int(b["timeout"])
    if container_timeout is not None:
        ceiling = max(_MIN_INNER_DEADLINE, int(container_timeout) - _INNER_DEADLINE_HEADROOM)
        timeout = min(timeout, ceiling)
    return ["--timeout", str(timeout), "--max-steps", str(b["max_steps"]),
            "--max-active", str(b["max_active"]), "--max-input-len", str(b["max_input_len"])]


class AngrSolver(Solver):
    """angr-backed symbolic execution (the first concrete behind this seam), wired in Phase 5C-B.

    `solve_reaching_input` / `solve_constraint` run `angr_probe.py` inside the DEDICATED angr
    image (D10), over the read-only artifact, and map its JSON to a `SolverResult` (or `None`
    when nothing was solved). The probe is hard-bounded (wall-clock + step + state caps, DFS for
    deterministic order + bounded memory) so symbolic execution — the one tool here that can
    genuinely exhaust memory/time — stays in its box.

    angr is **never imported in this module** — it lives only inside the probe, behind the
    sandbox boundary, so the host process never depends on it (the module imports cleanly
    offline). The policy gate (`policy.assert_allows_solver`) is consulted HERE, at the probe
    boundary, so even a directly-constructed `AngrSolver` (env override / `get_solver("angr")`)
    can't run the probe unless `features.angr` is on (defence-in-depth on top of `get_solver`'s
    selection-time gate)."""

    name = "angr"
    available = True

    def solve_reaching_input(self, artifact: str, sink: SinkRef, *,
                             project: Any = None, budget: Any = None) -> SolverResult | None:
        extra = ["--mode", "reaching-input"]
        if sink.func:
            extra += ["--sink-func", sink.func]
        if sink.call_addr:
            extra += ["--sink-addr", str(sink.call_addr)]
        if sink.function:
            extra += ["--function", sink.function]
        if sink.function_addr:
            extra += ["--function-addr", str(sink.function_addr)]
        payload = self._run_probe(artifact, extra, budget)
        return self._to_result(payload, kind="reaching_input")

    def solve_constraint(self, artifact: str, check: ConstraintRef, *,
                         project: Any = None, budget: Any = None) -> SolverResult | None:
        extra = ["--mode", "constraint"]
        if check.function:
            extra += ["--function", check.function]
        if check.function_addr:
            extra += ["--function-addr", str(check.function_addr)]
        if check.check_addr:
            extra += ["--check-addr", str(check.check_addr)]
        payload = self._run_probe(artifact, extra, budget)
        return self._to_result(payload, kind="constraint_value")

    # ── the probe boundary ────────────────────────────────────────────────────────────────
    def _run_probe(self, artifact: str, extra_args: list[str], budget: Any) -> dict:
        """Run the angr probe in the dedicated angr image and return its parsed JSON payload.
        Consults the policy gate HERE (the probe boundary) before any container is spawned."""
        from hexgraph import policy

        policy.assert_allows_solver()  # opt-in gate (raises PolicyViolation if features.angr off)

        from hexgraph.sandbox.executor import get_executor
        from hexgraph.sandbox.resources import resource_spec_for
        from hexgraph.sandbox.runner import SandboxError

        runner = get_executor()
        spec = resource_spec_for("sandbox")
        # Clamp the inner deadline below THIS container's resolved wall-clock cap (a user may
        # have lowered resources.sandbox.timeout below the deep tier's 240s).
        args = list(extra_args) + _budget_args(budget, container_timeout=spec.timeout)
        try:
            result = runner.run_probe(
                "angr_probe.py", artifact, extra_args=args, image=angr_image(),
                resources=spec,
            )
        except SandboxError as exc:
            # A real container/launch failure → an honest error payload (NOT a fabricated solve).
            return {"solved": False, "reason": "error", "error": str(exc)}
        import json

        try:
            return json.loads(result.stdout)
        except (ValueError, TypeError) as exc:
            return {"solved": False, "reason": "error",
                    "error": f"angr probe did not emit valid JSON: {exc}"}

    @staticmethod
    def _to_result(payload: dict, *, kind: str) -> SolverResult | None:
        """Map the probe JSON to a `SolverResult`, or `None` when nothing was solved (the
        caller treats None as 'no solution' and fabricates nothing — the seam contract)."""
        if not isinstance(payload, dict) or not payload.get("solved"):
            return None
        prov = {
            "backend": "angr",
            "angr_version": payload.get("angr_version"),
            "reason": payload.get("reason"),
            "steps": payload.get("steps"),
            "active_peak": payload.get("active_peak"),
            "elapsed": payload.get("elapsed"),
            "input_model": payload.get("input_model"),
            "targets": payload.get("targets"),
            "reached_addr": payload.get("reached_addr"),
            "function_addr": payload.get("function_addr"),
            "input_repr": payload.get("concrete_input_repr"),
            # The minimal-reproducer hints also ride in provenance so a finding's
            # evidence.extra.solver carries them (alongside the dedicated fields below).
            "minimal_input": payload.get("minimal_input"),
            "constrained_len": payload.get("constrained_len"),
        }
        return SolverResult(
            kind=kind,
            concrete_input=payload.get("concrete_input"),
            minimal_input=payload.get("minimal_input"),
            constrained_len=payload.get("constrained_len"),
            recovered_value=payload.get("recovered_value"),
            recovered_value_hex=payload.get("recovered_value_hex"),
            path_addrs=list(payload.get("path_addrs") or []),
            provenance={k: v for k, v in prov.items() if v is not None},
        )


def _resolve_name(explicit: str | None) -> str:
    """Pick the solver backend: explicit arg → `HEXGRAPH_SOLVER` env override → the
    `features.angr` gate → `NullSolver`. Mirrors `get_decompiler`'s `HEXGRAPH_DECOMPILER`
    override and `get_taint_analyzer`'s settings-driven selection.

    The env override (``HEXGRAPH_SOLVER=null|angr``) lets a test or operator pin the backend
    regardless of the gate — but selecting ``angr`` this way does NOT bypass the policy gate:
    `get_solver()` and `AngrSolver` both still consult `policy.assert_allows_solver()` (the latter
    at the probe boundary), so a directly-pinned angr backend is inert until `features.angr` is on.
    A config hiccup must never crash selection — it fails closed to ``none`` (the safe,
    fabricates-nothing backend). A BOGUS ``HEXGRAPH_SOLVER`` (an unrecognised value) therefore
    DEGRADES to ``none`` rather than raising — only an explicit, unrecognised `get_solver(name=…)`
    argument is a hard error (a programmer mistake), exactly as the env override should fail soft."""
    if explicit:
        return explicit.lower()
    env = os.environ.get("HEXGRAPH_SOLVER")
    if env:
        e = env.strip().lower()
        if e in ("none", "null", "angr"):
            return e
        # Fail closed: an unrecognised env value degrades to NullSolver (never crashes selection,
        # never widens the seam) — the env override fails soft, unlike an explicit bad arg.
        log.warning("ignoring unknown HEXGRAPH_SOLVER=%r; using NullSolver", env)
        return "none"
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
