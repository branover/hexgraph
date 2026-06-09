"""P-Code emulation for constant/key recovery (design §7 Phase 4).

Some routines DERIVE a magic value at runtime — a license code, an XOR key, a decoded
string — so it never appears as a literal and a static reader sees only the arithmetic.
`emulate_constant` runs the routine inside Ghidra's P-Code emulator (in the sandbox,
NEVER natively), recovers the value it returns, records it as an `emulation` Observation,
and annotates the function node with the recovered constant.

Opt-in + gated by `policy.assert_allows_emulation()` (`features.emulation`). It relaxes no
sandbox boundary — the routine runs in the JVM interpreter, with no native execution and no
network — so it is a heavy-analysis opt-in, not a policy relaxation. Requires Ghidra.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from hexgraph import policy

log = logging.getLogger(__name__)

# Guidance returned when the target routine takes arguments — emulating it over uninitialized
# inputs would just burn a sandbox run and (almost always) fail to reach a clean `ret`.
_ARG_DEPENDENT_HINT = (
    "function takes arguments — recover_constant needs a SELF-CONTAINED, parameterless routine "
    "(it emulates over uninitialized inputs, so an arg-dependent function won't reach a clean "
    "ret and yields no recoverable value). Use the solver re_solve_constraint / "
    "re_solve_reaching_input to recover a value/input that satisfies a check instead."
)


def _recovered_arg_count(session: Session, project: Any, target: Any, function: str) -> int | None:
    """Best-effort recovered argument count for `function` from the curated function node's
    enrichment attrs (`param_count`, else `len(params)`), so an arg-dependent routine is
    caught BEFORE a doomed emulation. Returns None when nothing is recorded yet (then we
    don't second-guess — the emulation's own arg guard is the authoritative fallback)."""
    try:
        from hexgraph.db.models import Node, NodeType
        from hexgraph.engine.graph.nodes import normalize_symbol_name

        want = normalize_symbol_name(function) or function
        node = (
            session.query(Node)
            .filter(
                Node.project_id == project.id,
                Node.target_id == target.id,
                Node.node_type == NodeType.function.value,
                Node.name == want,
            )
            .first()
        )
        if node is None:
            return None
        attrs = node.attrs_json or {}
        pc = attrs.get("param_count")
        if isinstance(pc, int):
            return pc
        params = attrs.get("params")
        if isinstance(params, list):
            return len(params)
    except Exception:  # noqa: BLE001 — a lookup hiccup just falls through to emulation
        return None
    return None


def _ghidra_headless_enabled() -> bool:
    try:
        from hexgraph import settings as st

        g = (st.resolved().get("features", {}) or {}).get("ghidra", {}) or {}
        return bool(g.get("enabled")) and (g.get("mode") or "headless") == "headless"
    except Exception:  # noqa: BLE001 — a settings hiccup must never crash analysis selection
        return False


def emulate_constant(session: Session, project: Any, target: Any, *, function: str) -> dict:
    """Emulate `function` and recover the constant it returns. Records an `emulation` Observation
    and annotates the function node with the recovered value. Returns
    ``{available, function, value, value_hex, reached_ret, steps, observation_id, error}``.

    Gated: raises `PolicyViolation` if `features.emulation` is off. Returns availability False
    when Ghidra (the only emulation backend) isn't the active headless decompiler — nothing is
    fabricated."""
    policy.assert_allows_emulation()  # opt-in gate (raises PolicyViolation if disabled)

    if not _ghidra_headless_enabled():
        return {"available": False, "function": function, "value": None, "value_hex": None,
                "reached_ret": False, "steps": None, "observation_id": None,
                "error": "emulation requires the Ghidra headless decompiler (features.ghidra)"}

    # PRE-CHECK: skip the doomed run for an argument-dependent routine. If a prior decompile
    # recorded the recovered signature on the function node and it takes arguments, emulating
    # it over uninitialized inputs won't reach a clean ret — return an informative result
    # instead of burning a sandbox emulation. (No recorded signature ⇒ fall through and let
    # the emulation's own in-probe arg guard decide; we never fabricate.)
    arg_count = _recovered_arg_count(session, project, target, function)
    if arg_count and arg_count > 0:
        return {"available": True, "function": function, "value": None, "value_hex": None,
                "reached_ret": False, "steps": 0, "observation_id": None,
                "skipped": "arg_dependent", "param_count": arg_count,
                "error": _ARG_DEPENDENT_HINT}

    from hexgraph.engine import observations as obs
    from hexgraph.engine.graph.nodes import get_or_create_node
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    out = GhidraDecompiler().run_emulate(getattr(target, "path", None), function, project=project) or {}
    emu = out.get("emulation") or {}
    value = emu.get("value")
    reached = bool(emu.get("reached_ret"))
    err = emu.get("error") or out.get("error")
    recovered = reached and value is not None and not err

    summary = (("emulation: %s() returns %s" % (function, value)) if recovered
               else "emulation: %s() did not return a recoverable constant" % function)
    observation, _cached = obs.record_observation(
        session, project_id=project.id, target_id=target.id, source="agent",
        tool="pcode_emulation", args={"function": function}, result_kind="emulation",
        payload=out, summary=summary, status="ok" if recovered else "error",
        content_hash=obs.content_hash_for(target),
    )

    if recovered:
        # Grounded enrichment: tag the function node with the value it derives at runtime.
        node = get_or_create_node(
            session, project_id=project.id, node_type="function", name=function,
            target_id=target.id, address=emu.get("function_addr"), created_by="emulation",
        )
        attrs = dict(node.attrs_json or {})
        attrs["recovered_constant"] = value
        attrs["recovered_constant_hex"] = emu.get("value_hex")
        node.attrs_json = attrs
        flag_modified(node, "attrs_json")
        log.info("emulation: %s() recovered constant %s on target %s", function, value, target.id)

    return {"available": True, "function": function, "value": value,
            "value_hex": emu.get("value_hex"), "reached_ret": reached,
            "steps": emu.get("steps"), "width_bytes": emu.get("width_bytes"),
            "observation_id": observation.id, "error": err}
