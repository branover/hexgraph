"""Phase 5C-A — the `get_solver()` seam + the `features.angr` heavy-analysis gate.

This is the seam-and-gate-only cut of the angr flagship: NO angr dependency, NO probe, NO
image, NO MCP verb (those land in 5C-B). These tests are FULLY OFFLINE — they exercise the
seam selection, the Null path's fabricates-nothing contract, the not-yet-wired AngrSolver
skeleton, and the policy hook — proving in particular that the gate raises NO execution/egress
tier (it is modeled on emulation, not on the exec tier).
"""

from __future__ import annotations

import subprocess
import sys

import pytest

from hexgraph import policy, settings as st
from hexgraph.engine.solver import (
    AngrSolver,
    ConstraintRef,
    NullSolver,
    SinkRef,
    Solver,
    SolverResult,
    get_solver,
)
from hexgraph.policy import PolicyViolation, assert_allows_solver


# ── the module imports cleanly with angr absent (no top-level `import angr`) ────────────

def test_module_does_not_import_angr_at_load():
    # angr is not installed in the offline lane; the seam module must import without it, so it
    # may never import angr at module scope (5C-B defers any import into the probe/method body).
    # Run in a FRESH interpreter so the assertion is about THIS module's own import side effects
    # (not whatever an earlier test may have already pulled into sys.modules), and so reloading
    # never disturbs the class identities the rest of this file's isinstance checks rely on.
    code = (
        "import sys; import hexgraph.engine.solver as S;"
        " assert 'angr' not in sys.modules, sorted(m for m in sys.modules if 'angr' in m)"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, (
        "engine.solver must not import angr at module load; "
        f"stderr={proc.stderr!r}"
    )


# ── the gate: off by default, opt-in flips it on, and it raises NO tier ─────────────────

def test_solver_gate_off_by_default_then_opt_in(hg_home):
    # OFF by default — angr is a heavy opt-in (default off, like emulation).
    with pytest.raises(PolicyViolation):
        assert_allows_solver()
    st.update_settings({"features.angr.enabled": True})
    assert_allows_solver()  # no raise once opted in


def test_solver_gate_raises_no_execution_or_egress_tier(hg_home):
    """The angr gate is modeled on emulation: it is a heavy-analysis opt-in that relaxes NO
    boundary. Enabling features.angr must NOT move the analysis policy — no execution, no
    network, no tier change — exactly as emulation is intentionally absent from
    AnalysisPolicy/current_policy."""
    before = policy.current_policy()
    st.update_settings({"features.angr.enabled": True})
    after = policy.current_policy()
    assert_allows_solver()  # gate now permits
    # The resolved policy is byte-for-byte unchanged: angr touches none of these axes.
    assert after == before
    assert after.allow_execution is False
    assert after.allow_network is False
    assert after.tier == policy.TIER_STATIC_ONLY
    assert after.static_only is True


def test_solver_gate_absent_from_policy_ceiling():
    # angr is NOT a policy GATE that the startup ceiling clamps (the ceiling only freezes the
    # boundary-relaxing gates). Like emulation, it is intentionally absent from POLICY_GATES.
    assert "angr" not in policy.POLICY_GATES


# ── get_solver() selection: NullSolver by default, AngrSolver when opted in ──────────────

def test_get_solver_is_null_when_gate_off(hg_home):
    s = get_solver()
    assert isinstance(s, NullSolver)
    assert s.available is False
    assert s.name == "none"


def test_get_solver_is_angr_when_gate_on(hg_home):
    st.update_settings({"features.angr.enabled": True})
    s = get_solver()
    assert isinstance(s, AngrSolver)
    assert s.available is True
    assert s.name == "angr"


def test_get_solver_env_override(hg_home, monkeypatch):
    # HEXGRAPH_SOLVER forces a backend regardless of the gate (mirrors HEXGRAPH_DECOMPILER).
    monkeypatch.setenv("HEXGRAPH_SOLVER", "null")
    st.update_settings({"features.angr.enabled": True})  # gate on, but env pins null
    assert isinstance(get_solver(), NullSolver)
    monkeypatch.setenv("HEXGRAPH_SOLVER", "angr")
    assert isinstance(get_solver(), AngrSolver)


def test_get_solver_explicit_name_wins(hg_home):
    assert isinstance(get_solver("null"), NullSolver)
    assert isinstance(get_solver("angr"), AngrSolver)


def test_get_solver_unknown_backend_raises(hg_home):
    with pytest.raises(ValueError):
        get_solver("ida-magic")


def test_get_solver_degrades_to_null_on_settings_hiccup(hg_home, monkeypatch):
    # A settings/gate problem must NEVER widen the seam — it fails closed to NullSolver.
    def _boom(*a, **k):
        raise RuntimeError("settings exploded")

    monkeypatch.setattr(policy, "assert_allows_solver", _boom)
    assert isinstance(get_solver(), NullSolver)


def test_bogus_solver_env_degrades_to_null(hg_home, monkeypatch):
    # 5C-A nit #1: a BOGUS HEXGRAPH_SOLVER value must fail CLOSED to NullSolver (the env override
    # fails soft), not raise — only an explicit bad get_solver(name=…) arg is a hard error.
    monkeypatch.setenv("HEXGRAPH_SOLVER", "ida-magic")
    st.update_settings({"features.angr.enabled": True})  # even with the gate on, a bogus env → null
    assert isinstance(get_solver(), NullSolver)


# ── NullSolver fabricates nothing (the graceful-degrade contract) ───────────────────────

def test_null_solver_fabricates_nothing():
    s = NullSolver()
    assert isinstance(s, Solver)
    sink = SinkRef(func="system", category="command_exec", call_addr="0x4010a0", arg_index=0)
    check = ConstraintRef(function="check_license", check_addr="0x401200")
    # Every method returns None — no solution, nothing invented.
    assert s.solve_reaching_input("/sandbox/target", sink) is None
    assert s.solve_constraint("/sandbox/target", check) is None
    # …and with a project + budget passed, still None.
    assert s.solve_reaching_input("/sandbox/target", sink, project=object(), budget="deep") is None
    assert s.solve_constraint("/sandbox/target", check, project=object(), budget="deep") is None


# ── AngrSolver is WIRED in 5C-B, but the policy gate is enforced at the probe boundary ──────

def test_angr_solver_consults_gate_at_probe_boundary(hg_home):
    # 5C-A nit #2 / 5C-B: AngrSolver now runs the probe, but it asserts the policy gate FIRST —
    # so even a directly-constructed AngrSolver (env override / get_solver("angr")) cannot spawn
    # the angr container while features.angr is off. With the gate off it raises PolicyViolation
    # BEFORE any executor/Docker call, so this is fully offline (no angr image needed).
    s = AngrSolver()
    assert isinstance(s, Solver)
    sink = SinkRef(func="system", category="command_exec", call_addr="0x401500")
    check = ConstraintRef(function="check_serial", check_addr="0x401234")
    with pytest.raises(PolicyViolation):
        s.solve_reaching_input("/sandbox/target", sink)
    with pytest.raises(PolicyViolation):
        s.solve_constraint("/sandbox/target", check)


# ── the SolverResult/ref dataclasses are the stable surface 5C-B implements against ──────

def test_solver_result_shape():
    r = SolverResult(kind="reaching_input", concrete_input="deadbeef",
                     path_addrs=["0x401000", "0x401010"], provenance={"backend": "angr"})
    assert r.kind == "reaching_input"
    assert r.concrete_input == "deadbeef"
    assert r.path_addrs == ["0x401000", "0x401010"]
    assert r.recovered_value is None
    # default mutable fields are independent instances (frozen dataclass + default_factory)
    other = SolverResult(kind="constraint_value", recovered_value=1234)
    assert other.path_addrs == [] and other.constraints == [] and other.provenance == {}
    assert other.path_addrs is not r.path_addrs


def test_sink_and_constraint_refs_carry_graph_references():
    sink = SinkRef(call_addr="0x4010a0", func="system", category="command_exec",
                   arg_index=0, function="handle_request", function_addr="0x401000")
    assert sink.func == "system" and sink.arg_index == 0
    check = ConstraintRef(function="check_license", function_addr="0x401200",
                          check_addr="0x401234", description="if (strcmp(input, secret))")
    assert check.function == "check_license" and check.check_addr == "0x401234"


# ── Fix 1: the minimal-reproducer fields ride from the probe JSON into the SolverResult ──────

def test_solver_result_carries_minimal_input_and_constrained_len():
    # The minimal reproducer (the part that matters) is a first-class field alongside the full input.
    r = SolverResult(kind="reaching_input", concrete_input="1cfe401a4b02010100000000",
                     minimal_input="1cfe401a4b020101", constrained_len=8)
    assert r.concrete_input == "1cfe401a4b02010100000000"   # the full buffer (back-compat)
    assert r.minimal_input == "1cfe401a4b020101"            # only the constrained prefix
    assert r.constrained_len == 8
    # Defaults are None when the probe couldn't determine them (older payload / no introspection).
    bare = SolverResult(kind="reaching_input", concrete_input="deadbeef")
    assert bare.minimal_input is None and bare.constrained_len is None


def test_to_result_maps_minimal_input_from_probe_payload():
    # AngrSolver._to_result maps the probe's minimal_input/constrained_len onto the SolverResult AND
    # echoes them into provenance (so evidence.extra.solver carries them). A buffer of 25 bytes where
    # only the first 8 are constrained → minimal_input is just those 8 bytes.
    payload = {
        "solved": True, "reason": "solved", "angr_version": "9.2.x", "input_model": "argv",
        "concrete_input": "1cfe401a4b020101" + "00" * 17,   # 8 real + 17 filler bytes
        "concrete_input_repr": "...", "minimal_input": "1cfe401a4b020101", "constrained_len": 8,
        "path_addrs": ["0x401146"], "reached_addr": "0x401080",
    }
    r = AngrSolver._to_result(payload, kind="reaching_input")
    assert r is not None
    assert r.minimal_input == "1cfe401a4b020101" and r.constrained_len == 8
    assert len(bytes.fromhex(r.concrete_input)) == 25       # the full buffer is preserved
    assert len(bytes.fromhex(r.minimal_input)) == 8          # the prefix is the 8 bytes that matter
    assert r.provenance.get("minimal_input") == "1cfe401a4b020101"
    assert r.provenance.get("constrained_len") == 8


def test_to_result_omits_minimal_input_when_probe_did_not_determine_it():
    # An older/older-build probe payload without the new keys → the fields are None (the caller
    # falls back to the full reproducer), and the absent keys don't pollute provenance.
    payload = {"solved": True, "reason": "solved", "concrete_input": "deadbeef", "input_model": "argv"}
    r = AngrSolver._to_result(payload, kind="reaching_input")
    assert r is not None
    assert r.minimal_input is None and r.constrained_len is None
    assert "minimal_input" not in r.provenance and "constrained_len" not in r.provenance
