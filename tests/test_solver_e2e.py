"""Phase 5C-B — angr end-to-end behind get_solver() (design §3.5, PRs 5C-2/5C-3/5C-4).

Three layers, mirroring the floss/yara curation contract:

- the opt-in gate: with features.angr OFF (the default) the engine refuses with a clear
  enable-message (no solve, no Observation, no finding) and the solve_* verbs are NOT
  advertised; with it ON they appear;
- the engine-orchestration contract with a FAKED Solver (offline, no Docker, no angr): a
  solved reaching-input records ONE `solver` Observation, promotes the grounded path (the
  sink as an is_sink node), and emits a high-confidence `vulnerability` finding carrying the
  concrete input in `evidence.reproducer` (assurance input_reachable/static); a re-run dedups
  and does NOT mint a duplicate finding; an unsolved result fabricates nothing; constraint
  solving annotates the function node (the emulation precedent);
- the REAL proof: a Docker-gated end-to-end solve of the committed `licensegate` fixture in
  the dedicated angr image — angr recovers a constraint-satisfying serial that reaches
  system("/bin/grant_admin"), and the finding carries it (skips when the angr image is absent).
"""

from __future__ import annotations

import pytest

from hexgraph import settings as st
from hexgraph.db.models import Edge, Finding, Node, NodeType, Observation
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.solver import SolverResult
from hexgraph.engine.solving import solve_constraint, solve_reaching_input

from conftest import ANGR_READY, fixture_path

HASH = "cafebabe00"

# A representative SOLVED reaching-input result (the shape AngrSolver returns from the probe).
# The full `concrete_input` is the whole symbolic buffer (8 real serial bytes + 4 unconstrained
# filler bytes); `minimal_input`/`constrained_len` carry the 8 bytes that actually matter.
_REACHING = SolverResult(
    kind="reaching_input",
    concrete_input="1cfe401a4b02010100000000",  # 12 bytes: 8 real serial + 4 filler (hex)
    minimal_input="1cfe401a4b020101",           # the 8 constrained bytes — the part that matters
    constrained_len=8,
    path_addrs=["0x401146", "0x4011a0", "0x4011f0"],
    provenance={"backend": "angr", "angr_version": "9.2.221", "reason": "solved",
                "input_model": "argv", "reached_addr": "0x401080", "steps": 42,
                "input_repr": "\\x1c\\xfe@\\x1aK\\x02\\x01\\x01",
                "minimal_input": "1cfe401a4b020101", "constrained_len": 8},
)
_CONSTRAINT = SolverResult(
    kind="constraint_value",
    concrete_input="1cfe401a4b020101", recovered_value=440460572, recovered_value_hex="0x1a40fe1c",
    provenance={"backend": "angr", "reason": "solved", "input_model": "argv"},
)


class _FakeSolver:
    """A Solver stand-in returning canned results, so the engine-orchestration tests need no
    Docker / no angr. `name`/`available` mirror the real seam surface."""

    name = "angr"
    available = True

    def __init__(self, reaching=_REACHING, constraint=_CONSTRAINT):
        self._reaching = reaching
        self._constraint = constraint
        self.calls: list[tuple[str, str]] = []

    def solve_reaching_input(self, artifact, sink, *, project=None, budget=None):
        self.calls.append(("reaching", artifact))
        return self._reaching

    def solve_constraint(self, artifact, check, *, project=None, budget=None):
        self.calls.append(("constraint", artifact))
        return self._constraint


def _seed(s, name="solv", fixture="vuln_httpd"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path(fixture), name=name)
    t.metadata_json = {**(t.metadata_json or {}), "sha256": HASH}
    s.flush()
    return p, t


def _enable():
    st.update_settings({"features.angr.enabled": True})


# ── the opt-in gate ───────────────────────────────────────────────────────────────────────

def test_solver_off_refuses_no_observation_no_finding(hg_home):
    """Feature OFF (default): the engine returns the enable-message WITHOUT solving, and records
    NO Observation and NO finding (the real path — no injected solver)."""
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, sink_func="system")
        assert "error" in out and "features.angr" in out["error"]
        assert s.query(Observation).filter(Observation.result_kind == "solver").count() == 0
        assert s.query(Finding).count() == 0


def test_solve_verbs_advertised_only_when_enabled(hg_home):
    """The MCP run verbs + the in-loop agent tools appear only when features.angr is on
    (the conditional-advertisement contract, mirroring floss/yara)."""
    from hexgraph.engine import mcp_tools as M
    from hexgraph.engine.agent_tools import ToolContext, available_tools

    def _mcp_present():
        names = {t["name"] for t in M.catalog({"run"})}
        return {"re_solve_reaching_input", "re_solve_constraint"} <= names

    assert _mcp_present() is False
    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        assert "solve_reaching_input" not in {sp.name for sp in available_tools(ctx)}
        _enable()
        assert _mcp_present() is True
        names_on = {sp.name for sp in available_tools(ctx)}
        assert {"solve_reaching_input", "solve_constraint"} <= names_on


def test_mcp_verb_returns_enable_message_when_off(hg_home):
    """The always-callable MCP verb returns a clean enable-message when the feature is off (it
    is advertised only when on, but a delegate could still call it by name)."""
    from hexgraph.engine import mcp_tools as M

    with session_scope() as s:
        p, t = _seed(s)
        tid = t.id
    out = M.solve_reaching_input(tid, sink_func="system")
    assert "error" in out and "features.angr" in out["error"]


# ── engine orchestration with a faked Solver (offline) ──────────────────────────────────────

def test_reaching_input_records_observation_and_emits_finding(hg_home):
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, sink_func="system", function="main", solver=fake)
        s.flush()
        assert fake.calls and fake.calls[0][0] == "reaching"
        assert out["solved"] is True and out["cached"] is False
        assert out["concrete_input"] == _REACHING.concrete_input
        assert out["finding_id"]

        # exactly one `solver` Observation, scoped to the analyzed bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "solver").all()
        assert len(obs) == 1 and obs[0].content_hash == HASH and obs[0].tool == "solve_reaching_input"

        # Fix 1: the minimal reproducer + its length ride the engine return dict too
        assert out["minimal_input"] == _REACHING.minimal_input
        assert out["constrained_len"] == _REACHING.constrained_len

        # the vulnerability finding carries the concrete input + the strong static assurance
        f = s.query(Finding).filter(Finding.id == out["finding_id"]).one()
        assert f.finding_type == "vulnerability"
        assert f.severity == "high" and f.confidence == "high"
        # Fix 2: a meaningful category, not the generic "other" — a command-exec sink classifies
        # as command-injection (a license/auth-style gate would be "auth"; see the unit test).
        assert f.category == "command-injection"
        assert f.category != "other"
        ev = f.evidence_json or {}
        assert ev.get("reproducer") == _REACHING.concrete_input          # the input rides the envelope
        assert ev.get("sink") == "system" and ev.get("function") == "main"
        solver_extra = (ev.get("extra") or {}).get("solver") or {}
        assert solver_extra.get("concrete_input_hex") == _REACHING.concrete_input
        # Fix 1: the finding envelope carries the minimal reproducer (the constrained-byte prefix)
        assert solver_extra.get("minimal_input_hex") == _REACHING.minimal_input
        assert solver_extra.get("constrained_len") == _REACHING.constrained_len
        asr = (ev.get("extra") or {}).get("assurance") or {}
        assert asr.get("standard") == "input_reachable" and asr.get("method") == "static"

        # grounded promotion: the sink became an is_sink symbol node (not a flood)
        sink_nodes = s.query(Node).filter(Node.target_id == t.id, Node.node_type == NodeType.symbol.value,
                                          Node.name == "system").all()
        assert len(sink_nodes) == 1 and (sink_nodes[0].attrs_json or {}).get("is_sink") is True


def test_reaching_input_dedups_and_no_duplicate_finding(hg_home):
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out1 = solve_reaching_input(s, p, t, sink_func="system", function="main", solver=fake)
        s.flush()
        out2 = solve_reaching_input(s, p, t, sink_func="system", function="main", solver=fake)
        s.flush()
        assert out1["cached"] is False and out2["cached"] is True
        assert out1["observation_id"] == out2["observation_id"]
        assert out2["finding_id"] is None  # a cached re-solve does NOT mint a duplicate finding
        assert s.query(Observation).filter(Observation.result_kind == "solver").count() == 1
        # only ONE vulnerability finding despite two calls
        assert s.query(Finding).filter(Finding.finding_type == "vulnerability").count() == 1


def test_resolve_same_sink_different_budget_no_duplicate_finding(hg_home):
    """Polish #1: re-solving the SAME sink at a DIFFERENT budget must NOT mint a second
    vulnerability finding. The Observation cache keys on the call args (incl. budget), so a
    different budget writes a FRESH Observation — but the finding-level dedup keeps it to ONE
    finding (the Phase-5 determinism check would flag the duplicate)."""
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out1 = solve_reaching_input(s, p, t, sink_func="system", function="main",
                                    budget="quick", solver=fake)
        s.flush()
        out2 = solve_reaching_input(s, p, t, sink_func="system", function="main",
                                    budget="deep", solver=fake)
        s.flush()
        assert out1["solved"] is True and out2["solved"] is True
        assert out1["finding_id"]
        # the second solve (different budget) is NOT an Observation-cache hit…
        assert out1["cached"] is False and out2["cached"] is False
        assert out2.get("duplicate_finding_suppressed") is True
        # …it records its own Observation (two now), but reuses the existing finding
        assert out2["finding_id"] == out1["finding_id"]
        assert s.query(Observation).filter(Observation.result_kind == "solver").count() == 2
        # crucially: still only ONE vulnerability finding despite the two solves
        assert s.query(Finding).filter(Finding.finding_type == "vulnerability").count() == 1


def test_reaching_input_threads_function_addr_onto_node(hg_home):
    """Polish #4: a caller-supplied function_addr is threaded onto the promoted function node's
    `address` (it was always None before — the probe parsed --function-addr but never surfaced
    it, and _promote_and_emit read it from a provenance key nothing set)."""
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, sink_func="system", function="main",
                                   function_addr="0x401000", solver=fake)
        s.flush()
        assert out["solved"] is True
        fn = s.query(Node).filter(Node.target_id == t.id,
                                  Node.node_type == NodeType.function.value,
                                  Node.name == "main").one()
        assert fn.address == "0x401000"
        # and the sink identity is recorded on the finding so the dedup key can match it
        f = s.query(Finding).filter(Finding.id == out["finding_id"]).one()
        solver_extra = ((f.evidence_json or {}).get("extra") or {}).get("solver") or {}
        assert solver_extra.get("sink_func") == "system"


def test_no_solution_fabricates_nothing(hg_home):
    """A Solver that finds nothing (returns None) must NOT emit a finding; the engine records an
    honest unsolved Observation and reports solved=false."""
    fake = _FakeSolver(reaching=None)
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, sink_func="system", solver=fake)
        s.flush()
        assert out["solved"] is False and out.get("finding_id") is None
        assert s.query(Finding).count() == 0
        # the attempt is still recorded (so the agent sees the sink was tried)
        obs = s.query(Observation).filter(Observation.result_kind == "solver").all()
        assert len(obs) == 1


def test_constraint_solving_annotates_function_node(hg_home):
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_constraint(s, p, t, function="check_serial", check_addr="0x401234", solver=fake)
        s.flush()
        assert out["solved"] is True and out["function_node_id"]
        assert out["recovered_value"] == _CONSTRAINT.recovered_value
        node = s.query(Node).filter(Node.id == out["function_node_id"]).one()
        attrs = node.attrs_json or {}
        assert attrs.get("recovered_value") == _CONSTRAINT.recovered_value
        assert attrs.get("satisfying_input_hex") == _CONSTRAINT.concrete_input
        # constraint solving records a `solver` Observation but emits NO finding (it enriches)
        assert s.query(Observation).filter(Observation.result_kind == "solver").count() == 1
        assert s.query(Finding).count() == 0


def test_reaching_input_requires_a_sink_selector(hg_home):
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, solver=fake)  # no sink_func/sink_addr
        assert "error" in out and "sink" in out["error"]


# ── Fix 2: the meaningful category (a crackable gate, not "other") ───────────────────────────

def test_classify_solver_category_picks_a_meaningful_category():
    """The solver finding's `category` is derived from the sink — never the generic 'other' — and
    always lands in the frozen Finding schema enum. A command-exec sink → command-injection; a
    memory-unsafe copy → memory-safety; anything else (a license/serial/auth gate behind a check)
    → auth (the check was PROVED satisfiable, i.e. bypassable)."""
    from hexgraph.engine.solving import _classify_solver_category
    from hexgraph.models.finding import Category
    from typing import get_args

    valid = set(get_args(Category))

    assert _classify_solver_category("system") == "command-injection"
    assert _classify_solver_category("sym.imp.system") == "command-injection"   # decompiler-prefixed
    assert _classify_solver_category("popen") == "command-injection"
    assert _classify_solver_category("strcpy") == "memory-safety"
    assert _classify_solver_category("memcpy") == "memory-safety"
    # A license/serial/auth gate (no dangerous-named sink) reads as a bypassable check → auth.
    assert _classify_solver_category("check_license") == "auth"
    assert _classify_solver_category("grant_admin") == "auth"
    assert _classify_solver_category(None) == "auth"
    # NEVER the generic catch-all, and ALWAYS a value the frozen schema accepts.
    for sink in ("system", "strcpy", "check_license", None):
        cat = _classify_solver_category(sink)
        assert cat != "other"
        assert cat in valid, f"{cat!r} not in the frozen Category enum"


def test_auth_gate_sink_classifies_as_auth(hg_home):
    """End-to-end (faked solver): a license/auth-style gate sink (no dangerous-named callee) gets
    the `auth` category — the crackable-gate case the eval flagged."""
    fake = _FakeSolver()
    with session_scope() as s:
        p, t = _seed(s)
        out = solve_reaching_input(s, p, t, sink_func="check_license", function="main", solver=fake)
        s.flush()
        assert out["solved"] is True
        f = s.query(Finding).filter(Finding.id == out["finding_id"]).one()
        assert f.category == "auth"


# ── the REAL proof: a Docker-gated end-to-end solve of the committed licensegate fixture ─────

def _check_serial(b: bytes) -> bool:
    """The licensegate gate, re-implemented (tests/fixtures/phase5_tool_eval/licensegate.c):
    a recovered serial is valid iff its first 8 bytes satisfy EVERY constraint. We re-check it
    here so the e2e proves angr solved a GENUINELY satisfying input, not merely that it returned
    bytes."""
    if len(b) < 8:
        return False
    if ((b[0] * 7 + b[1]) & 0xFFFFFFFF) != 0x1C2:
        return False
    if (b[2] ^ b[3]) != 0x5A:
        return False
    if (b[4] | 0x20) != ord("k"):
        return False
    rolling = sum(b[i] * (i + 1) for i in range(8)) & 0xFFFFFFFF
    return rolling == 0x4D2


@pytest.mark.skipif(not ANGR_READY,
                    reason="requires the dedicated angr image (`just angr-build`, docker/angr.Dockerfile)")
def test_licensegate_end_to_end_solve(hg_home, angr_image):
    """THE proof: angr, in the dedicated angr image, solves a concrete input that reaches the
    system("/bin/grant_admin") sink in licensegate — a serial defined only IMPLICITLY by
    arithmetic constraints (strings/FLOSS reveal nothing). We assert angr recovered a
    constraint-SATISFYING serial AND the vulnerability finding carries it (the input is the
    reproducer). This is the whole point of the phase — the in-image solve, not the offline mocks."""
    _enable()  # features.angr ON → get_solver() selects the real AngrSolver
    with session_scope() as s:
        p, t = _seed(s, name="licensegate", fixture="phase5_tool_eval/licensegate")
        out = solve_reaching_input(s, p, t, sink_func="system", function="main", budget="default")
        s.flush()
        assert "error" not in out, out
        assert out["solved"] is True, out
        recovered = bytes.fromhex(out["concrete_input"])
        # angr SOLVED a genuinely constraint-satisfying serial (not a guess) reaching the sink.
        assert _check_serial(recovered), (
            f"angr returned {recovered!r} (hex {out['concrete_input']}) which does NOT satisfy "
            "the licensegate constraints")
        # Polish #5: argv-mode input is constrained non-NUL, so the recovered reproducer has no
        # interior NUL that would truncate a real argv[1] — it survives as a faithful argument.
        assert b"\x00" not in recovered, (
            f"argv-mode reproducer {recovered!r} contains a NUL byte that wouldn't survive as a "
            "real argv[1] string")
        # Fix 1 (the real proof): angr reports WHICH bytes matter. licensegate constrains the first
        # 8 serial bytes, so constrained_len must be the SMALL serial length (~8) — NOT the full
        # symbolic buffer (the default budget's 64 bytes) — and minimal_input is that prefix, itself
        # a constraint-satisfying serial.
        assert out.get("constrained_len") is not None, out
        assert out["constrained_len"] <= 16, (
            f"constrained_len {out['constrained_len']} should reflect the ~8-byte serial, not the "
            "full symbolic buffer")
        assert out["constrained_len"] >= 8, out  # the gate checks all 8 leading bytes
        minimal = bytes.fromhex(out["minimal_input"])
        assert len(minimal) == out["constrained_len"]
        assert _check_serial(minimal), (
            f"the minimal_input prefix {minimal!r} should itself satisfy the licensegate constraints")
        # and the vulnerability finding carries that exact input in its envelope
        f = s.query(Finding).filter(Finding.id == out["finding_id"]).one()
        assert f.finding_type == "vulnerability"
        # Fix 2: a meaningful category for this crackable gate — system() reaches → command-injection
        assert f.category != "other"
        assert (f.evidence_json or {}).get("reproducer") == out["concrete_input"]
        assert _check_serial(bytes.fromhex((f.evidence_json or {})["reproducer"]))
        # the finding envelope carries the minimal reproducer too
        solver_extra = ((f.evidence_json or {}).get("extra") or {}).get("solver") or {}
        assert solver_extra.get("minimal_input_hex") == out["minimal_input"]
        assert solver_extra.get("constrained_len") == out["constrained_len"]
