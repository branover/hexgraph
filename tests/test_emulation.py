"""Phase 4 — P-Code emulation for constant/key recovery (engine.re.emulation + the
ghidra_probe --emulate pass, now pyghidra_lib.emulate_core).

Offline tests pin the opt-in gate, the graceful-degrade contract, and the emulate core's
arg-dependent guard. The Docker+Ghidra integration test (WITH_GHIDRA lane) proves the emulator
recovers a runtime-derived constant on the keyderive fixture, matching a native run, and
records/annotates it.
"""

import shutil
import subprocess
import tempfile

import pytest

from hexgraph.db.models import Node
from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.re.emulation import emulate_constant
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph import settings as st
from hexgraph.policy import PolicyViolation, assert_allows_emulation

from conftest import SANDBOX_READY, fixture_path


# ── offline: the opt-in gate ──────────────────────────────────────────────────────────

def test_emulation_gate_off_by_default_then_opt_in(hg_home):
    # OFF by default — emulation is a heavy opt-in.
    with pytest.raises(PolicyViolation):
        assert_allows_emulation()
    st.update_settings({"features.emulation.enabled": True})
    assert_allows_emulation()  # no raise once opted in


def test_emulate_constant_requires_opt_in(hg_home):
    with session_scope() as s:
        p = create_project(s, name="e")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        with pytest.raises(PolicyViolation):
            emulate_constant(s, p, t, function="anything")


def test_emulate_constant_unavailable_without_ghidra(hg_home):
    # Gate ON but Ghidra OFF → unavailable, nothing fabricated, no crash.
    st.update_settings({"features.emulation.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="e2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = emulate_constant(s, p, t, function="anything")
        assert out["available"] is False and out["value"] is None
        assert O.list_observations(s, t.id, kind="emulation") == []


# ── F18: skip the doomed emulation for an arg-dependent routine ───────────────────────

def test_emulate_constant_skips_arg_dependent_function(hg_home):
    """If a prior decompile recorded a signature showing the routine takes arguments,
    emulate_constant returns early (no doomed emulation over uninitialized inputs) with an
    informative result pointing at the solver — and records NO emulation Observation."""
    from hexgraph.engine.graph.nodes import get_or_create_node

    # Gate ON + Ghidra "headless" enabled so we get PAST the availability check and into the
    # arg pre-check (the point of the test — the early return must fire before any Ghidra call).
    st.update_settings({"features.emulation.enabled": True,
                        "features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    with session_scope() as s:
        p = create_project(s, name="argdep")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        # Curate the function node with a recovered signature that takes args.
        get_or_create_node(s, project_id=p.id, node_type="function", name="check_password",
                           target_id=t.id, attrs={"param_count": 1})
        s.flush()
        out = emulate_constant(s, p, t, function="check_password")
        assert out["skipped"] == "arg_dependent"
        assert out["param_count"] == 1
        assert out["reached_ret"] is False and out["value"] is None
        assert "argument" in out["error"].lower()
        assert "re_solve" in out["error"]
        # No emulation was run, so no Observation was recorded.
        assert O.list_observations(s, t.id, kind="emulation") == []


def test_emulate_constant_no_signature_falls_through(hg_home, monkeypatch):
    """With NO recorded signature, the pre-check must NOT second-guess — it falls through PAST
    the arg gate into the emulation path. We stub `run_emulate` so this stays an OFFLINE
    host-logic test (no sandbox image needed); a real emulation is covered by the
    GHIDRA_READY-gated tests below. (Without the stub this hit the real ghidra_probe and failed
    in the no-Docker offline CI with 'Unable to find image hexgraph-sandbox:latest'.)"""
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    monkeypatch.setattr(GhidraDecompiler, "run_emulate",
                        lambda self, *a, **k: {"emulation": {"reached_ret": False, "value": None}})
    st.update_settings({"features.emulation.enabled": True,
                        "features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    with session_scope() as s:
        p = create_project(s, name="nosig")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        out = emulate_constant(s, p, t, function="unknown_fn")
        # It went PAST the arg pre-check (no skipped marker) into the emulation path.
        assert out.get("skipped") != "arg_dependent"
        assert out["available"] is True


def test_emulate_core_guards_arg_dependent_functions():
    """The authoritative in-probe guard (pyghidra_lib.emulate_core) bails on getParameterCount() > 0
    before the step loop — the cold-path fallback when no signature is recorded on the node."""
    import inspect

    from hexgraph.sandbox.probes import pyghidra_lib as L

    src = inspect.getsource(L.emulate_core)
    assert "getParameterCount() > 0" in src
    assert "arg_dependent" in src


# ── the MCP agent surface (recover_constant) ──────────────────────────────────────────

def test_recover_constant_advertised_in_catalog():
    """The verb is reachable by a coding agent — advertised in the read group, callable, typed."""
    from hexgraph.agent import mcp_tools as M

    spec = next((t for t in M.catalog({"read"}) if t["name"] == "re_recover_constant"), None)
    assert spec is not None and callable(spec["fn"])
    assert spec["schema"]["properties"].keys() >= {"target_id", "function"}


def test_recover_constant_gate_off_returns_error_not_raise(hg_home):
    """The MCP wrapper turns the opt-in PolicyViolation into a friendly error dict — an agent
    sees a clear message, never an exception, when features.emulation is off (the default)."""
    from hexgraph.agent.mcp_tools import recover_constant

    with session_scope() as s:
        p = create_project(s, name="ec")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tid = t.id
    out = recover_constant(tid, "anything")
    assert "error" in out and "features.emulation" in out["error"]


def test_recover_constant_unknown_target(hg_home):
    from hexgraph.agent.mcp_tools import recover_constant

    assert recover_constant("no-such-target", "f") == {"error": "target not found"}


# ── Docker + Ghidra: the emulator recovers a runtime-derived constant ─────────────────

def _ghidra_in_image() -> bool:
    if not SANDBOX_READY:
        return False
    try:
        from hexgraph.sandbox.runner import SandboxRunner

        chk = SandboxRunner().run_json_probe(
            "ghidra_probe.py", fixture_path("vuln_httpd"), extra_args=["--check"])
        return bool(chk.get("present"))
    except Exception:
        return False


GHIDRA_READY = _ghidra_in_image()


@pytest.mark.skipif(not GHIDRA_READY, reason="requires Docker + a WITH_GHIDRA=1 sandbox image")
def test_emulate_recovers_derived_constant_on_keyderive(hg_home):
    if shutil.which("gcc") is None:
        pytest.skip("gcc unavailable to compile the keyderive fixture")
    src = fixture_path("challenges/keyderive.c")
    binpath = tempfile.mktemp(prefix="keyderive-")
    if subprocess.run(["gcc", "-O0", "-g", "-o", binpath, src], capture_output=True).returncode != 0:
        pytest.skip("could not compile keyderive")
    # Oracle: the true derived value, from a native run of the same binary.
    oracle = subprocess.run([binpath], capture_output=True, text=True).stdout.strip()
    assert oracle, "native keyderive produced no output"

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless",
                        "features.emulation.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="kd")
        t = ingest_file(s, p, binpath, name="keyderive")
        out = emulate_constant(s, p, t, function="derive_unlock_code")

        assert out["available"] is True and out["reached_ret"] is True, out
        assert out["value"] == "0x" + oracle, (out["value"], oracle)

        # Recorded as an emulation Observation in the substrate.
        rows = O.list_observations(s, t.id, kind="emulation")
        assert len(rows) == 1 and oracle in rows[0]["summary"]

        # And annotated on the function node (grounded enrichment).
        node = s.query(Node).filter_by(
            project_id=p.id, node_type="function", name="derive_unlock_code").one()
        assert node.attrs_json.get("recovered_constant") == "0x" + oracle
