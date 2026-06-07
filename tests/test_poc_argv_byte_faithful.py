"""Byte-faithful argv for a solver-style binary PoC (task 3.4).

`finding_verify_poc`'s binary path was byte-faithful on STDIN (`stdin_b64`) but argv was
text-passed (`str(a)`), so an angr-SOLVER argv reproducer whose bytes aren't printable —
e.g. the licensegate serial `3b25065c4b20040f` (contains 0x06/0x04/0x0f) — could not be
verified: `str()` mangles the non-printable bytes. This proves the fix:

- the probe (`sandbox/probes/poc_probe.py`) builds a RAW-BYTE argv from `argv_b64`, so the
  solved serial reaches the `system("/bin/grant_admin")` success path ("License valid.")
  where the text path would mangle it (a host-subprocess run of the committed x86-64 fixture
  — no Docker, runs everywhere);
- `_substitute` leaves the raw `argv_b64`/`stdin_b64` byte fields verbatim (no {{NONCE}}
  corruption of base64);
- `spec_from_solver_finding` reconstructs an `argv_b64` spec from a solver finding's
  `evidence.extra.solver` (input_model + minimal_input_hex), the handoff that lets
  `finding_verify_poc(finding_id=…)` verify a solved reproducer byte-faithfully;
- `repro_command` renders the raw argv as a copy-paste `$'\\xNN…'` literal;
- the Docker-gated e2e drives the WHOLE engine path (`verify_poc` → the real sandbox
  executor) and confirms the solved serial reaches the success path in the sandbox.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys

import pytest

from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.models.finding import Evidence, Finding as FModel
from hexgraph import settings as st

from conftest import SANDBOX_READY, fixture_path

# A genuinely constraint-satisfying licensegate serial (see licensegate.c). It contains the
# non-printable control bytes 0x06, 0x04, 0x0f (the solver-recovered serial from the eval) and
# no NUL. This is the primary byte-faithful target.
SERIAL_HEX = "3b25065c4b20040f"
SERIAL = bytes.fromhex(SERIAL_HEX)
# A SECOND valid serial that additionally carries a HIGH byte (0xb1 >= 0x80) — one that genuinely
# cannot survive a UTF-8 text-argv round-trip (latin-1→UTF-8 re-encodes it to TWO bytes), so the
# text path provably mangles it while argv_b64 carries it faithfully.
HIGH_SERIAL_HEX = "27b153094b0b050a"
HIGH_SERIAL = bytes.fromhex(HIGH_SERIAL_HEX)
LICENSEGATE = "phase5_tool_eval/licensegate"

# The path the success oracle keys on (printed by puts() before the privileged sink runs).
SUCCESS = "License valid."


def _check_serial(b: bytes) -> bool:
    """licensegate's gate, re-implemented — a serial is valid iff its first 8 bytes satisfy
    EVERY constraint (proves the chosen test serial really reaches the sink, not just 'runs')."""
    if len(b) < 8:
        return False
    return (
        ((b[0] * 7 + b[1]) & 0xFFFFFFFF) == 0x1C2
        and (b[2] ^ b[3]) == 0x5A
        and (b[4] | 0x20) == ord("k")
        and (sum(b[i] * (i + 1) for i in range(8)) & 0xFFFFFFFF) == 0x4D2
    )


def test_chosen_serials_are_valid_non_printable_solutions():
    """Guard: both serials really satisfy the gate, carry non-printable bytes, and have no NUL
    (so each survives as a real argv[1]). The HIGH serial additionally has a >=0x80 byte that a
    UTF-8 text-argv round-trip provably mangles."""
    assert _check_serial(SERIAL)
    assert any(c < 0x20 or c > 0x7E for c in SERIAL)  # non-printable → text rendering is fragile
    assert b"\x00" not in SERIAL
    assert _check_serial(HIGH_SERIAL)
    assert any(c >= 0x80 for c in HIGH_SERIAL)  # a high byte UTF-8 can't carry in one byte
    assert b"\x00" not in HIGH_SERIAL


# ── the probe builds a byte-faithful argv (unit) ───────────────────────────────────────────

def test_build_cmd_argv_b64_is_raw_bytes():
    """`argv_b64` decodes each element to RAW BYTES and builds a homogeneous bytes argv (the
    qemu prefix + target path are os.fsencode'd alongside it) — never str()-mangled."""
    from hexgraph.sandbox.probes.poc_probe import _build_cmd

    spec = {"argv_b64": [base64.b64encode(SERIAL).decode()]}
    cmd = _build_cmd([], "/out/poc_target", spec)
    assert cmd == [b"/out/poc_target", SERIAL]
    assert all(isinstance(p, bytes) for p in cmd)  # POSIX exec takes a bytes argv

    # the qemu-prefix path stays homogeneous bytes (a foreign-arch run mustn't break on a mixed list)
    cmd2 = _build_cmd(["qemu-mipsel", "-L", "/sysroot"], "/out/poc_target", spec)
    assert cmd2 == [b"qemu-mipsel", b"-L", b"/sysroot", b"/out/poc_target", SERIAL]
    assert all(isinstance(p, bytes) for p in cmd2)


def test_build_cmd_text_argv_unchanged_when_no_argv_b64():
    """Plain `argv` (text) keeps working when `argv_b64` is absent (back-compat)."""
    from hexgraph.sandbox.probes.poc_probe import _build_cmd

    cmd = _build_cmd([], "/out/poc_target", {"argv": ["--serve", 7]})
    assert cmd == ["/out/poc_target", "--serve", "7"]


def test_substitute_leaves_raw_byte_fields_verbatim():
    """{{NONCE}} substitution must NOT touch the raw base64 byte fields (argv_b64/stdin_b64) —
    rewriting them would corrupt the encoded bytes."""
    from hexgraph.engine.poc import _substitute

    b64 = base64.b64encode(SERIAL).decode()
    spec = {"argv_b64": [b64], "stdin_b64": b64,
            "env": {"Q": "x {{NONCE}}"}, "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}
    out = _substitute(spec, "TOKEN123")
    assert out["argv_b64"] == [b64]          # untouched
    assert out["stdin_b64"] == b64           # untouched
    assert out["env"]["Q"] == "x TOKEN123"   # text fields still substituted
    assert out["oracle"]["value"] == "TOKEN123"


# ── the probe run end-to-end against the native fixture (host subprocess, no Docker) ─────────

def _run_probe(spec: dict, tmp_path) -> dict:
    """Run poc_probe.py as a host subprocess against the committed x86-64 licensegate fixture —
    the probe is self-contained, so this exercises the REAL argv-build/exec path without Docker."""
    out = subprocess.run(
        [sys.executable, "-m", "hexgraph.sandbox.probes.poc_probe",
         fixture_path(LICENSEGATE), str(tmp_path), "--spec", json.dumps(spec)],
        capture_output=True, text=True, timeout=60,
    )
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.mark.skipif(sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64"),
                    reason="runs the committed x86-64 ELF natively (no qemu/Docker here)")
def test_probe_raw_argv_reaches_success_path(tmp_path):
    """The headline at the probe layer: the SOLVED serial fed via `argv_b64` reaches
    "License valid." (the sink path), proving byte-faithful argv works end to end."""
    spec = {"argv_b64": [base64.b64encode(SERIAL).decode()],
            "oracle": {"type": "output_contains", "value": SUCCESS}}
    r = _run_probe(spec, tmp_path)
    assert r["ran"] is True
    assert r["verified"] is True, r
    assert SUCCESS in r["output"]


@pytest.mark.skipif(sys.platform != "linux" or os.uname().machine not in ("x86_64", "amd64"),
                    reason="runs the committed x86-64 ELF natively (no qemu/Docker here)")
def test_probe_high_byte_argv_b64_succeeds_where_text_fails(tmp_path):
    """The contrast that justifies the fix, on a serial with a HIGH byte (0xb1): the byte field
    reaches the success path, the text field does NOT — UTF-8 re-encodes 0xb1 to two bytes, so
    the gate (which reads exactly 8 bytes) rejects the corrupted argv."""
    b64 = base64.b64encode(HIGH_SERIAL).decode()
    ok = _run_probe({"argv_b64": [b64], "oracle": {"type": "output_contains", "value": SUCCESS}}, tmp_path)
    assert ok["verified"] is True, ok  # byte-faithful → reaches the sink

    # latin-1 round-trips the raw bytes into a str the way a naive caller might; passed through the
    # text `argv` field it is re-encoded as UTF-8 (0xb1 → 0xc2 0xb1), corrupting the serial.
    mangled = HIGH_SERIAL.decode("latin-1")
    bad = _run_probe({"argv": [mangled], "oracle": {"type": "output_contains", "value": SUCCESS}}, tmp_path)
    assert bad["verified"] is False, (
        "text argv with a high byte must NOT verify — if it did, argv_b64 wouldn't be needed")
    assert SUCCESS not in bad["output"]


# ── the solver handoff: spec_from_solver_finding ────────────────────────────────────────────

def _solver_finding(input_model="argv", minimal=SERIAL_HEX, concrete=SERIAL_HEX + "00000000"):
    """A FModel shaped like an angr-solver finding's evidence (engine.solving._promote_and_emit)."""
    return FModel(
        title="Solver-reachable sink", severity="high", confidence="high",
        category="command-injection", summary="s", reasoning="r",
        evidence=Evidence(
            function="main", sink="system", reproducer=concrete,
            extra={"solver": {"backend": "angr", "sink_func": "system",
                              "concrete_input_hex": concrete, "minimal_input_hex": minimal,
                              "constrained_len": 8, "input_model": input_model}},
        ),
    )


def test_spec_from_solver_finding_builds_argv_b64(hg_home):
    """The handoff: an argv-model solver finding yields a byte-faithful `argv_b64` spec carrying
    the MINIMAL recovered input (the part that matters), with a sensible default oracle."""
    from hexgraph.engine.poc import spec_from_solver_finding

    with session_scope() as s:
        p = create_project(s, name="handoff")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="lg")
        row = _persist(s, p, t, _solver_finding())
        spec = spec_from_solver_finding(row)
    assert spec is not None
    # minimal_input_hex preferred → the 8 constrained bytes, fed as a single raw argv element
    assert spec["argv_b64"] == [base64.b64encode(SERIAL).decode()]
    assert base64.b64decode(spec["argv_b64"][0]) == SERIAL
    assert "argv" not in spec  # the byte field, not the text one
    assert spec["oracle"]  # a default oracle is supplied


def test_spec_from_solver_finding_stdin_model(hg_home):
    """An stdin-model solver finding yields `stdin_b64`, not `argv_b64`."""
    from hexgraph.engine.poc import spec_from_solver_finding

    with session_scope() as s:
        p = create_project(s, name="handoff-stdin")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="lg")
        row = _persist(s, p, t, _solver_finding(input_model="stdin"))
        spec = spec_from_solver_finding(row)
    assert spec is not None
    assert base64.b64decode(spec["stdin_b64"]) == SERIAL
    assert "argv_b64" not in spec


def test_spec_from_solver_finding_preserves_caller_oracle(hg_home):
    """A caller-supplied base_spec (its oracle) is preserved; only the input is filled in."""
    from hexgraph.engine.poc import spec_from_solver_finding

    with session_scope() as s:
        p = create_project(s, name="handoff-oracle")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="lg")
        row = _persist(s, p, t, _solver_finding())
        spec = spec_from_solver_finding(row, base_spec={"oracle": {"type": "output_contains",
                                                                   "value": SUCCESS}})
    assert spec["oracle"] == {"type": "output_contains", "value": SUCCESS}
    assert base64.b64decode(spec["argv_b64"][0]) == SERIAL


def test_spec_from_solver_finding_none_without_solver_evidence(hg_home):
    """A non-solver finding (no evidence.extra.solver) yields None — nothing to hand off."""
    from hexgraph.engine.poc import spec_from_solver_finding

    with session_scope() as s:
        p = create_project(s, name="no-solver")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="lg")
        row = _persist(s, p, t, FModel(title="x", severity="info", confidence="low",
                                       category="other", summary="s", reasoning="r",
                                       evidence=Evidence()))
        assert spec_from_solver_finding(row) is None
    assert spec_from_solver_finding(None) is None


def _persist(s, p, t, fmodel):
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.tasks import create_task

    task = create_task(s, project=p, target_id=t.id, type="solve", backend="agent")
    return persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                           finding=fmodel, finding_type="vulnerability")


# ── the human reproduction command renders raw argv ─────────────────────────────────────────

def test_repro_command_renders_argv_b64_as_ansi_c(hg_home):
    """`repro_command` renders an argv_b64 element as a $'\\xNN…' literal so a human pastes the
    exact non-printable serial — not a mangled string."""
    from hexgraph.engine.poc_repro import repro_command

    with session_scope() as s:
        p = create_project(s, name="repro-b64")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="lg")
        spec = {"argv_b64": [base64.b64encode(SERIAL).decode()],
                "oracle": {"type": "output_contains", "value": SUCCESS}}
        cmd = repro_command(spec, t)
    assert isinstance(cmd, str)
    assert "$'" in cmd
    for b in SERIAL:
        assert f"\\x{b:02x}" in cmd  # every byte rendered faithfully
    assert t.path in cmd


# ── the Docker-gated e2e: the whole engine path through the real sandbox ─────────────────────

@pytest.mark.skipif(not SANDBOX_READY,
                    reason="requires the sandbox image (executes the target in the sandbox)")
def test_verify_solved_argv_in_sandbox_end_to_end(hg_home):
    """THE proof end to end: the SOLVED serial, fed byte-faithfully via `argv_b64`, reaches the
    licensegate success path WHEN RUN IN THE REAL SANDBOX — the capability the eval flagged.
    Goes through the real engine `verify_poc` (policy-gated, real executor)."""
    from hexgraph.engine.poc import verify_poc

    st.update_settings({"features.poc.enabled": True})  # opt-in exec gate
    with session_scope() as s:
        p = create_project(s, name="lg-e2e")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="licensegate")
        spec = {"argv_b64": [base64.b64encode(SERIAL).decode()],
                "oracle": {"type": "output_contains", "value": SUCCESS}}
        r = verify_poc(s, p, t, spec)
    assert r["verified"] is True, r
    assert SUCCESS in (r.get("output") or "")


@pytest.mark.skipif(not SANDBOX_READY,
                    reason="requires the sandbox image (executes the target in the sandbox)")
def test_solver_handoff_verifies_in_sandbox_end_to_end(hg_home):
    """The full headline: a SOLVER finding's reproducer is verified byte-faithfully via the
    handoff — the MCP verify_poc fills argv_b64 from evidence.extra.solver and the solved serial
    reaches the sink in the sandbox."""
    from hexgraph.engine import mcp_tools as M

    st.update_settings({"features.poc.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="lg-handoff-e2e")
        t = ingest_file(s, p, fixture_path(LICENSEGATE), name="licensegate")
        tid, pid = t.id, p.id
        row = _persist(s, p, t, _solver_finding())
        fid = row.id

    # The agent calls finding_verify_poc with ONLY an oracle — the engine fills the solved input.
    out = M.verify_poc(tid, {"oracle": {"type": "output_contains", "value": SUCCESS}}, finding_id=fid)
    assert out.get("verified") is True, out
    assert SUCCESS in (out.get("output") or "")

    # the finding now carries the verified PoC (its byte-faithful spec)
    with session_scope() as s:
        from hexgraph.db.models import Finding as FRow
        f = s.get(FRow, fid)
        poc = ((f.evidence_json or {}).get("extra") or {}).get("poc") or {}
        assert "argv_b64" in poc
        assert base64.b64decode(poc["argv_b64"][0]) == SERIAL
