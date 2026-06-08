"""Phase 5A PR 5A-2 — the FLOSS string-deobfuscation probe (design §3.2).

FLOSS is now an ALWAYS-ON static tool (it relaxes no boundary — it emulates decode routines
in-process and never executes the target), so there is no `features.floss` gate. Two layers,
matching the Phase O curation contract:

- the always-on contract: the MCP/agent verb is ALWAYS advertised (no toggle) and the helper
  always runs;
- the engine-helper contract with a FAKED executor (offline, no Docker): records a single
  `floss_strings` Observation scoped by content_hash, mints ZERO graph nodes, dedups on a
  repeat call (and a different min_length is a DISTINCT pass), and errors cleanly when
  Docker is down — proving the helper never auto-floods the graph;
- a Docker-gated probe test that runs real FLOSS on a committed x86-64 PE fixture and
  asserts it recovers the known stack/decoded strings + the Observation shape (skips when
  the FLOSS-enabled sandbox image is absent).
"""

import pytest

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.engine.floss import collect_floss_strings
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path

HASH = "deadbeef"

# A representative probe payload (the shape floss_probe emits), for the offline
# engine-helper tests via a faked executor so they need no Docker.
_FACTS = {
    "tool": "floss_probe",
    "floss_version": "3.1.1",
    "language": "unknown",
    "min_length": 4,
    "degraded": False,
    "stack_strings": [
        {"string": "STACKSTRING", "encoding": "ASCII", "function": 5368714652, "offset": 56,
         "program_counter": 5368714544},
    ],
    "tight_strings": [],
    "decoded_strings": [
        {"string": "DECODEDSECRET", "encoding": "ASCII", "decoding_routine": 5368714544,
         "decoded_at": 5368714752, "address": 1, "address_type": "STACK"},
    ],
    "static_strings": [{"string": "/cgi-bin/", "encoding": "ASCII", "offset": 1024}],
    "counts": {"stack_strings": 1, "tight_strings": 0, "decoded_strings": 1, "static_strings": 1},
}


class _FakeExec:
    """Returns a fixed probe payload and records how the probe was invoked."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run_json_probe(self, probe, path, **kw):
        self.calls.append((probe, path, kw.get("extra_args")))
        return self.result


def _wire(monkeypatch, result=_FACTS):
    fake = _FakeExec(result)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


def _seed(s, name="fl"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": HASH}
    s.flush()
    return p, t


# --- always-on: the verb is ALWAYS advertised (no gate) ----------------------

def test_no_floss_gate_in_settings(hg_home):
    """FLOSS is always-on: there is NO features.floss settings key (it was removed when the
    tool went ungated). Attempting to write it is rejected by the settings schema."""
    from hexgraph import settings as st

    with pytest.raises(st.SettingsError):
        st.update_settings({"features.floss.enabled": True})


def test_verb_always_advertised(hg_home):
    """The MCP read verb is ALWAYS in the catalog (no gate), typed — always-on contract."""
    from hexgraph.agent import mcp_tools as M

    specs = [t for t in M.catalog({"read"}) if t["name"] == "re_floss_strings"]
    assert len(specs) == 1
    spec = specs[0]
    assert callable(spec["fn"])
    assert spec["schema"]["properties"].keys() >= {"target_id", "min_length"}


def test_agent_tool_always_advertised(hg_home):
    """The in-process agent loop ALWAYS advertises floss_strings (always-on static tool)."""
    from hexgraph.agent.agent_tools import ToolContext, available_tools

    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        names = {spec.name for spec in available_tools(ctx)}
        assert "floss_strings" in names


# --- engine helper: one Observation, zero nodes, dedup (offline) -------------

def test_collect_records_one_observation_and_mints_no_nodes(hg_home, monkeypatch):
    fake = _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = collect_floss_strings(s, p, t, source="agent")
        s.flush()
        assert fake.calls[-1][0] == "floss_probe.py"
        assert out["observation_id"] and out["cached"] is False and out["reuse_hint"]
        # QUERY: zero new graph nodes/edges
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "floss_strings").all()
        assert len(obs) == 1 and obs[0].content_hash == HASH
        assert obs[0].tool == "floss_strings"
        # NO enrichment extractor registered for floss_strings (FLOSS recovers results,
        # not always-welcome facts) — promotion is the agent's deliberate act.
        from hexgraph.engine import enrichment as E
        assert E.extractor_for("floss_strings") is None


def test_collect_dedups_on_repeat_call(hg_home, monkeypatch):
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        out1 = collect_floss_strings(s, p, t)
        s.flush()
        out2 = collect_floss_strings(s, p, t)
        s.flush()
        assert out1["cached"] is False and out2["cached"] is True
        assert out1["observation_id"] == out2["observation_id"]
        assert s.query(Observation).filter(
            Observation.result_kind == "floss_strings").count() == 1


def test_min_length_is_a_distinct_pass(hg_home, monkeypatch):
    """A different min_length is a legitimately distinct pass — it must NOT collide with the
    default-pass Observation (and the knob is forwarded to the probe)."""
    fake = _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        collect_floss_strings(s, p, t)                      # default
        s.flush()
        collect_floss_strings(s, p, t, min_length=8)        # distinct
        s.flush()
        assert s.query(Observation).filter(
            Observation.result_kind == "floss_strings").count() == 2
        # the knob reached the probe as --min-length 8
        assert fake.calls[-1][2] == ["--min-length", "8"]


def test_collect_reports_error_without_docker(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        p, t = _seed(s)
        out = collect_floss_strings(s, p, t)
        assert "error" in out and "Docker" in out["error"]
        assert s.query(Observation).filter(
            Observation.result_kind == "floss_strings").count() == 0


def test_collect_surfaces_probe_error_json(hg_home, monkeypatch):
    """A probe that returns an error JSON (a non-analyzable artifact) surfaces as an error,
    not a recorded Observation."""
    _wire(monkeypatch, result={"error": "floss could not analyze this artifact"})
    with session_scope() as s:
        p, t = _seed(s)
        out = collect_floss_strings(s, p, t)
        assert "error" in out and "could not analyze" in out["error"]
        assert s.query(Observation).filter(
            Observation.result_kind == "floss_strings").count() == 0


# --- the agent tool renders the recovered strings ----------------------------

def test_agent_tool_renders_floss_strings(hg_home, monkeypatch):
    _wire(monkeypatch)
    from hexgraph.agent.agent_tools import ToolContext, run_tool

    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        out = run_tool(ctx, "floss_strings", {})
        assert "FLOSS strings" in out
        assert "STACKSTRING" in out and "DECODEDSECRET" in out


# --- the probe's pure parsing/degradation logic (offline, no sandbox) --------

def test_probe_pe_detection_and_min_length_clamp():
    from hexgraph.sandbox.probes import floss_probe as F

    assert F._is_pe(b"MZ") is True
    assert F._is_pe(b"\x7fE") is False
    # the one agent knob is clamped into FLOSS's sane range
    assert F._parse_min_length(2) == 4          # floor
    assert F._parse_min_length(8) == 8
    assert F._parse_min_length(999) == 64       # ceiling
    assert F._parse_min_length("bogus") == 4    # default on garbage


def test_probe_assemble_bounds_and_degraded_note():
    from hexgraph.sandbox.probes import floss_probe as F

    raw = {
        "metadata": {"version": "3.1.1", "language": "unknown"},
        "strings": {
            "stack_strings": [{"string": "A", "function": 1, "offset": 2}],
            "tight_strings": [],
            "decoded_strings": [{"string": "B", "decoding_routine": 3}],
            "static_strings": [{"string": "C", "offset": 4}],
        },
    }
    facts = F._assemble(raw, degraded=True, note="non-PE: static only", min_length=4)
    assert facts["degraded"] is True and facts["note"] == "non-PE: static only"
    assert facts["counts"] == {"stack_strings": 1, "tight_strings": 0,
                               "decoded_strings": 1, "static_strings": 1}
    assert facts["stack_strings"][0]["string"] == "A"
    assert facts["decoded_strings"][0]["string"] == "B"
    # caps report truncation rather than silently dropping
    big = {"metadata": {}, "strings": {"static_strings": [{"string": str(i)} for i in range(F._MAX_STATIC + 5)]}}
    capped = F._assemble(big, degraded=False, note=None, min_length=4)
    assert capped["counts"]["static_strings"] == F._MAX_STATIC
    assert capped["truncated"]["static_strings"] is True


# --- Docker-gated: real FLOSS on the committed PE fixture ---------------------

def test_floss_probe_on_real_pe(hg_home, floss_sandbox, monkeypatch):
    """Real FLOSS runs in the sandbox over the committed x86-64 PE fixture and recovers the
    KNOWN hidden strings — the stack string STACKSTRING and the decoded string DECODEDSECRET,
    neither of which a plain strings pass finds — plus the expected Observation shape (skips
    without the FLOSS-enabled sandbox image)."""
    with session_scope() as s:
        p = create_project(s, name="fl-real")
        t = ingest_file(s, p, fixture_path("floss_fixture.exe"), name="floss_fixture")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "floss-pe-hash"}
        s.flush()
        out = collect_floss_strings(s, p, t, runner=floss_sandbox)
        s.flush()
        assert "error" not in out, out
        f = out["facts"]
        assert f["degraded"] is False  # a PE gets the full pass
        stack = [r["string"] for r in f["stack_strings"]]
        decoded = [r["string"] for r in f["decoded_strings"]]
        assert "STACKSTRING" in stack, f"stack strings: {stack}"
        assert "DECODEDSECRET" in decoded, f"decoded strings: {decoded}"
        # one durable Observation, scoped to the bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "floss_strings").all()
        assert len(obs) == 1 and obs[0].content_hash == "floss-pe-hash"


def test_floss_probe_degrades_on_elf(hg_home, floss_sandbox):
    """A non-PE ELF artifact degrades to a static-strings-only pass with a clear note,
    never crashing — the arch/format graceful-degradation the design requires."""
    with session_scope() as s:
        p = create_project(s, name="fl-elf")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "elf-hash"}
        s.flush()
        out = collect_floss_strings(s, p, t, runner=floss_sandbox)
        s.flush()
        assert "error" not in out, out
        f = out["facts"]
        assert f["degraded"] is True and "note" in f
        # static strings still come back; the emulation legs are honestly empty
        assert f["counts"]["static_strings"] > 0
        assert f["counts"]["stack_strings"] == 0 and f["counts"]["decoded_strings"] == 0
