"""Phase 5A PR 5A-1 — the binutils quick-facts probe (design §3.1).

Three layers, all matching the Phase O curation contract:

- the extractor unit test: `binutils_facts` distils ONLY the whitelisted always-welcome
  subset (`is_sink` on dangerous imports via the SHARED DANGEROUS_IMPORTS path), never a
  verdict/severity/new node, and re-applying is a no-op;
- the engine-helper contract with a FAKED executor (offline, no Docker): records a single
  `binutils_facts` Observation scoped by content_hash, mints ZERO graph nodes, enriches an
  ALREADY-curated dangerous symbol with `is_sink`, folds mitigation flags onto the target,
  and dedups on a repeat call;
- a Docker-gated probe test that runs the real binutils suite on a committed ELF fixture
  and asserts the Observation shape (skips when the sandbox image is absent).
"""

import pytest

from hexgraph.db.models import Edge, Node, Observation, Target
from hexgraph.db.session import session_scope
from hexgraph.engine import enrichment as E
from hexgraph.engine import binutils as BU
from hexgraph.engine.binutils import apply_mitigations_to_target, collect_binutils_facts
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import materialize_symbol

from conftest import fixture_path

HASH = "deadbeef"

# A representative probe payload (the shape binutils_probe emits), used by the offline
# engine-helper tests via a faked executor so they need no Docker.
_FACTS = {
    "tool": "binutils_probe",
    "format": "ELF",
    "elf_type": "EXEC (Executable file)",
    "machine": "Advanced Micro Devices X86-64",
    "entry": "0x4010b0",
    "soname": None,
    "symbols": [{"name": "main", "type": "T", "address": "0x401136"},
                {"name": "strcpy", "type": "U", "address": None}],
    "imports": ["printf", "strcpy", "strncmp", "strtok"],
    "exports": [],
    "libraries": ["libc.so.6"],
    "sections": [".text", ".plt", ".got", ".data"],
    "relocation_count": 6,
    "jump_slot_imports": ["printf", "strcpy", "strncmp", "strtok"],
    "mitigations": {"nx": True, "relro": "none", "pie": False, "canary": False, "fortify": False},
    "strings": ["/cgi-bin/", "GET", "POST"],
}


class _FakeExec:
    """Returns a fixed probe payload and records how the probe was invoked."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run_json_probe(self, probe, path, **kw):
        self.calls.append((probe, path))
        return self.result


def _wire(monkeypatch, result=_FACTS):
    fake = _FakeExec(result)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


def _seed(s, name="bu"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": HASH}
    s.flush()
    return p, t


# --- extractor unit test: only whitelisted facts come out --------------------

def test_extractor_emits_only_is_sink_for_dangerous_imports(hg_home):
    """binutils_facts → an `is_sink` symbol fact for EACH dangerous import, and NOTHING
    for a benign import (no verdict for the rest); only the whitelisted `is_sink` key."""
    payload = {"imports": ["printf", "strcpy", "system", "memcpy"],
               # never-whitelisted noise that must be ignored:
               "mitigations": {"canary": False}, "exports": ["foo"],
               "severity": "critical", "summary": "overflow!"}
    facts = E._extract_binutils(payload)
    # strcpy/system/memcpy are dangerous; printf is not.
    subjects = {f.subject_key for f in facts}
    assert subjects == {"strcpy", "system", "memcpy"}
    assert "printf" not in subjects
    # every fact is a symbol `is_sink` attribute fact and carries ONLY that key.
    for f in facts:
        assert f.node_type == "symbol" and f.fact_kind == "attrs"
        assert set(f.fact_json) == {"is_sink"} and f.fact_json["is_sink"] is True
        assert set(f.fact_json) <= E._ATTRIBUTE_WHITELIST["symbol"]
    # no severity/summary/mitigation ever becomes a node fact.
    keys = set().union(*[set(f.fact_json) for f in facts]) if facts else set()
    assert "severity" not in keys and "summary" not in keys


def test_extractor_handles_empty_and_malformed_payload(hg_home):
    assert E._extract_binutils({}) == []
    assert E._extract_binutils({"imports": "not-a-list"}) == []
    assert E._extract_binutils([]) == []  # a non-dict payload
    assert E._extract_binutils({"imports": []}) == []


def test_extractor_registered_under_binutils_facts():
    assert E.extractor_for("binutils_facts") is E._extract_binutils


# --- engine helper: observation + enrichment, mints no nodes (offline) -------

def test_collect_records_one_observation_and_mints_no_nodes(hg_home, monkeypatch):
    fake = _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = collect_binutils_facts(s, p, t, source="agent")
        s.flush()
        # the probe was invoked over the target's artifact
        assert fake.calls[-1][0] == "binutils_probe.py"
        assert out["observation_id"] and out["cached"] is False and out["reuse_hint"]
        # QUERY: zero new graph nodes/edges
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "binutils_facts").all()
        assert len(obs) == 1 and obs[0].content_hash == HASH
        assert obs[0].tool == "binutils_facts"


def test_collect_enriches_existing_dangerous_symbol_and_target_mitigations(hg_home, monkeypatch):
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        # Pre-curate a strcpy symbol; the always-welcome extractor must tag it is_sink.
        sym = materialize_symbol(s, project_id=p.id, target_id=t.id, name="strcpy", kind="import")
        s.flush()
        collect_binutils_facts(s, p, t, source="agent")
        s.flush()
        s.refresh(sym)
        assert (sym.attrs_json or {}).get("is_sink") is True
        # mitigation flags fold onto the TARGET metadata (the target analogue of enrichment)
        s.refresh(t)
        mit = (t.metadata_json or {}).get("mitigations") or {}
        assert mit.get("canary") is False and mit.get("nx") is True and mit.get("pie") is False
        # a benign import that has NO curated node mints nothing
        assert s.query(Node).filter(Node.name == "printf").count() == 0


def test_collect_dedups_on_repeat_call(hg_home, monkeypatch):
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        out1 = collect_binutils_facts(s, p, t)
        s.flush()
        out2 = collect_binutils_facts(s, p, t)
        s.flush()
        assert out1["cached"] is False and out2["cached"] is True
        assert out1["observation_id"] == out2["observation_id"]
        assert s.query(Observation).filter(
            Observation.result_kind == "binutils_facts").count() == 1


def test_collect_reports_error_without_docker(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        p, t = _seed(s)
        out = collect_binutils_facts(s, p, t)
        assert "error" in out and "Docker" in out["error"]
        assert s.query(Observation).filter(
            Observation.result_kind == "binutils_facts").count() == 0


# --- apply_mitigations_to_target: idempotent, never overwrites with None ------

def test_apply_mitigations_is_idempotent_and_skips_none(hg_home):
    with session_scope() as s:
        p, t = _seed(s)
        assert apply_mitigations_to_target(t, _FACTS) is True
        # a second identical apply changes nothing (no-op)
        assert apply_mitigations_to_target(t, {"mitigations": _FACTS["mitigations"]}) is False
        # a None value never clobbers an existing flag
        before = dict((t.metadata_json or {})["mitigations"])
        assert apply_mitigations_to_target(t, {"mitigations": {"nx": None}}) is False
        assert (t.metadata_json or {})["mitigations"] == before
        # a payload with no mitigations is a no-op
        assert apply_mitigations_to_target(t, {}) is False


# --- the agent tool + MCP read verb render the facts -------------------------

def test_agent_tool_renders_binutils_facts(hg_home, monkeypatch):
    _wire(monkeypatch)
    from hexgraph.engine.agent_tools import ToolContext, run_tool

    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        out = run_tool(ctx, "binutils_facts", {})
        assert "binutils facts" in out and "mitigations" in out
        assert "canary=False" in out and "nx=True" in out
        assert "strcpy" in out  # imports/jump-slots rendered


# --- Docker-gated: the real probe on a committed ELF fixture -----------------

def test_binutils_probe_on_real_elf(hg_home, sandbox):
    """The actual binutils suite runs in the sandbox over vuln_httpd and records the
    expected Observation shape (skips without the sandbox image)."""
    with session_scope() as s:
        p, t = _seed(s)
        out = collect_binutils_facts(s, p, t, runner=sandbox)
        s.flush()
        assert "error" not in out, out
        f = out["facts"]
        # the canonical facts the design promises
        assert f["format"] == "ELF" and "EXEC" in (f.get("elf_type") or "")
        assert "strcpy" in f["imports"] and "printf" in f["imports"]
        assert "libc.so.6" in f["libraries"]
        assert ".text" in f["sections"] and ".plt" in f["sections"]
        # vuln_httpd is the known weak-mitigations fixture
        mit = f["mitigations"]
        assert mit["nx"] is True and mit["canary"] is False and mit["pie"] is False
        # PLT jump-slot imports recovered from the relocations
        assert "strcpy" in f["jump_slot_imports"]
        # one durable Observation, scoped to the bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "binutils_facts").all()
        assert len(obs) == 1 and obs[0].content_hash == HASH


def test_binutils_probe_rejects_non_elf(hg_home, sandbox):
    """A non-ELF artifact is reported as an error (non-zero exit, surfaced reason) —
    the probe is an ELF facts tool; firmware/disk images stay on the recon path."""
    with session_scope() as s:
        p = create_project(s, name="bu-nonelf")
        t = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "fw-hash"}
        s.flush()
        out = collect_binutils_facts(s, p, t, runner=sandbox)
        assert "error" in out and "ELF" in out["error"]
        # nothing recorded for a failed pass
        assert s.query(Observation).filter(
            Observation.result_kind == "binutils_facts").count() == 0
