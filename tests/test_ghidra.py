"""Ghidra integration (optional). Logic-level tests — no real Ghidra binary:
decompiler selection honors Settings, the probe's --check contract, the headless
decompiler wrapper, and graph enrichment with a stubbed executor."""

import json
import subprocess
import sys
from pathlib import Path

from hexgraph import settings as st
from hexgraph.db.models import EdgeType, Node, NodeType
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.sandbox.decompiler import GhidraDecompiler, R2Decompiler, get_decompiler

from conftest import fixture_path

PROBE = Path("src/hexgraph/sandbox/probes/ghidra_probe.py")


class FakeExecutor:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, project_mount=None):
        self.calls.append((probe, extra_args, project_mount))
        return self.payload

    def run_probe(self, *a, **k):  # pragma: no cover - unused
        raise NotImplementedError


def test_default_is_radare2(hg_home):
    assert isinstance(get_decompiler(), R2Decompiler)


def test_settings_select_ghidra_headless(hg_home):
    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    assert isinstance(get_decompiler(), GhidraDecompiler)


def test_env_override_beats_settings(hg_home, monkeypatch):
    st.update_settings({"features.ghidra.enabled": True})
    monkeypatch.setenv("HEXGRAPH_DECOMPILER", "radare2")
    assert isinstance(get_decompiler(), R2Decompiler)


def test_ghidra_decompiler_uses_ghidra_probe(hg_home):
    fake = FakeExecutor({"tool": "ghidra_probe", "functions": ["main"], "focus": None})
    out = GhidraDecompiler(runner=fake).decompile("/artifact", "main")
    # No project ⇒ no persistent-project mount (the throwaway path), still uses ghidra_probe.
    assert fake.calls == [("ghidra_probe.py", ["main"], None)]
    assert out["functions"] == ["main"]


def test_probe_check_contract_without_ghidra():
    """The probe's --check path runs on the host and reports Ghidra absence cleanly."""
    r = subprocess.run([sys.executable, str(PROBE), "/tmp/whatever", "--check"],
                       capture_output=True, text=True, env={"GHIDRA_INSTALL_DIR": "/nonexistent"})
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["present"] is False and "WITH_GHIDRA" in out["detail"]


def test_enrich_target_records_substrate_not_bulk_graph(hg_home, monkeypatch):
    """Phase O §5.3: enrich_recon is redirected to the SUBSTRATE (the Observation store),
    NOT bulk graph nodes. Ghidra's whole inventory/call-graph/structs become queryable
    Observations + enrichment facts; they enrich already-curated objects and self-wire
    `calls` edges AMONG promoted functions, but never flood the graph with bulk nodes."""
    payload = {
        "functions": ["main", "parse", "helper"],
        "calls": [["main", "parse"], ["parse", "helper"], ["parse", "missing"]],
        "structs": [{"name": "Packet", "size": 16, "fields": [{"name": "len", "type": "int"}]},
                    {"name": "__elf_builtin", "size": 8, "builtin": True}],
    }
    fake = FakeExecutor(payload)
    # enrich_target routes through GhidraDecompiler, which resolves its executor via the
    # name imported into the decompiler module — patch THAT reference.
    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_executor", lambda *a, **k: fake)

    from hexgraph.db.models import Edge, EnrichmentFact, Observation
    from hexgraph.engine.ghidra import enrich_target
    from hexgraph.engine.nodes import get_or_create_node

    with session_scope() as s:
        p = create_project(s, name="g")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        # Curate two of the functions FIRST, so the recorded call graph can self-wire the
        # edge between them (both-endpoints-exist) and enrich nothing it shouldn't.
        get_or_create_node(s, project_id=p.id, node_type=NodeType.function, name="main", target_id=t.id)
        get_or_create_node(s, project_id=p.id, node_type=NodeType.function, name="parse", target_id=t.id)
        fn_before = s.query(Node).filter(Node.node_type == NodeType.function.value).count()

        res = enrich_target(s, p, t)
        assert res["ok"] and res["recorded"] is True
        assert res["functions"] == 3 and res["calls"] == 3 and res["structs"] == 2

        # NO bulk function nodes created (the curated set is unchanged — 'helper' never
        # became a node), and NO struct nodes at all (structs live only in the substrate).
        assert s.query(Node).filter(Node.node_type == NodeType.function.value).count() == fn_before
        assert s.query(Node).filter(Node.node_type == NodeType.struct.value).count() == 0

        # The inventory/call-graph/structs were recorded as Observations + enrichment facts.
        kinds = {o.result_kind for o in s.query(Observation).filter(Observation.target_id == t.id).all()}
        assert {"function_list", "call_graph", "structs"} <= kinds
        assert s.query(EnrichmentFact).count() >= 1

        # main→parse self-wired (both endpoints curated); parse→helper / parse→missing did
        # NOT (helper/missing aren't nodes) — the both-endpoints-exist rule holds.
        calls = s.query(Edge).filter(Edge.type == EdgeType.calls.value).all()
        assert len(calls) == 1
        # The real struct's layout fact is queryable; the builtin was filtered by the extractor.
        struct_facts = s.query(EnrichmentFact).filter(EnrichmentFact.node_type == "struct").all()
        keys = {f.subject_key for f in struct_facts}
        assert "Packet" in keys and "__elf_builtin" not in keys


def test_check_bridge_mode_not_running(hg_home):
    from hexgraph.engine.ghidra import check_ghidra

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "bridge",
                        "features.ghidra.bridge.port": 4799})
    r = check_ghidra()
    assert r["enabled"] is True and r["mode"] == "bridge" and r["ok"] is False
