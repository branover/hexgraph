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


def test_enrich_target_materializes_graph(hg_home, monkeypatch):
    payload = {
        "functions": ["main", "parse", "helper"],
        "calls": [["main", "parse"], ["parse", "helper"], ["parse", "missing"]],
        "structs": [{"name": "Packet", "size": 16, "fields": [{"name": "len", "type": "int"}]}],
    }
    fake = FakeExecutor(payload)
    # enrich_target routes through GhidraDecompiler, which resolves its executor via the
    # name imported into the decompiler module — patch THAT reference.
    monkeypatch.setattr("hexgraph.sandbox.decompiler.get_executor", lambda *a, **k: fake)

    from hexgraph.engine.ghidra import enrich_target

    with session_scope() as s:
        p = create_project(s, name="g")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        res = enrich_target(s, p, t)
        assert res == {"ok": True, "functions": 3, "calls": 2, "structs": 1}  # 'missing' callee dropped
        fns = s.query(Node).filter(Node.project_id == p.id, Node.node_type == NodeType.function.value).all()
        assert {f.name for f in fns} >= {"main", "parse", "helper"}
        structs = s.query(Node).filter(Node.node_type == NodeType.struct.value).all()
        assert len(structs) == 1 and structs[0].attrs_json["size"] == 16
        from hexgraph.db.models import Edge

        calls = s.query(Edge).filter(Edge.type == EdgeType.calls.value, Edge.origin == "ghidra").all()
        assert len(calls) == 2


def test_check_bridge_mode_not_running(hg_home):
    from hexgraph.engine.ghidra import check_ghidra

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "bridge",
                        "features.ghidra.bridge.port": 4799})
    r = check_ghidra()
    assert r["enabled"] is True and r["mode"] == "bridge" and r["ok"] is False
