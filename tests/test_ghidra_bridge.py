"""Ghidra bridge (connect to a running Ghidra). The live remote calls are
env-gated; here we inject a fake ops object to test the orchestration: decompiler
wrapper, program listing, and importing a program's real bytes as a target."""

from hexgraph.db.models import Target
from hexgraph.db.session import session_scope
from hexgraph.engine.ghidra_bridge import (
    BridgeUnavailable, GhidraBridgeDecompiler, import_program, list_open_programs,
)
from hexgraph.engine.ingest import create_project

from conftest import fixture_path


class FakeOps:
    def list_programs(self):
        return [{"name": "httpd", "path": "/x/httpd", "language": "x86:LE:64:default", "functions": 42}]

    def executable_path(self, program):
        return "/x/httpd" if program == "httpd" else None

    def decompile(self, program, function):
        focus = {"name": function, "resolved": function, "pseudocode": "int main(){}", "disasm": "", "callees": []} if function else None
        return {"functions": ["main", "cgi_handler"], "focus": focus, "tool": "ghidra_bridge"}


def test_bridge_decompiler_uses_ops():
    out = GhidraBridgeDecompiler(ops=FakeOps()).decompile("/artifact", "cgi_handler")
    assert out["tool"] == "ghidra_bridge"
    assert out["focus"]["pseudocode"] == "int main(){}"


def test_list_open_programs_with_ops():
    progs = list_open_programs(ops=FakeOps())
    assert progs[0]["name"] == "httpd" and progs[0]["functions"] == 42


def test_import_program_ingests_real_bytes(hg_home, monkeypatch):
    # No docker in unit tests → recon is skipped, but the target (real bytes) lands.
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        p = create_project(s, name="bridge")
        res = import_program(s, p, path=fixture_path("vuln_httpd"), name="httpd")
        assert res["recon"] is False
        t = s.get(Target, res["target_id"])
        assert t is not None and t.name == "httpd"


def test_import_rejects_missing_path(hg_home):
    with session_scope() as s:
        p = create_project(s, name="bridge2")
        try:
            import_program(s, p, path="/nope/not-here")
            assert False, "expected BridgeUnavailable"
        except BridgeUnavailable:
            pass


def test_programs_endpoint_without_bridge(hg_home):
    from fastapi.testclient import TestClient

    from hexgraph.api.app import create_app

    c = TestClient(create_app())
    r = c.get("/api/ghidra/programs")
    # ghidra_bridge client isn't installed in CI → clean 400, not a 500.
    assert r.status_code == 400
