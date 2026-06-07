"""The function source viewer's backend: the /disassemble endpoint (always radare2)
and the `backend` field now carried on /decompile. Bodies are recomputed on demand and
never stored — these endpoints just front the decompiler seam for the in-app viewer."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.sandbox import decompiler as dc
from hexgraph.sandbox import runner

from conftest import fixture_path


def _seed_target():
    with session_scope() as s:
        p = create_project(s, name="srcview")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        return t.id


class _FakeR2:
    """Stand-in for R2Decompiler — returns a canned focus regardless of the artifact."""
    name = "radare2"

    def decompile(self, artifact, function=None, *, address=None, reanalyze=False, project=None):
        subj = function or address
        if subj in (None, "missing"):
            return {"functions": ["main", "cgi_handler"], "focus": None}
        return {"functions": ["main", "cgi_handler"],
                "focus": {"name": subj, "address": "0x401200",
                          "disasm": "push rbp\nmov rbp, rsp\nret",
                          "callees": ["strcpy", "printf"]}}


def test_disassemble_without_docker_is_graceful(hg_home, monkeypatch):
    tid = _seed_target()
    monkeypatch.setattr(runner, "docker_available", lambda: False)
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/disassemble", json={"function": "cgi_handler"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False and "Docker" in body["detail"]


def test_disassemble_requires_a_focus(hg_home, monkeypatch):
    tid = _seed_target()
    monkeypatch.setattr(runner, "docker_available", lambda: True)
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/disassemble", json={})
    assert r.status_code == 400


def test_disassemble_returns_radare2_disasm(hg_home, monkeypatch):
    tid = _seed_target()
    monkeypatch.setattr(runner, "docker_available", lambda: True)
    monkeypatch.setattr(dc, "R2Decompiler", _FakeR2)
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/disassemble", json={"function": "cgi_handler"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["backend"] == "radare2"
    assert body["focus"]["disasm"].startswith("push rbp")
    assert body["focus"]["callees"] == ["strcpy", "printf"]


def test_disassemble_unknown_function_reports_not_found(hg_home, monkeypatch):
    tid = _seed_target()
    monkeypatch.setattr(runner, "docker_available", lambda: True)
    monkeypatch.setattr(dc, "R2Decompiler", _FakeR2)
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/disassemble", json={"function": "missing"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True and body["focus"] is None


def test_disassemble_404_for_unknown_target(hg_home):
    c = TestClient(create_app())
    r = c.post("/api/targets/does-not-exist/disassemble", json={"function": "main"})
    assert r.status_code == 404


def test_decompile_reports_backend(hg_home, monkeypatch):
    tid = _seed_target()
    monkeypatch.setattr(runner, "docker_available", lambda: True)

    class _FakeDecompiler:
        name = "ghidra"

        def decompile(self, artifact, function=None, *, address=None, project=None):
            subj = function or address
            return {"functions": ["main"], "focus": {"name": subj, "address": address,
                                                     "pseudocode": "int main(){}"}}

    monkeypatch.setattr(dc, "get_decompiler", lambda: _FakeDecompiler())
    c = TestClient(create_app())
    r = c.post(f"/api/targets/{tid}/decompile", json={"function": "main"})
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True and body["backend"] == "ghidra"
    # by ADDRESS (the reliable key when the name isn't a resolvable symbol)
    r2 = c.post(f"/api/targets/{tid}/decompile", json={"address": "0x401200"})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["available"] is True and b2["focus"]["address"] == "0x401200"
