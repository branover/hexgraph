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


# --- _RemoteOps: the actual remote_eval expressions (against a fake bridge) -------------

class _FakeBridge:
    """Records remote_eval(expr, **kwargs) calls and returns a scripted result per call."""

    def __init__(self, responder):
        self.calls = []
        self._responder = responder

    def remote_eval(self, expr, **kwargs):
        self.calls.append((expr, kwargs))
        return self._responder(expr, kwargs)


def test_remote_decompile_one_inlines_name_and_passes_no_kwarg():
    """The fn-scoping bug fix: the name is INLINED (no bound `fn` kwarg, which jfx_bridge would
    put in eval-locals where the nested lambda can't see it), and the resolved function is passed
    as a bound lambda PARAMETER. Returns (resolved_name, pseudocode)."""
    from hexgraph.engine.ghidra_bridge import _RemoteOps

    b = _FakeBridge(lambda expr, kw: ("check_password", "bool check_password(char *p){return 0;}"))
    name, pseudo = _RemoteOps(b)._decompile_one("check_password")

    assert name == "check_password" and "check_password" in pseudo
    expr, kwargs = b.calls[-1]
    assert kwargs == {}                       # NO bound fn= kwarg (the bug that broke every call)
    assert '"check_password"' in expr         # the validated name is inlined as a string literal
    assert "==fn]" not in expr                # not the old free-variable-in-lambda form
    assert "lambda di, fn:" in expr           # the function is a bound lambda parameter


def test_remote_decompile_one_address_resolves_containing_function():
    """An address focus resolves to the function CONTAINING it (analyze-at-address), so
    decompile_at works over the bridge — not just decompile_function by name."""
    from hexgraph.engine.ghidra_bridge import _RemoteOps

    b = _FakeBridge(lambda expr, kw: ("cmd_exec", "void cmd_exec(void){}"))
    name, _pseudo = _RemoteOps(b)._decompile_one("0x40132c")

    expr, kwargs = b.calls[-1]
    assert kwargs == {}
    assert "getFunctionContaining" in expr and '"0x40132c"' in expr
    assert "getFunctions(True)" not in expr   # the name-match path is NOT used for an address
    assert name == "cmd_exec"


def test_remote_decompile_focus_none_when_not_found():
    """A focus the live program doesn't have (the eval returns the ('', '') sentinel) yields no
    focus rather than a crash — mirrors the headless probe's not-found behavior."""
    from hexgraph.engine.ghidra_bridge import _RemoteOps

    def responder(expr, _kw):
        return ("", "") if "lambda di, fn" in expr else ["main", "helper"]

    out = _RemoteOps(_FakeBridge(responder)).decompile(None, "ghost")
    assert out["focus"] is None
    assert out["functions"] == ["main", "helper"] and out["tool"] == "ghidra_bridge"


def test_remote_decompile_one_rejects_unsafe_focus():
    from hexgraph.engine.ghidra_bridge import BridgeUnavailable, _RemoteOps

    b = _FakeBridge(lambda e, k: None)
    try:
        _RemoteOps(b)._decompile_one('evil"; __import__("os").system("x")')
        assert False, "expected BridgeUnavailable"
    except BridgeUnavailable:
        pass
    assert b.calls == []   # an unsafe focus never reaches the bridge


def test_remote_list_programs_falls_back_to_current_program_when_headless():
    """The GUI-only ProgramManager service is absent under a headless bridge server; list_programs
    must fall back to the single active currentProgram instead of erroring."""
    from hexgraph.engine.ghidra_bridge import _RemoteOps

    def responder(expr, _kw):
        if "getService" in expr:   # the GUI path errors under a headless server
            raise RuntimeError("no ProgramManager service (headless)")
        return [("authd", "/work/authd", "x86:LE:64:default", 12)]

    progs = _RemoteOps(_FakeBridge(responder)).list_programs()
    assert progs == [{"name": "authd", "path": "/work/authd",
                      "language": "x86:LE:64:default", "functions": 12}]


def test_bridge_smoke_decompile_reflects_real_decompile(monkeypatch):
    """check_ghidra's honest health: the smoke decompile reports ok only when a real decompile
    succeeds — a socket check alone would report green while decompilation throws."""
    from hexgraph.engine import ghidra as G

    monkeypatch.setattr("hexgraph.engine.ghidra_bridge.connect_ops", lambda host, port: FakeOps())
    ok, _detail, fn = G._bridge_smoke_decompile("127.0.0.1", 4768)
    assert ok and fn == "main"

    class _BrokenOps:
        def decompile(self, program, function):
            if function is None:
                return {"functions": ["main"], "focus": None, "tool": "ghidra_bridge"}
            raise RuntimeError("NameError: global name 'fn' is not defined")

    monkeypatch.setattr("hexgraph.engine.ghidra_bridge.connect_ops", lambda host, port: _BrokenOps())
    ok, detail, fn = G._bridge_smoke_decompile("127.0.0.1", 4768)
    assert not ok and "NameError" in detail and fn is None
