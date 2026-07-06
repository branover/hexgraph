"""The managed Ghidra bridge's transport — offline, no Ghidra.

Since the PyGhidra re-platform the managed bridge (engine.re.bridge) is a resident pyghidra process
serving a small line-delimited JSON RPC (pyghidra_lib.serve_bridge / bridge_dispatch) that the host
drives via engine.re.ghidra_bridge._ManagedOps — replacing the Jython analyzeHeadless + jfx_bridge
harness. These pin the wire protocol both ways with a fake program + a one-shot loopback server, so a
protocol break is caught without a container. The Ghidra-touching ops (decompile core) are exercised
end-to-end in the WITH_GHIDRA lane."""

from __future__ import annotations

import json
import socket
import threading

import pytest

from hexgraph.sandbox.probes import pyghidra_lib as L


class _FakeFn:
    def __init__(self, name):
        self._n = name

    def getName(self):
        return self._n


class _FakeFM:
    def __init__(self, names):
        self._names = names

    def getFunctionCount(self):
        return len(self._names)

    def getFunctions(self, _ordered):
        return [_FakeFn(n) for n in self._names]


class _FakeProgram:
    def __init__(self, names):
        self._fm = _FakeFM(names)

    def getFunctionManager(self):
        return self._fm


# ── server: bridge_dispatch maps a request to a core over the resident program ──────────

def test_dispatch_ping_reports_liveness_and_count():
    resp = L.bridge_dispatch(_FakeProgram(["a", "b", "c"]), None, None, {"op": "ping"})
    assert resp == {"ok": True, "functions_total": 3}


def test_dispatch_list_returns_function_inventory():
    resp = L.bridge_dispatch(_FakeProgram(["f1", "f2"]), None, None, {"op": "list"})
    assert resp["functions"] == ["f1", "f2"] and resp["tool"] == "ghidra_bridge"


def test_dispatch_decompile_delegates_to_the_core(monkeypatch):
    seen = {}

    def _fake_core(program, flat, monitor, *, focus=None, rename=None):
        seen["focus"] = focus
        return {"functions": ["x"], "focus": {"name": "x"}}

    monkeypatch.setattr(L, "decompile_core", _fake_core)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(), {"op": "decompile", "focus": "x"})
    assert seen["focus"] == "x"
    assert resp["focus"] == {"name": "x"} and resp["tool"] == "ghidra_bridge"


def test_dispatch_unknown_op_is_a_structured_error():
    resp = L.bridge_dispatch(_FakeProgram([]), None, None, {"op": "nope"})
    assert "unknown bridge op" in resp["error"]


def test_dispatch_never_raises_wraps_core_faults(monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(L, "decompile_core", _boom)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(), {"op": "decompile"})
    assert "kaboom" in resp["error"] and "tb" in resp  # one bad request never kills the server


def test_serve_one_round_trips_over_a_socket():
    """_serve_one reads one JSON request line + writes one JSON response line."""
    client, server = socket.socketpair()
    try:
        client.sendall(json.dumps({"op": "ping"}).encode() + b"\n")
        L._serve_one(server, _FakeProgram(["a", "b"]), None, None)
        resp = json.loads(client.makefile("rb").readline())
        assert resp["functions_total"] == 2
    finally:
        client.close()
        server.close()


def test_serve_one_bad_json_is_a_structured_error():
    client, server = socket.socketpair()
    try:
        client.sendall(b"not json\n")
        L._serve_one(server, _FakeProgram([]), None, None)
        resp = json.loads(client.makefile("rb").readline())
        assert resp["error"] == "bad request json"
    finally:
        client.close()
        server.close()


# ── client: _ManagedOps speaks the same protocol ───────────────────────────────────────

def _one_shot_server(response: dict):
    """A loopback server that accepts one connection, reads the request line, and replies once."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    captured: dict = {}

    def serve():
        conn, _ = srv.accept()
        try:
            captured["req"] = json.loads(conn.makefile("rb").readline())
            conn.sendall((json.dumps(response) + "\n").encode())
        finally:
            conn.close()
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return port, captured, t


def test_managed_ops_decompile_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server(
        {"functions": ["f1", "f2"], "focus": {"name": "f1"}, "tool": "ghidra_bridge"})
    out = _ManagedOps("127.0.0.1", port).decompile(None, "f1")
    t.join(timeout=5)
    assert captured["req"] == {"op": "decompile", "focus": "f1"}   # client sent the right request
    assert out["functions"] == ["f1", "f2"] and out["focus"] == {"name": "f1"}
    assert out["tool"] == "ghidra_bridge"


def test_managed_ops_error_response_reads_as_no_focus():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, _cap, t = _one_shot_server({"error": "not found", "functions": ["f1"]})
    out = _ManagedOps("127.0.0.1", port).decompile(None, "missing")
    t.join(timeout=5)
    assert out["focus"] is None and out["functions"] == ["f1"]     # mirrors the headless not-found


def test_managed_ops_list_programs_via_ping():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"ok": True, "functions_total": 7})
    rows = _ManagedOps("127.0.0.1", port).list_programs()
    t.join(timeout=5)
    assert captured["req"] == {"op": "ping"} and rows[0]["functions"] == 7


def test_managed_ops_unreachable_raises_bridge_unavailable():
    from hexgraph.engine.re.ghidra_bridge import BridgeUnavailable, _ManagedOps

    # Port 1 is not listening -> connect refused -> a clean BridgeUnavailable (routing falls back).
    with pytest.raises(BridgeUnavailable):
        _ManagedOps("127.0.0.1", 1, timeout=1.0).decompile(None, "x")
