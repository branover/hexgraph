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


def test_dispatch_xrefs_delegates_to_the_core(monkeypatch):
    seen = {}

    def _fake(program, flat, monitor, mode, subject):
        seen.update(mode=mode, subject=subject)
        return {"mode": mode, "callers": []}

    monkeypatch.setattr(L, "xrefs_core", _fake)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(),
                             {"op": "xrefs", "mode": "callers", "subject": "foo"})
    assert seen == {"mode": "callers", "subject": "foo"} and resp["mode"] == "callers"


def test_dispatch_taint_delegates_to_the_core(monkeypatch):
    monkeypatch.setattr(L, "taint_core", lambda p, f, m: {"taint": {"flows": [], "analyzed": 3}})
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(), {"op": "taint"})
    assert resp["taint"]["analyzed"] == 3


def test_dispatch_emulate_delegates_to_the_core(monkeypatch):
    seen = {}

    def _fake(program, flat, monitor, focus):
        seen["focus"] = focus
        return {"emulation": {"function": focus}}

    monkeypatch.setattr(L, "emulate_core", _fake)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(), {"op": "emulate", "focus": "keyfn"})
    assert seen["focus"] == "keyfn" and resp["emulation"]["function"] == "keyfn"


def test_dispatch_rename_delegates_to_decompile_core_with_rename(monkeypatch):
    seen = {}

    def _fake(program, flat, monitor, *, focus=None, rename=None):
        seen["rename"] = rename
        return {"functions": [], "focus": {"name": "renamed"}}

    monkeypatch.setattr(L, "decompile_core", _fake)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(),
                             {"op": "rename", "address": "0x1000", "new_name": "renamed"})
    assert seen["rename"] == ("0x1000", "renamed")
    assert resp["focus"] == {"name": "renamed"} and resp["tool"] == "ghidra_bridge"


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


def test_managed_ops_xrefs_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"mode": "callers", "callers": [], "total": 0})
    out = _ManagedOps("127.0.0.1", port).xrefs("callers", "foo")
    t.join(timeout=5)
    assert captured["req"] == {"op": "xrefs", "mode": "callers", "subject": "foo"}
    assert out["mode"] == "callers"


def test_managed_ops_taint_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"taint": {"flows": [], "analyzed": 5}})
    out = _ManagedOps("127.0.0.1", port).run_taint()
    t.join(timeout=5)
    assert captured["req"] == {"op": "taint"} and out["taint"]["analyzed"] == 5


def test_managed_ops_emulate_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"emulation": {"value": "0x2a", "reached_ret": True}})
    out = _ManagedOps("127.0.0.1", port).run_emulate("keyfn")
    t.join(timeout=5)
    assert captured["req"] == {"op": "emulate", "focus": "keyfn"}
    assert out["emulation"]["value"] == "0x2a"


def test_managed_ops_rename_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"focus": {"name": "renamed"}, "tool": "ghidra_bridge"})
    out = _ManagedOps("127.0.0.1", port).rename_function("0x1200", "renamed")
    t.join(timeout=5)
    assert captured["req"] == {"op": "rename", "address": "0x1200", "new_name": "renamed"}
    assert out["focus"]["name"] == "renamed"


def test_managed_ops_unreachable_raises_bridge_unavailable():
    from hexgraph.engine.re.ghidra_bridge import BridgeUnavailable, _ManagedOps

    # Port 1 is not listening -> connect refused -> a clean BridgeUnavailable (routing falls back).
    with pytest.raises(BridgeUnavailable):
        _ManagedOps("127.0.0.1", 1, timeout=1.0).decompile(None, "x")


# ── search: pattern encoding + dispatch + client ────────────────────────────────────────

class _FakeLang:
    def __init__(self, big):
        self._big = big

    def isBigEndian(self):
        return self._big


class _EndianProgram:
    def __init__(self, big=False):
        self._lang = _FakeLang(big)

    def getLanguage(self):
        return self._lang


def test_search_patterns_bytes_hex():
    resp = L._search_patterns(_EndianProgram(), "de ad be ef", None)  # whitespace tolerated
    assert resp == [bytes.fromhex("deadbeef")]


def test_search_patterns_immediate_both_widths_and_endianness():
    little = L._search_patterns(_EndianProgram(big=False), None, "0x41")
    assert little == [(0x41).to_bytes(4, "little"), (0x41).to_bytes(8, "little")]
    big = L._search_patterns(_EndianProgram(big=True), None, "255")
    assert big == [(255).to_bytes(4, "big"), (255).to_bytes(8, "big")]


def test_search_patterns_invalid_inputs():
    assert L._search_patterns(_EndianProgram(), "zz", None) is None       # bad hex
    assert L._search_patterns(_EndianProgram(), None, "notanum") is None  # bad immediate
    assert L._search_patterns(_EndianProgram(), None, None) is None       # neither given


def test_dispatch_search_delegates_to_the_core(monkeypatch):
    seen = {}

    def _fake(program, flat, monitor, *, bytes_pattern=None, immediate=None):
        seen.update(bytes_pattern=bytes_pattern, immediate=immediate)
        return {"mode": "search", "hits": [], "total": 0}

    monkeypatch.setattr(L, "search_bytes_core", _fake)
    resp = L.bridge_dispatch(_FakeProgram([]), object(), object(),
                             {"op": "search", "bytes_pattern": "deadbeef", "immediate": None})
    assert seen == {"bytes_pattern": "deadbeef", "immediate": None}
    assert resp["mode"] == "search"


def test_managed_ops_search_round_trip():
    from hexgraph.engine.re.ghidra_bridge import _ManagedOps

    port, captured, t = _one_shot_server({"mode": "search", "kind": "bytes", "total": 1,
                                          "hits": [{"addr": "0x1000", "in_function": "main"}]})
    out = _ManagedOps("127.0.0.1", port).search_bytes("deadbeef", None)
    t.join(timeout=5)
    assert captured["req"] == {"op": "search", "bytes_pattern": "deadbeef", "immediate": None}
    assert out["total"] == 1 and out["hits"][0]["in_function"] == "main"
