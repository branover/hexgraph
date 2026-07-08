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
        L._serve_one(server, _FakeProgram(["a", "b"]), None, lambda: None)
        resp = json.loads(client.makefile("rb").readline())
        assert resp["functions_total"] == 2
    finally:
        client.close()
        server.close()


def test_serve_one_bad_json_is_a_structured_error():
    client, server = socket.socketpair()
    try:
        client.sendall(b"not json\n")
        L._serve_one(server, _FakeProgram([]), None, lambda: None)
        resp = json.loads(client.makefile("rb").readline())
        assert resp["error"] == "bad request json"
    finally:
        client.close()
        server.close()


def test_serve_one_mints_a_fresh_monitor_per_request(monkeypatch):
    """Regression: the resident bridge must hand each request its OWN TaskMonitor.

    Ghidra's DecompInterface.decompileFunction(f, timeout, monitor) cancels the monitor it's given
    on a per-function timeout, and a ConsoleTaskMonitor stays cancelled — so one slow function under
    a SHARED monitor poisoned every later decompile into an empty body. _serve_one must call the
    make_monitor factory once per request and dispatch with that fresh instance, never a reused one."""
    captured = []
    monkeypatch.setattr(
        L, "bridge_dispatch",
        lambda program, flat, monitor, req: (captured.append(monitor) or {"ok": True}))
    minted = []

    def make_monitor():
        m = object()
        minted.append(m)
        return m

    for _ in range(3):
        client, server = socket.socketpair()
        try:
            client.sendall(b'{"op": "ping"}\n')
            L._serve_one(server, _FakeProgram([]), None, make_monitor)
        finally:
            client.close()
            server.close()

    assert len(minted) == 3               # a fresh monitor was minted for every request
    assert captured == minted             # each request dispatched with its own freshly-minted monitor
    assert len({id(m) for m in captured}) == 3  # …and never the same instance twice (no cross-request leak)


# ── decompiler lifecycle: the resident bridge must DISPOSE each DecompInterface ─────────────
# A DecompInterface spawns a native `decompile` subprocess + I/O threads; leaking one per request
# on the long-lived bridge exhausts threads (pthread_create EAGAIN) until decompiles return empty
# bodies. _focus_facts imports DecompInterface locally, so a fake ghidra module makes the
# otherwise Ghidra-only path exercisable offline.

class _FakeDf:
    def getC(self):
        return "int f(void) { return 0; }"

    def getSignature(self):
        return "int f(void)"


class _FakeRes:
    def decompileCompleted(self):
        return True

    def getDecompiledFunction(self):
        return _FakeDf()

    def getHighFunction(self):
        return None


class _FakeDeci:
    def __init__(self, on_decompile=None, on_open=None):
        self.opened = self.disposed = 0
        self._on_decompile = on_decompile
        self._on_open = on_open

    def openProgram(self, program):
        self.opened += 1
        if self._on_open is not None:
            self._on_open()

    def decompileFunction(self, target, secs, monitor):
        return self._on_decompile() if self._on_decompile is not None else _FakeRes()

    def dispose(self):
        self.disposed += 1


class _FakeAddr:
    def toString(self):
        return "100000"


class _FakeSig:
    def getPrototypeString(self):
        return "int f(void)"


class _FakeTarget:
    def __init__(self, name="f"):
        self._name = name

    def getName(self):
        return self._name

    def getCalledFunctions(self, monitor):
        return []

    def getEntryPoint(self):
        return _FakeAddr()

    def getSignature(self):
        return _FakeSig()

    def getCallingConventionName(self):
        return "default"

    def getParameters(self):
        return []

    def getLocalVariables(self):
        return []


def _install_fake_ghidra_decompiler(monkeypatch, deci):
    """Route _focus_facts's local `from ghidra.app.decompiler import DecompInterface` to a fake
    yielding `deci`, so the Ghidra-only decompile path runs offline."""
    import sys
    import types

    for name in ("ghidra", "ghidra.app", "ghidra.app.decompiler"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ghidra.app.decompiler"].DecompInterface = lambda: deci


def test_focus_facts_disposes_the_decompiler(monkeypatch):
    """Regression: every decompile must tear down its native decompiler subprocess, not leak it."""
    deci = _FakeDeci()
    _install_fake_ghidra_decompiler(monkeypatch, deci)
    focus = L._focus_facts(object(), _FakeTarget("f"), None)
    assert focus["pseudocode"] == "int f(void) { return 0; }"  # the body still comes back…
    assert deci.disposed == 1                                   # …and the interface is disposed, not leaked


def test_focus_facts_disposes_even_when_decompile_raises(monkeypatch):
    """The dispose is in a finally, so a failing decompile (e.g. the subprocess can't start under
    thread exhaustion) still frees the interface instead of leaking on the error path."""
    def _boom():
        raise RuntimeError("decompiler process could not start")

    deci = _FakeDeci(on_decompile=_boom)
    _install_fake_ghidra_decompiler(monkeypatch, deci)
    with pytest.raises(RuntimeError):
        L._focus_facts(object(), _FakeTarget("f"), None)
    assert deci.disposed == 1  # freed via finally even when decompilation raised


_PCODE_OPS = (
    "COPY CAST INT_ADD INT_SUB INT_AND INT_OR INT_XOR INT_MULT INT_ZEXT INT_SEXT INT_2COMP "
    "INT_NEGATE INT_LEFT INT_RIGHT INT_SRIGHT INT_DIV INT_REM SUBPIECE PIECE PTRADD PTRSUB "
    "MULTIEQUAL INDIRECT LOAD"
).split()


class _FakeEmptyFM:
    def getFunctions(self, _ordered):
        return []


class _FakeTaintProgram:
    def getFunctionManager(self):
        return _FakeEmptyFM()


def _install_fake_ghidra_taint(monkeypatch, deci):
    """Fake the java/ghidra modules taint_core imports (DecompInterface, PcodeOp opcodes, System) so
    the Ghidra-only taint core runs offline with no candidates."""
    import sys
    import types

    for name in ("ghidra", "ghidra.app", "ghidra.app.decompiler", "ghidra.program",
                 "ghidra.program.model", "ghidra.program.model.pcode", "java", "java.lang"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    sys.modules["ghidra.app.decompiler"].DecompInterface = lambda: deci
    pcode = type("PcodeOp", (), {op: i + 1 for i, op in enumerate(_PCODE_OPS)})
    sys.modules["ghidra.program.model.pcode"].PcodeOp = pcode
    sys.modules["java.lang"].System = type("System", (), {"identityHashCode": staticmethod(id)})


def test_taint_core_disposes_the_decompiler(monkeypatch):
    """taint_core reuses ONE DecompInterface across its whole run; it must dispose it (here with no
    candidates, so the interface is opened then freed)."""
    deci = _FakeDeci()
    _install_fake_ghidra_taint(monkeypatch, deci)
    out = L.taint_core(_FakeTaintProgram(), object(), None)
    assert out["taint"]["analyzed"] == 0
    assert deci.disposed == 1


def test_taint_core_disposes_even_when_it_raises(monkeypatch):
    """Regression for the finding: the taint dispose must be in a finally, so a failure inside the
    try (raw Java in the candidate loop can raise) still frees the interface. Pre-fix the dispose was
    a bare pre-return statement, skipped on the error path."""
    def _boom():
        raise RuntimeError("openProgram failed")

    deci = _FakeDeci(on_open=_boom)
    _install_fake_ghidra_taint(monkeypatch, deci)
    with pytest.raises(RuntimeError):
        L.taint_core(_FakeTaintProgram(), object(), None)
    assert deci.disposed == 1  # freed via finally even though the try raised


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
    assert L._search_patterns(_EndianProgram(), None, "-1") is None       # negative: matches r2 _IMM
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
