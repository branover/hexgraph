"""Raw-range disassembly (dogfood F16): read the bytes at a CFG blind spot both backends miss.

When NO function is defined at an address, `re_disassemble(0xADDR)` / `re_decompile_at(0xADDR)`
both return "not found" — exactly where you most need instruction-level sight. `re_disassemble_range`
disassembles a raw ADDRESS + LENGTH byte range with no function required, via radare2 `pD`/`pd` in
the sandbox probe.

Offline + mock: the real disassembly needs the sandbox image, so these monkeypatch the
`R2Decompiler` seam (the same way test_address_access stubs it for the by-address disassemble) — the
unit under test is the HOST-side logic (arg handling, the probe-arg shape, the QUERY/no-mutation
contract, the clip/truncation marker, the not-found path) plus the probe/seam pure helpers, NOT a
real r2 pass. Verified offline-safe with a bogus sandbox image.
"""

import json

import pytest

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import SANDBOX_READY, fixture_path


def _ctx(s):
    p = create_project(s, name="disrange")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


class _FakeR2:
    """Records how disassemble_range was called and returns a fixed probe `range` payload."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def disassemble_range(self, artifact, address, *, length=None, count=None):
        self.calls.append({"address": address, "length": length, "count": count})
        return {"tool": "decompile_probe", "range": self.payload}


def _wire(monkeypatch, fake):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.R2Decompiler", lambda *a, **k: fake)


# --- the core path: disassemble a raw range, QUERY only (no graph mutation) ---------------

def test_range_disassembles_and_records_no_mutation(hg_home, monkeypatch):
    disasm = "0x67158  push rbp\n0x67159  mov rbp, rsp\n0x6715c  ret"
    fake = _FakeR2({"address": "0x67158", "length": 256, "disasm": disasm})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = run_tool(ctx, "disassemble_range", {"address": "0x67158"})

        assert "push rbp" in out and "0x67158" in out
        # the host routed BY ADDRESS with no length/count → probe applies its default
        assert fake.calls[-1] == {"address": "0x67158", "length": None, "count": None}
        # QUERY: no graph mutation
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb
        # ...recorded as a discoverable disassembly Observation keyed to the address + bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.tool == "disassemble_range").all()
        assert len(obs) == 1 and obs[0].result_kind == "disassembly"
        assert (obs[0].args_json or {}).get("address") == "0x67158"
        assert obs[0].content_hash == "abc123"


def test_range_passes_length_through_to_probe(hg_home, monkeypatch):
    fake = _FakeR2({"address": "0x1000", "length": 64, "disasm": "0x1000  nop"})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "disassemble_range", {"address": "0x1000", "length": 64})
        assert "nop" in out
        assert fake.calls[-1] == {"address": "0x1000", "length": 64, "count": None}
        # the length is echoed onto the Observation args for discoverability
        obs = s.query(Observation).filter(Observation.tool == "disassemble_range").one()
        assert (obs.args_json or {}).get("length") == 64


def test_range_count_overrides_length(hg_home, monkeypatch):
    fake = _FakeR2({"address": "0x1000", "count": 5, "disasm": "0x1000  nop\n0x1001  nop"})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "disassemble_range", {"address": "0x1000", "length": 999, "count": 5})
        # count wins → length is NOT forwarded
        assert fake.calls[-1] == {"address": "0x1000", "length": 999, "count": 5}
        assert "5 instructions" in out
        obs = s.query(Observation).filter(Observation.tool == "disassemble_range").one()
        # the Observation args reflect count (the mode actually used), not length
        assert (obs.args_json or {}).get("count") == 5
        assert "length" not in (obs.args_json or {})


# --- guard rails: a bad address never reaches the probe -----------------------------------

def test_range_requires_address(hg_home):
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        assert "required" in run_tool(ctx, "disassemble_range", {})


def test_range_rejects_non_hex_address(hg_home, monkeypatch):
    # an injection attempt / a bare name is not a hex address → refused host-side, no probe call
    fake = _FakeR2({"disasm": "should not be reached"})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        for bad in ("system", "0x67158; !sh", "0x1000 && rm -rf /", "deadbeef"):
            out = run_tool(ctx, "disassemble_range", {"address": bad})
            assert "invalid address" in out
        assert fake.calls == []  # never round-tripped to the probe


# --- not-found / unmapped: record the miss, mutate no graph ------------------------------

def test_range_no_disasm_records_miss(hg_home, monkeypatch):
    fake = _FakeR2({"address": "0xdeadbeef", "length": 256,
                    "error": "no disassembly at this address (out of range, or not mapped)"})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        nb = s.query(Node).count()
        out = run_tool(ctx, "disassemble_range", {"address": "0xdeadbeef"})
        assert "no disassembly" in out and "0xdeadbeef" in out
        assert s.query(Node).count() == nb  # QUERY: no mutation even on a miss
        obs = s.query(Observation).filter(Observation.tool == "disassemble_range").all()
        assert len(obs) == 1 and obs[0].result_kind == "disassembly"


# --- truncation is recoverable, never silent --------------------------------------------

def test_range_long_body_truncates_with_actionable_marker(hg_home, monkeypatch):
    big = "\n".join(f"0x{0x1000+i:04x}  nop" for i in range(2000))  # well over the default cap
    fake = _FakeR2({"address": "0x1000", "length": 8192, "disasm": big})
    _wire(monkeypatch, fake)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        out = run_tool(ctx, "disassemble_range", {"address": "0x1000", "max_chars": 500})
        assert "truncated" in out
        # the marker names BOTH recovery paths (bigger max_chars / obs_get the full body)
        assert "max_chars" in out and ("obs_get" in out or "get_observation" in out)
        # ...and the full body lives in the Observation, uncapped
        obs = s.query(Observation).filter(Observation.tool == "disassemble_range").one()
        assert obs.result_kind == "disassembly"


def test_range_unavailable_when_docker_down(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "disassemble_range", {"address": "0x1000"})
        assert "unavailable" in out


# --- probe + seam pure helpers (no sandbox) ----------------------------------------------

def test_seam_range_args_builds_probe_argv():
    from hexgraph.sandbox.decompiler import _range_args

    assert _range_args("0x1000", None, None) == ["--range", "0x1000"]
    assert _range_args("0x1000", 256, None) == ["--range", "0x1000", "--length", "256"]
    assert _range_args("0x1000", None, 10) == ["--range", "0x1000", "--count", "10"]
    # count wins when both are (defensively) supplied
    assert _range_args("0x1000", 256, 10) == ["--range", "0x1000", "--count", "10"]


def test_probe_disassemble_range_byte_and_count_modes():
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def __init__(self):
            self.cmds = []

        def cmd(self, c):
            self.cmds.append(c)
            return "0x1000  nop\n0x1001  nop"

    # byte mode → `pD <length> @ addr`
    r2 = _R2()
    out = DP._disassemble_range(r2, "0x1000", length=64, count=None)
    assert r2.cmds == ["pD 64 @ 0x1000"]
    assert out["length"] == 64 and "disasm" in out and "error" not in out

    # instruction mode → `pd <count> @ addr` (count wins)
    r2 = _R2()
    out = DP._disassemble_range(r2, "0x1000", length=999, count=5)
    assert r2.cmds == ["pd 5 @ 0x1000"]
    assert out["count"] == 5

    # default length when neither given
    r2 = _R2()
    out = DP._disassemble_range(r2, "0x2000", length=None, count=None)
    assert r2.cmds == [f"pD {DP._RANGE_DEFAULT_LENGTH} @ 0x2000"]


def test_probe_disassemble_range_clamps_bounds():
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def __init__(self):
            self.cmds = []

        def cmd(self, c):
            self.cmds.append(c)
            return "x"

    r2 = _R2()
    DP._disassemble_range(r2, "0x1000", length=10_000_000, count=None)  # over the byte ceiling
    assert r2.cmds == [f"pD {DP._RANGE_MAX_LENGTH} @ 0x1000"]

    r2 = _R2()
    DP._disassemble_range(r2, "0x1000", length=None, count=10_000_000)  # over the insn ceiling
    assert r2.cmds == [f"pd {DP._RANGE_MAX_COUNT} @ 0x1000"]

    r2 = _R2()
    DP._disassemble_range(r2, "0x1000", length=0, count=None)  # floor at 1
    assert r2.cmds == ["pD 1 @ 0x1000"]


def test_probe_disassemble_range_empty_is_error():
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def cmd(self, c):
            return "   "  # r2 produced nothing (out of range / unmapped)

    out = DP._disassemble_range(_R2(), "0xdeadbeef", length=256, count=None)
    assert "error" in out and "disasm" not in out


def test_probe_parse_int_accepts_dec_and_hex():
    from hexgraph.sandbox.probes import decompile_probe as DP

    assert DP._parse_int("256") == 256
    assert DP._parse_int("0x100") == 256
    assert DP._parse_int(None) is None
    assert DP._parse_int("not-a-number") is None


def test_probe_range_argv_keeps_address_off_positionals():
    """`--range <addr>` must NOT be parsed as a focus positional — otherwise a range request
    would also trigger the function-focus path. The address rides the flag value."""
    from hexgraph.sandbox.probes import decompile_probe as DP

    rest = ["--range", "0x67158", "--length", "256"]
    assert DP._flag_value(rest, "--range") == "0x67158"
    assert DP._flag_value(rest, "--length") == "256"
    # a dangling flag (no value) is tolerated, not an index error
    assert DP._flag_value(["--range"], "--range") is None


# --- targeted disassembly (re_disassemble): one-function `af` + `pdf`, NEVER whole-binary aaa ----
# `re_disassemble` used to borrow the decompiler pipeline (whole-binary `aaa` + a discarded `pdc`),
# which could run for HOURS on a large binary. The targeted path analyzes ONLY the one function at
# the subject (`af`) and disassembles it, falling back to a raw linear read at an address.

def test_seam_disassemble_func_builds_probe_argv():
    from hexgraph.sandbox.decompiler import R2Decompiler

    class _Runner:
        def __init__(self):
            self.calls = []

        def run_json_probe(self, probe, artifact, *, extra_args=None, **kw):
            self.calls.append((probe, list(extra_args or [])))
            return {"tool": "decompile_probe", "mode": "disasm", "focus": None}

    run = _Runner()
    R2Decompiler(runner=run).disassemble_func("/artifact", "cgi_handler")
    assert run.calls == [("decompile_probe.py", ["--disasm", "cgi_handler"])]


def test_probe_resolve_disasm_seek():
    """A hex address is used as-is; a name resolves against r2's already-loaded flag table (symbols/
    imports are known on OPEN, no aaa); an unresolvable/unsafe name is refused."""
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def __init__(self, flags):
            self._flags = flags

        def cmd(self, c):
            return json.dumps([{"name": n} for n in self._flags]) if c == "fj" else ""

    assert DP._resolve_disasm_seek(_R2([]), "0x401200") == ("0x401200", True)
    r2 = _R2(["sym.cgi_handler", "sym.imp.strcpy"])
    assert DP._resolve_disasm_seek(r2, "cgi_handler") == ("sym.cgi_handler", False)
    assert DP._resolve_disasm_seek(r2, "strcpy") == ("sym.imp.strcpy", False)  # import candidate
    assert DP._resolve_disasm_seek(_R2(["sym.other"]), "ghost") == (None, False)  # not without aaa
    assert DP._resolve_disasm_seek(_R2([]), "bad; name") == (None, False)  # unsafe → refused


def test_probe_targeted_disasm_uses_af_never_aaa():
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def __init__(self):
            self.cmds = []

        def cmd(self, c):
            self.cmds.append(c)
            if c.startswith("pdf"):
                return "0x401200  push rbp\n0x401201  call sym.imp.strcpy"
            if c.startswith("afij"):
                return json.dumps([{"name": "sym.cgi_handler", "offset": 0x401200}])
            return ""  # afvj etc.

    r2 = _R2()
    focus = DP._targeted_disasm(r2, "0x401200", True)
    assert focus is not None and focus["disasm_mode"] == "function"
    assert focus["name"] == "sym.cgi_handler" and focus["address"] == "0x401200"
    assert "strcpy" in focus["callees"]
    # ONLY the single-function `af` ran — never a whole-binary aaa/aaaa.
    assert any(c.startswith("af @") for c in r2.cmds)
    assert not any(c.strip() in ("aaa", "aaaa") for c in r2.cmds)


def test_probe_targeted_disasm_linear_fallback_at_address():
    """No function at the address → a raw linear `pd` read, flagged disasm_mode='linear'."""
    from hexgraph.sandbox.probes import decompile_probe as DP

    class _R2:
        def cmd(self, c):
            if c.startswith("pdf"):
                return "   "                 # no function defined here
            if c.startswith("pd "):
                return "0x401337  nop\n0x401338  nop"  # raw linear works
            return ""

    focus = DP._targeted_disasm(_R2(), "0x401337", True)
    assert focus["disasm_mode"] == "linear" and "nop" in focus["disasm"]


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_targeted_disasm_end_to_end():
    """Real r2: disassemble cgi_handler by name via one-function `af` — NO whole-binary aaa — and
    recover its call to strcpy."""
    from hexgraph.sandbox.decompiler import R2Decompiler

    out = R2Decompiler().disassemble_func(fixture_path("vuln_httpd"), "cgi_handler")
    focus = out.get("focus") or {}
    assert focus.get("disasm_mode") == "function", out
    assert focus.get("disasm"), out
    assert "strcpy" in (focus.get("callees") or []), out  # cgi_handler calls strcpy
