"""re_resolve triages a hex ADDRESS -> {nearest_symbol+offset, section, containing_function} WITHOUT
a decompile.

Assembled in the SANDBOX: radare2's section table (`iSj`) + sized symbol table (`isj`) via
`R2Decompiler.resolve_layout`, computed host-side by `elf_layout.section_of` /
`nearest_and_containing` — so the hostile ELF is parsed in the sandbox, never the host process.
PARTIAL by design — a STRIPPED FUN_* has no symbol-table entry, so containing_function is None and
only section + nearest come back; when Docker/the sandbox is down it DEGRADES to a symbols-only
nearest over the binutils facts.symbols index. Records an address_resolve Observation, mutates no
graph.

Layers, mirroring test_re_hexdump:
  * UNIT — `section_of` / `nearest_and_containing` over SYNTHETIC tables (pure host-side compute).
  * TOOL — the assembly in `_resolve_address` with `R2Decompiler.resolve_layout` mocked (no Docker),
    the bad-address guard, and the sandbox-down degrade.
  * INTEGRATION — one non-mocked resolve over tests/fixtures/vuln_httpd through the real sandbox,
    guarded by SANDBOX_READY.
"""

import pytest

import hexgraph.agent.agent_tools as AT
import hexgraph.engine.re.elf_layout as EL
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import SANDBOX_READY, fixture_path


def _ctx(s):
    p = create_project(s, name="resolve")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "rv123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


# A synthetic value-sorted symbol table: two FUNCs with size, one data OBJECT, one size-0 stub.
_SYMS = [
    {"name": "start", "value": 0x1000, "size": 0x0, "is_func": True},     # size-0 stub (can't contain)
    {"name": "parse", "value": 0x1100, "size": 0x80, "is_func": True},    # FUNC [0x1100,0x1180)
    {"name": "handle", "value": 0x1200, "size": 0x40, "is_func": True},   # FUNC [0x1200,0x1240)
    {"name": "table", "value": 0x4000, "size": 0x20, "is_func": False},   # data OBJECT [0x4000,0x4020)
]


# --- UNIT: nearest-symbol + offset, containment, section lookup (pure compute) --------------

def test_nearest_symbol_and_offset_between_two_symbols():
    """An address between two symbols resolves to the LOWER one + the byte offset into it."""
    near, cont = EL.nearest_and_containing(_SYMS, 0x1130)
    assert near["name"] == "parse" and near["offset"] == 0x30
    assert cont["name"] == "parse" and cont["address"] == 0x1100 and cont["end"] == 0x1180


def test_containing_function_is_the_covering_func():
    near, cont = EL.nearest_and_containing(_SYMS, 0x1210)
    assert cont["name"] == "handle" and cont["size"] == 0x40


def test_address_past_a_function_has_no_containing_func():
    """An address in the gap AFTER a function (past parse's end) is not contained — nearest is
    still parse, but containing_function is None (no symbol's range covers it)."""
    near, cont = EL.nearest_and_containing(_SYMS, 0x1190)
    assert near["name"] == "parse"
    assert cont is None


def test_data_object_containment_is_reported():
    """An address inside a data OBJECT's range is contained by it (the non-FUNC fallback)."""
    near, cont = EL.nearest_and_containing(_SYMS, 0x4010)
    assert cont is not None and cont["name"] == "table"


def test_empty_symbol_table_returns_none():
    """A STRIPPED binary (no symbol entries) yields no nearest and no containing function."""
    near, cont = EL.nearest_and_containing([], 0x1130)
    assert near is None and cont is None


def test_section_lookup():
    """`section_of` returns the section whose [vaddr,vaddr+size) window contains the address."""
    secs = [{"name": ".text", "vaddr": 0x1000, "size": 0x500},
            {"name": ".data", "vaddr": 0x4000, "size": 0x100}]
    assert EL.section_of(secs, 0x1200) == ".text"
    assert EL.section_of(secs, 0x4050) == ".data"
    assert EL.section_of(secs, 0x9000) is None            # out of range -> None (gracefully)


# --- TOOL: the assembled answer over a mocked sandbox layout (no Docker) --------------------

def _mock_layout(monkeypatch, *, sections, symbols):
    """Patch the sandbox seam the tool uses: Docker is 'up' and R2Decompiler.resolve_layout returns
    the given section + symbol tables (the probe's {'layout': ...} envelope)."""
    from hexgraph.sandbox.decompiler import R2Decompiler

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr(
        R2Decompiler, "resolve_layout",
        lambda self, artifact: {"layout": {"sections": sections, "symbols": symbols}})


def test_resolve_assembles_all_three_fields(hg_home, monkeypatch):
    """re_resolve renders section + nearest_symbol+offset + containing_function bounds from the
    sandbox-sourced tables (the assembly + host-side compute is the unit under test)."""
    _mock_layout(monkeypatch,
                 sections=[{"name": ".text", "vaddr": 0x1000, "size": 0x500}],
                 symbols=[{"name": "parse", "value": 0x1100, "size": 0x80, "is_func": True}])
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1130"})
        assert "parse" in out
        assert "0x30" in out                               # the offset into it
        assert ".text" in out                              # the section
        assert "0x1100-0x1180" in out                      # the containing function bounds


def test_resolve_stripped_reports_section_and_nearest_only(hg_home, monkeypatch):
    """On a stripped binary the tables give a section + nearest symbol but NO covering FUNC — the
    PARTIAL case: containing_function is reported as unknown, not fabricated."""
    _mock_layout(monkeypatch,
                 sections=[{"name": ".text", "vaddr": 0x1000, "size": 0x500}],
                 symbols=[{"name": "dynsym_x", "value": 0x1000, "size": 0x0, "is_func": True}])
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1050"})
        assert "dynsym_x" in out and ".text" in out
        assert "unknown" in out.lower()                    # containing unknown (stripped FUN_)


def test_out_of_range_address_section_none_gracefully(hg_home, monkeypatch):
    """An address mapped to no section/symbol returns section=None + no nearest, not a crash."""
    _mock_layout(monkeypatch,
                 sections=[{"name": ".text", "vaddr": 0x1000, "size": 0x100}], symbols=[])
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x900000"})
        assert "not mapped" in out or "no section" in out
        assert "none" in out.lower()


def test_non_hex_address_is_a_friendly_error(hg_home):
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "not_an_addr"})
        assert "invalid address" in out


def test_degraded_when_sandbox_down(hg_home, monkeypatch):
    """With Docker/the sandbox down, re_resolve degrades to a nearest-symbol answer over the
    binutils facts.symbols index (name+addr only — no section/containment) rather than failing."""
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    # Stub the shared symbol index (its source is collect_binutils_facts, which needs the sandbox).
    monkeypatch.setattr(AT, "_symbol_index",
                        lambda ctx: [{"name": "parse", "address": 0x1100},
                                     {"name": "handle", "address": 0x1200}])
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1150"})
        assert "degraded" in out and "sandbox" in out.lower()
        assert "parse" in out and "0x50" in out            # nearest symbol + offset from the index
        assert "sandbox down" in out.lower()               # containing_function unavailable note


def test_records_observation_and_no_graph(hg_home, monkeypatch):
    _mock_layout(monkeypatch,
                 sections=[{"name": ".text", "vaddr": 0x1000, "size": 0x500}],
                 symbols=[{"name": "parse", "value": 0x1100, "size": 0x80, "is_func": True}])
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "resolve_address", {"address": "0x1130"})
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "address_resolve").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "rv123"


def test_resolve_is_not_analysis_gated():
    """re_resolve is the lightweight orientation tool — it must not require a saved analysis."""
    assert "resolve_address" not in AT._ANALYSIS_GATED_TOOLS


# --- INTEGRATION: a real ELF through the real sandbox (radare2 iSj/isj) --------------------

@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_integration_resolves_a_function_via_the_sandbox(hg_home):
    """Over the real vuln_httpd ELF, resolving an address inside cgi_handler reports section='.text'
    and cgi_handler as the nearest + containing symbol — end-to-end through the sandbox r2, and
    recovering the CONTAINING FUNCTION the binutils/nm degraded path (no sizes) cannot."""
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x4011a0"})   # inside cgi_handler
        assert ".text" in out
        assert "cgi_handler" in out
        assert "containing_function: cgi_handler" in out                  # the sized-symbol win
        # A .rodata address resolves its section, not a function.
        ctx.cache.clear()
        out2 = run_tool(ctx, "resolve_address", {"address": "0x402005"})
        assert ".rodata" in out2
        assert s.query(Node).count() == 0                                 # pure QUERY end to end
