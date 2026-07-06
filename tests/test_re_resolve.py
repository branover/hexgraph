"""re_resolve triages a hex ADDRESS -> {nearest_symbol+offset, section, containing_function} WITHOUT
a decompile.

The cheap crash-addr / pointer / DAT_ orientation before spending a re_decompile_at. Assembled
server-side from the on-disk ELF via pyelftools (`elf_layout.resolve_layout`): the section a vaddr
falls in + section ranges, the nearest defined symbol at-or-below the address, and the containing
FUNC when the symbol table knows it. PARTIAL by design — a STRIPPED FUN_* has no symtab entry, so
containing_function is None and only section + nearest come back; and when pyelftools isn't
installed (probe-only per pyproject) it DEGRADES to a symbols-only nearest over binutils
facts.symbols. Records an address_resolve Observation, mutates no graph.

Layers, mirroring test_re_symbol / test_re_hexdump:
  * UNIT — `_nearest_and_containing` over a SYNTHETIC sorted symbol table (nearest+offset,
    containment, FUNC-vs-data, stripped->None), the assembly in `_resolve_address` with
    `resolve_layout` stubbed, the bad-address guard, and the degraded (no-pyelftools) fallback.
  * INTEGRATION — one non-mocked resolve over tests/fixtures/vuln_httpd, guarded by
    importorskip('elftools').
"""

import pytest

import hexgraph.agent.agent_tools as AT
import hexgraph.engine.re.elf_layout as EL
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="resolve")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "rv123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


# A synthetic address-sorted symbol table: two FUNCs with size, one data OBJECT, one size-0 stub.
_SYMS = [
    {"name": "start", "value": 0x1000, "size": 0x0, "is_func": True},     # size-0 stub (can't contain)
    {"name": "parse", "value": 0x1100, "size": 0x80, "is_func": True},    # FUNC [0x1100,0x1180)
    {"name": "handle", "value": 0x1200, "size": 0x40, "is_func": True},   # FUNC [0x1200,0x1240)
    {"name": "table", "value": 0x4000, "size": 0x20, "is_func": False},   # data OBJECT [0x4000,0x4020)
]


# --- UNIT: nearest-symbol + offset, and containment -----------------------------------------

def test_nearest_symbol_and_offset_between_two_symbols():
    """An address between two symbols resolves to the LOWER one + the byte offset into it."""
    near, cont = EL._nearest_and_containing(_SYMS, 0x1130)
    assert near["name"] == "parse" and near["offset"] == 0x30
    # 0x1130 is inside parse's [0x1100,0x1180) FUNC range -> containing_function is parse
    assert cont["name"] == "parse" and cont["address"] == 0x1100 and cont["end"] == 0x1180


def test_containing_function_is_the_covering_func():
    near, cont = EL._nearest_and_containing(_SYMS, 0x1210)
    assert cont["name"] == "handle" and cont["size"] == 0x40


def test_address_past_a_function_has_no_containing_func():
    """An address in the gap AFTER a function (0x1180, just past parse's end) is not contained —
    nearest is still parse, but containing_function is None (no symbol's range covers it)."""
    near, cont = EL._nearest_and_containing(_SYMS, 0x1190)
    assert near["name"] == "parse"
    assert cont is None


def test_data_object_containment_is_reported():
    """An address inside a data OBJECT's range is contained by it (the non-FUNC fallback)."""
    near, cont = EL._nearest_and_containing(_SYMS, 0x4010)
    assert cont is not None and cont["name"] == "table"


def test_empty_symbol_table_returns_none():
    """A STRIPPED binary (no symtab entries) yields no nearest and no containing function."""
    near, cont = EL._nearest_and_containing([], 0x1130)
    assert near is None and cont is None


def test_section_lookup():
    """`_section_of` returns the section whose [vaddr,vaddr+size) window contains the address."""
    secs = [{"name": ".text", "vaddr": 0x1000, "size": 0x500, "nobits": False},
            {"name": ".data", "vaddr": 0x4000, "size": 0x100, "nobits": False}]
    assert EL._section_of(secs, 0x1200) == ".text"
    assert EL._section_of(secs, 0x4050) == ".data"
    assert EL._section_of(secs, 0x9000) is None            # out of range -> None (gracefully)


# --- the assembled answer (resolve_layout stubbed) ----------------------------------------

def test_resolve_assembles_all_three_fields(hg_home, monkeypatch):
    """re_resolve renders the section + nearest_symbol+offset + containing_function bounds from
    the layout the ELF read produced (stubbed here so the assembly is the unit under test)."""
    monkeypatch.setattr(EL, "resolve_layout", lambda path, vaddr: {
        "section": ".text",
        "nearest_symbol": {"name": "parse", "address": 0x1100, "offset": 0x30},
        "containing_function": {"name": "parse", "address": 0x1100, "size": 0x80, "end": 0x1180},
        "n_symbols": 4})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1130"})
        assert "parse" in out
        assert "0x30" in out                               # the offset into it
        assert ".text" in out                              # the section
        assert "0x1100-0x1180" in out                      # the containing function bounds


def test_resolve_stripped_reports_section_and_nearest_only(hg_home, monkeypatch):
    """On a stripped binary the ELF gives a section + nearest dynsym but NO containing FUNC — the
    PARTIAL case: containing_function is reported as unknown, not fabricated."""
    monkeypatch.setattr(EL, "resolve_layout", lambda path, vaddr: {
        "section": ".text", "nearest_symbol": {"name": "dynsym_x", "address": 0x1000, "offset": 0x50},
        "containing_function": None, "n_symbols": 3})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1050"})
        assert "dynsym_x" in out and ".text" in out
        assert "unknown" in out.lower()                    # containing_function unknown (stripped)


def test_out_of_range_address_section_none_gracefully(hg_home, monkeypatch):
    """An address mapped to no section/symbol returns section=None + no nearest, not a crash."""
    monkeypatch.setattr(EL, "resolve_layout", lambda path, vaddr: {
        "section": None, "nearest_symbol": None, "containing_function": None, "n_symbols": 0})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x900000"})
        assert "not mapped" in out or "no section" in out
        assert "none" in out.lower()


# --- bad address -> friendly error (mirrors _HEX_ADDR validation) -------------------------

def test_non_hex_address_is_a_friendly_error(hg_home):
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "not_an_addr"})
        assert "invalid address" in out


# --- degraded: pyelftools missing -> symbols-only nearest over the binutils index ---------

def test_degraded_falls_back_to_symbols_only(hg_home, monkeypatch):
    """With pyelftools unavailable, re_resolve degrades to a nearest-symbol answer over the
    binutils facts.symbols index (name+addr only — no section/containment) rather than failing."""
    monkeypatch.setattr(EL, "resolve_layout", lambda path, vaddr: {
        "error": "pyelftools not available in this environment", "degraded": True})
    # Stub the shared symbol index (its source is collect_binutils_facts, which needs the sandbox).
    monkeypatch.setattr(AT, "_symbol_index",
                        lambda ctx: [{"name": "parse", "address": 0x1100},
                                     {"name": "handle", "address": 0x1200}])
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x1150"})
        assert "degraded" in out
        assert "parse" in out and "0x50" in out            # nearest symbol + offset from the index
        assert "needs pyelftools" in out                   # containing_function unavailable note


# --- QUERY contract: one address_resolve Observation, zero graph mutation ------------------

def test_records_observation_and_no_graph(hg_home, monkeypatch):
    monkeypatch.setattr(EL, "resolve_layout", lambda path, vaddr: {
        "section": ".text", "nearest_symbol": {"name": "parse", "address": 0x1100, "offset": 0x30},
        "containing_function": None, "n_symbols": 4})
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "resolve_address", {"address": "0x1130"})
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "address_resolve").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "rv123"


# --- re_resolve must NOT be analysis-gated (it answers without a warm Ghidra project) ------

def test_resolve_is_not_analysis_gated():
    """re_resolve is the lightweight orientation tool — it must not require a saved analysis."""
    assert "resolve_address" not in AT._ANALYSIS_GATED_TOOLS


# --- INTEGRATION: a real ELF (guarded by the probe-only pyelftools) ----------------------

def test_integration_resolves_entry_to_text_and_start(hg_home):
    """Over the real vuln_httpd ELF, resolving the entry point (0x4010b0) reports section='.text'
    and _start as the nearest/containing symbol — end-to-end through pyelftools, no Docker. Skips
    cleanly when the probe-only pyelftools isn't installed in the venv."""
    pytest.importorskip("elftools")
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "resolve_address", {"address": "0x4010b0"})
        assert ".text" in out
        assert "_start" in out
        # An address in the middle of a symboled function resolves the containing function.
        ctx.cache.clear()
        out2 = run_tool(ctx, "resolve_address", {"address": "0x401200"})
        assert "parse_request" in out2
        assert s.query(Node).count() == 0                  # pure QUERY end to end
