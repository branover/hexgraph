"""re_hexdump dumps raw BYTES at a virtual ADDRESS as hex + ascii, bounded (default 256, max 4096).

The raw-bytes view of a DAT_ table / embedded key / struct / string constant — for the objective's
stack-canary/base-leak table reads. Maps the vaddr to a file offset via the ELF program headers and
reads the on-disk artifact SERVER-SIDE (pyelftools over target.path) — no decompile, no Docker. A
.bss/zero-fill address reads as 00 with a note; an unmapped address is REPORTED, not faked; when
pyelftools is missing (it's probe-only per pyproject) it DEGRADES to an error pointing at
re_disassemble_range rather than returning wrong bytes. Records a hexdump Observation, mutates no
graph.

Two layers, mirroring test_re_symbol / test_list_functions:
  * UNIT — the vaddr->offset mapping (`elf_layout.vaddr_to_offset`) over a SYNTHETIC segment table,
    and the render/clamp/degrade behaviour, none of which need pyelftools or Docker.
  * INTEGRATION — one non-mocked dump over tests/fixtures/vuln_httpd (a real ELF), guarded by
    importorskip('elftools') so it skips cleanly in a venv without the probe-only lib.
"""

import pytest

import hexgraph.engine.re.elf_layout as EL
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _ctx(s):
    p = create_project(s, name="hexdump")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "hd123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


# --- UNIT: the vaddr->file-offset mapping over a synthetic PT_LOAD segment table -----------

class _FakeSeg:
    def __init__(self, **h):
        self.header = h


class _FakeElf:
    """Just enough of pyelftools' ELFFile for vaddr_to_offset: an iter_segments()."""
    def __init__(self, segs):
        self._segs = segs

    def iter_segments(self):
        return iter(self._segs)


def _seg(p_vaddr, p_offset, p_filesz, p_memsz, p_type="PT_LOAD"):
    return _FakeSeg(p_type=p_type, p_vaddr=p_vaddr, p_offset=p_offset,
                    p_filesz=p_filesz, p_memsz=p_memsz)


def test_vaddr_to_offset_maps_within_a_segment():
    """An address inside a PT_LOAD's filesz maps to p_offset + (vaddr - p_vaddr)."""
    elf = _FakeElf([_seg(0x401000, 0x1000, 0x200, 0x200)])
    off, zero = EL.vaddr_to_offset(elf, 0x401040)
    assert off == 0x1040 and zero is False


def test_vaddr_to_offset_flags_bss_zero_fill():
    """An address in the memsz-beyond-filesz tail (.bss) is flagged zero_fill with no file off."""
    elf = _FakeElf([_seg(0x403000, 0x2000, 0x100, 0x180)])   # filesz 0x100, memsz 0x180
    off, zero = EL.vaddr_to_offset(elf, 0x403140)            # 0x140 >= filesz 0x100
    assert off is None and zero is True


def test_vaddr_to_offset_unmapped_is_none():
    """An address in no loadable segment maps to nothing (reported, not faked)."""
    elf = _FakeElf([_seg(0x401000, 0x1000, 0x200, 0x200)])
    off, zero = EL.vaddr_to_offset(elf, 0x900000)
    assert off is None and zero is False


def test_vaddr_to_offset_ignores_non_load_segments():
    """A non-PT_LOAD segment covering the address is skipped (only PT_LOAD maps bytes)."""
    elf = _FakeElf([_seg(0x401000, 0x1000, 0x200, 0x200, p_type="PT_DYNAMIC")])
    off, zero = EL.vaddr_to_offset(elf, 0x401040)
    assert off is None and zero is False


def test_render_hexdump_shape():
    """render_hexdump lays out 16 bytes/line: running vaddr offset, hex, |ascii| (non-print -> .)."""
    out = EL.render_hexdump(b"AB\x00\xff", 0x402000)
    assert out.startswith("00402000")
    assert "41 42 00 ff" in out
    assert "|AB..|" in out


# --- clamp: an over-large length clamps to the 4096 ceiling with a note --------------------

def test_length_clamps_to_ceiling(hg_home, monkeypatch):
    """A length past the ceiling clamps to 4096 and SAYS so (the no-silent-caps discipline). The
    ELF read is stubbed so the test needs no pyelftools/Docker — only the host-side clamp is under
    test (the clamped length is what's passed to read_bytes)."""
    seen = {}

    def _fake_read(path, vaddr, length):
        seen["length"] = length
        return {"data": b"\x00" * length, "address": vaddr, "length": length, "zero_fill": False}

    monkeypatch.setattr(EL, "read_bytes", _fake_read)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x401000", "length": 99999})
        assert seen["length"] == EL.HEXDUMP_MAX            # clamped to 4096 before the read
        assert "clamped to 4096" in out


def test_default_length_is_256(hg_home, monkeypatch):
    seen = {}

    def _fake_read(path, vaddr, length):
        seen["length"] = length
        return {"data": b"\x00" * length, "address": vaddr, "length": length, "zero_fill": False}

    monkeypatch.setattr(EL, "read_bytes", _fake_read)
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "hexdump", {"address": "0x401000"})
        assert seen["length"] == 256


# --- error paths: a bad address, an unmapped address, a .bss note -------------------------

def test_non_hex_address_is_a_friendly_error(hg_home):
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "deadbeef"})
        assert "invalid address" in out


def test_unmapped_address_is_reported_not_faked(hg_home, monkeypatch):
    """An address in no PT_LOAD segment returns a clear 'not mapped' message, never a stack trace
    or fabricated bytes."""
    monkeypatch.setattr(EL, "read_bytes",
                        lambda path, vaddr, length: {"error": f"address {vaddr:#x} is not mapped "
                                                     "in any PT_LOAD segment"})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x900000"})
        assert "not mapped" in out and "0x900000" in out


def test_bss_address_returns_zero_fill_with_note(hg_home, monkeypatch):
    """A .bss address dumps as 00 with the zero-fill note (bytes synthesized, not read as garbage)."""
    monkeypatch.setattr(EL, "read_bytes",
                        lambda path, vaddr, length: {"data": b"\x00" * length, "address": vaddr,
                                                     "length": length, "zero_fill": True})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x403380", "length": 8})
        assert "zero-fill" in out
        assert "00 00 00 00" in out


# --- degraded: pyelftools import forced to fail -> point at re_disassemble_range ----------

def test_degraded_when_pyelftools_missing(hg_home, monkeypatch):
    """With pyelftools unavailable, hexdump returns the degraded {error} pointing at
    re_disassemble_range — it must NOT silently return wrong bytes."""
    monkeypatch.setattr(EL, "read_bytes",
                        lambda path, vaddr, length: {"error": "pyelftools not available in this "
                                                     "environment", "degraded": True})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000"})
        assert "re_disassemble_range" in out
        assert "unavailable" in out


# --- QUERY contract: one hexdump Observation, zero graph mutation -------------------------

def test_records_observation_and_no_graph(hg_home, monkeypatch):
    monkeypatch.setattr(EL, "read_bytes",
                        lambda path, vaddr, length: {"data": b"ABCD", "address": vaddr,
                                                     "length": 4, "zero_fill": False})
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "hexdump", {"address": "0x402000", "length": 4})
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "hexdump").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "hd123"


# --- INTEGRATION: a real ELF (guarded by the probe-only pyelftools) ----------------------

def test_integration_dumps_a_known_rodata_string(hg_home):
    """Over the real vuln_httpd ELF, dumping .rodata (0x402000) shows a known string in the ascii
    pane and the matching hex — end-to-end through pyelftools, no Docker. Skips cleanly when the
    probe-only pyelftools isn't installed in the venv."""
    pytest.importorskip("elftools")
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000", "length": 32})
        assert "handled %s" in out                        # the ascii pane of the .rodata string
        # 'hand' in hex — a within-group fragment (the hexdump -C gutter double-spaces at byte 8,
        # so the full 'handled' straddles the group boundary; assert a fragment that doesn't).
        assert "68 61 6e 64" in out
        # And it recorded exactly one hexdump Observation, no graph mutation.
        assert s.query(Node).count() == 0
        obs = s.query(Observation).filter(Observation.result_kind == "hexdump").all()
        assert len(obs) == 1
