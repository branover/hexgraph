"""re_hexdump dumps raw BYTES at a virtual ADDRESS as hex + ascii, bounded (default 256, max 4096).

The raw-bytes view of a DAT_ table / embedded key / struct / string constant — for the objective's
stack-canary/base-leak table reads. The bytes are read in the SANDBOX via radare2 (`p8` at the
vaddr, the same mapping re_disassemble_range uses) and the hexdump is rendered host-side, so the
hostile ELF is parsed in the sandbox, never the host process. A .bss/zero-fill address reads as 00
with a note; an UNMAPPED address is REPORTED, not faked (r2's raw `p8` returns 0xff io-fill for an
unmapped read, so the probe classifies the vaddr against the PT_LOAD table first). Records a hexdump
Observation, mutates no graph.

Three layers, mirroring test_disassemble_range:
  * PROBE UNIT — `decompile_probe._read_raw_bytes` over a synthetic IO map (`omj`) via a fake r2:
    the file-backed / .bss / unmapped classification, the mapped-region clamp, and the p8 hex parse.
  * TOOL UNIT — the render/clamp/error behaviour of the tool with `R2Decompiler.read_bytes` mocked
    (no Docker), including the Docker-down degrade and the QUERY (one Observation, zero graph) contract.
  * INTEGRATION — non-mocked dumps through the real sandbox (guarded by SANDBOX_READY): vuln_httpd
    (ET_EXEC) for file-backed / unmapped / .bss, and libupnp.so (ET_DYN/PIE) for the shared-object
    path r2's iSSj can't serialize but omj can.
"""

import json

import pytest

import hexgraph.engine.re.elf_layout as EL
from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import SANDBOX_READY, fixture_path


def _ctx(s):
    p = create_project(s, name="hexdump")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "hd123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t)


# --- PROBE UNIT: the vaddr classification + p8 read over a synthetic IO map (omj) -----------

class _FakeR2:
    """Minimal r2 for `_read_raw_bytes`: answers `omj` with a synthetic IO map and `p8` with canned
    hex. `maps` are `(start, end_inclusive, name)` — r2's `omj` keys are from/to/name, where a
    `fmap.*` name is a file-backed region and `mmap.*` a .bss/zero-fill region."""

    def __init__(self, maps, p8="deadbeef"):
        self._maps = [{"from": s, "to": e, "name": n} for (s, e, n) in maps]
        self._p8 = p8
        self.cmds = []

    def cmd(self, c):
        self.cmds.append(c)
        if c == "omj":
            return json.dumps(self._maps)
        if c.startswith("p8 "):
            return self._p8
        return ""


def _dp():
    from hexgraph.sandbox.probes import decompile_probe as DP
    return DP


def test_probe_reads_file_backed_bytes_with_p8():
    """A vaddr inside a file-backed IO map is read with `p8 <n> @ <addr>` and returned as hex."""
    DP = _dp()
    r2 = _FakeR2([(0x401000, 0x4011ff, "fmap.LOAD1")], p8="aabbccdd")
    out = DP._read_raw_bytes(r2, "0x401040", length=4)
    assert out == {"address": "0x401040", "length": 4, "hex": "aabbccdd", "zero_fill": False}
    assert "p8 4 @ 0x401040" in r2.cmds


def test_probe_bss_map_is_zero_fill_and_never_reads_p8():
    """A vaddr in a .bss/zero-fill map (`mmap.*`) returns synthesized 00s with the flag and issues
    NO p8 — the bytes are known-zero, never a garbage/io-fill read."""
    DP = _dp()
    r2 = _FakeR2([(0x403000, 0x40337f, "fmap.LOAD3"), (0x403380, 0x403387, "mmap.LOAD3")])
    out = DP._read_raw_bytes(r2, "0x403380", length=8)
    assert out["zero_fill"] is True and out["hex"] == "00" * 8 and out["length"] == 8
    assert "note" not in out
    assert not any(c.startswith("p8") for c in r2.cmds)


def test_probe_unmapped_is_reported_not_faked():
    """A vaddr in no IO map is an error — never r2's 0xff io-fill. NO p8 is issued."""
    DP = _dp()
    r2 = _FakeR2([(0x401000, 0x4011ff, "fmap.LOAD1")])
    out = DP._read_raw_bytes(r2, "0x900000", length=16)
    assert "error" in out and "not mapped" in out["error"] and "hex" not in out
    assert not any(c.startswith("p8") for c in r2.cmds)


def test_probe_clamps_read_to_end_of_mapped_region():
    """A read that would spill past mapped memory is clamped (never the 0xff io-fill past the end)
    and noted. The contiguous run crosses a file-backed map straight into its adjacent .bss map."""
    DP = _dp()
    # fmap.LOAD3 [..0x40337f] immediately followed by mmap.LOAD3 [0x403380..0x403387], then a GAP.
    # A 32-byte read from 0x403378 spans the fmap tail + the whole bss (contiguous) but must stop
    # at 0x403388 — i.e. 16 bytes — never reading into the gap past the mapped end.
    r2 = _FakeR2([(0x403148, 0x40337f, "fmap.LOAD3"), (0x403380, 0x403387, "mmap.LOAD3"),
                  (0x500000, 0x500fff, "fmap.OTHER")], p8="00" * 16)
    out = DP._read_raw_bytes(r2, "0x403378", length=32)
    assert out["length"] == 16 and out["zero_fill"] is False
    assert out.get("note") and "clamped" in out["note"]
    assert "p8 16 @ 0x403378" in r2.cmds


def test_probe_read_does_not_cross_a_gap():
    """The contiguous-extent walk stops at a GAP between maps — a read near a map's end clamps to
    that map, never jumping across unmapped space to the next map."""
    DP = _dp()
    r2 = _FakeR2([(0x1000, 0x1fff, "fmap.A"), (0x3000, 0x3fff, "fmap.B")], p8="00" * 16)
    out = DP._read_raw_bytes(r2, "0x1ff0", length=64)
    assert out["length"] == 16 and out.get("note")           # clamped to 0x1fff, not extended to 0x3000
    assert "p8 16 @ 0x1ff0" in r2.cmds


def test_probe_p8_hex_is_sanitised_to_whole_bytes():
    """`p8` output is stripped to hex digits and trimmed to a whole byte, so separators/newlines or
    an odd nibble can't yield bytes the host can't decode."""
    DP = _dp()
    r2 = _FakeR2([(0x401000, 0x4011ff, "fmap.LOAD1")], p8="aa bb\ncc d")   # spaces/newline + odd nibble
    out = DP._read_raw_bytes(r2, "0x401000", length=4)
    assert out["hex"] == "aabbcc" and out["length"] == 3                  # trailing 'd' dropped


def test_probe_clamps_and_floors_length():
    """The byte count is clamped to the ceiling and floored at 1 — a fat-fingered length can't pull
    unbounded bytes out of the sandbox (mirrors the range-mode clamp). Uses a large map so the
    mapped-region clamp doesn't bind first."""
    DP = _dp()
    big = [(0x401000, 0x421000, "fmap.BIG")]
    r2 = _FakeR2(big)
    DP._read_raw_bytes(r2, "0x401000", length=10_000_000)
    assert f"p8 {DP._HEXDUMP_MAX_BYTES} @ 0x401000" in r2.cmds
    r2 = _FakeR2(big)
    DP._read_raw_bytes(r2, "0x401000", length=0)
    assert "p8 1 @ 0x401000" in r2.cmds
    r2 = _FakeR2(big)
    DP._read_raw_bytes(r2, "0x401000", length=None)             # default when unset
    assert f"p8 {DP._HEXDUMP_DEFAULT_BYTES} @ 0x401000" in r2.cmds


def test_render_hexdump_shape():
    """render_hexdump lays out 16 bytes/line: running vaddr offset, hex, |ascii| (non-print -> .)."""
    out = EL.render_hexdump(b"AB\x00\xff", 0x402000)
    assert out.startswith("00402000")
    assert "41 42 00 ff" in out
    assert "|AB..|" in out


def test_seam_bytes_args_builds_probe_argv():
    """The decompiler seam builds `--bytes <addr> [--length N]`; length is omitted when unset."""
    from hexgraph.sandbox.decompiler import _bytes_args

    assert _bytes_args("0x1000", None) == ["--bytes", "0x1000"]
    assert _bytes_args("0x1000", 256) == ["--bytes", "0x1000", "--length", "256"]


# --- TOOL UNIT: the tool over a mocked R2Decompiler.read_bytes (no Docker) ------------------

def _mock_read(monkeypatch, fn):
    """Patch the sandbox seam the tool uses: Docker is 'up' and R2Decompiler.read_bytes returns
    whatever `fn(address, length)` yields (wrapped in the probe's {'bytes': ...} envelope)."""
    from hexgraph.sandbox.decompiler import R2Decompiler

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr(
        R2Decompiler, "read_bytes",
        lambda self, artifact, address, length=None: {"bytes": fn(address, length)})


def test_length_clamps_to_ceiling(hg_home, monkeypatch):
    """A length past the ceiling clamps to 4096 host-side and SAYS so (no-silent-caps); the clamped
    length is what's passed to the sandbox read."""
    seen = {}

    def _fn(address, length):
        seen["length"] = length
        return {"address": address, "length": length, "hex": "00" * (length or 0), "zero_fill": False}

    _mock_read(monkeypatch, _fn)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x401000", "length": 99999})
        assert seen["length"] == EL.HEXDUMP_MAX            # clamped to 4096 before the read
        assert "clamped to 4096" in out


def test_default_length_is_256(hg_home, monkeypatch):
    seen = {}

    def _fn(address, length):
        seen["length"] = length
        return {"address": address, "length": length, "hex": "00" * (length or 0), "zero_fill": False}

    _mock_read(monkeypatch, _fn)
    with session_scope() as s:
        ctx = _ctx(s)
        run_tool(ctx, "hexdump", {"address": "0x401000"})
        assert seen["length"] == 256


def test_non_hex_address_is_a_friendly_error(hg_home):
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "deadbeef"})
        assert "invalid address" in out


def test_unmapped_address_is_reported_not_faked(hg_home, monkeypatch):
    """An address the probe reports as unmapped surfaces as a clear 'not mapped' message with the
    address, never a stack trace or fabricated bytes."""
    _mock_read(monkeypatch, lambda address, length: {
        "address": address, "error": f"address {address} is not mapped in any PT_LOAD segment"})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x900000"})
        assert "not mapped" in out and "0x900000" in out


def test_bss_address_returns_zero_fill_with_note(hg_home, monkeypatch):
    """A .bss address dumps as 00 with the zero-fill note (bytes synthesized, not read as garbage)."""
    _mock_read(monkeypatch, lambda address, length: {
        "address": address, "length": length, "hex": "00" * (length or 0), "zero_fill": True})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x403380", "length": 8})
        assert "zero-fill" in out
        assert "00 00 00 00" in out


def test_malformed_bytes_from_sandbox_is_a_clean_error(hg_home, monkeypatch):
    """If the sandbox ever returns undecodable hex, the tool reports it — never raises."""
    _mock_read(monkeypatch, lambda address, length: {"address": address, "hex": "zznothex"})
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000", "length": 4})
        assert "malformed bytes" in out


def test_degraded_when_docker_down(hg_home, monkeypatch):
    """With Docker/sandbox down the read can't run — the tool says so and points at the sandbox,
    never silently returning wrong bytes."""
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000"})
        assert "unavailable" in out and "re_disassemble_range" in out


def test_records_observation_and_no_graph(hg_home, monkeypatch):
    _mock_read(monkeypatch, lambda address, length: {
        "address": address, "length": 4, "hex": "41424344", "zero_fill": False})   # 'ABCD'
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000", "length": 4})
        assert "|ABCD|" in out
        assert s.query(Node).count() == 0
        assert s.query(Edge).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == ctx.target.id,
                                          Observation.result_kind == "hexdump").all()
        assert len(obs) == 1
        assert obs[0].content_hash == "hd123"


# --- INTEGRATION: a real ELF through the real sandbox (radare2 p8) ------------------------

@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_integration_dumps_a_known_rodata_string(hg_home):
    """Over the real vuln_httpd ELF, dumping .rodata (0x402000) shows a known string in the ascii
    pane and the matching hex — end-to-end through the sandbox `p8`, recording one Observation."""
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x402000", "length": 32})
        assert "handled %s" in out                        # the ascii pane of the .rodata string
        # 'hand' in hex — a within-group fragment (the hexdump -C gutter double-spaces at byte 8,
        # so the full 'handled' straddles the group boundary; assert a fragment that doesn't).
        assert "68 61 6e 64" in out
        assert s.query(Node).count() == 0
        obs = s.query(Observation).filter(Observation.result_kind == "hexdump").all()
        assert len(obs) == 1


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_integration_unmapped_is_reported_not_ff_fill(hg_home):
    """The regression this fix exists for: an UNMAPPED address must be reported, NOT rendered as a
    page of r2's 0xff io-fill. Proves the PT_LOAD classification runs before the p8 read."""
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x900000", "length": 32})
        assert "not mapped" in out
        assert "ff ff ff ff" not in out                   # never the faked io-fill


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_integration_bss_reads_zero_fill(hg_home):
    """The real .bss (0x403380 in vuln_httpd, the LOAD segment's memsz tail) dumps as 00 with the
    zero-fill note — mapped, backed by no file bytes."""
    with session_scope() as s:
        ctx = _ctx(s)
        out = run_tool(ctx, "hexdump", {"address": "0x403380", "length": 8})
        assert "zero-fill" in out
        assert "00 00 00 00" in out


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image (radare2)")
def test_integration_pie_shared_object_reads_header(hg_home):
    """A PIE/ET_DYN shared object (libupnp.so) maps + reads correctly through the sandbox — the ELF
    header at 0x0 shows the magic in the hex and `ELF` in the ascii pane. Guards the shared-object
    path specifically: r2's `iSSj` can serialize empty for a .so, but the `omj` IO map does not, so
    a segment-table approach would have failed closed here."""
    with session_scope() as s:
        p = create_project(s, name="hexdump-pie")
        t = ingest_file(s, p, fixture_path("libupnp.so"), name="libupnp")
        s.flush()
        ctx = ToolContext(session=s, project=p, target=t)
        out = run_tool(ctx, "hexdump", {"address": "0x0", "length": 16})
        assert "7f 45 4c 46" in out               # ELF magic bytes, proving a real mapped read
        assert "ELF" in out                        # its ascii pane
