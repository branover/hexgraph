"""ELF PT_LOAD <-> Ghidra address-space validation and re_script translation helpers.

No JVM/Docker: tiny fake Program/Memory objects exercise the same API calls the sandbox probe uses.
"""

from __future__ import annotations

import json
import os
import struct

import pytest

from hexgraph.sandbox.probes import pyghidra_lib as L


def _elf64(path, *, elf_type=3):
    """Two-load ELF whose executable file offset -> vaddr delta is exactly +0x100000."""
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    ehsize = 64
    phentsize = 56
    phnum = 2
    entry = 0x100100
    header = struct.pack(
        "<HHIQQQIHHHHHH",
        elf_type, 0x3E, 1, entry, ehsize, 0, 0, ehsize, phentsize, phnum, 0, 0, 0,
    )
    load_headers = b"".join([
        struct.pack("<IIQQQQQQ", 1, 4, 0, 0, 0, 0x100, 0x100, 0x1000),
        struct.pack(
            "<IIQQQQQQ", 1, 5, 0x100, 0x100100, 0x100100, 0x100, 0x120, 0x1000,
        ),
    ])
    payload = ident + header + load_headers
    path.write_bytes(payload.ljust(0x200, b"\x90"))
    return path


class _Address:
    def __init__(self, value):
        self.value = value

    def getUnsignedOffset(self):
        return self.value

    def getOffset(self):
        return self.value


class _Space:
    def getAddress(self, value):
        return _Address(value)


class _Factory:
    def getDefaultAddressSpace(self):
        return _Space()


class _Memory:
    def __init__(self, ranges):
        self.ranges = ranges

    def getBlock(self, address):
        value = address.getUnsignedOffset()
        return object() if any(start <= value <= end for start, end in self.ranges) else None


class _Program:
    def __init__(self, ranges, image_base=0):
        self.memory = _Memory(ranges)
        self.image_base = _Address(image_base)

    def getMemory(self):
        return self.memory

    def getAddressFactory(self):
        return _Factory()

    def getImageBase(self):
        return self.image_base

    def startTransaction(self, _name):
        return 1

    def setImageBase(self, address, _commit):
        new_base = address.getUnsignedOffset()
        delta = new_base - self.image_base.getUnsignedOffset()
        self.memory.ranges = [(start + delta, end + delta) for start, end in self.memory.ranges]
        self.image_base = address

    def endTransaction(self, _txid, _commit):
        pass


class _Flat:
    def toAddr(self, value):
        return _Address(value)


def test_validated_mapping_distinguishes_file_offsets_from_virtual_addresses(tmp_path):
    artifact = _elf64(tmp_path / "offset-elf")
    program = _Program([(0, 0xFF), (0x100100, 0x10021F)])

    report = L.validate_address_mapping(program, artifact)

    assert report["status"] == "validated"
    assert report["coordinate_system"] == "elf_virtual_address"
    assert report["entry_point"] == "0x100100"
    executable = report["load_segments"][1]
    assert executable["file_offset"] == "0x100"
    assert executable["virtual_address"] == "0x100100"
    assert executable["file_to_virtual_delta"] == "0x100000"
    assert L.mapping_file_offset_to_vaddr(report, "0x180") == 0x100180
    assert L.mapping_vaddr_to_file_offset(report, "0x100180") == 0x180


def test_cold_mapping_mismatch_is_structured(tmp_path):
    artifact = _elf64(tmp_path / "offset-elf")
    # The executable bytes are incorrectly present at their file offsets, not their ELF vaddrs.
    program = _Program([(0, 0x21F)])

    with pytest.raises(L.AddressMappingMismatch) as raised:
        L.validate_address_mapping(program, artifact)

    report = raised.value.report
    assert report["status"] == "mismatch"
    assert "0x100100" in report["unmapped_addresses"]
    assert "new analysis cannot be committed" in str(raised.value)


def test_cold_import_normalizes_ghidra_pie_image_base(tmp_path):
    artifact = _elf64(tmp_path / "offset-elf")
    # Mirrors Ghidra 12.1's default PIE import: every block and the image base are +0x100000.
    program = _Program([(0x100000, 0x1000FF), (0x200100, 0x20021F)], image_base=0x100000)

    L.normalize_program_image_base(program, artifact)
    report = L.validate_address_mapping(program, artifact)

    assert report["status"] == "validated"
    assert report["image_base"] == report["preferred_image_base"] == "0x0"
    assert report["ghidra_load_bias"] == "0x0"


def test_cold_import_does_not_rebase_non_pie_elf(tmp_path):
    artifact = _elf64(tmp_path / "exec-elf", elf_type=2)
    program = _Program([(0x100000, 0x1000FF), (0x200100, 0x20021F)], image_base=0x100000)

    L.normalize_program_image_base(program, artifact)

    assert program.getImageBase().getUnsignedOffset() == 0x100000


def test_warm_legacy_base_is_preserved_and_warned(tmp_path, monkeypatch):
    marker = tmp_path / L.META_NAME
    marker.write_text(json.dumps({"program_name": "hexgraph"}))
    project_bytes = tmp_path / "project" / "hexgraph.gpr"
    project_bytes.parent.mkdir()
    project_bytes.write_text("expensive analysis retained")
    monkeypatch.setattr(L, "PROJECT_MOUNT", str(tmp_path))
    artifact = _elf64(tmp_path / "offset-elf")
    program = _Program([(0x100000, 0x1000FF), (0x200100, 0x20021F)], image_base=0x100000)

    report = L._validate_warm_address_mapping(program, artifact)

    assert marker.exists()
    assert project_bytes.read_text() == "expensive analysis retained"
    assert report["status"] == "validated"
    assert report["image_base"] == "0x100000"
    assert report["ghidra_load_bias"] == "0x100000"
    assert report["legacy_image_base"] is True
    assert "image base 0x100000" in report["warning"]
    assert L.mapping_file_offset_to_vaddr(report, "0x180") == 0x200180
    assert L.mapping_vaddr_to_file_offset(report, "0x200180") == 0x180


def test_warm_project_with_unverified_ranges_is_warned_not_rejected(tmp_path):
    artifact = _elf64(tmp_path / "offset-elf")
    program = _Program([(0, 0x20)], image_base=0)

    report = L.validate_address_mapping(program, artifact, allow_existing_base=True)

    assert report["status"] == "warning"
    assert report["image_base"] == "0x0"
    assert "image base 0x0" in report["warning"]
    assert "could not be fully verified" in report["warning"]
    assert report["unmapped_addresses"]


def test_script_namespace_translates_file_offsets_before_querying_ghidra(tmp_path):
    mapping = {
        "status": "validated",
        "load_segments": [{
            "file_offset": "0x100",
            "virtual_address": "0x100100",
            "file_size": "0x100",
            "memory_size": "0x120",
        }],
    }
    script = """
addr = file_offset_to_address(0x180)
result = {
    'address': hex(addr.getUnsignedOffset()),
    'offset': hex(address_to_file_offset(addr)),
    'status': address_mapping['status'],
}
"""

    out = L.script_core(
        _Program([]), _Flat(), object(), script,
        out_path=str(tmp_path / "out.json"), address_mapping=mapping,
    )

    assert out == {
        "address": "0x100180",
        "offset": "0x180",
        "status": "validated",
        "tool": "ghidra_script",
    }


def test_non_elf_mapping_is_reported_without_guessing(tmp_path):
    artifact = tmp_path / "blob"
    artifact.write_bytes(b"not an elf")

    report = L.validate_address_mapping(_Program([], image_base=0x400000), artifact)

    assert report == {
        "schema": L.ADDRESS_MAPPING_SCHEMA,
        "format": "other",
        "status": "not_applicable",
        "coordinate_system": "ghidra_program_address",
        "image_base": "0x400000",
    }


def test_unparseable_warm_elf_reports_its_base_as_a_warning(tmp_path):
    artifact = tmp_path / "broken-elf"
    artifact.write_bytes(b"\x7fELF" + bytes([2, 1]) + b"\0" * 10)

    report = L.validate_address_mapping(
        _Program([], image_base=0x100000), artifact, allow_existing_base=True)

    assert report["status"] == "unverified"
    assert report["image_base"] == "0x100000"
    assert "image base 0x100000" in report["warning"]


def test_probe_surfaces_cold_mapping_mismatch(tmp_path, monkeypatch, capsys):
    from hexgraph.sandbox.probes import ghidra_probe as G

    artifact = _elf64(tmp_path / "offset-elf")
    report = {"status": "mismatch", "unmapped_addresses": ["0x100100"]}
    error = G.L.AddressMappingMismatch(report)
    monkeypatch.setattr(G, "_pyghidra_installed", lambda: True)
    real_isdir = os.path.isdir
    monkeypatch.setattr(
        G.os.path, "isdir",
        lambda p: True if str(p).endswith("Ghidra") else real_isdir(p),
    )
    monkeypatch.setattr(G, "_warm_slot_present", lambda: True)
    monkeypatch.setattr(G.L, "start", lambda: None)
    monkeypatch.setattr(
        G, "_run", lambda _m: (_ for _ in ()).throw(error),
    )
    monkeypatch.setattr(G.sys, "argv", ["ghidra_probe.py", str(artifact), "main"])

    assert G.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["analysis_invalid"] is True
    assert out["needs_analysis"] is True
    assert out["address_mapping"] == report
    assert "new analysis cannot be committed" in out["error"]
