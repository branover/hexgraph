"""Foreign-arch (qemu-user) execution + firmware sysroot resolution.

Unit-level: arch detection from the ELF header and locating the FHS root inside a
nested binwalk extraction. The full path (qemu-mipsel running a real MIPS uClibc
binary from DVRF with the firmware as sysroot) is exercised manually against real
firmware — see PROGRESS.md — since the firmware isn't a committed fixture."""

import struct

from hexgraph.engine.poc import _find_sysroot
from hexgraph.sandbox.probes import poc_probe


def _elf_header(e_machine: int, little: bool = True, elf64: bool = True) -> bytes:
    h = bytearray(20)
    h[0:4] = b"\x7fELF"
    h[4] = 2 if elf64 else 1          # EI_CLASS
    h[5] = 1 if little else 2          # EI_DATA
    struct.pack_into("<H" if little else ">H", h, 18, e_machine)
    return bytes(h)


def test_qemu_prefix_host_arch_is_native(tmp_path):
    # x86-64 target → no qemu wrapper (runs natively).
    f = tmp_path / "x64"; f.write_bytes(_elf_header(62))   # EM_X86_64
    assert poc_probe._qemu_prefix(str(f), None) == []
    # Non-ELF → also native (no qemu).
    g = tmp_path / "plain"; g.write_bytes(b"not an elf")
    assert poc_probe._qemu_prefix(str(g), None) == []


def test_qemu_prefix_foreign_arch_selects_qemu(tmp_path, monkeypatch):
    # MIPS LE → qemu-mipsel; MIPS BE → qemu-mips; ARM BE → qemu-armeb. We stub
    # shutil.which so the test doesn't require qemu on the host.
    seen = {}

    def fake_which(name):
        seen["last"] = name
        return f"/usr/bin/{name}"

    monkeypatch.setattr(poc_probe.shutil, "which", fake_which)

    mips_le = tmp_path / "m"; mips_le.write_bytes(_elf_header(8, little=True))
    pre = poc_probe._qemu_prefix(str(mips_le), str(tmp_path), argv0="busybox")
    assert pre[0] == "/usr/bin/qemu-mipsel"
    assert "-L" in pre and str(tmp_path) in pre and "-0" in pre and "busybox" in pre

    mips_be = tmp_path / "mb"; mips_be.write_bytes(_elf_header(8, little=False))
    assert poc_probe._qemu_prefix(str(mips_be), None)[0] == "/usr/bin/qemu-mips"

    arm_be = tmp_path / "ab"; arm_be.write_bytes(_elf_header(40, little=False))
    assert poc_probe._qemu_prefix(str(arm_be), None)[0] == "/usr/bin/qemu-armeb"


def test_find_sysroot_descends_to_fhs_root(tmp_path):
    # Mimic a binwalk extraction where the rootfs is nested below the unpack root.
    rootfs = tmp_path / "_artifact.extracted" / "squashfs-root"
    (rootfs / "lib").mkdir(parents=True)
    (rootfs / "bin").mkdir()
    (rootfs / "lib" / "ld-uClibc.so.0").write_bytes(b"\x7fELF")
    assert _find_sysroot(tmp_path) == rootfs


def test_find_sysroot_root_itself(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "libc.so.6").write_bytes(b"\x7fELF")
    assert _find_sysroot(tmp_path) == tmp_path
