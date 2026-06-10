"""F08: a firmware that re-packs the SAME binary at several paths (a FIT inner image == the
top-level cpio, a busybox hard-link farm, a package shipped in two layers) must register the bytes
ONCE — not mint a duplicate hidden target per path. unpack_firmware dedups byte-identical extracted
ELFs by sha256 and records a `dedup_of` ref on the duplicate manifest paths. No-Docker fake executor.
"""

from pathlib import Path

from hexgraph.db.models import Target
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.targets.unpack import unpack_firmware

ELF_DUP = b"\x7fELF\x01\x01\x01" + b"the very same bytes, packed at two paths" + b"\x00" * 8
ELF_UNIQUE = b"\x7fELF\x01\x01\x01" + b"a different, unique binary" + b"\x00" * 8


class _FakeDupExecutor:
    """Lays the SAME ELF at two paths + a distinct third (binwalk-style, root == /out)."""

    def run_json_probe(self, probe, artifact, *, outdir=None, **kw):
        assert probe == "unpack_probe.py"
        out = Path(outdir)
        for rel, data in (("boot/svc", ELF_DUP), ("pkg/svc", ELF_DUP), ("bin/busybox", ELF_UNIQUE)):
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            (out / rel).write_bytes(data)
        return {
            "method": "fake", "root": "/out",
            "files": [
                {"rel": "boot/svc", "container_path": "/out/boot/svc", "size": len(ELF_DUP), "is_elf": True},
                {"rel": "pkg/svc", "container_path": "/out/pkg/svc", "size": len(ELF_DUP), "is_elf": True},
                {"rel": "bin/busybox", "container_path": "/out/bin/busybox", "size": len(ELF_UNIQUE), "is_elf": True},
            ],
        }


def test_byte_identical_children_are_deduped(hg_home, tmp_path):
    fw_src = tmp_path / "firmware.bin"
    fw_src.write_bytes(b"FAKEFW" + b"\x00" * 64)
    with session_scope() as session:
        project = create_project(session, name="fw")
        firmware = ingest_file(session, project, fw_src, name="firmware.bin")
        children = unpack_firmware(session, project, firmware, runner=_FakeDupExecutor())

        # the two byte-identical paths collapse to ONE child; busybox is its own -> 2 children, not 3.
        assert len(children) == 2
        elf_targets = session.query(Target).filter(Target.parent_id == firmware.id).all()
        assert len(elf_targets) == 2                                   # no duplicate row was minted

        files = {f["rel"]: f for f in firmware.metadata_json["filesystem"]["files"]}
        keeper_id = files["boot/svc"]["child_target_id"]               # first occurrence keeps the row
        assert files["pkg/svc"]["child_target_id"] == keeper_id        # the dup path reuses that target
        assert files["pkg/svc"]["dedup_of"] == keeper_id               # ...and is flagged as a dedup
        assert "dedup_of" not in files["boot/svc"]                     # the keeper is not a dup
        assert "dedup_of" not in files["bin/busybox"]                  # nor is the distinct binary


def test_reveal_dir_finds_a_binary_via_its_deduped_path(hg_home, tmp_path):
    # F08 regression guard: the shared binary's keeper is named "boot/svc", but it also lives at
    # "pkg/svc" (deduped, no row of its own). Revealing the "pkg" directory must still reveal it —
    # reveal_dir consults the manifest path map, not just live Target.name.
    from hexgraph.engine.targets.reveal import reveal_dir

    fw_src = tmp_path / "firmware.bin"
    fw_src.write_bytes(b"FAKEFW" + b"\x00" * 64)
    with session_scope() as session:
        project = create_project(session, name="fw")
        firmware = ingest_file(session, project, fw_src, name="firmware.bin")
        unpack_firmware(session, project, firmware, runner=_FakeDupExecutor())

        files = {f["rel"]: f for f in firmware.metadata_json["filesystem"]["files"]}
        keeper_id = files["boot/svc"]["child_target_id"]
        res = reveal_dir(session, project.id, firmware.id, "pkg")       # the dir only the DEDUPED path is in
        assert res["revealed"] == 1 and res["target_ids"] == [keeper_id]
        assert session.get(Target, keeper_id).visible is True
