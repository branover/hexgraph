"""Regression: two unpacked firmware children that share a basename must not
clobber each other's on-disk artifact.

A flat ``artifacts/<basename>`` layout meant a firmware containing e.g. both
``bin/foo`` and ``sbin/foo`` would copy the second over the first, so recon/
decompile later read the WRONG bytes for one child — silent graph corruption.
This drives ``unpack_firmware`` with a fake executor (no Docker) whose manifest
lists two distinct ELFs sharing a basename and asserts both children keep their
own bytes on disk.
"""

import os
from pathlib import Path

from hexgraph.db.models import Target
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.unpack import unpack_firmware

ELF_A = b"\x7fELF\x01\x01\x01" + b"AAAA distinct child one" + b"\x00" * 8
ELF_B = b"\x7fELF\x01\x01\x01" + b"BB different bytes, child two, longer" + b"\x00" * 8


class _FakeUnpackExecutor:
    """Pretends to be the sandbox: lays two same-basename ELFs into the outdir
    (binwalk-style, root == /out) and returns the manifest the host walks."""

    def run_json_probe(self, probe, artifact, *, outdir=None, **kw):
        assert probe == "unpack_probe.py"
        out = Path(outdir)
        (out / "bin").mkdir(parents=True, exist_ok=True)
        (out / "sbin").mkdir(parents=True, exist_ok=True)
        (out / "bin" / "foo").write_bytes(ELF_A)
        (out / "sbin" / "foo").write_bytes(ELF_B)
        return {
            "method": "fake",
            "root": "/out",
            "files": [
                {"rel": "bin/foo", "container_path": "/out/bin/foo",
                 "size": len(ELF_A), "is_elf": True},
                {"rel": "sbin/foo", "container_path": "/out/sbin/foo",
                 "size": len(ELF_B), "is_elf": True},
            ],
        }


def test_unpack_children_sharing_basename_keep_own_bytes(hg_home, tmp_path):
    fw_src = tmp_path / "firmware.bin"
    fw_src.write_bytes(b"FAKEFW" + b"\x00" * 64)

    with session_scope() as session:
        project = create_project(session, name="fw")
        firmware = ingest_file(session, project, fw_src, name="firmware.bin")
        children = unpack_firmware(session, project, firmware, runner=_FakeUnpackExecutor())
        assert len(children) == 2
        ids = [c.id for c in children]

    with session_scope() as session:
        kids = [session.get(Target, i) for i in ids]
        paths = [k.path for k in kids]
        # Distinct on-disk artifacts despite the shared "foo" basename.
        assert os.path.basename(paths[0]) == os.path.basename(paths[1]) == "foo"
        assert paths[0] != paths[1]
        contents = {Path(k.path).read_bytes() for k in kids}
        assert contents == {ELF_A, ELF_B}  # neither clobbered the other
        # Distinct sizes/hashes recorded too.
        assert kids[0].metadata_json["sha256"] != kids[1].metadata_json["sha256"]
        assert {k.metadata_json["size"] for k in kids} == {len(ELF_A), len(ELF_B)}
