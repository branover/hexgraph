"""Firmware filesystem manifest + add-from-FS (browse the unpacked tree, add any
file as a child target). The unpack itself is sandbox-gated; here we seed a
manifest + on-disk files and exercise list/add."""

import os

from hexgraph.db.models import Edge, EdgeType, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.filesystem import (
    FilesystemError, promote_file, list_filesystem, persistent_base, record_manifest,
)
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def _firmware_with_fs(s):
    p = create_project(s, name="fs")
    fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
    fw.kind  # noqa
    # lay down a fake extracted tree under the persistent base
    base = persistent_base(p, fw.id) / "root"
    (base / "usr" / "sbin").mkdir(parents=True, exist_ok=True)
    binpath = base / "usr" / "sbin" / "httpd"
    with open(fixture_path("vuln_httpd"), "rb") as src, open(binpath, "wb") as dst:
        dst.write(src.read())
    (base / "etc").mkdir(parents=True, exist_ok=True)
    (base / "etc" / "passwd").write_text("root:x:0:0\n")
    record_manifest(fw, method="unsquashfs", root_rel="root", files=[
        {"rel": "usr/sbin/httpd", "size": os.path.getsize(binpath), "is_elf": True},
        {"rel": "etc/passwd", "size": 10, "is_elf": False},
    ])
    return p, fw


def test_list_filesystem(hg_home):
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        fs = list_filesystem(p, fw)
        assert fs["unpacked"] is True and len(fs["files"]) == 2
        assert any(f["rel"] == "usr/sbin/httpd" and f["is_elf"] for f in fs["files"])
        assert all(f["added"] is False for f in fs["files"])


def test_promote_file(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)  # skip recon
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        child = promote_file(s, p, fw, "usr/sbin/httpd")
        assert child.name == "usr/sbin/httpd" and child.parent_id == fw.id
        # contains edge firmware → child
        e = s.query(Edge).filter(Edge.type == EdgeType.contains.value, Edge.src_id == fw.id,
                                 Edge.dst_id == child.id).all()
        assert len(e) == 1
        # manifest now marks it added; idempotent
        assert list_filesystem(p, fw)["files"][0]["added"] is True
        again = promote_file(s, p, fw, "usr/sbin/httpd")
        assert again.id == child.id


def test_add_unknown_rel_rejected(hg_home):
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        try:
            promote_file(s, p, fw, "nope/missing")
            assert False
        except FilesystemError:
            pass
