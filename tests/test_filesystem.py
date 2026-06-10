"""Firmware filesystem manifest + promote-file (browse the unpacked tree, promote any
file to a child target). The unpack itself is sandbox-gated; here we seed a
manifest + on-disk files and exercise list/add."""

import os

from hexgraph.db.models import Edge, EdgeType, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.filesystem import (
    FilesystemError, promote_file, list_filesystem, persistent_base, record_manifest,
)
from hexgraph.engine.targets.ingest import create_project, ingest_file

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
        # limit=None (the UI path) returns everything + a total, unchanged behavior + new counts.
        assert fs["total"] == 2 and fs["has_more"] is False and fs["next_offset"] is None


def test_list_filesystem_pagination_and_filters(hg_home):
    """F05: a big firmware unpacks to thousands of files; fs_list must page + filter so it
    doesn't overflow an agent's context. limit=None still returns all (the UI relies on it)."""
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        record_manifest(fw, method="binwalk", root_rel="root", files=[
            {"rel": "usr/sbin/svcd", "size": 100, "is_elf": True},
            {"rel": "usr/sbin/snmpd", "size": 200, "is_elf": True},
            {"rel": "usr/lib/libc.so", "size": 300, "is_elf": True},
            {"rel": "etc/passwd", "size": 10, "is_elf": False},
            {"rel": "etc/config.conf", "size": 20, "is_elf": False},
        ])
        # limit=None → all 5, no more pages
        allf = list_filesystem(p, fw)
        assert allf["total"] == 5 and len(allf["files"]) == 5 and allf["has_more"] is False
        # paginate
        pg = list_filesystem(p, fw, limit=2)
        assert len(pg["files"]) == 2 and pg["total"] == 5 and pg["next_offset"] == 2 and pg["has_more"] is True
        tail = list_filesystem(p, fw, offset=4, limit=2)
        assert len(tail["files"]) == 1 and tail["has_more"] is False and tail["next_offset"] is None
        # path_prefix scopes to a directory
        sbin = list_filesystem(p, fw, path_prefix="usr/sbin")
        assert sbin["total"] == 2 and all(f["rel"].startswith("usr/sbin") for f in sbin["files"])
        # elf_only keeps binaries
        elves = list_filesystem(p, fw, elf_only=True)
        assert elves["total"] == 3 and all(f["is_elf"] for f in elves["files"])
        # combined
        assert list_filesystem(p, fw, path_prefix="usr", elf_only=True)["total"] == 3


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
        # manifest now marks it added; a promoted file is a VISIBLE child (revealed).
        entry = list_filesystem(p, fw, session=s)["files"][0]
        assert entry["added"] is True and entry["revealed"] is True
        again = promote_file(s, p, fw, "usr/sbin/httpd")
        assert again.id == child.id


def test_list_filesystem_marks_hidden_child_unrevealed(hg_home):
    """An unpack-registered HIDDEN child reads as added but NOT revealed, so the UI
    can offer a 'Reveal' affordance instead of just 'added'."""
    from hexgraph.engine.targets.ingest import ingest_file

    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        # Register the ELF as a hidden child (what unpack does) + mark the manifest entry.
        child = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd",
                            parent=fw, visible=False)
        meta = dict(fw.metadata_json)
        fsmeta = dict(meta["filesystem"])
        fsmeta["files"] = [{**f, "child_target_id": child.id} if f["rel"] == "usr/sbin/httpd" else f
                           for f in fsmeta["files"]]
        meta["filesystem"] = fsmeta
        fw.metadata_json = meta
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(fw, "metadata_json")
        s.flush()

        entry = next(f for f in list_filesystem(p, fw, session=s)["files"] if f["rel"] == "usr/sbin/httpd")
        assert entry["added"] is True and entry["revealed"] is False


def test_add_unknown_rel_rejected(hg_home):
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        try:
            promote_file(s, p, fw, "nope/missing")
            assert False
        except FilesystemError:
            pass
