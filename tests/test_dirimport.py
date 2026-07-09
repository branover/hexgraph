"""Directory-import: the alternative to `hexgraph ingest <firmware.bin>` for when the
operator already has an extracted/mounted filesystem on disk (no packed blob to unpack).
Covers the host-side walk+copy (symlink/special-file skip, F08 ELF dedup), the shared
`recon_children` threshold reuse (small=inline, large=one detached batch — same
infrastructure `analyze_target`'s firmware path uses, so this doesn't become a fourth
instance of the synchronous-per-item-loop bug), and the CLI/MCP/API consumer wiring.
"""

import os

from hexgraph.db.models import Target, Task, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine import pipeline
from hexgraph.engine.targets.dirimport import ingest_directory
from hexgraph.engine.targets.ingest import create_project

ELF_A = b"\x7fELF\x01\x01\x01" + b"binary A" + b"\x00" * 8
ELF_B = b"\x7fELF\x01\x01\x01" + b"binary B, distinct bytes" + b"\x00" * 8


def _fake_facts(session, project, target, runner):
    return {"kind": "executable", "format": "elf"}


def test_walk_skips_symlinks_and_special_files(hg_home, tmp_path):
    src = tmp_path / "rootfs"
    (src / "usr" / "bin").mkdir(parents=True)
    (src / "usr" / "bin" / "real").write_bytes(b"regular file contents")
    os.symlink(src / "usr" / "bin" / "real", src / "usr" / "bin" / "link_to_real")
    os.symlink(src / "usr" / "bin", src / "usr" / "bin_link")  # a symlinked directory
    try:
        os.mkfifo(src / "usr" / "bin" / "a_fifo")
    except (AttributeError, OSError):
        pass  # platform without mkfifo — the regular-file/symlink assertions still hold

    with session_scope() as s:
        p = create_project(s, name="dirimport-walk")
        target, children = ingest_directory(s, p, src, name="rootfs")

        files = {f["rel"]: f for f in target.metadata_json["filesystem"]["files"]}
        assert "usr/bin/real" in files
        assert not any(rel.startswith("usr/bin_link") for rel in files)  # symlinked dir not walked
        assert "usr/bin/link_to_real" not in files                       # symlinked file skipped
        assert "usr/bin/a_fifo" not in files                             # special file skipped
        assert children == []                                            # no ELF in this tree


def test_ingest_directory_registers_elf_children_hidden(hg_home, tmp_path):
    src = tmp_path / "rootfs"
    (src / "usr" / "sbin").mkdir(parents=True)
    (src / "usr" / "sbin" / "httpd").write_bytes(ELF_A)
    (src / "etc").mkdir()
    (src / "etc" / "config.txt").write_bytes(b"not an elf")

    with session_scope() as s:
        p = create_project(s, name="dirimport-elf")
        target, children = ingest_directory(s, p, src, name="rootfs")

        assert target.path == ""             # no single byte artifact at the root
        assert target.kind.value == "firmware_image"
        assert len(children) == 1
        child = children[0]
        assert child.parent_id == target.id
        assert child.visible is False         # eager ELF registration is hidden, like unpack_firmware

        files = {f["rel"]: f for f in target.metadata_json["filesystem"]["files"]}
        assert files["usr/sbin/httpd"]["is_elf"] is True
        assert files["usr/sbin/httpd"]["child_target_id"] == child.id
        assert files["etc/config.txt"]["is_elf"] is False
        assert files["etc/config.txt"]["child_target_id"] is None

        from hexgraph.db.models import Edge, EdgeType
        edge = (s.query(Edge)
                .filter(Edge.project_id == p.id, Edge.type == EdgeType.contains.value,
                        Edge.src_id == target.id, Edge.dst_id == child.id)
                .one())
        assert edge.attrs_json.get("path") == "usr/sbin/httpd"


def test_ingest_directory_dedups_byte_identical_elfs(hg_home, tmp_path):
    src = tmp_path / "rootfs"
    src.mkdir()
    (src / "boot").mkdir()
    (src / "pkg").mkdir()
    (src / "boot" / "svc").write_bytes(ELF_A)
    (src / "pkg" / "svc").write_bytes(ELF_A)          # byte-identical, different path
    (src / "bin_unique").write_bytes(ELF_B)

    with session_scope() as s:
        p = create_project(s, name="dirimport-dedup")
        target, children = ingest_directory(s, p, src, name="rootfs")

        assert len(children) == 2  # the dup collapses to one; bin_unique is its own
        elf_targets = s.query(Target).filter(Target.parent_id == target.id).all()
        assert len(elf_targets) == 2

        # os.walk's directory-entry order isn't guaranteed, so either "boot/svc" or
        # "pkg/svc" may be the keeper — assert the dedup relationship, not which one wins.
        files = {f["rel"]: f for f in target.metadata_json["filesystem"]["files"]}
        boot_entry, pkg_entry = files["boot/svc"], files["pkg/svc"]
        assert boot_entry["child_target_id"] == pkg_entry["child_target_id"]
        assert ("dedup_of" in boot_entry) != ("dedup_of" in pkg_entry)  # exactly one is the dup


def test_not_a_directory_raises(hg_home, tmp_path):
    f = tmp_path / "plainfile"
    f.write_bytes(b"hi")
    with session_scope() as s:
        p = create_project(s, name="dirimport-notadir")
        try:
            ingest_directory(s, p, f)
            assert False, "expected NotADirectoryError"
        except NotADirectoryError:
            pass


def _rootfs_with_n_elfs(tmp_path, n):
    src = tmp_path / "rootfs"
    src.mkdir()
    for i in range(n):
        (src / f"bin{i}").write_bytes(ELF_A[:-1] + bytes([i % 256]))  # unique bytes each — no dedup
    return src


def test_ingest_directory_and_analyze_stays_synchronous_below_threshold(hg_home, tmp_path, monkeypatch):
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    monkeypatch.setattr(pipeline, "run_recon", _fake_facts)

    src = _rootfs_with_n_elfs(tmp_path, pipeline.CHILD_RECON_DETACH_THRESHOLD - 1)
    with session_scope() as s:
        p = create_project(s, name="dirimport-small")
        summary = pipeline.ingest_directory_and_analyze(s, p, src, name="rootfs", runner=None)

        assert summary["recon_status"] == "done"
        assert summary["children_count"] == pipeline.CHILD_RECON_DETACH_THRESHOLD - 1
        assert len(spawned) == 0
        root = s.get(Target, summary["root_target_id"])
        assert "recon_children_task_id" not in (root.metadata_json or {})


def test_ingest_directory_and_analyze_detaches_large_tree(hg_home, tmp_path, monkeypatch):
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    monkeypatch.setattr(pipeline, "run_recon", _fake_facts)

    n = pipeline.CHILD_RECON_DETACH_THRESHOLD + 5
    src = _rootfs_with_n_elfs(tmp_path, n)
    with session_scope() as s:
        p = create_project(s, name="dirimport-large")
        summary = pipeline.ingest_directory_and_analyze(s, p, src, name="rootfs", runner=None)

        assert summary["recon_status"] == "queued"
        assert summary["children_count"] == n
        assert len(summary["children"]) == n     # child rows exist even though unreconned
        assert len(spawned) == 1                 # ONE batch task, not one per child

        task = s.get(Task, spawned[0])
        assert task.type == "recon_children_batch" and task.status == TaskStatus.queued
        assert task.target_id == summary["root_target_id"]
        assert len(task.params_json["target_ids"]) == n


def test_cli_ingest_routes_directory_to_dir_import(hg_home, tmp_path, capsys):
    import argparse

    from hexgraph.cli import _cmd_ingest

    src = tmp_path / "rootfs"
    src.mkdir()
    (src / "readme.txt").write_bytes(b"not a binary")

    args = argparse.Namespace(path=str(src), name="myrootfs", project=None,
                              backend="mock", no_recon=True)
    rc = _cmd_ingest(args)
    assert rc == 0
    out = capsys.readouterr().out
    assert "0 child target(s) registered, recon skipped" in out

    with session_scope() as s:
        t = s.query(Target).filter(Target.name == "myrootfs").one()
        assert t.kind.value == "firmware_image"


def test_mcp_ingest_dir_reports_docker_unavailable(hg_home, tmp_path, monkeypatch):
    from hexgraph.agent import mcp_tools as M

    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)

    src = tmp_path / "rootfs"
    src.mkdir()
    (src / "bin").write_bytes(ELF_A)

    r = M.ingest_dir(str(src), name="dockerless")
    assert r["recon"] is False
    assert r["children_count"] == 1
    assert "root_target_id" in r


def test_mcp_ingest_dir_rejects_missing_path(hg_home, tmp_path):
    from hexgraph.agent import mcp_tools as M

    r = M.ingest_dir(str(tmp_path / "does-not-exist"))
    assert "error" in r


def test_api_add_target_dir_no_recon(hg_home, tmp_path):
    from fastapi.testclient import TestClient

    from hexgraph.api.app import create_app
    from hexgraph.engine.targets.ingest import create_project

    src = tmp_path / "rootfs"
    src.mkdir()
    (src / "bin").write_bytes(ELF_A)

    with session_scope() as s:
        p = create_project(s, name="api-dirimport")
        pid = p.id

    client = TestClient(create_app())
    resp = client.post(f"/api/projects/{pid}/targets/dir",
                       json={"path": str(src), "name": "rootfs", "recon": False})
    assert resp.status_code == 200
    body = resp.json()
    assert body["recon"] is False
    assert len(body["children"]) == 1


def test_api_add_target_dir_rejects_non_directory(hg_home, tmp_path):
    from fastapi.testclient import TestClient

    from hexgraph.api.app import create_app
    from hexgraph.engine.targets.ingest import create_project

    f = tmp_path / "plainfile"
    f.write_bytes(b"hi")
    with session_scope() as s:
        p = create_project(s, name="api-dirimport-bad")
        pid = p.id

    client = TestClient(create_app())
    resp = client.post(f"/api/projects/{pid}/targets/dir", json={"path": str(f)})
    assert resp.status_code == 400
