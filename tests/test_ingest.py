"""M1: ingest a lone file -> project + one target, artifact copied (SPEC §9 M1)."""

from pathlib import Path

from hexgraph.db.models import Project, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file


def test_ingest_creates_project_and_target(hg_home, tmp_path):
    src = tmp_path / "vuln_httpd"
    src.write_bytes(b"\x7fELF fake binary bytes")

    with session_scope() as session:
        project = create_project(session, name="demo", llm_backend="mock")
        target = ingest_file(session, project, src, name="httpd")
        project_id, target_id = project.id, target.id

    with session_scope() as session:
        p = session.get(Project, project_id)
        t = session.get(Target, target_id)
        assert p is not None and p.name == "demo"
        assert t is not None and t.name == "httpd"
        assert t.kind == TargetKind.unknown  # recon refines this in M2
        assert t.parent_id is None
        # artifact was copied under the project's data dir, original untouched.
        copied = Path(t.path)
        assert copied.is_file()
        assert copied.read_bytes() == src.read_bytes()
        assert str(project_id) in t.path
        assert t.metadata_json["size"] == src.stat().st_size


def test_ingest_into_existing_project(hg_home, tmp_path):
    src = tmp_path / "lib.so"
    src.write_bytes(b"\x7fELF lib")
    with session_scope() as session:
        project = create_project(session, name="p2")
        t1 = ingest_file(session, project, src, name="a")
        t2 = ingest_file(session, project, src, name="b", parent=t1)
        assert t2.parent_id == t1.id
        assert t1.project_id == t2.project_id == project.id


def test_ingest_basename_collision_no_overwrite(hg_home, tmp_path):
    """Two DIFFERENT files that share a basename must NOT clobber each other on
    disk. A flat artifacts/<basename> layout silently overwrote the first with the
    second, so recon/decompile later read the WRONG bytes for one target — undetected
    graph corruption. Each target now lands in its own per-id artifact dir."""
    a = tmp_path / "a" / "image.bin"
    b = tmp_path / "b" / "image.bin"
    a.parent.mkdir()
    b.parent.mkdir()
    a.write_bytes(b"\x7fELF AAAA distinct bytes for target one")
    b.write_bytes(b"\x7fELF BB different bytes, different size, target two")
    assert a.read_bytes() != b.read_bytes()

    with session_scope() as session:
        project = create_project(session, name="collide")
        ta = ingest_file(session, project, a, name="image.bin")
        tb = ingest_file(session, project, b, name="image.bin")
        ta_id, tb_id = ta.id, tb.id

    with session_scope() as session:
        ta = session.get(Target, ta_id)
        tb = session.get(Target, tb_id)
        # Distinct on-disk paths despite the shared basename.
        assert ta.path != tb.path
        assert Path(ta.path).is_file() and Path(tb.path).is_file()
        # Each artifact reads back its OWN original bytes (no clobber).
        assert Path(ta.path).read_bytes() == a.read_bytes()
        assert Path(tb.path).read_bytes() == b.read_bytes()
        # Recon-derived facts (size + content hash) differ, as the inputs do.
        assert ta.metadata_json["size"] != tb.metadata_json["size"]
        assert ta.metadata_json["sha256"] != tb.metadata_json["sha256"]
        # Both artifacts namespaced under their target id (browsable layout).
        assert ta.id in ta.path and tb.id in tb.path
