"""M1: ingest a lone file -> project + one target, artifact copied (SPEC §9 M1)."""

from pathlib import Path

from hexgraph.db.models import Project, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file


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
