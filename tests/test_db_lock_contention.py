"""SQLite write-lock contention under HexGraph's multi-writer model (the web app + a CLI
ingest + a detached recon task all write the same file). A real user hit repeated
"database is locked" crashes importing a large firmware partition while `hexgraph serve`
was running: recon holds the single SQLite write lock across its whole Docker sandbox run,
far longer than the old 5s busy_timeout, so a concurrent writer's very first INSERT failed.

These guard the three fixes: a generous busy_timeout, recon releasing the lock before its
Docker probe, and directory-import committing its registration before the recon phase.
"""

from sqlalchemy import text

from hexgraph.db.models import Project, Target
from hexgraph.db.session import BUSY_TIMEOUT_MS, get_engine, get_session, session_scope
from hexgraph.engine.re import recon
from hexgraph.engine.targets.dirimport import ingest_directory
from hexgraph.engine.targets.ingest import create_project, ingest_file

ELF = b"\x7fELF\x01\x01\x01" + b"a binary" + b"\x00" * 8


def test_busy_timeout_is_generous():
    """The busy_timeout must comfortably exceed a normal slow-but-legitimate write hold
    (a Docker recon, a file copy) so a concurrent writer WAITS rather than crashing. 5s was
    too short; regression-guard the generous value on an actual connection."""
    assert BUSY_TIMEOUT_MS >= 30_000
    with get_engine().connect() as conn:
        got = conn.exec_driver_sql("PRAGMA busy_timeout").scalar()
    assert got == BUSY_TIMEOUT_MS


def test_execute_recon_releases_write_lock_before_docker_probe(hg_home, tmp_path):
    """The core fix: recon must COMMIT (release the single SQLite write lock) before it runs
    the seconds-to-minutes Docker probe, otherwise every other writer is starved for the whole
    sandbox run. Proven from INSIDE a fake probe: a separate connection must be able to acquire
    the write lock while the probe 'runs' — impossible if recon still held it."""
    f = tmp_path / "bin"
    f.write_bytes(ELF)
    captured = {}

    class _Probe:
        def run_json_probe(self, probe, path, **kw):
            # We are now "inside Docker". A fresh connection must be able to WRITE, which is
            # only true if execute_recon already committed and released the lock.
            conn = get_session()
            try:
                conn.execute(text("UPDATE project SET name = name WHERE id = :i"),
                             {"i": captured["pid"]})
                conn.commit()
                captured["acquired_during_probe"] = True
            except Exception as exc:  # noqa: BLE001
                captured["acquired_during_probe"] = False
                captured["err"] = str(exc)
            finally:
                conn.close()
            return {"kind": "executable", "format": "elf", "imports": [], "strings": []}

    with session_scope() as s:
        p = create_project(s, name="recon-lock")
        captured["pid"] = p.id
        t = ingest_file(s, p, f, name="bin")
        recon.run_recon(s, p, t, _Probe())

    assert captured.get("acquired_during_probe") is True, captured.get("err")


def test_ingest_directory_commits_registration_before_returning(hg_home, tmp_path):
    """Directory-import must release the write lock the moment the tree is registered (root +
    children + manifest committed) rather than holding it open into the caller's recon phase —
    otherwise a concurrent writer waits on the ingest for the entire recon run. Verified by
    reading the children back from an INDEPENDENT session opened after ingest_directory returns
    but before any recon: they must already be committed."""
    src = tmp_path / "rootfs"
    (src / "usr").mkdir(parents=True)
    (src / "usr" / "httpd").write_bytes(ELF)

    with session_scope() as s:
        p = create_project(s, name="dir-commit")
        pid = p.id
        root, children = ingest_directory(s, p, src, name="rootfs")
        root_id = root.id
        assert len(children) == 1

        # A DIFFERENT connection — sees only COMMITTED rows. If ingest_directory hadn't
        # committed, this fresh session would see zero children for the new root.
        with session_scope() as s2:
            seen = s2.query(Target).filter(Target.parent_id == root_id).all()
            assert len(seen) == 1
            assert s2.get(Project, pid) is not None
