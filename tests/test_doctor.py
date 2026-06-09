"""F02 — the orphaned project-dir doctor (engine.maintenance + the CLI/MCP surfaces).

proj_list and the on-disk project dirs (HEXGRAPH_HOME/projects/) can drift: a removed DB
project leaves its dir behind, a half-finished ingest leaves a dir with no committed project.
The doctor reconciles the two — read-only report by default, --clean to delete orphan dirs.
A DB project is NEVER deleted here (only via the explicit delete path); a DB project with a
missing dir is flagged, not auto-fixed.
"""

from hexgraph.config import projects_dir
from hexgraph.db.session import session_scope
from hexgraph.engine import maintenance
from hexgraph.engine.targets.ingest import create_project


def _seed_project_with_dir(s, name):
    """A DB project whose data_dir actually exists on disk (create_project makes the dir)."""
    p = create_project(s, name=name)
    return p


def test_report_flags_orphan_dir(hg_home):
    with session_scope() as s:
        p = _seed_project_with_dir(s, "live")
        live_id = p.id
    # Plant an orphan dir (no matching DB project) — the dogfood "3 dirs, 1 project" shape.
    orphan = projects_dir() / "orphan-no-db-project"
    orphan.mkdir(parents=True)
    (orphan / "artifacts").mkdir()

    with session_scope() as s:
        report = maintenance.project_dir_report(s)

    assert report["db_projects"] == 1
    assert report["on_disk_dirs"] == 2  # the live project dir + the orphan
    assert "orphan-no-db-project" in report["orphan_dirs"]
    assert live_id not in report["orphan_dirs"]  # the live project's dir is NOT an orphan
    assert report["missing_dirs"] == []  # the live project's dir exists
    # Read-only: the orphan dir is still on disk.
    assert orphan.is_dir()


def test_report_flags_missing_dir(hg_home):
    """A DB project whose dir was deleted out from under it is flagged (data gone, not fixed)."""
    import shutil

    with session_scope() as s:
        p = _seed_project_with_dir(s, "gone")
        pid, ddir = p.id, p.data_dir
    shutil.rmtree(ddir)

    with session_scope() as s:
        report = maintenance.project_dir_report(s)
    missing = {m["project_id"] for m in report["missing_dirs"]}
    assert pid in missing
    assert report["orphan_dirs"] == []


def test_clean_deletes_orphans_only(hg_home):
    with session_scope() as s:
        p = _seed_project_with_dir(s, "keep")
        keep_dir = p.data_dir
    orphan = projects_dir() / "delete-me"
    orphan.mkdir(parents=True)

    with session_scope() as s:
        report = maintenance.prune_orphan_dirs(s)

    assert report["deleted"] == ["delete-me"]
    assert not orphan.exists()  # orphan removed
    from pathlib import Path
    assert Path(keep_dir).is_dir()  # the live project's dir is untouched
    # The DB project itself is never deleted by the doctor.
    with session_scope() as s:
        report2 = maintenance.project_dir_report(s)
    assert report2["db_projects"] == 1
    assert report2["orphan_dirs"] == []


def test_cli_doctor_reports_and_cleans(hg_home, capsys):
    from hexgraph.cli import main

    with session_scope() as s:
        _seed_project_with_dir(s, "cliproj")
    orphan = projects_dir() / "cli-orphan"
    orphan.mkdir(parents=True)

    # Default: read-only report mentions the orphan and does NOT delete it.
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "cli-orphan" in out
    assert "--clean" in out  # hint to clean
    assert orphan.is_dir()

    # --clean removes the orphan.
    assert main(["doctor", "--clean"]) == 0
    out = capsys.readouterr().out
    assert "DELETED" in out and "cli-orphan" in out
    assert not orphan.exists()


def test_mcp_proj_doctor(hg_home):
    from hexgraph.agent.mcp_tools import doctor

    with session_scope() as s:
        _seed_project_with_dir(s, "mcpproj")
    orphan = projects_dir() / "mcp-orphan"
    orphan.mkdir(parents=True)

    report = doctor()
    assert "mcp-orphan" in report["orphan_dirs"]
    assert orphan.is_dir()  # read-only by default

    cleaned = doctor(clean=True)
    assert cleaned["deleted"] == ["mcp-orphan"]
    assert not orphan.exists()


def test_proj_doctor_advertised_in_catalog():
    from hexgraph.agent import mcp_tools as M

    spec = next((t for t in M.catalog({"read"}) if t["name"] == "proj_doctor"), None)
    assert spec is not None and callable(spec["fn"])
    assert "clean" in spec["schema"]["properties"]


def test_clean_never_prunes_through_a_symlink(hg_home):
    """A symlinked 'orphan' (name isn't a live id) must NOT be pruned: `.resolve()` would
    rewrite it to its real target, so rmtree'ing the resolved path could wipe a live sibling
    project's dir. The symlink is reported but never deleted, and its target survives."""
    import os
    from pathlib import Path

    with session_scope() as s:
        live = _seed_project_with_dir(s, "live")
        live_dir = Path(live.data_dir)
    (live_dir / "keep.txt").write_text("precious")
    # An orphan ENTRY that is a symlink pointing at the live sibling's real dir.
    link = projects_dir() / "orphan-symlink"
    os.symlink(live_dir, link)

    with session_scope() as s:
        report = maintenance.prune_orphan_dirs(s)

    assert "orphan-symlink" in report["orphan_dirs"]   # still surfaced in the report
    assert "orphan-symlink" not in report["deleted"]    # but NEVER pruned through the link
    assert link.is_symlink()                            # the link itself is left alone
    assert (live_dir / "keep.txt").read_text() == "precious"  # the real target is intact
