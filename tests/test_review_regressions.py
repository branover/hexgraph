"""Regression guards for the code-review fixes — each test fails if the bug returns."""

import os

from sqlalchemy import or_

from hexgraph.db.models import Edge, Target
from hexgraph.db.session import session_scope
from hexgraph.engine.dedup import dedupe_findings
from hexgraph.engine.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.targets import archive_target, file_sha256, restore_matching
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def test_ingest_sets_sha256_so_restore_works_without_recon(hg_home):
    """Archive/restore identity must not depend on a Docker recon run: ingest_file
    computes sha256, so re-adding the same bytes restores instead of duplicating."""
    src = fixture_path("vuln_httpd")
    with session_scope() as s:
        p = create_project(s, name="r")
        t = ingest_file(s, p, src, name="httpd")          # no recon
        assert (t.metadata_json or {}).get("sha256") == file_sha256(src)
        archive_target(s, p.id, t.id)
        s.refresh(t)                                      # bulk update; refresh the ORM object
        assert t.archived is True
        restored = restore_matching(s, p, src)            # same bytes
        assert restored is not None and restored.id == t.id
        s.refresh(restored)                               # bulk update; re-read DB state
        assert restored.archived is False
        # exactly one target — restored, not duplicated
        assert s.query(Target).filter(Target.project_id == p.id).count() == 1


def test_dedupe_findings_does_not_orphan_edges(hg_home):
    with session_scope() as s:
        p = create_project(s, name="d")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = FModel(title="overflow in h", severity="high", confidence="high",
                   category="memory-safety", summary="s", reasoning="r",
                   evidence=Evidence(function="h", sink="strcpy"))
        # two identical-signature findings → each persist_finding makes an `about` edge
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f)
        keeper = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=f)
        pid, keeper_id = p.id, keeper.id
        # the keeper is the EARLIER row; capture both ids
        all_finding_edges = lambda: (s.query(Edge).filter(
            Edge.project_id == pid,
            or_(Edge.src_kind == "finding", Edge.dst_kind == "finding")).all())
        assert len(all_finding_edges()) == 2

        removed = dedupe_findings(s, pid)
        assert removed == 1
        remaining = all_finding_edges()
        # the duplicate's edge is gone (no orphan), and every remaining finding-edge
        # points at a finding that still exists.
        assert len(remaining) == 1
        from hexgraph.db.models import Finding
        live_ids = {fid for (fid,) in s.query(Finding.id).filter(Finding.project_id == pid)}
        for e in remaining:
            ref = e.src_id if e.src_kind == "finding" else e.dst_id
            assert ref in live_ids


def test_worker_marks_task_failed_on_exception(hg_home):
    """An exception inside a task (here: a fuzzing task while the static-only policy
    forbids execution) is caught by the worker → status 'failed' + error.txt."""
    with session_scope() as s:
        p = create_project(s, name="w")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="fuzzing")
        tid, log_path = task.id, task.log_path

    status = run_task_sync(tid)
    assert status == "failed"
    assert os.path.isfile(os.path.join(log_path, "error.txt"))
