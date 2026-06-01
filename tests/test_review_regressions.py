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


def test_dedupe_keeps_earlier_drops_later_edges_and_spares_distinct(hg_home):
    """Offline pin (review #11) of the dedup edge-cascade with the rigor of test_nodemerge:
    two same-signature findings with DISTINCT created_at (each with its own `about` edge) plus
    one DISTINCT finding → exactly one removed, the EARLIER row survives, the later row's edges
    are gone, and the distinct finding + its edge are untouched."""
    import datetime as _dt

    from hexgraph.db.models import Finding
    from hexgraph.engine.edges import add_edge
    from hexgraph.db.models import EdgeType

    with session_scope() as s:
        p = create_project(s, name="dd")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        dup = FModel(title="overflow in h", severity="high", confidence="high",
                     category="memory-safety", summary="s", reasoning="r",
                     evidence=Evidence(function="h", sink="strcpy"))
        distinct = FModel(title="auth bypass in g", severity="critical", confidence="high",
                          category="auth", summary="s2", reasoning="r2",
                          evidence=Evidence(function="g"))
        early = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=dup)
        late = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=dup)
        other = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=distinct)
        # Force DISTINCT, ordered created_at so "earliest survives" is unambiguous.
        base = _dt.datetime(2026, 1, 1, 0, 0, 0)
        early.created_at = base
        late.created_at = base + _dt.timedelta(seconds=10)
        other.created_at = base + _dt.timedelta(seconds=5)
        # An extra edge on each finding beyond the auto `about`, so the cascade is visible.
        add_edge(s, project_id=p.id, src=("finding", late.id), dst=("target", t.id),
                 type=EdgeType.about, origin="test")
        add_edge(s, project_id=p.id, src=("finding", other.id), dst=("target", t.id),
                 type=EdgeType.about, origin="test")
        s.flush()
        pid, early_id, late_id, other_id = p.id, early.id, late.id, other.id

        edges_of = lambda fid: s.query(Edge).filter(
            Edge.project_id == pid,
            or_((Edge.src_kind == "finding") & (Edge.src_id == fid),
                (Edge.dst_kind == "finding") & (Edge.dst_id == fid))).count()
        assert edges_of(late_id) >= 1 and edges_of(other_id) >= 1

        removed = dedupe_findings(s, pid)
        assert removed == 1
        live = {fid for (fid,) in s.query(Finding.id).filter(Finding.project_id == pid)}
        assert early_id in live          # the EARLIER same-signature row survives
        assert late_id not in live       # the later duplicate is gone
        assert other_id in live          # the distinct finding is untouched
        assert edges_of(late_id) == 0    # the removed row's edges cascaded away (no orphans)
        assert edges_of(other_id) >= 1   # the distinct finding keeps its edges


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
