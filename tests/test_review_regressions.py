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


def test_host_is_local_rejects_ipv4_mapped_metadata():
    """Review #14: an IPv4-mapped/transitional IPv6 literal must not smuggle a
    link-local cloud-metadata IP past the loopback/private gate (it parses as IPv6
    with is_link_local False). Plain loopback/private/native-v6 forms still pass;
    the bare metadata v4 is still rejected."""
    from hexgraph.policy import _host_is_local

    # Accepted: real local destinations.
    assert _host_is_local("127.0.0.1")
    assert _host_is_local("::1")
    assert _host_is_local("10.0.0.5")
    assert _host_is_local("192.168.1.1")
    assert _host_is_local("172.16.0.9")

    # Rejected: the cloud-metadata endpoint and its IPv4-mapped/transitional disguises.
    assert not _host_is_local("169.254.169.254")
    assert not _host_is_local("::ffff:169.254.169.254")
    assert not _host_is_local("::ffff:a9fe:a9fe")          # same address, hextet form
    # Mapped/transitional forms are refused outright at this tier, even when the
    # embedded v4 would itself be private — a real local target is a plain literal.
    assert not _host_is_local("::ffff:127.0.0.1")
    assert not _host_is_local("::ffff:192.168.1.1")
    assert not _host_is_local("2002:7f00:0001::")          # 6to4 wrapping 127.0.0.1


def test_remote_probe_run_tool_allowlist_rejects_ls():
    """Review #15: `ls` is NOT in TOOLS, so an op=run_tool with tool=ls hits the
    allowlist boundary and yields an empty command (the real `ls` is op=='ls')."""
    from hexgraph.sandbox.probes.remote_probe import _build_command

    assert _build_command({"op": "run_tool", "tool": "ls", "path": "/etc"}) == ""
    assert _build_command({"op": "run_tool", "tool": "not_a_tool"}) == ""
    # A genuine allowlisted tool still resolves to its fixed template (no path appended).
    assert _build_command({"op": "run_tool", "tool": "id"}) == "id"
    assert _build_command({"op": "run_tool", "tool": "uname", "path": "/ignored"}) == "uname -a"
    # The real `ls` op is the separate op=='ls' block (path shell-quoted).
    assert _build_command({"op": "ls", "path": "/etc"}) == "ls -la /etc"


def test_ghidra_bridge_rejects_unsafe_function_name():
    """Review #17: a caller-supplied function name is validated against the strict
    symbol-name allowlist before any remote_eval, and the safe path passes the name
    as a BOUND variable (never interpolated into the eval'd code)."""
    import pytest

    from hexgraph.engine.ghidra_bridge import BridgeUnavailable, _RemoteOps

    class _FakeBridge:
        def __init__(self):
            self.calls = []

        def remote_eval(self, code, **kwargs):
            self.calls.append((code, kwargs))
            return "decompiled"

    ops = _RemoteOps(_FakeBridge())

    # Breakout attempts are refused before touching the bridge.
    for bad in ("'); __import__('os').system('id'); ('", "foo bar", "a\nb", "f()", ""):
        with pytest.raises(BridgeUnavailable):
            ops._decompile_one(bad)

    # A valid symbol name is passed as a bound `fn` kwarg, not interpolated.
    out = ops._decompile_one("sym.process_request")
    assert out == "decompiled"
    code, kwargs = ops.b.calls[-1]
    assert kwargs == {"fn": "sym.process_request"}
    assert "sym.process_request" not in code  # name never spliced into the eval string
