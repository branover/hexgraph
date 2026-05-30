"""M3: LLM-backed tasks via the backend seam (developed against the mock)."""

import pytest

from hexgraph.db.models import Edge, EdgeType, Finding, Project, Target, TaskStatus
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync


def _project_with_two_targets(session):
    """A project with two ELF targets (no Docker needed: register, skip recon)."""
    from conftest import fixture_path

    project = create_project(session, name="m3")
    httpd = ingest_file(session, project, fixture_path("vuln_httpd"), name="sbin/httpd")
    httpd.metadata_json = {"imports": ["strcpy", "printf"], "mitigations": {"canary": False}}
    lib = ingest_file(session, project, fixture_path("libupnp.so"), name="usr/lib/libupnp.so")
    session.flush()
    return project, httpd, lib


def test_static_analysis_critical_overflow(hg_home):
    with session_scope() as s:
        project, httpd, _lib = _project_with_two_targets(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="static_analysis",
            backend="mock", params={"mock_scenario": "critical_overflow", "function": "cgi_handler"},
        )
        tid, pid, hid = task.id, project.id, httpd.id

    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).one()
        assert f.severity == "critical"
        assert f.category == "memory-safety"
        assert "cgi_handler" in f.title
        assert f.evidence_json["function"] == "cgi_handler"
        # critical_overflow carries two suggested follow-ups (harness + sweep).
        assert len(f.suggested_followups_json) == 2
        # related_target_refs (sibling) -> a related_to edge.
        rel = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.related_to).all()
        assert len(rel) == 1 and rel[0].src_target_id == hid


def test_no_findings_scenario_succeeds_empty(hg_home):
    with session_scope() as s:
        project, httpd, _ = _project_with_two_targets(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="static_analysis",
            backend="mock", params={"mock_scenario": "no_findings"},
        )
        tid = task.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        assert s.query(Finding).filter(Finding.task_id == tid).count() == 0


def test_malformed_then_valid_repairs(hg_home):
    with session_scope() as s:
        project, httpd, _ = _project_with_two_targets(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="static_analysis",
            backend="mock", params={"mock_scenario": "malformed_then_valid"},
        )
        tid = task.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).one()
        assert f.evidence_json["function"] == "log_event"


@pytest.mark.parametrize("scenario", ["error_rate_limit", "error_timeout"])
def test_error_scenarios_mark_task_failed(hg_home, scenario):
    with session_scope() as s:
        project, httpd, _ = _project_with_two_targets(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="static_analysis",
            backend="mock", params={"mock_scenario": scenario},
        )
        tid = task.id
    assert run_task_sync(tid) == "failed"
    with session_scope() as s:
        assert s.query(Finding).filter(Finding.task_id == tid).count() == 0


def test_reverse_engineering_annotation(hg_home):
    with session_scope() as s:
        project, httpd, _ = _project_with_two_targets(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="reverse_engineering", backend="mock",
        )
        tid = task.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).one()
        assert f.category == "annotation" and f.severity == "info"


def test_hash_fallback_never_picks_error_scenario(hg_home):
    """Without an explicit scenario, auto-pick must land on a successful scenario."""
    from hexgraph.llm.mock import MockLLMBackend
    from hexgraph.llm.base import LLMRequest

    m = MockLLMBackend()
    for i in range(50):
        sc = m._resolve_scenario(LLMRequest(task_type="static_analysis", task_id=f"t-{i}"))
        assert not sc.startswith("error_")
