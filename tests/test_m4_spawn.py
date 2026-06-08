"""M4: one-click follow-up spawn, pattern_sweep sibling findings, harness compile."""

import pytest

from hexgraph.db.models import Edge, EdgeType, Finding, Task, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.followups import spawn_followup
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync

from conftest import fixture_path


def _two_target_project(s):
    project = create_project(s, name="m4")
    httpd = ingest_file(s, project, fixture_path("vuln_httpd"), name="sbin/httpd")
    httpd.kind = TargetKind.executable
    httpd.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
    lib = ingest_file(s, project, fixture_path("libupnp.so"), name="usr/lib/libupnp.so")
    lib.kind = TargetKind.shared_library
    s.flush()
    return project, httpd, lib


def test_followup_spawns_task_with_parent_finding(hg_home):
    with session_scope() as s:
        project, httpd, _lib = _two_target_project(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="static_analysis",
            backend="mock", params={"mock_scenario": "critical_overflow", "function": "cgi_handler"},
        )
        tid = task.id
    run_task_sync(tid)

    with session_scope() as s:
        seed = s.query(Finding).filter(Finding.task_id == tid).one()
        # critical_overflow suggests a harness_generation + pattern_sweep follow-up.
        labels = [fu["task_type"] for fu in seed.suggested_followups_json]
        assert "pattern_sweep" in labels and "harness_generation" in labels
        idx = labels.index("harness_generation")
        spawned = spawn_followup(s, seed.id, idx)
        spawned_id, sfid = spawned.id, seed.id

    with session_scope() as s:
        t = s.get(Task, spawned_id)
        assert t.type == "harness_generation"
        assert t.parent_finding_id == sfid


def test_pattern_sweep_homes_finding_on_sibling_and_links(hg_home):
    with session_scope() as s:
        project, httpd, lib = _two_target_project(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="pattern_sweep",
            backend="mock", params={"mock_scenario": "match_found", "sink": "strcpy"},
        )
        tid, pid, hid, lid = task.id, project.id, httpd.id, lib.id
    assert run_task_sync(tid) == "succeeded"

    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).one()
        # finding is homed on the sibling library, not the seed executable
        assert f.target_id == lid
        # pattern_sweep draws an attributed instance_of_pattern edge seed → sibling
        rel = s.query(Edge).filter(
            Edge.project_id == pid, Edge.type == EdgeType.instance_of_pattern.value
        ).all()
        assert any(e.src_id == hid and e.dst_id == lid and e.origin == "llm" for e in rel)


def test_followup_index_out_of_range_raises(hg_home):
    with session_scope() as s:
        project, httpd, _ = _two_target_project(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="reverse_engineering", backend="mock",
        )
        tid = task.id
    run_task_sync(tid)
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).first()
        with pytest.raises(IndexError):
            spawn_followup(s, f.id, 99)


def test_harness_generation_compiles_in_sandbox(hg_home, sandbox, monkeypatch):
    monkeypatch.delenv("HEXGRAPH_DISABLE_SANDBOX_BUILD", raising=False)
    with session_scope() as s:
        project, httpd, _ = _two_target_project(s)
        task = create_task(
            s, project=project, target_id=httpd.id, type="harness_generation",
            backend="mock", params={"mock_scenario": "compiles", "function": "parse_request"},
        )
        tid = task.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        f = s.query(Finding).filter(Finding.task_id == tid).one()
        build = (f.evidence_json.get("extra") or {}).get("build") or {}
        # real compile result from the sandbox (compile_probe), not the mock's claim
        assert build.get("tool") == "compile_probe"
        assert build.get("result") == "ok"
