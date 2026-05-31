"""P2: Context Bundle, CAS, cassette, analysis_run + diff."""

import json

from hexgraph.db.models import AnalysisRun, ContextBundle, ContextItem
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync

from conftest import fixture_path


def _run_sa(s, name, scenario="critical_overflow"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {"imports": ["strcpy", "printf"], "mitigations": {"canary": False},
                       "strings": ["/cgi-bin/", "token="]}
    task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                       backend="mock", params={"mock_scenario": scenario, "function": "cgi_handler"})
    return p, t, task


def test_cas_dedup_and_roundtrip(hg_home):
    from hexgraph.engine import cas

    with session_scope() as s:
        p = create_project(s, name="cas")
        sha1 = cas.put(p, "hello world")
        sha2 = cas.put(p, "hello world")
        assert sha1 == sha2
        assert cas.get_text(p, sha1) == "hello world"
        assert cas.size_report(p)["objects"] == 1


def test_bundle_created_and_linked(hg_home):
    with session_scope() as s:
        p, t, task = _run_sa(s, "b")
        tid, pid = task.id, p.id
    assert run_task_sync(tid) == "succeeded"
    with session_scope() as s:
        from hexgraph.db.models import Task

        task = s.get(Task, tid)
        assert task.context_bundle_id
        bundle = s.get(ContextBundle, task.context_bundle_id)
        assert bundle and bundle.bundle_sha and bundle.token_estimate > 0
        items = s.query(ContextItem).filter(ContextItem.bundle_id == bundle.id).all()
        kinds = {i.kind for i in items if i.included}
        assert "recon_facts" in kinds and "imports" in kinds


def test_bundle_sha_is_deterministic(hg_home):
    """Same inputs → identical bundle_sha across two runs (reproducibility)."""
    with session_scope() as s:
        p1, _t, task1 = _run_sa(s, "det1")
        t1 = task1.id
    run_task_sync(t1)
    with session_scope() as s:
        p2, _t2, task2 = _run_sa(s, "det2")
        t2 = task2.id
    run_task_sync(t2)
    with session_scope() as s:
        shas = [b.bundle_sha for b in s.query(ContextBundle).all()]
        # both projects assembled the same facts → same sha
        assert len(set(shas)) == 1


def test_analysis_run_recorded_and_diff(hg_home):
    with session_scope() as s:
        p, t, task = _run_sa(s, "run1", scenario="critical_overflow")
        tA, pid, tgt = task.id, p.id, t.id
    run_task_sync(tA)
    with session_scope() as s:
        # second run over the same target, clean scenario → different findings
        from hexgraph.db.models import Project, Target

        project = s.get(Project, pid)
        task2 = create_task(s, project=project, target_id=tgt, type="static_analysis",
                            backend="mock", params={"mock_scenario": "no_findings"})
        tB = task2.id
    run_task_sync(tB)
    with session_scope() as s:
        runs = s.query(AnalysisRun).filter(AnalysisRun.anchor_id == tgt).all()
        assert len(runs) == 2
        ra = next(r for r in runs if r.finding_count == 1)
        rb = next(r for r in runs if r.finding_count == 0)
        from hexgraph.engine.runs import diff_runs

        d = diff_runs(s, rb.id, ra.id)  # b(clean) -> a(overflow): the finding is added
        assert any("cgi_handler" in x["title"] for x in d["added"])


def test_cassette_record_then_replay(hg_home, monkeypatch):
    """Record a response keyed by bundle_sha, then replay it without the backend."""
    from hexgraph.db.models import Project
    from hexgraph.engine.context import build_context_bundle
    from hexgraph.llm.base import LLMRequest
    from hexgraph.llm.cassette import maybe_wrap_cassette

    with session_scope() as s:
        p = create_project(s, name="cass")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"]}
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")

        class _Ctx:
            objective = None
            tool_outputs = {}
            sibling_name = None
            sibling_target_id = None

        bundle = build_context_bundle(s, p, t, task, _Ctx())
        key = bundle.row.bundle_sha
        pid = p.id

    # A fake backend that we will prove is NOT called on replay.
    class _Counter:
        name = "fake"
        calls = 0

        def complete(self, req):
            from hexgraph.llm.base import LLMResponse, Usage
            _Counter.calls += 1
            return LLMResponse(text='{"findings": []}', usage=Usage(cost_source="anthropic", cost_usd=0.01))

        def stream(self, req):
            yield self.complete(req).text

    inner = _Counter()
    with session_scope() as s:
        project = s.get(Project, pid)
        req = LLMRequest(task_type="static_analysis", task_id="x", cache_key=key)

        monkeypatch.setenv("HEXGRAPH_CASSETTE", "record")
        rec = maybe_wrap_cassette(inner, project)
        rec.complete(req)
        assert _Counter.calls == 1

        monkeypatch.setenv("HEXGRAPH_CASSETTE", "replay")
        rep = maybe_wrap_cassette(inner, project)
        resp = rep.complete(req)
        assert _Counter.calls == 1  # not called again
        assert json.loads(resp.text) == {"findings": []}
