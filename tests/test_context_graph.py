"""Selective graph context: a task's bundle pulls the target's relationships and
cross-target prior findings — not the whole graph."""

from hexgraph.db.models import EdgeType
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.edges import add_edge
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.llm_tasks import preview_context
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def test_bundle_includes_relations_and_related_findings(hg_home):
    with session_scope() as s:
        p = create_project(s, name="ctxg")
        t1 = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t2 = ingest_file(s, p, fixture_path("libupnp.so"), name="libupnp.so")
        t1.metadata_json = {"imports": ["strcpy"]}
        # t1 is related to t2 (shared sink pattern)
        add_edge(s, project_id=p.id, src=("target", t1.id), dst=("target", t2.id),
                 type=EdgeType.similar_to, origin="llm", confidence=0.6)
        # t2 already has a finding (cross-target prior art)
        task = create_task(s, project=p, target_id=t2.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t2.id, task_id=task.id, finding=FModel(
            title="strcpy sink in ssdp_recv", severity="high", confidence="medium",
            category="memory-safety", summary="s", reasoning="r", evidence=Evidence(function="ssdp_recv")))

        prev = preview_context(s, p, t1, task_type="static_analysis", objective="analyze httpd")
        kinds = {i["kind"] for i in prev["items"]}
        assert "graph.relations" in kinds
        assert "related_findings" in kinds
        # the related finding's title is actually carried in the prompt
        assert "ssdp_recv" in prev["prompt"]
