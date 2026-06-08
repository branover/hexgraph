"""LLM-task findings auto-populate an agent-proposed note on the function node
they concern, so freshly-materialized nodes carry context (HITL: proposed)."""

from hexgraph.db.models import Annotation, Edge, EdgeType, Node
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _finding(title, function="cgi_handler", sink="strcpy"):
    return FModel(title=title, severity="critical", confidence="high", category="memory-safety",
                  summary="overflow", reasoning="r", evidence=Evidence(function=function, sink=sink))


def test_function_finding_auto_annotates_node(hg_home):
    with session_scope() as s:
        p = create_project(s, name="aa")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                        finding=_finding("Stack buffer overflow in cgi_handler"))
        node = s.query(Node).filter(Node.project_id == p.id, Node.fq_name == "cgi_handler").one()
        anns = s.query(Annotation).filter(Annotation.node_kind == "node", Annotation.node_id == node.id).all()
        assert len(anns) == 1
        a = anns[0]
        assert a.origin == "agent" and a.status == "proposed" and a.kind == "note"
        assert "Stack buffer overflow" in a.value and "[critical]" in a.value and "strcpy" in a.value


def test_auto_note_is_deduped_across_reruns(hg_home):
    with session_scope() as s:
        p = create_project(s, name="aa2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        for _ in range(3):
            persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id,
                            finding=_finding("Same overflow"))
        node = s.query(Node).filter(Node.fq_name == "cgi_handler").one()
        anns = s.query(Annotation).filter(Annotation.node_id == node.id, Annotation.kind == "note").all()
        assert len(anns) == 1  # not three


def test_target_level_finding_does_not_annotate(hg_home):
    with session_scope() as s:
        p = create_project(s, name="aa3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="recon")
        # no evidence.function → finding is about the target, no node note
        persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="recon", severity="info", confidence="high", category="recon",
            summary="s", reasoning="r", evidence=Evidence()))
        assert s.query(Annotation).filter(Annotation.project_id == p.id).count() == 0
        # the about edge points at the target, not a node
        e = s.query(Edge).filter(Edge.type == EdgeType.about.value, Edge.src_kind == "finding").one()
        assert e.dst_kind == "target"
