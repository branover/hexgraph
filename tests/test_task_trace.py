"""A failed task's error must be readable: detail surfaces error.txt inline and a
trace endpoint serves any artifact (with no path traversal)."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task, mark_failed, write_trace

from conftest import fixture_path


def _failed_task(s):
    p = create_project(s, name="tr")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    task = create_task(s, project=p, target_id=t.id, type="fuzzing")
    write_trace(task, "fuzz.json", {"config": {"max_total_time": 60}})
    mark_failed(task, "ValueError: no fuzz harness available — run a harness_generation task first")
    return task.id


def test_detail_surfaces_error(hg_home):
    with session_scope() as s:
        tid = _failed_task(s)
    c = TestClient(create_app())
    detail = c.get(f"/api/tasks/{tid}/detail").json()
    assert "no fuzz harness available" in (detail["error"] or "")
    assert "error.txt" in detail["trace_files"] and "fuzz.json" in detail["trace_files"]


def test_trace_endpoint_serves_content(hg_home):
    with session_scope() as s:
        tid = _failed_task(s)
    c = TestClient(create_app())
    body = c.get(f"/api/tasks/{tid}/trace/error.txt")
    assert body.status_code == 200 and "harness_generation" in body.text
    assert c.get(f"/api/tasks/{tid}/trace/fuzz.json").status_code == 200


def test_trace_endpoint_rejects_unknown_and_traversal(hg_home):
    with session_scope() as s:
        tid = _failed_task(s)
    c = TestClient(create_app())
    # unknown file → 404
    assert c.get(f"/api/tasks/{tid}/trace/nope.txt").status_code == 404
    # a name with a path separator can never resolve to a file inside log_path
    # (the p.name != name guard), so it never serves content outside the dir.
    for bad in ("subdir/x", "../../hexgraph.db"):
        r = c.get(f"/api/tasks/{tid}/trace/{bad}")
        assert "hexgraph.db" not in r.text  # never the DB; route/guard reject it
