"""GET /api/projects/{id}/target-children — paginated, per-directory-level target listing
for the Targets sidebar tree, so it can lazy-load a large firmware's target set instead of
fetching everything from GET /api/projects/{id} in one shot. Visibility here is independent
of the curated graph's: include_hidden lists extracted-but-unrevealed children too."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


def _project_with_tree(s):
    """root(visible) -> [a(visible), b(hidden)]; b -> [c(hidden)]"""
    p = create_project(s, name="children-api")
    root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
    root.kind = TargetKind.firmware_image
    a = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd", parent=root, visible=True)
    b = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/telnetd", parent=root, visible=False)
    c = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/telnetd/helper", parent=b, visible=False)
    s.flush()
    return p, root, a, b, c


def test_root_level_defaults_to_visible_only(hg_home):
    with session_scope() as s:
        p, root, a, b, c = _project_with_tree(s)
        pid = p.id

    client = TestClient(create_app())
    out = client.get(f"/api/projects/{pid}/target-children").json()
    # Only the firmware root itself is a top-level (parent_id is None) target, and it's visible.
    assert out["total"] == 1
    assert out["items"][0]["kind"] == "firmware_image"
    assert out["items"][0]["child_count"] == 2  # a + b, regardless of visibility


def test_children_of_a_parent_include_hidden_toggle(hg_home):
    with session_scope() as s:
        p, root, a, b, c = _project_with_tree(s)
        pid, rootid, aid, bid = p.id, root.id, a.id, b.id

    client = TestClient(create_app())
    visible_only = client.get(f"/api/projects/{pid}/target-children",
                              params={"parent_id": rootid}).json()
    assert visible_only["total"] == 1
    assert {i["id"] for i in visible_only["items"]} == {aid}

    everything = client.get(f"/api/projects/{pid}/target-children",
                            params={"parent_id": rootid, "include_hidden": "true"}).json()
    assert everything["total"] == 2
    assert {i["id"] for i in everything["items"]} == {aid, bid}
    # b itself has one (hidden) child, reported regardless of the include_hidden filter used
    # for THIS page.
    b_row = next(i for i in everything["items"] if i["id"] == bid)
    assert b_row["child_count"] == 1
    assert b_row["visible"] is False


def test_pagination_shape(hg_home):
    with session_scope() as s:
        p = create_project(s, name="paginate")
        root = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        root.kind = TargetKind.firmware_image
        for i in range(5):
            ingest_file(s, p, fixture_path("vuln_httpd"), name=f"usr/sbin/svc{i}", parent=root, visible=True)
        s.flush()
        pid, rootid = p.id, root.id

    client = TestClient(create_app())
    page1 = client.get(f"/api/projects/{pid}/target-children",
                       params={"parent_id": rootid, "limit": 2}).json()
    assert len(page1["items"]) == 2 and page1["total"] == 5
    assert page1["has_more"] is True and page1["next_offset"] == 2

    page3 = client.get(f"/api/projects/{pid}/target-children",
                       params={"parent_id": rootid, "offset": 4, "limit": 2}).json()
    assert len(page3["items"]) == 1
    assert page3["has_more"] is False and page3["next_offset"] is None

    # limit is clamped, not rejected
    clamped = client.get(f"/api/projects/{pid}/target-children",
                         params={"parent_id": rootid, "limit": 999999}).json()
    assert len(clamped["items"]) == 5


def test_archived_children_excluded(hg_home):
    with session_scope() as s:
        p, root, a, b, c = _project_with_tree(s)
        from hexgraph.engine.targets.targets import archive_target
        archive_target(s, p.id, a.id)
        pid, rootid = p.id, root.id

    client = TestClient(create_app())
    out = client.get(f"/api/projects/{pid}/target-children",
                     params={"parent_id": rootid, "include_hidden": "true"}).json()
    assert out["total"] == 1  # only b; archived a excluded


def test_unknown_project_404s(hg_home):
    client = TestClient(create_app())
    assert client.get("/api/projects/nope/target-children").status_code == 404
