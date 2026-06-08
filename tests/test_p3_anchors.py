"""P3: task anchors, capability table, follow-up suggester seam."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, Task
from hexgraph.db.session import session_scope
from hexgraph import settings as st
from hexgraph.engine.capabilities import capabilities_for, capability_table
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.suggester import suggest_followups
from hexgraph.engine.tasks import create_task

from conftest import fixture_path


def test_capability_table():
    assert "static_analysis" in capabilities_for("target", "executable")
    assert "static_analysis" in capabilities_for("node", "function")
    assert capabilities_for("node", "string") == ["pattern_sweep"]
    assert "static_analysis" in capabilities_for("edge", "calls")
    assert capabilities_for("target", "firmware_image") == ["recon", "unpack"]


def test_surface_targets_do_not_offer_byte_recon(hg_home):
    """A web_app (and service/remote) is a reachable SURFACE with no bytes at rest, so the
    Run menu must NOT advertise byte 'recon' (the worker would route it to a confusing
    'artifact not found' / a clear NotImplementedError). web_app offers surface_recon
    instead; service/remote have no offline single-shot task wired."""
    web = capabilities_for("target", "web_app")
    assert "recon" not in web                 # byte recon is wrong for a surface
    assert "surface_recon" in web             # the surface analogue IS offered
    # No byte-file tasks leak onto a surface.
    for byte_task in ("harness_generation", "static_analysis", "reverse_engineering", "unpack"):
        assert byte_task not in web

    # service / remote: honest minimal set — no offline single-shot task, and crucially no
    # byte recon (they previously fell through to the ["recon"] default).
    assert capabilities_for("target", "service") == []
    assert capabilities_for("target", "remote") == []

    # The full UI table carries the surface kinds explicitly (not the byte default).
    table = capability_table()
    assert "recon" not in table["target"]["web_app"]
    assert "surface_recon" in table["target"]["web_app"]
    assert table["target"]["service"] == []
    assert table["target"]["remote"] == []


def test_web_app_live_tasks_gated_on_network(hg_home):
    """The live web tasks (web_recon/web_discover, bounded audited egress) appear only when
    features.network is enabled — mirroring the worker's egress gating."""
    assert capabilities_for("target", "web_app") == ["surface_recon"]
    st.update_settings({"features.network.enabled": True})
    web = capabilities_for("target", "web_app")
    assert web == ["surface_recon", "web_recon", "web_discover"]
    assert "recon" not in web  # still never byte recon
    assert capability_table()["target"]["web_app"] == ["surface_recon", "web_recon", "web_discover"]


def test_task_records_anchor(hg_home):
    with session_scope() as s:
        p = create_project(s, name="anc")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           anchor_kind="node", anchor_id="node-123")
        tid = task.id
    with session_scope() as s:
        task = s.get(Task, tid)
        assert task.anchor_kind == "node" and task.anchor_id == "node-123"


def test_default_anchor_is_target(hg_home):
    with session_scope() as s:
        p = create_project(s, name="anc2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="recon")
        assert task.anchor_kind == "target" and task.anchor_id == t.id


def test_rule_based_suggester():
    fake = Finding(
        project_id="p", target_id="t", task_id="k",
        title="Stack overflow in cgi_handler", severity="critical", confidence="high",
        category="memory-safety", summary="s", reasoning="r",
        evidence_json={"function": "cgi_handler", "sink": "strcpy"},
    )
    sugg = suggest_followups(fake)
    types = {s.task_type for s in sugg}
    assert "harness_generation" in types and "pattern_sweep" in types
    assert any("cgi_handler" in s.label for s in sugg)


def test_capabilities_and_suggestions_endpoints(hg_home):
    from hexgraph.engine.findings.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel

    with session_scope() as s:
        p = create_project(s, name="ep")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="overflow in cgi_handler", severity="critical", confidence="high",
            category="memory-safety", summary="s", reasoning="r",
            evidence=Evidence(function="cgi_handler", sink="strcpy"),
        ))
        fid = f.id

    client = TestClient(create_app())
    caps = client.get("/api/capabilities").json()
    assert "target" in caps and "node" in caps and "edge" in caps

    sugg = client.get(f"/api/findings/{fid}/suggestions").json()
    assert any(s["task_type"] == "pattern_sweep" for s in sugg)
