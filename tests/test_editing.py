"""Editing graph entities from the UI: full-field finding PATCH, node PATCH (rename/
attrs), the one-click PoC re-verify endpoint, and the firmware file viewer."""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.session import session_scope
from hexgraph.engine.findings.findings import persist_finding
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.graph.nodes import materialize_function
from hexgraph.engine.tasks import create_task
from hexgraph.models.finding import Evidence, Finding as FModel

from conftest import fixture_path


def _seed_finding(s):
    p = create_project(s, name="ed")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    task = create_task(s, project=p, target_id=t.id, type="static_analysis")
    f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
        title="overflow", severity="medium", confidence="low", category="memory-safety",
        summary="s", reasoning="r", evidence=Evidence(function="main")))
    return p, t, f


def test_patch_finding_full_fields(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s)
        fid = f.id

    c = TestClient(create_app())
    r = c.patch(f"/api/findings/{fid}", json={
        "title": "Stack overflow in main", "severity": "high", "confidence": "high",
        "category": "command-injection", "summary": "new summary", "reasoning": "new reasoning",
        "evidence": {"function": "main", "address": "0x401200", "sink": "system"}})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["title"] == "Stack overflow in main" and d["category"] == "command-injection"
    assert d["summary"] == "new summary" and d["reasoning"] == "new reasoning"
    assert d["evidence"]["address"] == "0x401200" and d["evidence"]["sink"] == "system"


def test_patch_finding_rejects_bad_evidence(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s)
        fid = f.id
    c = TestClient(create_app())
    r = c.patch(f"/api/findings/{fid}", json={"evidence": {"not_a_field": "x"}})
    assert r.status_code == 400


def test_patch_node_rename_and_attrs(hg_home):
    with session_scope() as s:
        p = create_project(s, name="nd")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        n = materialize_function(s, project_id=p.id, target_id=t.id, name="handler")
        pid, nid = p.id, n.id

    c = TestClient(create_app())
    # rename with a decompiler prefix → normalized identity
    r = c.patch(f"/api/projects/{pid}/nodes/{nid}",
                json={"name": "sym.parse_request", "address": "0x4010a0",
                      "attrs": {"summary": "parses the HTTP request line"}})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["name"] == "parse_request" and d["address"] == "0x4010a0"
    assert d["attrs"]["summary"].startswith("parses")
    # unknown node 404s
    assert c.patch(f"/api/projects/{pid}/nodes/nope", json={"name": "x"}).status_code == 404


def test_verify_finding_without_spec_400(hg_home):
    with session_scope() as s:
        p, t, f = _seed_finding(s)
        fid = f.id
    c = TestClient(create_app())
    r = c.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 400 and "no stored PoC" in r.json()["detail"]


def test_verify_finding_preserves_original_spec(hg_home, monkeypatch):
    """Re-verify must keep the {{NONCE}} template in evidence.extra.poc, not the
    nonce-substituted copy verify_poc ran — else a later re-verify is unrepeatable."""
    spec = {"oracle": {"type": "output_contains", "value": "{{NONCE}}"},
            "argv": ["./x", "; echo {{NONCE}}"]}
    with session_scope() as s:
        p = create_project(s, name="rv")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="poc")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="poc", severity="high", confidence="low", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence(extra={"poc": spec})))
        fid = f.id

    def fake_verify(session, project, target, in_spec, runner=None):
        # The real verify_poc returns the substituted spec; the endpoint must NOT store it.
        return {"verified": True, "detail": "ok", "exit_code": 0, "nonce": "HEXGRAPH_PWNED_x",
                "output": "...", "spec": {"oracle": {"type": "output_contains", "value": "HEXGRAPH_PWNED_x"}}}
    monkeypatch.setattr("hexgraph.engine.findings.poc.verify_poc", fake_verify)

    c = TestClient(create_app())
    r = c.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 200, r.text
    assert r.json()["verified"] is True
    with session_scope() as s:
        from hexgraph.db.models import Finding
        ev = s.get(Finding, fid).evidence_json
        assert ev["extra"]["poc"]["oracle"]["value"] == "{{NONCE}}"
        assert ev["extra"]["verification"]["verified"] is True


def test_read_firmware_file_and_traversal_guard(hg_home, tmp_path):
    # Build a tiny fake "unpacked firmware" manifest pointing at a real on-disk tree.
    from pathlib import Path

    from hexgraph.db.models import TargetKind
    from hexgraph.engine.filesystem import persistent_base, read_file, FilesystemError

    with session_scope() as s:
        p = create_project(s, name="fw")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        root = persistent_base(p, fw.id) / "rootfs"
        (root / "etc").mkdir(parents=True, exist_ok=True)
        (root / "etc" / "config").write_text("admin_password=hunter2\nport=8080\n")
        (root / "bin").mkdir(parents=True, exist_ok=True)
        (root / "bin" / "blob").write_bytes(bytes(range(256)))
        fw.metadata_json = {"filesystem": {"method": "test", "root_rel": "rootfs", "files": [
            {"rel": "etc/config", "size": 30}, {"rel": "bin/blob", "size": 256}]}}
        s.flush()
        # text file
        txt = read_file(p, fw, "etc/config")
        assert txt["encoding"] == "text" and "hunter2" in txt["content"]
        # binary file → hex
        b = read_file(p, fw, "bin/blob")
        assert b["encoding"] == "binary" and len(b["content"]) == 512
        # traversal is refused (not in manifest, and escapes root)
        try:
            read_file(p, fw, "../../../../etc/passwd")
        except FilesystemError:
            pass
        else:
            assert False, "expected FilesystemError for traversal"
