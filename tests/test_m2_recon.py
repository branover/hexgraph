"""M2: deterministic recon + firmware unpack + graph (the zero-model-call loop)."""

import json

from jsonschema import Draft202012Validator

from hexgraph.db.models import Edge, EdgeType, Finding, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.graph import build_graph
from hexgraph.engine.ingest import create_project
from hexgraph.engine.pipeline import ingest_and_analyze
from hexgraph.engine.re.recon import build_recon_finding
from hexgraph.models.finding import Finding as FindingModel
from hexgraph.paths import finding_schema_path

from conftest import fixture_path


def test_recon_finding_builder_is_schema_valid():
    """Pure (no Docker): the recon finding builder emits a schema-valid finding."""
    facts = {
        "format": "ELF", "arch": "x64", "kind": "executable",
        "sha256": "deadbeef", "md5": "cafe", "size": 1234,
        "imports": ["strcpy", "printf", "strtok"],
        "libraries": ["libc.so.6"],
        "strings": ["/cgi-bin/", "token="],
        "mitigations": {"nx": True, "canary": False, "pie": False, "relro": "none"},
    }
    finding = build_recon_finding(facts, "/sbin/httpd")
    # Pydantic + JSON Schema both accept it.
    FindingModel.model_validate(finding.to_payload())
    validator = Draft202012Validator(json.loads(finding_schema_path().read_text()))
    assert not list(validator.iter_errors(finding.to_payload()))
    # Risky sink (strcpy) yields a static_analysis follow-up.
    assert finding.suggested_followups
    assert finding.suggested_followups[0].task_type == "static_analysis"


def test_recon_on_lone_elf(hg_home, sandbox):
    with session_scope() as s:
        project = create_project(s, name="elf")
        summary = ingest_and_analyze(s, project, fixture_path("vuln_httpd"), runner=sandbox)
        pid, tid = project.id, summary["root_target_id"]

    with session_scope() as s:
        from hexgraph.db.models import Target

        t = s.get(Target, tid)
        assert t.kind == TargetKind.executable
        assert t.metadata_json["mitigations"]["canary"] is False
        assert "strcpy" in t.metadata_json["imports"]
        findings = s.query(Finding).filter(Finding.project_id == pid).all()
        assert len(findings) == 1 and findings[0].category == "recon"


def test_firmware_unpack_creates_children_and_edges(hg_home, sandbox):
    with session_scope() as s:
        project = create_project(s, name="fw")
        summary = ingest_and_analyze(s, project, fixture_path("synthetic_fw.bin"), runner=sandbox)
        pid = project.id
        assert len(summary["children"]) == 2  # httpd + libupnp.so

    with session_scope() as s:
        # firmware→child containment (target→target); excludes binary→symbol/string contains
        contains = s.query(Edge).filter(
            Edge.project_id == pid, Edge.type == EdgeType.contains, Edge.dst_kind == "target"
        ).all()
        assert len(contains) == 2
        # one recon finding per target (3 total)
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 3
        graph = build_graph(s, pid)
        targets = [n for n in graph["nodes"] if n["type"] == "target"]
        finding_nodes = [n for n in graph["nodes"] if n["type"] == "finding"]
        assert len(targets) == 3 and len(finding_nodes) == 3
        assert {n["kind"] for n in targets} == {"firmware_image", "executable", "shared_library"}
        # recon also materialized typed symbol/string nodes
        assert any(n["type"] == "node" for n in graph["nodes"])


def test_worker_runs_recon_task(hg_home, sandbox):
    """The worker executes a queued recon task end-to-end."""
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        project = create_project(s, name="w")
        target = ingest_file(s, project, fixture_path("vuln_httpd"))
        task = create_task(s, project=project, target_id=target.id, type="recon")
        task_id = task.id

    assert run_task_sync(task_id) == "succeeded"
    with session_scope() as s:
        assert s.query(Finding).count() == 1


def test_recon_classifies_wrapped_firmware():
    """Real firmware is wrapped (TRX/uImage/vendor header); recon must spot an
    embedded filesystem signature and classify it firmware_image so it gets carved."""
    from hexgraph.sandbox.probes.recon_probe import _firmware_signature
    assert _firmware_signature(b"1550\x00\x00HDR0" + b"\x00" * 100) == "trx"
    assert _firmware_signature(b"\x00" * 64 + b"hsqs" + b"\x00" * 64) == "squashfs"
    assert _firmware_signature(b"\x27\x05\x19\x56" + b"\x00" * 32) == "uimage"
    assert _firmware_signature(b"just some random non-firmware bytes" * 10) is None
