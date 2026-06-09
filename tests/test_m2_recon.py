"""M2: deterministic recon + firmware unpack + graph (the zero-model-call loop).

Recon ENRICHES a target (metadata + a recon Observation) and, for VISIBLE targets,
materializes nodes — it no longer mints a per-target finding (PR: hidden-by-default
children + recon-as-enrichment). Firmware children are registered HIDDEN, so they
add nothing to the curated graph until revealed.
"""

from hexgraph.db.models import Edge, EdgeType, Finding, Observation, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.graph import build_graph
from hexgraph.engine.targets.ingest import create_project
from hexgraph.engine.pipeline import ingest_and_analyze
from hexgraph.engine.suggester import suggest_target_followups

from conftest import fixture_path


def test_recon_summary_flags_risky_sinks():
    """Pure (no Docker): the recon summary names weak mitigations + risky sinks."""
    from hexgraph.engine.re.recon import recon_summary

    facts = {
        "format": "ELF", "arch": "x64", "kind": "executable",
        "imports": ["strcpy", "printf", "strtok"],
        "mitigations": {"nx": True, "canary": False, "pie": False, "relro": "none"},
    }
    summary = recon_summary(facts, "/sbin/httpd")
    assert "weak mitigations" in summary and "strcpy" in summary


def test_recon_on_lone_elf(hg_home, sandbox):
    with session_scope() as s:
        project = create_project(s, name="elf")
        summary = ingest_and_analyze(s, project, fixture_path("vuln_httpd"), runner=sandbox)
        pid, tid = project.id, summary["root_target_id"]

    with session_scope() as s:
        from hexgraph.db.models import Target

        t = s.get(Target, tid)
        assert t.kind == TargetKind.executable
        assert t.visible is True  # a lone ingest is visible
        assert t.metadata_json["mitigations"]["canary"] is False
        assert "strcpy" in t.metadata_json["imports"]
        # Recon mints NO finding — it enriches + records a recon Observation instead.
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 0
        obs = s.query(Observation).filter(Observation.target_id == tid,
                                          Observation.result_kind == "recon").all()
        assert len(obs) == 1
        # The risky-sink follow-up now surfaces at the target level (suggester seam).
        fus = suggest_target_followups(t)
        assert fus and fus[0].task_type == "static_analysis"


def test_firmware_unpack_hides_children_and_keeps_graph_lean(hg_home, sandbox):
    with session_scope() as s:
        project = create_project(s, name="fw")
        summary = ingest_and_analyze(s, project, fixture_path("synthetic_fw.bin"), runner=sandbox)
        pid = project.id
        assert len(summary["children"]) == 2  # httpd + libupnp.so

    with session_scope() as s:
        from hexgraph.db.models import Target

        # firmware→child containment (target→target); excludes binary→symbol/string contains
        contains = s.query(Edge).filter(
            Edge.project_id == pid, Edge.type == EdgeType.contains, Edge.dst_kind == "target"
        ).all()
        assert len(contains) == 2
        # The firmware itself is visible; both ELF children are HIDDEN.
        targets = s.query(Target).filter(Target.project_id == pid).all()
        fw = next(t for t in targets if t.kind == TargetKind.firmware_image)
        kids = [t for t in targets if t.parent_id == fw.id]
        assert fw.visible is True
        assert len(kids) == 2 and all(k.visible is False for k in kids)
        # Recon minted NO findings (was 3 per-target findings before).
        assert s.query(Finding).filter(Finding.project_id == pid).count() == 0
        # Each child recorded a recon Observation (enriched, queryable, re-usable).
        for k in kids:
            assert s.query(Observation).filter(
                Observation.target_id == k.id, Observation.result_kind == "recon").count() == 1

        # The graph shows ONLY the visible firmware (its hidden children add nothing).
        graph = build_graph(s, pid)
        gtargets = [n for n in graph["nodes"] if n["type"] == "target"]
        assert len(gtargets) == 1 and gtargets[0]["kind"] == "firmware_image"
        assert not [n for n in graph["nodes"] if n["type"] == "finding"]
        # Any code nodes belong to the VISIBLE firmware itself; the hidden children
        # contribute none (their recon nodes are deferred to reveal).
        child_ids = {k.id for k in kids}
        assert not [n for n in graph["nodes"]
                    if n["type"] == "node" and n.get("target_id") in child_ids]

        # include_hidden surfaces the children as target rows (their recon nodes are
        # still deferred to reveal — included here only to be picked for reveal).
        full = build_graph(s, pid, include_hidden=True)
        assert len([n for n in full["nodes"] if n["type"] == "target"]) == 3


def test_worker_runs_recon_task(hg_home, sandbox):
    """The worker executes a queued recon task end-to-end: enriches + records an
    Observation, mints no finding."""
    from hexgraph.engine.targets.ingest import ingest_file
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        project = create_project(s, name="w")
        target = ingest_file(s, project, fixture_path("vuln_httpd"))
        task = create_task(s, project=project, target_id=target.id, type="recon")
        task_id, tid = task.id, target.id

    assert run_task_sync(task_id) == "succeeded"
    with session_scope() as s:
        assert s.query(Finding).count() == 0
        assert s.query(Observation).filter(
            Observation.target_id == tid, Observation.result_kind == "recon").count() == 1


def test_recon_classifies_wrapped_firmware():
    """Real firmware is wrapped (TRX/uImage/vendor header); recon must spot an
    embedded filesystem signature and classify it firmware_image so it gets carved."""
    from hexgraph.sandbox.probes.recon_probe import _firmware_signature
    assert _firmware_signature(b"1550\x00\x00HDR0" + b"\x00" * 100) == "trx"
    assert _firmware_signature(b"\x00" * 64 + b"hsqs" + b"\x00" * 64) == "squashfs"
    assert _firmware_signature(b"\x27\x05\x19\x56" + b"\x00" * 32) == "uimage"
    assert _firmware_signature(b"just some random non-firmware bytes" * 10) is None
