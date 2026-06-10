"""Hidden-by-default firmware children + recon-as-enrichment + selective reveal.

unpack registers each firmware ELF HIDDEN: recorded + searchable + addressable, but
contributing nothing to the curated graph (no node, no finding) until revealed. Recon
ENRICHES every target (metadata + a recon Observation) and only materializes nodes for
VISIBLE targets. Reveal (per-target or per-directory) flips visibility and materializes
the recon nodes from the already-stored facts (no re-run).

The recon-dependent cases use the sandbox (Docker); the pure visibility/reveal logic is
exercised directly so it runs even without it.
"""

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding, Node, Observation, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine.graph.graph import build_graph, graph_size, graph_stats
from hexgraph.engine.graph.nodes import materialize_symbol
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.engine.targets.reveal import reveal_dir, set_visible

from conftest import fixture_path


# ── visibility defaults (no Docker) ────────────────────────────────────────────────────

def test_visible_defaults_true(hg_home):
    with session_scope() as s:
        p = create_project(s, name="vis")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        assert t.visible is True


def test_ingest_file_can_register_hidden(hg_home):
    with session_scope() as s:
        p = create_project(s, name="hid")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd", visible=False)
        assert t.visible is False


# ── graph / targets default-filter to visible (no Docker; nodes materialized by hand) ───

def _seed_hidden_child(s):
    """A firmware (visible) with one HIDDEN child that already has a materialized node —
    so we can prove the filter hides it WITHOUT needing the sandbox."""
    p = create_project(s, name="filt")
    fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
    fw.kind = TargetKind.firmware_image
    child = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd",
                        parent=fw, visible=False)
    # a node hanging off the hidden child (as if recon had materialized it)
    materialize_symbol(s, project_id=p.id, target_id=child.id, name="strcpy", kind="import", is_sink=True)
    s.flush()
    return p, fw, child


def test_graph_filters_hidden_targets_and_their_nodes(hg_home):
    with session_scope() as s:
        p, fw, child = _seed_hidden_child(s)
        g = build_graph(s, p.id)
        ids = {n["id"] for n in g["nodes"]}
        assert fw.id in ids                 # visible firmware shows
        assert child.id not in ids          # hidden child hidden
        assert not [n for n in g["nodes"] if n["type"] == "node"]  # its node hidden too

        # include_hidden brings them back.
        full = build_graph(s, p.id, include_hidden=True)
        fids = {n["id"] for n in full["nodes"]}
        assert child.id in fids
        assert any(n["type"] == "node" for n in full["nodes"])


def test_graph_size_and_stats_exclude_hidden(hg_home):
    with session_scope() as s:
        p, fw, child = _seed_hidden_child(s)
        size = graph_size(s, p.id)
        assert size["targets"] == 1 and size["nodes"] == 0   # only the visible firmware
        stats = graph_stats(s, p.id)
        assert stats["targets"] == 1 and stats["totals"]["nodes"] == 0


# ── per-target reveal (no Docker) ───────────────────────────────────────────────────────

def test_set_visible_reveals_and_materializes_from_stored_facts(hg_home):
    with session_scope() as s:
        p = create_project(s, name="reveal")
        child = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd", visible=False)
        # Simulate recon having enriched the hidden child + recorded its facts as an Observation.
        child.metadata_json = {**(child.metadata_json or {}),
                               "imports": ["strcpy", "printf"], "strings": ["/cgi-bin/"]}
        from hexgraph.engine.observations import record_observation
        record_observation(
            s, project_id=p.id, target_id=child.id, source="recon", tool="recon_probe",
            args=None, result_kind="recon",
            payload={"imports": ["strcpy", "printf"], "strings": ["/cgi-bin/"], "kind": "executable"},
            summary="recon", content_hash=(child.metadata_json or {}).get("sha256"),
        )
        cid, pid = child.id, p.id

    with session_scope() as s:
        # No nodes while hidden.
        assert s.query(Node).filter(Node.target_id == cid).count() == 0
        out = set_visible(s, pid, cid, True)
        assert out["visible"] is True and out["materialized"] is True

    with session_scope() as s:
        t = s.get(Target, cid)
        assert t.visible is True
        # Reveal materialized the recon symbol/string nodes from the stored facts.
        names = {n.name for n in s.query(Node).filter(Node.target_id == cid).all()}
        assert "strcpy" in names
        g = build_graph(s, pid)
        assert cid in {n["id"] for n in g["nodes"]}


def test_set_visible_can_rehide(hg_home):
    with session_scope() as s:
        p = create_project(s, name="rehide")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        tid, pid = t.id, p.id
        out = set_visible(s, pid, tid, False)
        assert out["visible"] is False and out["materialized"] is False
    with session_scope() as s:
        assert s.get(Target, tid).visible is False
        assert tid not in {n["id"] for n in build_graph(s, pid)["nodes"]}


# ── project payload: findings on hidden children come back in a SEPARATE bucket ─────────

def _mk_finding(s, *, project_id, target_id, title, finding_type="vulnerability"):
    s.add(Finding(project_id=project_id, target_id=target_id, task_id="task",
                  title=title, severity="high", confidence="high", category="auth",
                  summary="s", reasoning="r", evidence_json={"function": "f"},
                  finding_type=finding_type, status="new"))


def test_project_payload_splits_hidden_target_findings(hg_home):
    """GET /api/projects/{id}: findings on VISIBLE targets land in `findings`; findings on
    HIDDEN children land in `hidden_findings` (with their `hidden_targets` names) so the UI
    can reveal them on a toggle WITHOUT putting the hidden children in `targets`."""
    with session_scope() as s:
        p = create_project(s, name="payload")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        child = ingest_file(s, p, fixture_path("vuln_httpd"), name="lib/security/pam.so",
                            parent=fw, visible=False)
        s.flush()
        _mk_finding(s, project_id=p.id, target_id=fw.id, title="visible-finding")
        _mk_finding(s, project_id=p.id, target_id=child.id, title="hidden-finding")
        # A recon finding on the hidden child must NOT leak into the toggle bucket — recon is
        # the high-volume flood that hiding children exists to suppress.
        _mk_finding(s, project_id=p.id, target_id=child.id, title="hidden-recon", finding_type="recon")
        pid, fwid, cid = p.id, fw.id, child.id

    client = TestClient(create_app())
    body = client.get(f"/api/projects/{pid}").json()

    # `targets` stays visible-only — the hidden child is NOT dumped into the Targets pane.
    assert {t["id"] for t in body["targets"]} == {fwid}
    # The visible finding shows; the substantive hidden one is split out, not lost; recon excluded.
    assert [f["title"] for f in body["findings"]] == ["visible-finding"]
    assert [f["title"] for f in body["hidden_findings"]] == ["hidden-finding"]
    # Only the findings-bearing hidden target's name is shipped (for grouping), not the tree.
    assert {t["id"] for t in body["hidden_targets"]} == {cid}
    assert next(t for t in body["hidden_targets"] if t["id"] == cid)["name"].endswith("pam.so")

    # include_hidden folds them into `targets`/`findings` (the full firehose, recon and all);
    # `hidden_findings` is then empty (no double-count) and `hidden_targets` collapses too.
    full = client.get(f"/api/projects/{pid}?include_hidden=true").json()
    assert {cid, fwid} <= {t["id"] for t in full["targets"]}
    assert {f["title"] for f in full["findings"]} == {"visible-finding", "hidden-finding", "hidden-recon"}
    assert full["hidden_findings"] == [] and full["hidden_targets"] == []


def test_project_payload_excludes_archived_target_findings(hg_home):
    """A finding on an ARCHIVED (soft-removed) target appears in NEITHER bucket — archive is
    a deliberate removal, distinct from a merely-hidden child."""
    with session_scope() as s:
        p = create_project(s, name="arch")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        gone = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin/old", parent=fw, visible=False)
        gone.archived = True
        s.flush()
        _mk_finding(s, project_id=p.id, target_id=gone.id, title="archived-finding")
        pid = p.id

    body = TestClient(create_app()).get(f"/api/projects/{pid}").json()
    titles = {f["title"] for f in body["findings"]} | {f["title"] for f in body["hidden_findings"]}
    assert "archived-finding" not in titles


# ── per-directory reveal (no Docker) ────────────────────────────────────────────────────

def test_reveal_dir_reveals_only_matching_prefix(hg_home):
    with session_scope() as s:
        p = create_project(s, name="dir")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        a = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/httpd", parent=fw, visible=False)
        b = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbin/telnetd", parent=fw, visible=False)
        c = ingest_file(s, p, fixture_path("vuln_httpd"), name="bin/busybox", parent=fw, visible=False)
        s.flush()
        pid, fwid, aid, bid, cid = p.id, fw.id, a.id, b.id, c.id

    with session_scope() as s:
        out = reveal_dir(s, pid, fwid, "usr/sbin")
        assert out["revealed"] == 2 and set(out["target_ids"]) == {aid, bid}

    with session_scope() as s:
        assert s.get(Target, aid).visible is True
        assert s.get(Target, bid).visible is True
        assert s.get(Target, cid).visible is False  # bin/busybox untouched


def test_reveal_dir_prefix_is_not_a_bare_substring(hg_home):
    with session_scope() as s:
        p = create_project(s, name="dir2")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        # "usr/sb" must NOT match "usr/sbnet/x" — only a real dir boundary.
        x = ingest_file(s, p, fixture_path("vuln_httpd"), name="usr/sbnet/x", parent=fw, visible=False)
        s.flush()
        pid, fwid, xid = p.id, fw.id, x.id

    with session_scope() as s:
        out = reveal_dir(s, pid, fwid, "usr/sb")
        assert out["revealed"] == 0
        assert s.get(Target, xid).visible is False


def test_reveal_dir_empty_prefix_reveals_all(hg_home):
    with session_scope() as s:
        p = create_project(s, name="dir3")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        for nm in ("usr/sbin/httpd", "bin/busybox"):
            ingest_file(s, p, fixture_path("vuln_httpd"), name=nm, parent=fw, visible=False)
        s.flush()
        pid, fwid = p.id, fw.id

    with session_scope() as s:
        out = reveal_dir(s, pid, fwid, "")
        assert out["revealed"] == 2


# ── the full sandbox-backed loop ────────────────────────────────────────────────────────

def test_recon_on_hidden_child_enriches_but_adds_no_graph(hg_home, sandbox):
    """A hidden child: recon enriches metadata + records a recon Observation, materializes
    NO nodes and mints NO finding. Revealing it then materializes the nodes."""
    from hexgraph.engine.pipeline import ingest_and_analyze

    with session_scope() as s:
        p = create_project(s, name="loop")
        ingest_and_analyze(s, p, fixture_path("synthetic_fw.bin"), runner=sandbox)
        pid = p.id

    with session_scope() as s:
        fw = next(t for t in s.query(Target).filter(Target.project_id == pid).all()
                  if t.kind == TargetKind.firmware_image)
        child = next(t for t in s.query(Target).filter(Target.project_id == pid).all()
                     if t.parent_id == fw.id)
        cid = child.id
        # Enriched (metadata) + Observation recorded, but no nodes / no finding while hidden.
        assert child.metadata_json.get("imports") is not None
        assert s.query(Observation).filter(
            Observation.target_id == cid, Observation.result_kind == "recon").count() == 1
        assert s.query(Node).filter(Node.target_id == cid).count() == 0
        assert s.query(Finding).filter(Finding.target_id == cid).count() == 0

    with session_scope() as s:
        out = set_visible(s, pid, cid, True)
        assert out["materialized"] is True

    with session_scope() as s:
        # Reveal materialized the recon nodes from the stored facts (no re-run).
        assert s.query(Node).filter(Node.target_id == cid).count() > 0
        assert cid in {n["id"] for n in build_graph(s, pid)["nodes"]}
