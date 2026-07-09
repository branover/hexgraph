"""Hidden-by-default firmware children + recon-as-enrichment + selective reveal.

unpack registers each firmware ELF HIDDEN: recorded + searchable + addressable, but
contributing nothing to the curated graph (no node, no finding) until revealed. Recon
ENRICHES every target (metadata + a recon Observation) and only materializes nodes for
VISIBLE targets. Reveal (per-target or per-directory) flips visibility and materializes
the recon nodes from the already-stored facts (no re-run).

The recon-dependent cases use the sandbox (Docker); the pure visibility/reveal logic is
exercised directly so it runs even without it.
"""

import json

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


def _executable_child(s, p, *, name="usr/sbin/httpd", parent=None, visible=False):
    """A hidden child whose recon facts mark it as an executable — the kind gate
    `_materialize_on_reveal` checks before attempting Ghidra enrichment at all."""
    child = ingest_file(s, p, fixture_path("vuln_httpd"), name=name, parent=parent, visible=visible)
    child.metadata_json = {**(child.metadata_json or {}), "kind": "executable"}
    from hexgraph.engine.observations import record_observation
    record_observation(
        s, project_id=p.id, target_id=child.id, source="recon", tool="recon_probe",
        args=None, result_kind="recon", payload={"kind": "executable"},
        summary="recon", content_hash=(child.metadata_json or {}).get("sha256"))
    return child


def test_set_visible_detaches_ghidra_enrichment(hg_home, monkeypatch):
    """Real incident: revealing a directory of a dozen+ binaries ran a cold headless Ghidra
    full-analysis per binary SEQUENTIALLY inline, turning one MCP call into a multi-hour
    block (target_reveal_dir hung 2+ hours on an Erlang erts/bin directory). Reveal must
    materialize the graph nodes immediately and kick off enrichment detached instead."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    with session_scope() as s:
        p = create_project(s, name="reveal-enrich")
        child = _executable_child(s, p)
        cid, pid = child.id, p.id

    with session_scope() as s:
        out = set_visible(s, pid, cid, True, enrich=True)
        assert out["visible"] is True and out["materialized"] is True
        assert out["enrichment_queued"] is True
        assert len(spawned) == 1

        from hexgraph.db.models import Task, TaskStatus
        t = s.get(Target, cid)
        task_id = t.metadata_json["ghidra_enrich_task_id"]
        assert task_id == spawned[0]
        task = s.get(Task, task_id)
        assert task.type == "ghidra_enrich" and task.status == TaskStatus.queued

        # A second call while enrichment is queued/running must not re-spawn.
        again = set_visible(s, pid, cid, True, enrich=True)
        assert again["enrichment_queued"] is False
        assert len(spawned) == 1


def test_set_visible_does_not_enrich_by_default(hg_home, monkeypatch):
    """Real incident: revealing auto-enriched every executable, even though the operator
    never asked for it — a directory of a dozen+ binaries silently queued a dozen+ background
    Ghidra jobs. Even with the feature globally enabled, a plain reveal (no enrich=True) must
    NOT queue anything."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    with session_scope() as s:
        p = create_project(s, name="reveal-no-enrich")
        child = _executable_child(s, p)
        cid, pid = child.id, p.id

    with session_scope() as s:
        out = set_visible(s, pid, cid, True)
        assert out["visible"] is True and out["materialized"] is True
        assert out["enrichment_queued"] is False
        assert len(spawned) == 0


def test_reveal_dir_batches_ghidra_enrichment_into_one_task(hg_home, monkeypatch):
    """Multiple binaries revealed in one call must NOT each get their own detached process —
    a directory can have a dozen+ binaries, and that many CONCURRENT cold headless Ghidra
    containers would contend hard for host resources. One `ghidra_enrich_batch` task covers
    the whole batch; the call itself returns without waiting for any of it."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    with session_scope() as s:
        p = create_project(s, name="reveal-dir-enrich")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        a = _executable_child(s, p, name="usr/sbin/httpd", parent=fw)
        b = _executable_child(s, p, name="usr/sbin/telnetd", parent=fw)
        s.flush()
        pid, fwid, aid, bid = p.id, fw.id, a.id, b.id

    with session_scope() as s:
        out = reveal_dir(s, pid, fwid, "usr/sbin", enrich=True)
        assert out["revealed"] == 2
        assert out["enrichment_queued"] == 2
        assert len(spawned) == 1   # ONE batch task, not one per binary

        from hexgraph.db.models import Task, TaskStatus
        task = s.get(Task, spawned[0])
        assert task.type == "ghidra_enrich_batch" and task.status == TaskStatus.queued
        assert task.target_id == fwid
        assert set(task.params_json["target_ids"]) == {aid, bid}


def test_reveal_dir_does_not_enrich_by_default(hg_home, monkeypatch):
    """The exact real incident, reproduced and asserted against: revealing a directory of
    binaries must NOT auto-queue Ghidra enrichment for any of them, even with the feature
    globally enabled, unless the caller explicitly passes enrich=True."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    with session_scope() as s:
        p = create_project(s, name="reveal-dir-no-enrich")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        _executable_child(s, p, name="usr/sbin/httpd", parent=fw)
        _executable_child(s, p, name="usr/sbin/telnetd", parent=fw)
        s.flush()
        pid, fwid = p.id, fw.id

    with session_scope() as s:
        out = reveal_dir(s, pid, fwid, "usr/sbin")
        assert out["revealed"] == 2
        assert out["enrichment_queued"] == 0
        assert len(spawned) == 0


def test_ghidra_enrichment_self_heals_after_lost_task(hg_home, monkeypatch):
    """A task that ends without marking the target enriched (died, or a soft failure) must
    not leave it permanently unenriched — the next reveal call retries."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)
    spawned = []
    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task",
                        lambda task_id: spawned.append(task_id) or 1)
    with session_scope() as s:
        p = create_project(s, name="reveal-self-heal")
        child = _executable_child(s, p)
        cid, pid = child.id, p.id

    with session_scope() as s:
        set_visible(s, pid, cid, True, enrich=True)
        assert len(spawned) == 1
        from hexgraph.db.models import Task, TaskStatus
        task = s.get(Task, spawned[0])
        task.status = TaskStatus.failed
        s.commit()

        # Re-hide then re-reveal (the natural way an operator/agent would retry).
        set_visible(s, pid, cid, False)
        again = set_visible(s, pid, cid, True, enrich=True)
        assert again["enrichment_queued"] is True
        assert len(spawned) == 2


def test_ghidra_enrich_task_dispatches_to_enrich_target(hg_home, monkeypatch):
    """The `ghidra_enrich` task type — what the detached spawn runs — must route to
    enrich_target and mark the target enriched only on success."""
    calls = []

    def _fake_enrich(session, project, target):
        calls.append(target.id)
        return {"ok": True, "recorded": True, "functions": 0, "calls": 0, "structs": 0}

    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_target", _fake_enrich)
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        p = create_project(s, name="dispatch-enrich")
        child = _executable_child(s, p)
        task = create_task(s, project=p, target_id=child.id, type="ghidra_enrich")
        task_id, cid = task.id, child.id

    status = run_task_sync(task_id)
    assert status == "succeeded"
    assert calls == [cid]
    with session_scope() as s:
        assert s.get(Target, cid).metadata_json.get("ghidra_enriched") is True


def test_ghidra_enrich_batch_task_processes_all_targets_sequentially(hg_home, monkeypatch):
    """The `ghidra_enrich_batch` task type — what reveal_dir's detached spawn runs — must
    enrich every target in params_json.target_ids, marking each enriched independently, and
    a failure on ONE target must not abort the rest of the batch."""
    calls = []

    def _fake_enrich(session, project, target):
        calls.append(target.id)
        if target.name == "bad":
            raise RuntimeError("boom")
        return {"ok": True, "recorded": True, "functions": 0, "calls": 0, "structs": 0}

    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_target", _fake_enrich)
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        p = create_project(s, name="dispatch-enrich-batch")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        a = _executable_child(s, p, name="usr/sbin/httpd", parent=fw, visible=True)
        bad = ingest_file(s, p, fixture_path("vuln_httpd"), name="bad", parent=fw, visible=True)
        c = _executable_child(s, p, name="usr/sbin/telnetd", parent=fw, visible=True)
        s.flush()
        task = create_task(s, project=p, target_id=fw.id, type="ghidra_enrich_batch",
                           params={"target_ids": [a.id, bad.id, c.id]})
        task_id, aid, badid, cid = task.id, a.id, bad.id, c.id

    status = run_task_sync(task_id)
    assert status == "succeeded"           # one bad target doesn't fail the whole batch
    assert calls == [aid, badid, cid]      # processed in order, including past the failure
    with session_scope() as s:
        assert s.get(Target, aid).metadata_json.get("ghidra_enriched") is True
        assert s.get(Target, badid).metadata_json.get("ghidra_enriched") is not True
        assert s.get(Target, cid).metadata_json.get("ghidra_enriched") is True


def test_ghidra_enrichment_marks_failed_task_on_spawn_error(hg_home, monkeypatch):
    """If spawn_detached_task itself raises (e.g. fork/exec resource exhaustion), the Task
    must end up terminal (failed), not stuck 'queued' forever — a permanently-queued task
    would wrongly block every future reveal from ever retrying (the already_running check)."""
    monkeypatch.setattr("hexgraph.engine.re.ghidra.enrich_enabled", lambda: True)

    def _boom(task_id):
        raise OSError("Resource temporarily unavailable")

    monkeypatch.setattr("hexgraph.engine.worker.spawn_detached_task", _boom)
    with session_scope() as s:
        p = create_project(s, name="spawn-fails")
        child = _executable_child(s, p)
        cid, pid = child.id, p.id

    with session_scope() as s:
        out = set_visible(s, pid, cid, True, enrich=True)
        assert out["enrichment_queued"] is False   # spawn failed — nothing actually queued

        from hexgraph.db.models import Task, TaskStatus
        task_id = s.get(Target, cid).metadata_json["ghidra_enrich_task_id"]
        assert s.get(Task, task_id).status == TaskStatus.failed  # terminal, not stuck queued


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


def test_project_payload_tolerates_string_evidence_json(hg_home):
    """Regression: a finding whose `evidence_json` reads back as a *string* (a legacy or
    hand-edited double-encoded row) must NOT 500 the project endpoint. The read path coerces
    it to an object — recovering a double-encoded dict where possible — so one malformed
    finding can't take down the whole listing (the `is_verified` 'str has no .get' crash)."""
    with session_scope() as s:
        p = create_project(s, name="strev")
        fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
        fw.kind = TargetKind.firmware_image
        child = ingest_file(s, p, fixture_path("vuln_httpd"), name="lib/x.so", parent=fw, visible=False)
        s.flush()
        # Assigning a str to a JSON column double-encodes it, so it reads back as a str.
        # A double-encoded dict is recoverable; a non-JSON string degrades to {}.
        s.add(Finding(project_id=p.id, target_id=child.id, task_id="t", title="dbl-encoded",
                      severity="high", confidence="high", category="auth", summary="s", reasoning="r",
                      evidence_json=json.dumps({"extra": {"verification": {"verified": True}}}),
                      finding_type="poc", status="new"))
        s.add(Finding(project_id=p.id, target_id=fw.id, task_id="t", title="garbage-ev",
                      severity="low", confidence="low", category="auth", summary="s", reasoning="r",
                      evidence_json="not json at all", finding_type="vulnerability", status="new"))
        pid = p.id

    resp = TestClient(create_app()).get(f"/api/projects/{pid}")
    assert resp.status_code == 200  # was 500 before the fix
    body = resp.json()
    # Visible finding with garbage evidence: coerced to an object, not verified.
    g = next(f for f in body["findings"] if f["title"] == "garbage-ev")
    assert g["evidence"] == {} and g["verified"] is False
    # Hidden double-encoded finding: parsed back, its verification recovered.
    d = next(f for f in body["hidden_findings"] if f["title"] == "dbl-encoded")
    assert d["verified"] is True
    assert d["evidence"]["extra"]["verification"]["verified"] is True


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
