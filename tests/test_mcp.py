"""MCP driver-mode surface: the sandboxed tool functions + agent setup help.
The MCP transport (stdio) needs the optional `mcp` SDK; the tool *logic* is tested
directly here."""

from hexgraph.db.session import session_scope
from hexgraph.engine import mcp_tools
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def test_catalog_exposes_core_tools():
    names = {t["name"] for t in mcp_tools.catalog()}
    assert {"list_targets", "decompile_function", "record_finding", "run_task", "search"} <= names
    # every tool is callable and schema-typed
    for t in mcp_tools.catalog():
        assert callable(t["fn"]) and t["schema"]["type"] == "object"


def test_list_and_facts(hg_home):
    with session_scope() as s:
        p = create_project(s, name="m")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}, "exports": ["ssdp_recv"]}
        pid, tid = p.id, t.id

    assert any(pr["id"] == pid for pr in mcp_tools.list_projects())
    targets = mcp_tools.list_targets(pid)
    assert targets and targets[0]["id"] == tid
    facts = mcp_tools.target_facts(tid)
    assert facts["imports"] == ["strcpy"] and facts["exports"] == ["ssdp_recv"]


def test_record_finding_validates_and_persists(hg_home):
    with session_scope() as s:
        p = create_project(s, name="m2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id

    bad = mcp_tools.record_finding(pid, tid, {"title": "x"})  # missing required fields
    assert "error" in bad

    good = mcp_tools.record_finding(pid, tid, {
        "title": "Hardcoded key in init", "severity": "high", "confidence": "high",
        "category": "hardcoded-secret", "summary": "s", "reasoning": "r",
        "evidence": {"function": "init"}})
    assert good.get("id")
    findings = mcp_tools.list_findings(pid)
    assert any(f["title"] == "Hardcoded key in init" and f["function"] == "init" for f in findings)

    # get_finding reads ONE finding back in full, including evidence.extra (where
    # verify_poc stores its result) — the finding analog of get_node.
    full = mcp_tools.get_finding(good["id"])
    assert full["title"] == "Hardcoded key in init"
    assert full["evidence"]["function"] == "init" and full["finding_type"]
    assert mcp_tools.get_finding("nope").get("error")


def test_run_task_static_analysis_offline(hg_home):
    with session_scope() as s:
        p = create_project(s, name="m3")  # mock backend
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}}
        tid = t.id

    res = mcp_tools.run_task(tid, "static_analysis", params={"mock_scenario": "critical_overflow",
                                                             "function": "cgi_handler"})
    assert res["status"] in ("succeeded", "needs_triage")
    assert any(f["severity"] == "critical" for f in res["findings"])


def test_write_tools_populate_graph(hg_home):
    from hexgraph.db.models import Edge, Node
    with session_scope() as s:
        p = create_project(s, name="w")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        pid, tid = p.id, t.id

    n = mcp_tools.create_node(pid, "function", "ssdp_recv", target_id=tid)
    assert n.get("id") and n["node_type"] == "function"
    # node bound to a missing target is rejected by the invariant
    assert "error" in mcp_tools.create_node(pid, "function", "x", target_id="nope")
    h = mcp_tools.create_hypothesis(pid, "parser overruns a buffer", target_id=tid)
    assert h.get("id") and h["status"] == "open"
    e = mcp_tools.create_edge(pid, "node", n["id"], "target", tid, "contains")
    assert e.get("id")
    with session_scope() as s:
        assert s.query(Node).filter(Node.project_id == pid, Node.name == "ssdp_recv").count() == 1
        assert s.query(Edge).filter(Edge.project_id == pid, Edge.type == "contains").count() >= 1


def test_catalog_group_filtering():
    read_only = {t["name"] for t in mcp_tools.catalog({"read"})}
    assert "decompile_function" in read_only
    assert "record_finding" not in read_only and "create_node" not in read_only and "run_task" not in read_only
    write_only = {t["name"] for t in mcp_tools.catalog({"write"})}
    assert {"record_finding", "create_node", "create_edge"} <= write_only
    assert "decompile_function" not in write_only
    # every catalog entry is tagged with a known group
    assert all(t["group"] in mcp_tools.GROUPS for t in mcp_tools.catalog())


def test_enabled_groups_from_settings(hg_home):
    from hexgraph import settings as st
    from hexgraph.mcp_server import enabled_groups

    assert enabled_groups() == {"read", "write", "run"}  # default all
    st.update_settings({"features.mcp.run": False, "features.mcp.write": False})
    assert enabled_groups() == {"read"}
    assert enabled_groups({"write"}) == {"write"}  # explicit override wins


def test_install_help_for_each_agent():
    from hexgraph.agent_setup import install_help

    assert "claude mcp add hexgraph" in install_help("claude")
    assert "mcp_servers.hexgraph" in install_help("codex")
    assert ".gemini/settings.json" in install_help("gemini")
    allh = install_help(None)
    assert "Claude Code" in allh and "Codex" in allh and "gemini-cli" in allh


def test_mcp_server_requires_sdk():
    # When the optional MCP SDK is absent, serving must fail clearly (SystemExit
    # with install guidance), not raise an opaque ImportError. Skip when the SDK
    # is installed (its presence can't exercise the absence path).
    import importlib.util

    import pytest

    if importlib.util.find_spec("mcp") is not None:
        pytest.skip("mcp SDK installed; absence path not exercisable")
    from hexgraph.mcp_server import serve_stdio

    with pytest.raises(SystemExit):
        serve_stdio()


def test_ingest_tool_offline(hg_home, monkeypatch):
    from hexgraph.engine import mcp_tools
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    r = mcp_tools.ingest(fixture_path("vuln_httpd"), name="x")
    assert r.get("project_id") and r.get("recon") is False
    assert "ingest" in {t["name"] for t in mcp_tools.catalog({"run"})}


def test_skill_markdown_is_a_claude_skill():
    from hexgraph.agent_setup import skill_markdown, write_skill
    import tempfile, os
    md = skill_markdown()
    assert md.startswith("---\n") and "name: hexgraph-vr" in md and "Never execute" in md
    d = tempfile.mkdtemp()
    p = write_skill(d)
    assert os.path.isfile(p) and p.endswith("hexgraph-vr/SKILL.md")


def test_cli_mcp_check_lists_tools(capsys):
    from hexgraph.cli import main
    rc = main(["mcp", "--check", "--tools", "read"])
    out = capsys.readouterr().out
    assert rc == 0 and "decompile_function" in out and "record_finding" not in out


def test_install_help_includes_sdk_and_check():
    from hexgraph.agent_setup import install_help
    h = install_help("claude")
    assert "pip install" in h and "--check" in h and "serve" in h and "same time" in h


def test_get_schemas_contract():
    from hexgraph.engine import mcp_tools
    sch = mcp_tools.get_schemas()
    assert "command-injection" in sch["finding"]["category"]
    assert "critical" in sch["finding"]["severity"]
    assert "input" in sch["node_types"] and "sink" in sch["node_types"]
    assert "taints" in sch["edge_types"]
    assert "extra" in sch["finding"]["evidence_fields"]


def test_create_node_address_and_input_sink(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="addr")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    fn = mcp_tools.create_node(pid, "function", "run_diagnostic", target_id=tid, address="0x401234",
                               attrs={"params": [{"name": "host", "note": "attacker-controlled"}]})
    assert fn["address"] == "0x401234"
    assert mcp_tools.create_node(pid, "input", "QUERY_STRING").get("id")
    assert mcp_tools.create_node(pid, "sink", "system", target_id=tid).get("id")


def test_target_facts_dangerous_imports(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="dg")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        t.metadata_json = {"imports": ["system", "getenv", "snprintf", "strcpy"]}
        tid = t.id
    assert set(mcp_tools.target_facts(tid)["dangerous_imports"]) == {"system", "strcpy"}


def test_update_finding_and_hypothesis_lifecycle(hg_home):
    from hexgraph.engine import mcp_tools
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel
    with session_scope() as s:
        p = create_project(s, name="life")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="cmd inj", severity="high", confidence="low", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence(function="run_diagnostic")))
        pid, tid, fid = p.id, t.id, f.id
    h = mcp_tools.create_hypothesis(pid, "pre-auth RCE via host param", target_id=tid)
    # link the finding as supporting evidence → hypothesis becomes supported
    res = mcp_tools.link_evidence(h["id"], fid, "supports")
    assert res["status"] == "supported" and len(res["supports"]) == 1
    # confirm the finding in place
    up = mcp_tools.update_finding(fid, status="confirmed", confidence="high")
    assert up["status"] == "confirmed" and up["confidence"] == "high"
    assert mcp_tools.set_hypothesis_status(h["id"], "confirmed")["status"] == "confirmed"


def test_verify_poc_attaches_to_finding(hg_home, monkeypatch):
    from hexgraph.engine import mcp_tools
    from hexgraph.db.models import Finding
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel

    def fake_verify(session, project, target, spec, runner=None):
        # Mirror the real verify_poc: it returns the NONCE-SUBSTITUTED spec. The caller
        # must NOT persist that (it would bake in a stale literal nonce) — it stores the
        # original template instead. Return a substituted copy so the test can tell them apart.
        substituted = {"oracle": {"type": "output_contains", "value": "HEXGRAPH_PWNED_x"}}
        return {"verified": True, "detail": "nonce in output", "exit_code": 0,
                "nonce": "HEXGRAPH_PWNED_x", "output": "...HEXGRAPH_PWNED_x...", "spec": substituted}
    monkeypatch.setattr("hexgraph.engine.poc.verify_poc", fake_verify)

    with session_scope() as s:
        p = create_project(s, name="vp")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        task = create_task(s, project=p, target_id=t.id, type="poc")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="poc", severity="high", confidence="low", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence()))
        tid, fid = t.id, f.id
    r = mcp_tools.verify_poc(tid, {"oracle": {"type": "output_contains", "value": "{{NONCE}}"}}, finding_id=fid)
    assert r["verified"] is True and r["attached_to"] == fid
    with session_scope() as s:
        f = s.get(Finding, fid)
        assert f.evidence_json["extra"]["verification"]["verified"] is True
        # The stored PoC spec must be the ORIGINAL template (with {{NONCE}} intact), not the
        # nonce-substituted copy — otherwise a later re-verify carries a stale literal token.
        assert f.evidence_json["extra"]["poc"]["oracle"]["value"] == "{{NONCE}}"


def test_record_finding_accepts_finding_type(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="ft")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    r = mcp_tools.record_finding(pid, tid, {
        "title": "RCE PoC", "severity": "critical", "confidence": "high",
        "category": "command-injection", "summary": "s", "reasoning": "r",
        "evidence": {"function": "f"}}, finding_type="poc")
    assert r.get("finding_type") == "poc"
    assert "error" in mcp_tools.record_finding(pid, tid, {
        "title": "x", "severity": "low", "confidence": "low", "category": "other",
        "summary": "s", "reasoning": "r", "evidence": {}}, finding_type="bogus")


def test_graph_read_tools(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="rd")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    n = mcp_tools.create_node(pid, "function", "cgi_handler", target_id=tid, address="0x401200",
                              attrs={"params": [{"name": "req"}]})
    got = mcp_tools.get_node(n["id"])
    assert got["address"] == "0x401200" and got["attrs"]["params"][0]["name"] == "req"
    assert any(x["id"] == n["id"] for x in mcp_tools.list_nodes(pid, node_type="function"))
    mcp_tools.create_edge(pid, "node", n["id"], "target", tid, "contains")
    assert any(e["src_id"] == n["id"] for e in mcp_tools.list_edges(pid, node_id=n["id"]))
