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


def test_install_help_for_each_agent():
    from hexgraph.agent_setup import install_help

    assert "claude mcp add hexgraph" in install_help("claude")
    assert "mcp_servers.hexgraph" in install_help("codex")
    assert ".gemini/settings.json" in install_help("gemini")
    allh = install_help(None)
    assert "Claude Code" in allh and "Codex" in allh and "gemini-cli" in allh


def test_mcp_server_requires_sdk():
    # The SDK isn't installed in CI; serving must fail clearly, not import-error elsewhere.
    import pytest

    from hexgraph.mcp_server import serve_stdio

    with pytest.raises(SystemExit):
        serve_stdio()
