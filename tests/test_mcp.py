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
    # The SDK isn't installed in CI; serving must fail clearly, not import-error elsewhere.
    import pytest

    from hexgraph.mcp_server import serve_stdio

    with pytest.raises(SystemExit):
        serve_stdio()
