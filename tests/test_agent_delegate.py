"""UI-driven delegate: HexGraph launches a coding agent CLI wired to the MCP
server with restricted tools. The real CLI is env-gated; here we inject a fake
run_cli and test command construction, the prompt, gating, and failure handling."""

import pytest

from hexgraph.db.session import session_scope
from hexgraph.engine.agent_delegate import (
    DelegateError, build_command, delegate_prompt, execute_delegate,
)
from hexgraph.record_keeping import RECORD_KEEPING
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph import settings as st

from conftest import fixture_path


def test_build_command_claude_restricts_tools():
    cmd = build_command("claude", "claude", "PROMPT", model="claude-opus-4-8")
    assert cmd[0] == "claude" and "-p" in cmd
    j = cmd[cmd.index("--mcp-config") + 1]
    assert "hexgraph" in j  # MCP server wired inline
    allowed = cmd[cmd.index("--allowedTools") + 1]
    assert "mcp__hexgraph" in allowed and "Bash" not in allowed
    assert "Bash" in cmd[cmd.index("--disallowedTools") + 1]  # no shell on the target
    assert "--model" in cmd


def test_build_command_unknown_agent():
    with pytest.raises(DelegateError):
        build_command("nope", "x", "p")


def test_delegate_prompt_carries_ids_and_rules(hg_home):
    with session_scope() as s:
        p = create_project(s, name="d")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        prompt = delegate_prompt(p.id, t, "task-123", "look at cgi_handler")
        assert "task-123" in prompt and t.id in prompt and p.id in prompt
        assert "Never execute" in prompt and "finding_record" in prompt
        assert "look at cgi_handler" in prompt
        # delegate mode inlines the record-keeping rubric (no sub-file is materialized,
        # so the SKILL's "read record-keeping.md" pointer must resolve to inlined content)
        assert RECORD_KEEPING in prompt


def test_execute_delegate_disabled_raises(hg_home):
    with session_scope() as s:
        p = create_project(s, name="d2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="agent_delegate")
        with pytest.raises(DelegateError):
            execute_delegate(s, p, t, task, run_cli=lambda cmd, timeout: (0, "", ""))


def test_execute_delegate_runs_and_traces(hg_home):
    st.update_settings({"features.agent.enabled": True, "features.agent.cli": "claude"})
    seen = {}

    def fake(cmd, timeout):
        seen["cmd"] = cmd
        return 0, '{"result": "done"}', ""

    with session_scope() as s:
        p = create_project(s, name="d3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="agent_delegate", objective="find bugs")
        n = execute_delegate(s, p, t, task, run_cli=fake)
        assert n == 0  # the stub recorded nothing
        assert seen["cmd"][0] == "claude"
        from pathlib import Path
        assert (Path(task.log_path) / "delegate_prompt.txt").is_file()
        assert (Path(task.log_path) / "delegate_output.txt").is_file()


def test_execute_delegate_failure_raises(hg_home):
    st.update_settings({"features.agent.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="d4")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="agent_delegate")
        with pytest.raises(DelegateError):
            execute_delegate(s, p, t, task, run_cli=lambda cmd, timeout: (1, "", "boom: not found"))


def test_capability_gating(hg_home):
    from hexgraph.engine.capabilities import capabilities_for

    assert "agent_delegate" not in capabilities_for("target", "executable")
    st.update_settings({"features.agent.enabled": True})
    assert "agent_delegate" in capabilities_for("target", "executable")
    assert "agent_delegate" in capabilities_for("node", "function")


def test_record_finding_attributes_to_task(hg_home):
    from hexgraph.db.models import Finding
    from hexgraph.engine import mcp_tools

    with session_scope() as s:
        p = create_project(s, name="d5")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        task = create_task(s, project=p, target_id=t.id, type="agent_delegate")
        pid, tid, task_id = p.id, t.id, task.id

    mcp_tools.record_finding(pid, tid, {
        "title": "UAF in handler", "severity": "high", "confidence": "medium",
        "category": "memory-safety", "summary": "s", "reasoning": "r",
        "evidence": {"function": "handler"}}, task_id=task_id)
    with session_scope() as s:
        fs = s.query(Finding).filter(Finding.task_id == task_id).all()
        assert len(fs) == 1 and fs[0].origin == "agent"
