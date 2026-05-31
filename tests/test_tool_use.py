"""Tool-use / agent loop. The mock drives a canned tool sequence so the loop runs
offline at $0; the real sandboxed tools degrade gracefully when Docker is absent."""

import json
from pathlib import Path

from hexgraph.db.models import Finding, Node, Task
from hexgraph.db.session import session_scope
from hexgraph.engine.agent_tools import ToolContext, available_tools, run_tool
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync
from hexgraph.llm.base import LLMRequest, LLMResponse, ToolCall, ToolSpec, Usage
from hexgraph.llm.runner import run_findings_agentic
from hexgraph import settings as st

from conftest import fixture_path

_U = Usage(input_tokens=10, output_tokens=5, cost_source="mock", cost_usd=0.0)
_SPEC = ToolSpec("decompile_function", "d", {"type": "object", "properties": {}})


class FakeBackend:
    name = "fake"

    def __init__(self, turns):
        self.turns = turns
        self.i = 0
        self.saw_messages = []

    def complete(self, req):
        self.saw_messages.append(list(req.messages or []))
        t = self.turns[min(self.i, len(self.turns) - 1)]
        self.i += 1
        return t


def test_loop_runs_tools_then_parses():
    turns = [
        LLMResponse(text="let me look", usage=_U, stop_reason="tool_use",
                    tool_calls=[ToolCall("c1", "decompile_function", {"function": "cgi_handler"})]),
        LLMResponse(text=json.dumps({"findings": []}), usage=_U),
    ]
    be = FakeBackend(turns)
    seen = []
    findings, usage, transcript = run_findings_agentic(
        be, LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC], tool_runner=lambda c: seen.append(c.name) or "decompiled: void f(){}",
    )
    assert findings == [] and seen == ["decompile_function"]
    assert len(transcript) == 1 and transcript[0]["tool"] == "decompile_function"
    # turn 2 saw the tool result in the conversation
    assert any(m.get("role") == "tool" for m in be.saw_messages[1])
    assert usage.input_tokens == 20  # accumulated across two turns


def test_single_pass_when_no_tool_calls():
    be = FakeBackend([LLMResponse(text=json.dumps({"findings": []}), usage=_U)])
    called = []
    findings, _u, transcript = run_findings_agentic(
        be, LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC], tool_runner=lambda c: called.append(c) or "x",
    )
    assert findings == [] and called == [] and transcript == []  # identical to single pass


def test_step_budget_forces_answer():
    # Always asks for a tool; on the final (tools-disabled) step it must answer.
    tool_turn = LLMResponse(text="", usage=_U, stop_reason="tool_use",
                            tool_calls=[ToolCall("c", "decompile_function", {})])
    final = LLMResponse(text=json.dumps({"findings": []}), usage=_U)

    class Budget:
        name = "b"
        def __init__(self): self.n = 0
        def complete(self, req):
            self.n += 1
            return final if not req.tools else tool_turn  # tools=[] on the last step

    findings, _u, transcript = run_findings_agentic(
        Budget(), LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC], tool_runner=lambda c: "x", max_steps=3,
    )
    assert findings == []  # forced final answer, no exception


def test_read_imports_tool_offline(hg_home):
    with session_scope() as s:
        p = create_project(s, name="t")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy", "printf"], "mitigations": {"canary": False},
                           "strings": ["/cgi-bin/admin", "token="]}
        ctx = ToolContext(session=s, project=p, target=t)
        assert "strcpy" in run_tool(ctx, "read_imports", {})
        assert "/cgi-bin/admin" in run_tool(ctx, "list_strings", {"pattern": "cgi"})
        assert "token=" not in run_tool(ctx, "list_strings", {"pattern": "cgi"})


def test_fuzz_tool_only_when_enabled(hg_home):
    with session_scope() as s:
        p = create_project(s, name="t2")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        ctx = ToolContext(session=s, project=p, target=t)
        assert "fuzz_function" not in {sp.name for sp in available_tools(ctx)}
    st.update_settings({"features.fuzzing.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="t3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        ctx = ToolContext(session=s, project=p, target=t)
        assert "fuzz_function" in {sp.name for sp in available_tools(ctx)}


def test_end_to_end_agentic_mock(hg_home):
    """The agentic_overflow mock scenario drives the loop through execute_llm_task."""
    with session_scope() as s:
        p = create_project(s, name="e2e")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {"imports": ["strcpy"], "mitigations": {"canary": False}, "strings": []}
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           params={"mock_scenario": "agentic_overflow", "function": "cgi_handler"})
        task_id = task.id

    assert run_task_sync(task_id) in ("succeeded", "needs_triage")
    with session_scope() as s:
        fs = s.query(Finding).filter(Finding.task_id == task_id).all()
        assert any(f.severity == "critical" and "cgi_handler" in f.title for f in fs)
        task = s.get(Task, task_id)
        trace = Path(task.log_path) / "agent_trace.json"
        assert trace.is_file()
        steps = json.loads(trace.read_text())["steps"]
        assert any(stp["tool"] == "decompile_function" for stp in steps)
