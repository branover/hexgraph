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
from hexgraph.llm.base import (LLMRequest, LLMResponse, RateLimitError, ToolCall, ToolSpec,
                               Usage)
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


def test_loop_runs_multiple_tool_calls_in_one_turn():
    """A single turn returning TWO ToolCalls must run BOTH, in order, and feed both results
    back (review #12)."""
    turns = [
        LLMResponse(text="look at both", usage=_U, stop_reason="tool_use", tool_calls=[
            ToolCall("c1", "decompile_function", {"function": "a"}),
            ToolCall("c2", "disassemble", {"function": "b"})]),
        LLMResponse(text=json.dumps({"findings": []}), usage=_U),
    ]
    be = FakeBackend(turns)
    seen = []
    findings, _u, transcript = run_findings_agentic(
        be, LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC, ToolSpec("disassemble", "d", {"type": "object", "properties": {}})],
        tool_runner=lambda c: seen.append(c.name) or f"ran {c.name}",
    )
    assert findings == [] and seen == ["decompile_function", "disassemble"]  # both, in order
    assert [t["tool"] for t in transcript] == ["decompile_function", "disassemble"]
    # the second turn saw BOTH tool results fed back
    tool_msgs = [m for m in be.saw_messages[1] if m.get("role") == "tool"]
    assert {m["name"] for m in tool_msgs} == {"decompile_function", "disassemble"}


def test_loop_retries_on_rate_limit_then_succeeds():
    """A backend that raises RateLimitError once, then returns findings, must be RETRIED by
    the agentic loop (base_delay=0) and ultimately succeed (review #12)."""
    class Flaky:
        name = "flaky"
        def __init__(self):
            self.calls = 0
        def complete(self, req):
            self.calls += 1
            if self.calls == 1:
                raise RateLimitError("429 slow down")
            return LLMResponse(text=json.dumps({"findings": []}), usage=_U)

    be = Flaky()
    findings, _u, transcript = run_findings_agentic(
        be, LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC], tool_runner=lambda c: "x", base_delay=0.0,
    )
    assert findings == [] and be.calls == 2  # retried once, then succeeded


def test_loop_repairs_invalid_json_on_reask():
    """The final step returns invalid JSON; the schema-repair path re-asks and the next reply
    is valid — the loop must recover and produce findings (review #12)."""
    turns = [
        LLMResponse(text="not json {{{", usage=_U),                 # final step: unparseable
        LLMResponse(text=json.dumps({"findings": []}), usage=_U),   # re-ask: valid
    ]
    be = FakeBackend(turns)
    findings, _u, _transcript = run_findings_agentic(
        be, LLMRequest(task_type="static_analysis", task_id="t", prompt="go"),
        tools=[_SPEC], tool_runner=lambda c: "x", base_delay=0.0,
    )
    assert findings == [] and be.i == 2  # consumed the bad reply, then the repaired one


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


def test_check_decompiler_tool_offline(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.engine.mcp_tools._sandbox_image_built", lambda tag: True)
    with session_scope() as s:
        p = create_project(s, name="t")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        ctx = ToolContext(session=s, project=p, target=t)
        assert "check_decompiler" in {sp.name for sp in available_tools(ctx)}
        out = run_tool(ctx, "check_decompiler", {})
        assert "radare2" in out and "WORKING" in out


def test_check_features_tool_offline(hg_home, monkeypatch):
    """The in-loop agent tool: disabled features render plainly; an enabled-but-broken one
    surfaces BROKEN + its remediation so the model can plan instead of failing blind."""
    st.update_settings({"features.floss.enabled": True})
    monkeypatch.setattr("hexgraph.engine.mcp_tools._image_smoke",
                        lambda image, argv, timeout=30: (False, "image not built"))
    with session_scope() as s:
        p = create_project(s, name="t")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        ctx = ToolContext(session=s, project=p, target=t)
        assert "check_features" in {sp.name for sp in available_tools(ctx)}
        out = run_tool(ctx, "check_features", {})
        assert "floss: BROKEN" in out
        assert "just sandbox-build" in out
        # a gated-off feature still appears, as DISABLED
        assert "yara: DISABLED" in out


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
