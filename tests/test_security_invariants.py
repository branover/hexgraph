"""Enforce the security invariants from CLAUDE.md as tests (not just by construction):
the API key never lands in task-trace artifacts or API responses, and the server
refuses to bind a non-loopback address before reaching uvicorn."""

import os

import pytest

from hexgraph.api.app import create_app, run_server
from hexgraph.api.loopback import OVERRIDE_ENV
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.tasks import create_task
from hexgraph.engine.worker import run_task_sync

from fastapi.testclient import TestClient
from conftest import fixture_path

SENTINEL = "sk-ant-SENTINEL-DEADBEEF-do-not-leak"


def test_api_key_never_in_traces_or_api(hg_home, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SENTINEL)
    monkeypatch.setenv("HEXGRAPH_LLM_BACKEND", "mock")
    with session_scope() as s:
        p = create_project(s, name="sec")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "imports": ["strcpy"],
                           "mitigations": {"canary": False}}
        task = create_task(s, project=p, target_id=t.id, type="static_analysis",
                           params={"function": "cgi_handler"})
        pid, tid, log_path = p.id, task.id, task.log_path

    run_task_sync(tid)

    # 1) The key must not appear in any trace artifact the task wrote.
    leaked = []
    if log_path and os.path.isdir(log_path):
        for root, _dirs, names in os.walk(log_path):
            for n in names:
                try:
                    if SENTINEL in open(os.path.join(root, n), "r", errors="ignore").read():
                        leaked.append(os.path.join(root, n))
                except OSError:
                    pass
    assert leaked == [], f"API key leaked into trace files: {leaked}"

    # 2) The key must not appear in any API response for the project/task.
    c = TestClient(create_app())
    for url in (f"/api/projects/{pid}", f"/api/tasks/{tid}/detail"):
        assert SENTINEL not in c.get(url).text


def test_run_server_refuses_non_loopback(monkeypatch):
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    reached = {"uvicorn": False}
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: reached.update(uvicorn=True))
    with pytest.raises(RuntimeError):
        run_server(host="0.0.0.0", port=8765)
    assert reached["uvicorn"] is False  # refused BEFORE binding


def test_run_server_override_allows_non_loopback(monkeypatch):
    monkeypatch.setenv(OVERRIDE_ENV, "1")
    reached = {"host": None}
    import uvicorn
    monkeypatch.setattr(uvicorn, "run", lambda app, host=None, port=None, **k: reached.update(host=host))
    run_server(host="0.0.0.0", port=8765)
    assert reached["host"] == "0.0.0.0"  # override lets it through to bind
