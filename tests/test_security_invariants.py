"""Enforce the security invariants from CLAUDE.md as tests (not just by construction):
the API key never lands in task-trace artifacts or API responses, and the server
refuses to bind a non-loopback address before reaching uvicorn."""

import os

import pytest

from hexgraph.api.app import create_app, run_server
from hexgraph.api import loopback as _loopback
from hexgraph.api.loopback import CONTAINER_ENV, OVERRIDE_ENV, assert_loopback
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


def test_container_bind_outside_a_container_warns_loudly(monkeypatch, capsys):
    # HEXGRAPH_IN_CONTAINER=1 set OUTSIDE a real container would silently bind all interfaces
    # (no compose publish boundary). It still binds (best-effort check, never a hard refusal),
    # but it must NOT be silent — warn loudly so an accidental/misused flag isn't a quiet leak.
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    monkeypatch.setenv(CONTAINER_ENV, "1")
    monkeypatch.setattr(_loopback, "_looks_like_container", lambda: False)
    assert_loopback("0.0.0.0")  # honored — does NOT raise
    err = capsys.readouterr().err
    assert "WARNING" in err and "0.0.0.0" in err and CONTAINER_ENV in err


def test_container_bind_inside_a_real_container_is_silent(monkeypatch, capsys):
    # The supported compose path (an actual container): accepted with no warning noise.
    monkeypatch.delenv(OVERRIDE_ENV, raising=False)
    monkeypatch.setenv(CONTAINER_ENV, "1")
    monkeypatch.setattr(_loopback, "_looks_like_container", lambda: True)
    assert_loopback("0.0.0.0")
    assert capsys.readouterr().err == ""  # no warning on the legitimate container path
