"""A verified PoC finding must be PRESENTABLE: a human reproduction command derived per
flavour (web/tcp/binary), and re-verify must PRESERVE/refresh the assurance triple."""

import json

from fastapi.testclient import TestClient

from hexgraph.api.app import create_app
from hexgraph.db.models import Finding
from hexgraph.db.session import session_scope
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.findings.poc import execute_poc, verify_poc
from hexgraph.engine.findings.poc_repro import repro_command
from hexgraph.engine.surfaces import register_web_surface
from hexgraph.engine.tasks import create_task
from hexgraph import settings as st

from conftest import fixture_path
from test_poc import FakeRunner, SPEC, _enable


# ── repro_command, per flavour ──────────────────────────────────────────────────────

def test_repro_command_web(hg_home):
    with session_scope() as s:
        p = create_project(s, name="repro-web")
        t = register_web_surface(s, p, "http://192.168.0.1:8080", name="vr")
        spec = {"steps": [
            {"method": "POST", "path": "/login", "body": {"user": "admin", "pw": "x"}},
            {"method": "GET", "path": "/cgi-bin/exec", "params": {"cmd": "id;echo {{NONCE}}"},
             "headers": {"X-Test": "1"}},
        ], "oracle": {"type": "body_contains", "value": "{{NONCE}}"}}
        cmd = repro_command(spec, t)
    assert isinstance(cmd, str)
    # one curl per step, against the surface base_url, placeholder left verbatim
    assert cmd.count("curl") == 2
    assert "http://192.168.0.1:8080/login" in cmd
    assert "-X POST" in cmd and "-X GET" in cmd
    assert "{{NONCE}}" in cmd  # not substituted in the human rendering
    assert "&&" in cmd  # steps chained
    # example: curl -sk -X POST ... && curl -sk -X GET 'http://192.168.0.1:8080/cgi-bin/exec?cmd=...'


def test_repro_command_tcp(hg_home):
    with session_scope() as s:
        p = create_project(s, name="repro-tcp")
        t = register_web_surface(s, p, "http://10.0.0.5:80", name="dev")
        spec = {"transport": "tcp", "port": 9999, "payload": "EXEC {{NONCE}}\n",
                "oracle": {"type": "response_contains", "value": "{{NONCE}}"}}
        cmd = repro_command(spec, t)
    assert isinstance(cmd, str)
    assert "nc" in cmd and "9999" in cmd
    assert cmd.startswith("printf ")  # payload piped in
    assert "10.0.0.5" in cmd  # host resolved from the surface
    assert "{{NONCE}}" in cmd


def test_repro_command_tcp_nested_block_no_payload(hg_home):
    with session_scope() as s:
        p = create_project(s, name="repro-tcp2")
        t = register_web_surface(s, p, "http://10.0.0.6:80", name="dev")
        spec = {"tcp": {"port": 23}, "oracle": {}}
        cmd = repro_command(spec, t)
    assert cmd == "nc 10.0.0.6 23"  # no payload → plain nc


def test_repro_command_binary(hg_home):
    with session_scope() as s:
        p = create_project(s, name="repro-bin")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        path = t.path
        spec = {"env": {"QUERY_STRING": "host=127.0.0.1;echo {{NONCE}}"},
                "argv": ["--serve"], "stdin": "data {{NONCE}}",
                "oracle": {"type": "output_contains", "value": "{{NONCE}}"}}
        cmd = repro_command(spec, t)
    assert isinstance(cmd, str)
    assert "QUERY_STRING=" in cmd  # env assignment precedes the program
    assert path in cmd  # the real target path
    assert "--serve" in cmd
    assert cmd.startswith("printf ")  # stdin piped in
    assert "{{NONCE}}" in cmd
    # example: printf 'data {{NONCE}}' | env 'QUERY_STRING=...{{NONCE}}' /path/to/diag --serve


def test_repro_command_binary_no_target():
    """No target context still yields a runnable binary line (placeholder path)."""
    cmd = repro_command({"argv": ["-x"], "oracle": {}}, None)
    assert isinstance(cmd, str) and "-x" in cmd


def test_repro_command_binary_shell_safe_against_hostile_env_and_argv():
    """The rendered line is for copy-paste; a hostile env KEY/VALUE, argv, or stdin must
    not break out of quoting. shlex.split must round-trip to the literal tokens, and the
    injected command must not appear as a bare (unquoted) shell word."""
    import shlex

    spec = {
        "env": {"A; rm -rf / #": "v$(touch /pwned)", "OK": "fine"},
        "argv": ["--x; reboot", "$(id)"],
        "stdin": "payload; halt",
        "oracle": {},
    }
    cmd = repro_command(spec, None)
    assert isinstance(cmd, str)
    # The whole pipeline tokenizes (as a POSIX shell would) to EXACTLY the literal tokens:
    # every hostile value is one inert word, and the env utility carries the hostile key as
    # a single KEY=VALUE token — no `;`, `$(...)`, or `#` ever becomes a separate shell word.
    assert shlex.split(cmd) == [
        "printf", "payload; halt", "|",
        "env", "A; rm -rf / #=v$(touch /pwned)", "OK=fine",
        "./target", "--x; reboot", "$(id)",
    ]


# ── re-verify preserves / refreshes the assurance triple ─────────────────────────────

def test_execute_poc_records_assurance_and_repro(hg_home):
    _enable()
    with session_scope() as s:
        p = create_project(s, name="assur")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        task = create_task(s, project=p, target_id=t.id, type="poc",
                           params={"poc": SPEC, "function": "run_diagnostic"})
        execute_poc(s, p, t, task, runner=FakeRunner())
        f = s.query(Finding).filter(Finding.task_id == task.id).one()
        extra = f.evidence_json["extra"]
        # assurance at the canonical location AND nested in verification
        assert extra["assurance"]["standard"] == "code_present"  # isolated binary = lab-confirmed
        assert extra["verification"]["assurance"] == extra["assurance"]
        # a human reproducer (not the raw JSON spec)
        assert extra["repro_command"]
        assert f.evidence_json["reproducer"] != json.dumps(SPEC)


def test_api_reverify_preserves_assurance(hg_home, monkeypatch):
    """Clicking Re-verify must NOT drop evidence.extra.assurance — it must set/refresh it
    (the regression this fix targets)."""
    _enable()
    with session_scope() as s:
        p = create_project(s, name="reverify")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="diag")
        task = create_task(s, project=p, target_id=t.id, type="poc",
                           params={"poc": SPEC, "function": "run_diagnostic"})
        execute_poc(s, p, t, task, runner=FakeRunner())
        fid = s.query(Finding).filter(Finding.task_id == task.id).one().id

    # Re-verify goes through the real engine; stub the sandbox runner via verify_poc's
    # get_executor so no Docker is needed.
    from hexgraph.engine.findings import poc as poc_mod
    monkeypatch.setattr(poc_mod, "get_executor", lambda: FakeRunner())

    client = TestClient(create_app())
    r = client.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 200, r.text
    assert r.json()["verified"] is True

    with session_scope() as s:
        f = s.get(Finding, fid)
        extra = f.evidence_json["extra"]
        # assurance is present at BOTH locations after re-verify (was dropped before the fix)
        assert extra["assurance"] is not None
        assert extra["assurance"]["standard"] == "code_present"
        assert extra["assurance"]["method"] == "dynamic"
        assert extra["verification"]["assurance"] == extra["assurance"]
        # the original spec (with {{NONCE}}) is preserved so re-verify stays repeatable
        assert extra["poc"] == SPEC
        # repro command refreshed
        assert extra["repro_command"]
