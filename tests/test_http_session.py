"""http_request cookie jar (session handle): cookies the server sets are remembered and
re-sent on the next call with the same session label, so a free-form auth flow works
across separate http_request calls. Offline (faked runner) + a live vulnrouter case."""

import subprocess

import pytest

from conftest import SANDBOX_READY, container_ip, fixture_path, wait_for_port
from hexgraph.engine.targets.surfaces import _parse_set_cookie


def test_parse_set_cookie():
    assert _parse_set_cookie(["session=abc123; Path=/; HttpOnly"]) == {"session": "abc123"}
    assert _parse_set_cookie(["a=1; Path=/", "b=2; Secure"]) == {"a": "1", "b": "2"}
    assert _parse_set_cookie([]) == {}
    assert _parse_set_cookie(["malformed"]) == {}


class _FakeRunner:
    """Records the channels it's given and replays canned responses (one per call)."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.channels = []

    def run_channel_probe(self, probe, *, channel, **kw):
        self.channels.append(channel)
        return {"response": self.responses.pop(0)}


def test_session_jar_injects_stored_cookies(hg_home, monkeypatch):
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.surfaces import clear_http_session, register_web_surface, run_http_request

    settings.update_settings({"features": {"network": {"enabled": True}}})
    runner = _FakeRunner([
        # 1) login → server sets a session cookie
        {"ok": True, "status": 200, "headers": {}, "set_cookie": ["session=tok-9; Path=/"], "body": "ok"},
        # 2) next call → we expect the jar to have injected the cookie
        {"ok": True, "status": 200, "headers": {}, "set_cookie": [], "body": "FLAG"},
    ])
    with session_scope() as s:
        p = create_project(s, name="cj")
        t = register_web_surface(s, p, "http://127.0.0.1:8080", name="x")
        clear_http_session(t.id, "admin")  # start clean

        r1 = run_http_request(s, p, t, request={"method": "POST", "path": "/api/login",
                                                "body": {"token": ""}},
                              runner=runner, http_session="admin")
        assert r1["session_cookies"] == ["session"]
        # the FIRST request carried no Cookie header
        assert "Cookie" not in (runner.channels[0]["request"].get("headers") or {})

        r2 = run_http_request(s, p, t, request={"method": "GET", "path": "/admin/flag"},
                              runner=runner, http_session="admin")
        # the SECOND request had the stored cookie injected
        assert runner.channels[1]["request"]["headers"]["Cookie"] == "session=tok-9"
        assert r2["body"] == "FLAG"


def test_no_session_means_no_jar(hg_home):
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.surfaces import register_web_surface, run_http_request

    settings.update_settings({"features": {"network": {"enabled": True}}})
    runner = _FakeRunner([{"ok": True, "status": 200, "headers": {},
                           "set_cookie": ["session=x; Path=/"], "body": "ok"}])
    with session_scope() as s:
        p = create_project(s, name="ns")
        t = register_web_surface(s, p, "http://127.0.0.1:8080", name="x")
        r = run_http_request(s, p, t, request={"method": "GET", "path": "/"}, runner=runner)
        assert "session_cookies" not in r  # no jar without a session label


@pytest.fixture(scope="module")
def vulnrouter():
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image")
    img, name, flag = "hexgraph-vulnrouter:latest", "hexgraph-vr-session", "ROUTER-FLAG-SESS"
    subprocess.run(["docker", "build", "-q", "-t", img, fixture_path("vulnrouter")], check=True,
                   capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, "-e", f"ROUTER_FLAG={flag}", img],
                   check=True, capture_output=True)
    try:
        ip = container_ip(name)
        wait_for_port(ip, 8080)
        yield {"base_url": f"http://{ip}:8080", "flag": flag}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_live_session_auth_flow_across_calls(hg_home, vulnrouter):
    """Log in (empty-token bypass) on one http_request call, then read /admin/flag on a
    SEPARATE call with the same session label — the jar carries the cookie."""
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.agent import mcp_tools as M
    from hexgraph.engine.targets.ingest import create_project
    from hexgraph.engine.targets.surfaces import register_web_surface

    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p = create_project(s, name="vr")
        t = register_web_surface(s, p, vulnrouter["base_url"], name="vr")
        tid = t.id

    # no session yet → protected route denied
    assert M.http_request(tid, "GET", "/admin/flag", session="admin").get("status") == 401
    # log in with the bypass; the jar stores the session cookie
    login = M.http_request(tid, "POST", "/api/login", body={"token": ""}, session="admin")
    assert "session" in (login.get("session_cookies") or [])
    # separate call, same session → now authorized, flag visible
    flag = M.http_request(tid, "GET", "/admin/flag", session="admin")
    assert flag.get("status") == 200 and vulnrouter["flag"] in (flag.get("body") or "")
