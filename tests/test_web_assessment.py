"""Dynamic web assessment (docs/design-dynamic-surfaces.md, Phase 3): the crafted-HTTP
`http_request` tool and the multi-step web `verify_poc` over a live surface.

Two layers:
- OFFLINE: the probe's oracle/request logic (pure functions) + the egress gate (http_request
  is denied + audited when features.network is off) — no Docker.
- LIVE (Docker + sandbox image gated): build/run the vulnrouter container and let HexGraph
  find + verify the auth bypass and the post-auth RCE end to end through the sandbox.
"""

import importlib.util
import os
import subprocess

import pytest

from conftest import SANDBOX_READY, fixture_path

# --- import the in-sandbox probe module directly for offline unit tests ---
_spec = importlib.util.spec_from_file_location(
    "http_probe", os.path.join(os.path.dirname(__file__), "..", "src", "hexgraph",
                               "sandbox", "probes", "http_probe.py"))
http_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(http_probe)


# ---------------- offline: probe pure logic ----------------

def test_build_form_vs_json():
    m, url, req = http_probe._build("http://h:8080", {"method": "post", "path": "/x",
                                    "params": {"a": "1"}, "body": {"k": "v"}})
    assert m == "POST" and url == "http://h:8080/x?a=1"
    assert req.data == b"k=v" and req.get_header("Content-type") == "application/x-www-form-urlencoded"
    _, _, jreq = http_probe._build("http://h:8080", {"method": "POST", "path": "/x",
                                   "body": {"k": "v"}, "json": True})
    assert jreq.data == b'{"k": "v"}' and jreq.get_header("Content-type") == "application/json"


def test_oracle_variants():
    ok = lambda body, status=200: [{"ok": True, "status": status, "body": body}]
    assert http_probe._check_oracle({"type": "body_contains", "value": "FLAG"}, ok("x FLAG y"))[0]
    assert not http_probe._check_oracle({"type": "body_contains", "value": "FLAG"}, ok("nope"))[0]
    assert http_probe._check_oracle({"type": "status_is", "value": 200}, ok("", 200))[0]
    assert not http_probe._check_oracle({"type": "status_is", "value": 200}, ok("", 401))[0]
    # status_differs: baseline 401 (unbypassed) → this bypassed request returned 200 = success
    assert http_probe._check_oracle({"type": "status_differs", "value": 401}, ok("", 200))[0]
    assert not http_probe._check_oracle({"type": "status_differs", "value": 401}, ok("", 401))[0]
    # a failed last request never verifies
    assert not http_probe._check_oracle({"type": "body_contains", "value": "x"},
                                        [{"ok": False, "error": "Timeout"}])[0]


def test_oracle_only_inspects_final_step():
    steps = [{"ok": True, "status": 200, "body": "NONCE-here"}, {"ok": True, "status": 200, "body": "clean"}]
    assert not http_probe._check_oracle({"type": "body_contains", "value": "NONCE"}, steps)[0]


# ---------------- offline: egress gate on http_request ----------------

def test_http_request_denied_and_audited_when_network_off(hg_home):
    from hexgraph.db.models import EgressEvent
    from hexgraph.db.session import session_scope
    from hexgraph.engine import mcp_tools as M
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface

    with session_scope() as s:
        p = create_project(s, name="he")
        t = register_web_surface(s, p, "http://127.0.0.1:8080", name="x")
        pid, tid = p.id, t.id
    out = M.http_request(tid, "GET", "/")
    assert "error" in out and "features.network" in out["error"]
    with session_scope() as s:
        ev = s.query(EgressEvent).filter(EgressEvent.project_id == pid).all()
        assert len(ev) == 1 and ev[0].allowed is False and ev[0].tool == "http_request"


# ---------------- live: full vulnrouter assessment ----------------

@pytest.fixture(scope="module")
def vulnrouter():
    """Build + run the vulnrouter container; yield its base_url on the docker bridge.
    Skips unless Docker + the sandbox image are present. (The http_probe is mounted
    from the package into the sandbox automatically, so no image rebuild is needed.)"""
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image (make sandbox-build)")
    img, name, flag = "hexgraph-vulnrouter:latest", "hexgraph-vr-pytest", "ROUTER-FLAG-PYTEST"
    subprocess.run(["docker", "build", "-q", "-t", img, fixture_path("vulnrouter")], check=True,
                   capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, "-e", f"ROUTER_FLAG={flag}", img],
                   check=True, capture_output=True)
    try:
        ip = subprocess.run(["docker", "inspect", "-f",
                             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
                            check=True, capture_output=True, text=True).stdout.strip()
        import time
        time.sleep(1.0)
        yield {"base_url": f"http://{ip}:8080", "flag": flag}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_live_vulnrouter_auth_bypass_and_rce(hg_home, vulnrouter):
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine import mcp_tools as M
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface

    settings.update_settings({"features": {"network": {"enabled": True}}})
    base = vulnrouter["base_url"]
    with session_scope() as s:
        p = create_project(s, name="vr")
        t = register_web_surface(s, p, base, name="vulnrouter")
        tid = t.id

    # baseline: the protected route is denied without a session
    r = M.http_request(tid, "GET", "/admin/flag")
    assert r.get("status") == 401

    # auth bypass: empty token authenticates → the flag (a server secret) appears = unforgeable
    bypass = M.verify_poc(tid, {
        "steps": [{"method": "POST", "path": "/api/login", "body": {"token": ""}},
                  {"method": "GET", "path": "/admin/flag"}],
        "oracle": {"type": "body_contains", "value": vulnrouter["flag"]}})
    assert bypass["verified"] is True

    # post-auth RCE: injected `echo {{NONCE}}` output proves command execution
    rce = M.verify_poc(tid, {
        "steps": [{"method": "POST", "path": "/api/login", "body": {"token": ""}},
                  {"method": "POST", "path": "/api/diag", "body": {"host": "127.0.0.1; echo {{NONCE}}"}}],
        "oracle": {"type": "body_contains", "value": "{{NONCE}}"}})
    assert rce["verified"] is True and "HEXGRAPH_PWNED_" in (rce.get("output") or "")


def test_live_http_request_returns_body(hg_home, vulnrouter):
    from hexgraph import settings
    from hexgraph.db.session import session_scope
    from hexgraph.engine import mcp_tools as M
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface

    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p = create_project(s, name="vr")
        t = register_web_surface(s, p, vulnrouter["base_url"], name="vr")
        tid = t.id
    r = M.http_request(tid, "GET", "/")
    assert r.get("status") == 200 and "admin console" in (r.get("body") or "")
    assert r.get("headers", {}).get("Server", "").startswith("Orbweaver")
