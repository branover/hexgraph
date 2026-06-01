"""Live web route discovery (gap #2): web_discover crawls a registered/rehosted surface
(links + forms + common paths) and materializes endpoint/param nodes — so the agent isn't
limited to a hand-supplied surface_recon spec. Offline HTML-parser test + a Docker-gated
live crawl of the vulnrouter container."""

import importlib.util
import os
import subprocess

import pytest

from conftest import SANDBOX_READY, fixture_path

_spec = importlib.util.spec_from_file_location(
    "web_discover_probe", os.path.join(os.path.dirname(__file__), "..", "src", "hexgraph",
                                       "sandbox", "probes", "web_discover_probe.py"))
web_discover = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(web_discover)


def test_link_and_form_parser():
    p = web_discover._Links()
    p.feed("""<html><body>
        <a href="/admin/status">status</a> <a href="login.cgi">login</a>
        <form action="/api/diag" method="post">
          <input name="host"><input name="count"><select name="proto"></select>
        </form>
        <form><input name="q"></form>
    </body></html>""")
    assert "/admin/status" in p.hrefs and "login.cgi" in p.hrefs
    diag = next(f for f in p.forms if f["action"] == "/api/diag")
    assert diag["method"] == "POST" and set(diag["params"]) == {"host", "count", "proto"}
    bare = next(f for f in p.forms if not f["action"])
    assert bare["params"] == ["q"]


def test_seeds_cover_common_embedded_paths():
    for p in ("/", "/cgi-bin/luci", "/admin", "/login"):
        assert p in web_discover.SEEDS


@pytest.fixture(scope="module")
def vulnrouter():
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image")
    img, name = "hexgraph-vulnrouter:latest", "hexgraph-vr-discover"
    subprocess.run(["docker", "build", "-q", "-t", img, fixture_path("vulnrouter")], check=True,
                   capture_output=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", name, "-e", "ROUTER_FLAG=FLAG-D", img],
                   check=True, capture_output=True)
    try:
        ip = subprocess.run(["docker", "inspect", "-f",
                             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name],
                            check=True, capture_output=True, text=True).stdout.strip()
        import time
        time.sleep(1.0)
        yield f"http://{ip}:8080"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_live_web_discover_materializes_endpoints(hg_home, vulnrouter):
    from hexgraph import settings
    from hexgraph.db.models import Node, NodeType
    from hexgraph.db.session import session_scope
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface, run_web_discover

    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        p = create_project(s, name="wd")
        t = register_web_surface(s, p, vulnrouter, name="vr")
        r = run_web_discover(s, p, t)
        assert r["endpoints"] > 0 and r["pages_fetched"] > 0
        eps = s.query(Node).filter(Node.project_id == p.id,
                                   Node.node_type == NodeType.endpoint.value).all()
        names = {n.name for n in eps}
        assert "GET /" in names            # the root always resolves
        # every endpoint node carries method/path/status attrs
        assert all("method" in (n.attrs_json or {}) for n in eps)


def test_web_discover_denied_when_network_off(hg_home):
    from hexgraph import policy
    from hexgraph.db.session import session_scope
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface, run_web_discover

    with session_scope() as s:
        p = create_project(s, name="off")
        t = register_web_surface(s, p, "http://127.0.0.1:8080", name="x")
        with pytest.raises(policy.PolicyViolation):
            run_web_discover(s, p, t)
