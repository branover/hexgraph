"""MCP driver-mode surface: the sandboxed tool functions + agent setup help.
The MCP transport (stdio) needs the optional `mcp` SDK; the tool *logic* is tested
directly here."""

from hexgraph.db.session import session_scope
from hexgraph.engine import mcp_tools
from hexgraph.engine.ingest import create_project, ingest_file

from conftest import fixture_path


def test_catalog_exposes_core_tools():
    names = {t["name"] for t in mcp_tools.catalog()}
    assert {"target_list", "re_decompile_function", "finding_record", "task_run", "graph_search"} <= names
    # every tool is callable and schema-typed
    for t in mcp_tools.catalog():
        assert callable(t["fn"]) and t["schema"]["type"] == "object"


def test_start_fuzz_campaign_schema_declares_network_and_seed_params():
    """Battle-test fix D: the tool DESCRIPTION told the agent to pass host/port/protocol/
    proto_spec (network) + seeds/dictionary, but the JSON SCHEMA omitted them, so a
    schema-respecting agent couldn't model a binary protocol or supply a corpus. The
    schema must now declare every param the function accepts (and CampaignCreate honors)."""
    import inspect

    from hexgraph.engine.mcp_tools import start_fuzz_campaign

    tool = next(t for t in mcp_tools.catalog() if t["name"] == "fuzz_start")
    props = tool["schema"]["properties"]
    for p in ("host", "port", "protocol", "proto_spec", "seeds", "dictionary",
              "max_len", "max_total_time", "max_crashes", "instances", "engine",
              "surface", "function", "resources", "environment"):
        assert p in props, f"start_fuzz_campaign schema is missing declared param {p!r}"
    assert props["protocol"].get("enum") == ["tcp", "udp"]
    assert props["port"]["type"] == "integer"
    assert props["seeds"]["type"] == "array" and props["dictionary"]["type"] == "array"
    # The schema must not advertise a param the function can't accept (no phantom args).
    sig = set(inspect.signature(start_fuzz_campaign).parameters)
    assert set(props) - {"target_id"} <= sig, set(props) - sig - {"target_id"}


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


def test_create_project_tool_makes_empty_project(hg_home):
    """Eval finding F1: a source-first workflow couldn't start from MCP (ingest needs a
    binary path, import_source_tree errors without a project). create_project makes an
    EMPTY project that then accepts import_source_tree and shows up via list_projects."""
    res = mcp_tools.create_project("src-first", backend="mock")
    pid = res["id"]
    assert res["name"] == "src-first" and res["backend"] == "mock"
    # it's a real, empty project: visible in the listing, no targets yet
    assert any(pr["id"] == pid for pr in mcp_tools.list_projects())
    assert mcp_tools.list_targets(pid) == []
    # and it now accepts a source tree (the workaround the evaluator needed HTTP for)
    tree = mcp_tools.import_source_tree(pid, "h", files=[{"rel": "h.c", "content": "int main(){}"}])
    assert tree.get("id") and tree["written"] == 1
    # backend defaults to mock; a blank name is rejected
    assert mcp_tools.create_project("dflt")["backend"] == "mock"
    assert "error" in mcp_tools.create_project("  ")
    # a real (non-mock) enum backend is accepted, an unknown one is a clean {error}
    # (not an uncaught ValueError — the MCP server doesn't wrap tool exceptions)
    assert mcp_tools.create_project("anth", backend="anthropic")["backend"] == "anthropic"
    assert "error" in mcp_tools.create_project("bad", backend="anthropic_api")
    assert "error" in mcp_tools.create_project("bad2", backend="garbage")


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

    # get_finding reads ONE finding back in full, including evidence.extra (where
    # verify_poc stores its result) — the finding analog of get_node.
    full = mcp_tools.get_finding(good["id"])
    assert full["title"] == "Hardcoded key in init"
    assert full["evidence"]["function"] == "init" and full["finding_type"]
    assert mcp_tools.get_finding("nope").get("error")


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
    assert "re_decompile_function" in read_only
    assert "finding_record" not in read_only and "graph_create_node" not in read_only and "task_run" not in read_only
    write_only = {t["name"] for t in mcp_tools.catalog({"write"})}
    assert {"finding_record", "graph_create_node", "graph_create_edge"} <= write_only
    assert "re_decompile_function" not in write_only
    # the RUN group must advertise every live/network/exec run-tool (review #8) — these were
    # added without a catalog-membership assertion, so a drop would go unnoticed.
    run_only = {t["name"] for t in mcp_tools.catalog({"run"})}
    assert {"net_tcp_request", "net_remote_launch", "target_register_remote", "target_rehost",
            "net_http_request", "finding_verify_poc"} <= run_only
    assert "re_decompile_function" not in run_only
    # every catalog entry is tagged with a known group
    assert all(t["group"] in mcp_tools.GROUPS for t in mcp_tools.catalog())


# ── direct tests for the new run-tools (review #8): only the engine/probe layer beneath
#    them was covered. A fake runner stands in for the sandbox so we exercise the MCP wrapper
#    itself — success shape, the features-off `{"error": "...not permitted..."}` string (NOT an
#    exception), and int(port) coercion — all offline. ─────────────────────────────────────
class _FakeExecutor:
    """Stands in for the sandbox executor; records channel-probe calls, replays a response."""
    def __init__(self, response):
        self.response = response
        self.calls = []

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None, **kw):
        self.calls.append({"probe": probe, "channel": channel, "secret": secret})
        return dict(self.response)


def _patch_executor(monkeypatch, fake):
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)


def _rehosted_surface(s):
    from hexgraph.engine.surfaces import register_web_surface
    p = create_project(s, name="dev")
    surface = register_web_surface(s, p, "http://192.168.0.1", name="rehosted")
    ch = dict(surface.metadata_json["channel"])
    ch["rehost"] = {"container": "firmae-xyz", "ip": "192.168.0.1"}
    surface.metadata_json = {**surface.metadata_json, "channel": ch}
    s.flush()
    return p, surface


def test_mcp_tcp_request_success_and_port_coercion(hg_home, monkeypatch):
    from hexgraph import settings
    settings.update_settings({"features": {"network": {"enabled": True}}})
    fake = _FakeExecutor({"ok": True, "response": "BusyBox v1.0"})
    _patch_executor(monkeypatch, fake)
    with session_scope() as s:
        _p, surface = _rehosted_surface(s)
        tid = surface.id
    out = mcp_tools.tcp_request(tid, port="1337", payload="ping")   # port as a STRING
    assert out.get("ok") is True and out["response"] == "BusyBox v1.0"
    # int(port) coercion: the probe channel carries an int, allowlist is host:int.
    chan = fake.calls[0]["channel"]
    assert chan["port"] == 1337 and chan["allow"] == ["192.168.0.1:1337"]


def test_mcp_tcp_request_features_off_returns_error_string(hg_home):
    """network off → the gate raises PolicyViolation internally, but the MCP tool must return
    a `{"error": "...not permitted..."}` string, never propagate the exception."""
    with session_scope() as s:
        _p, surface = _rehosted_surface(s)
        tid = surface.id
    out = mcp_tools.tcp_request(tid, port=1337, payload="x")
    assert "error" in out and "not permitted" in out["error"]


def test_mcp_remote_launch_success_and_features_off(hg_home, monkeypatch):
    from hexgraph import settings
    from hexgraph.engine.remote import register_remote_target

    # features.remote OFF → error string, not an exception.
    with session_scope() as s:
        p = create_project(s, name="rem-off")
        t = register_remote_target(s, p, "192.168.1.5", port=22, username="root")
        tid = t.id
    off = mcp_tools.remote_launch(tid, "/usr/sbin/telnetd", args=["-p", "23"])
    assert "error" in off and "not permitted" in off["error"]

    # features.remote ON → success shape from the fake probe.
    settings.update_settings({"features": {"remote": {"enabled": True}}})
    fake = _FakeExecutor({"ok": True, "output": "launched pid 4242"})
    _patch_executor(monkeypatch, fake)
    out = mcp_tools.remote_launch(tid, "/usr/sbin/telnetd", args=["-p", "23"])
    assert out.get("ok") is True and "4242" in out["output"]
    assert fake.calls[0]["probe"] == "remote_probe.py"
    assert fake.calls[0]["channel"]["op"] == "launch"


def test_mcp_register_remote_success_and_port_coercion(hg_home):
    with session_scope() as s:
        p = create_project(s, name="reg-rem")
        pid = p.id
    out = mcp_tools.register_remote(pid, "192.168.1.50", port="2222", username="admin",
                                    transport="ssh")
    assert "error" not in out and out["kind"] == "remote"
    # int(port) coercion happened in register_remote_target.
    assert out["channel"]["port"] == 2222 and out["channel"]["host"] == "192.168.1.50"
    assert out["channel"]["username"] == "admin"
    # no secret material anywhere in the returned channel
    assert "password" not in str(out) and "key" not in out["channel"]


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
    # When the optional MCP SDK is absent, serving must fail clearly (SystemExit
    # with install guidance), not raise an opaque ImportError. Skip when the SDK
    # is installed (its presence can't exercise the absence path).
    import importlib.util

    import pytest

    if importlib.util.find_spec("mcp") is not None:
        pytest.skip("mcp SDK installed; absence path not exercisable")
    from hexgraph.mcp_server import serve_stdio

    with pytest.raises(SystemExit):
        serve_stdio()


def test_ingest_tool_offline(hg_home, monkeypatch):
    from hexgraph.engine import mcp_tools
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    r = mcp_tools.ingest(fixture_path("vuln_httpd"), name="x")
    assert r.get("project_id") and r.get("recon") is False
    assert "target_ingest" in {t["name"] for t in mcp_tools.catalog({"run"})}


def test_skill_markdown_is_a_claude_skill():
    from hexgraph.agent_setup import skill_markdown, write_skill
    import tempfile, os
    md = skill_markdown()
    assert md.startswith("---\n") and "name: hexgraph-vr" in md and "Never execute" in md
    d = tempfile.mkdtemp()
    p = write_skill(d)
    assert os.path.isfile(p) and p.endswith("hexgraph-vr/SKILL.md")


def test_cli_mcp_check_lists_tools(capsys):
    from hexgraph.cli import main
    rc = main(["mcp", "--check", "--tools", "read"])
    out = capsys.readouterr().out
    assert rc == 0 and "decompile_function" in out and "record_finding" not in out


def test_install_help_includes_sdk_and_check():
    from hexgraph.agent_setup import install_help
    h = install_help("claude")
    assert "pip install" in h and "--check" in h and "serve" in h and "same time" in h


def test_get_schemas_contract():
    from hexgraph.engine import mcp_tools
    sch = mcp_tools.get_schemas()
    assert "command-injection" in sch["finding"]["category"]
    assert "critical" in sch["finding"]["severity"]
    assert "input" in sch["node_types"] and "sink" in sch["node_types"]
    assert "taints" in sch["edge_types"]
    assert "extra" in sch["finding"]["evidence_fields"]
    # the decompiler block now carries a health verdict, not just a configured name
    dec = sch["decompiler"]
    assert "working" in dec and isinstance(dec["working"], bool)
    assert isinstance(dec["health"], dict) and dec["health"]["detail"]


def test_check_decompiler_in_catalog():
    names = {t["name"] for t in mcp_tools.catalog()}
    assert "meta_check_decompiler" in names


def test_check_decompiler_radare2_working(hg_home, monkeypatch):
    """Default config: radare2 reports working when Docker is up AND the image is built."""
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.engine.mcp_tools._sandbox_image_built", lambda tag: True)
    d = mcp_tools.check_decompiler()
    assert d["active"] == "radare2"
    assert d["working"] is True
    assert "radare2" in d["detail"]
    assert d["mode"] is None


def test_check_decompiler_radare2_docker_down(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    d = mcp_tools.check_decompiler()
    assert d["active"] == "radare2"
    assert d["working"] is False
    assert "Docker" in d["detail"]


def test_check_decompiler_radare2_image_not_built(hg_home, monkeypatch):
    """Docker up but the sandbox image was never built → not working, with a build hint."""
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.engine.mcp_tools._sandbox_image_built", lambda tag: False)
    d = mcp_tools.check_decompiler()
    assert d["active"] == "radare2"
    assert d["working"] is False
    assert "not built" in d["detail"]


def test_check_decompiler_ghidra_broken(hg_home, monkeypatch):
    """Ghidra configured but unavailable: a clear, actionable broken-detail."""
    from hexgraph import settings as st

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    monkeypatch.setattr(
        "hexgraph.engine.ghidra.check_ghidra",
        lambda: {"enabled": True, "mode": "headless", "ok": False,
                 "detail": "Ghidra not found in sandbox image (build with WITH_GHIDRA=1)."},
    )
    d = mcp_tools.check_decompiler()
    assert d["active"] == "ghidra"
    assert d["working"] is False
    assert d["mode"] == "headless"
    assert "WITH_GHIDRA" in d["detail"]
    # and the schema block reflects the same broken verdict
    sch = mcp_tools.get_schemas()
    assert sch["decompiler"]["active"] == "ghidra"
    assert sch["decompiler"]["working"] is False


# ---- meta_check_features: the optional-feature preflight tri-state ----------------------

def test_check_features_in_catalog():
    names = {t["name"] for t in mcp_tools.catalog()}
    assert "meta_check_features" in names


def test_check_features_all_disabled_by_default(hg_home):
    """No optional feature enabled (the shipped default) → every row is `disabled`, nothing probed."""
    out = mcp_tools.check_features()
    states = {r["feature"]: r["state"] for r in out["features"]}
    # the features the tool covers, all gated off out of the box
    assert {"floss", "yara", "angr", "ghidra", "emulation"} <= set(states)
    assert all(v == "disabled" for v in states.values())
    # a disabled row carries no remediation (nothing to fix)
    assert all("remediation" not in r for r in out["features"])
    assert "no optional features enabled" in out["summary"]


def test_check_features_enabled_and_available(hg_home, monkeypatch):
    """Enabled AND its in-image dep present → `available`, no remediation."""
    from hexgraph import settings as st

    st.update_settings({"features.floss.enabled": True})
    # fake the lightweight in-image dep probe as PRESENT (no Docker needed)
    monkeypatch.setattr("hexgraph.engine.mcp_tools._image_smoke",
                        lambda image, argv, timeout=30: (True, "3.1.1"))
    out = mcp_tools.check_features()
    floss = next(r for r in out["features"] if r["feature"] == "floss")
    assert floss["enabled"] is True
    assert floss["state"] == "available"
    assert "remediation" not in floss
    assert "FLOSS" in floss["detail"]


def test_check_features_enabled_but_broken_has_remediation(hg_home, monkeypatch):
    """The stale-image trap: enabled but the dep/image is MISSING → `broken` + an actionable hint."""
    from hexgraph import settings as st

    st.update_settings({"features.yara.enabled": True})
    # fake the in-image dep probe as MISSING (the stale-sandbox-image case)
    monkeypatch.setattr("hexgraph.engine.mcp_tools._image_smoke",
                        lambda image, argv, timeout=30: (False, "the image 'hexgraph-sandbox:latest' is not built"))
    out = mcp_tools.check_features()
    yara = next(r for r in out["features"] if r["feature"] == "yara")
    assert yara["enabled"] is True
    assert yara["state"] == "broken"
    assert yara["remediation"] and "just sandbox-build" in yara["remediation"]
    assert "BROKEN" in out["summary"] and "yara" in out["summary"]


def test_check_features_angr_uses_the_angr_image(hg_home, monkeypatch):
    """angr's broken-state remediation points at the DEDICATED angr image, not the sandbox."""
    from hexgraph import settings as st

    st.update_settings({"features.angr.enabled": True})
    monkeypatch.setattr("hexgraph.engine.mcp_tools._image_smoke",
                        lambda image, argv, timeout=30: (False, "not built"))
    out = mcp_tools.check_features()
    angr = next(r for r in out["features"] if r["feature"] == "angr")
    assert angr["state"] == "broken"
    assert "just angr-build" in angr["remediation"]


def test_check_features_ghidra_defers_to_check_ghidra(hg_home, monkeypatch):
    """Ghidra/emulation borrow the existing check_ghidra verdict (shared with-Ghidra image)."""
    from hexgraph import settings as st

    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})
    monkeypatch.setattr(
        "hexgraph.engine.ghidra.check_ghidra",
        lambda: {"enabled": True, "mode": "headless", "ok": False,
                 "detail": "Ghidra not found in sandbox image (build with WITH_GHIDRA=1)."},
    )
    out = mcp_tools.check_features()
    ghidra = next(r for r in out["features"] if r["feature"] == "ghidra")
    assert ghidra["state"] == "broken"
    assert "WITH_GHIDRA" in ghidra["detail"]
    assert "with_ghidra=1" in ghidra["remediation"]


def test_create_node_address_and_input_sink(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="addr")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    fn = mcp_tools.create_node(pid, "function", "run_diagnostic", target_id=tid, address="0x401234",
                               attrs={"params": [{"name": "host", "note": "attacker-controlled"}]})
    assert fn["address"] == "0x401234"
    assert mcp_tools.create_node(pid, "input", "QUERY_STRING").get("id")
    assert mcp_tools.create_node(pid, "sink", "system", target_id=tid).get("id")


def test_target_facts_dangerous_imports(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="dg")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        t.metadata_json = {"imports": ["system", "getenv", "snprintf", "strcpy"]}
        tid = t.id
    assert set(mcp_tools.target_facts(tid)["dangerous_imports"]) == {"system", "strcpy"}


def test_update_finding_and_hypothesis_lifecycle(hg_home):
    from hexgraph.engine import mcp_tools
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel
    with session_scope() as s:
        p = create_project(s, name="life")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        task = create_task(s, project=p, target_id=t.id, type="static_analysis")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="cmd inj", severity="high", confidence="low", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence(function="run_diagnostic")))
        pid, tid, fid = p.id, t.id, f.id
    h = mcp_tools.create_hypothesis(pid, "pre-auth RCE via host param", target_id=tid)
    # link the finding as supporting evidence → hypothesis becomes supported
    res = mcp_tools.link_evidence(h["id"], fid, "supports")
    assert res["status"] == "supported" and len(res["supports"]) == 1
    # confirm the finding in place
    up = mcp_tools.update_finding(fid, status="confirmed", confidence="high")
    assert up["status"] == "confirmed" and up["confidence"] == "high"
    assert mcp_tools.set_hypothesis_status(h["id"], "confirmed")["status"] == "confirmed"


def test_verify_poc_attaches_to_finding(hg_home, monkeypatch):
    from hexgraph.engine import mcp_tools
    from hexgraph.db.models import Finding
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.findings import persist_finding
    from hexgraph.models.finding import Evidence, Finding as FModel

    def fake_verify(session, project, target, spec, runner=None):
        # Mirror the real verify_poc: it returns the NONCE-SUBSTITUTED spec. The caller
        # must NOT persist that (it would bake in a stale literal nonce) — it stores the
        # original template instead. Return a substituted copy so the test can tell them apart.
        substituted = {"oracle": {"type": "output_contains", "value": "HEXGRAPH_PWNED_x"}}
        return {"verified": True, "detail": "nonce in output", "exit_code": 0,
                "nonce": "HEXGRAPH_PWNED_x", "output": "...HEXGRAPH_PWNED_x...", "spec": substituted}
    monkeypatch.setattr("hexgraph.engine.poc.verify_poc", fake_verify)

    with session_scope() as s:
        p = create_project(s, name="vp")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        task = create_task(s, project=p, target_id=t.id, type="poc")
        f = persist_finding(s, project_id=p.id, target_id=t.id, task_id=task.id, finding=FModel(
            title="poc", severity="high", confidence="low", category="command-injection",
            summary="s", reasoning="r", evidence=Evidence()))
        tid, fid = t.id, f.id
    r = mcp_tools.verify_poc(tid, {"oracle": {"type": "output_contains", "value": "{{NONCE}}"}}, finding_id=fid)
    assert r["verified"] is True and r["attached_to"] == fid
    with session_scope() as s:
        f = s.get(Finding, fid)
        assert f.evidence_json["extra"]["verification"]["verified"] is True
        # The stored PoC spec must be the ORIGINAL template (with {{NONCE}} intact), not the
        # nonce-substituted copy — otherwise a later re-verify carries a stale literal token.
        assert f.evidence_json["extra"]["poc"]["oracle"]["value"] == "{{NONCE}}"


def test_record_finding_accepts_finding_type(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="ft")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    r = mcp_tools.record_finding(pid, tid, {
        "title": "RCE PoC", "severity": "critical", "confidence": "high",
        "category": "command-injection", "summary": "s", "reasoning": "r",
        "evidence": {"function": "f"}}, finding_type="poc")
    assert r.get("finding_type") == "poc"
    assert "error" in mcp_tools.record_finding(pid, tid, {
        "title": "x", "severity": "low", "confidence": "low", "category": "other",
        "summary": "s", "reasoning": "r", "evidence": {}}, finding_type="bogus")


def test_graph_read_tools(hg_home):
    from hexgraph.engine import mcp_tools
    with session_scope() as s:
        p = create_project(s, name="rd")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        pid, tid = p.id, t.id
    n = mcp_tools.create_node(pid, "function", "cgi_handler", target_id=tid, address="0x401200",
                              attrs={"params": [{"name": "req"}]})
    got = mcp_tools.get_node(n["id"])
    assert got["address"] == "0x401200" and got["attrs"]["params"][0]["name"] == "req"
    assert any(x["id"] == n["id"] for x in mcp_tools.list_nodes(pid, node_type="function"))
    mcp_tools.create_edge(pid, "node", n["id"], "target", tid, "contains")
    assert any(e["src_id"] == n["id"] for e in mcp_tools.list_edges(pid, node_id=n["id"]))


# ── agent-surface audit: tools an agent needs but couldn't reach (build log, promote a
#    firmware file to a target, resume a campaign) + their catalog membership / skill docs. ──

def test_new_tools_in_catalog_groups():
    """build_log is read-only; promote_file + resume_fuzz_campaign execute in the
    sandbox, so they live in `run`. A drop would otherwise go unnoticed."""
    read_names = {t["name"] for t in mcp_tools.catalog({"read"})}
    run_names = {t["name"] for t in mcp_tools.catalog({"run"})}
    assert "src_build_log" in read_names
    assert {"target_promote_file", "fuzz_resume"} <= run_names
    for name in ("src_build_log", "target_promote_file", "fuzz_resume"):
        t = next(x for x in mcp_tools.catalog() if x["name"] == name)
        assert callable(t["fn"]) and t["schema"]["type"] == "object"


def test_build_log_tool(hg_home):
    """A failed build's compile log is the only iteration signal — the agent must be able
    to read it. A build with no stored log returns "" (not an error); an unknown id errors."""
    from hexgraph.db.models import Build
    from hexgraph.engine import cas
    with session_scope() as s:
        p = create_project(s, name="bl")
        sha = cas.put(p, "configure: error: missing zlib\nmake: *** [all] Error 1\n")
        b = Build(project_id=p.id, build_spec_id="spec1", source_tree_id="tree1",
                  status="failed", returncode=1, error="build failed", log_cas=sha)
        s.add(b)
        s.flush()
        bid = b.id
        empty = Build(project_id=p.id, build_spec_id="s2", source_tree_id="t2", status="queued")
        s.add(empty)
        s.flush()
        empty_id = empty.id

    out = mcp_tools.build_log(bid)
    assert out["status"] == "failed" and out["returncode"] == 1 and out["error"] == "build failed"
    assert "missing zlib" in out["log"]
    assert mcp_tools.build_log(empty_id)["log"] == ""           # no log → "", not an error
    assert mcp_tools.build_log("nope").get("error") == "build not found"


def test_promote_file_tool(hg_home, monkeypatch):
    """Promote a binary from an unpacked firmware FS into its own analyzable target — the
    bridge from browsing the rootfs to decompiling it. Idempotent; bad path/target → error."""
    from test_filesystem import _firmware_with_fs
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)  # skip recon
    with session_scope() as s:
        p, fw = _firmware_with_fs(s)
        fwid = fw.id

    out = mcp_tools.promote_file(fwid, "usr/sbin/httpd")
    assert out.get("id") and out["name"] == "usr/sbin/httpd" and out["parent_id"] == fwid
    assert isinstance(out["kind"], str) and out["kind"]
    again = mcp_tools.promote_file(fwid, "usr/sbin/httpd")   # idempotent per path
    assert again["id"] == out["id"]
    assert mcp_tools.promote_file(fwid, "no/such/file").get("error")
    assert mcp_tools.promote_file("nope", "x").get("error") == "target not found"


def test_resume_fuzz_campaign_guards(hg_home):
    """The wrapper must surface the engine's guards as `{"error": ...}` strings, never raise:
    a still-running campaign can't resume, and an unknown id is reported plainly."""
    from hexgraph.db.models import FuzzCampaign
    with session_scope() as s:
        p = create_project(s, name="rz")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="x")
        c = FuzzCampaign(project_id=p.id, target_id=t.id, status="running")
        s.add(c)
        s.flush()
        cid = c.id
    out = mcp_tools.resume_fuzz_campaign(cid)
    assert "error" in out and "resume" in out["error"].lower()
    assert mcp_tools.resume_fuzz_campaign("nope").get("error") == "campaign not found"


def test_skill_documents_fs_browsing_and_new_tools():
    """The agent only knows what the SKILL tells it: the firmware-FS workflow, the new tools,
    and the strict 'surface, don't prune' stance must all be present."""
    from hexgraph.agent_setup import SKILL
    for token in ("fs_list", "target_promote_file", "src_build_log",
                  "fuzz_resume", "proj_list",
                  "You SURFACE for the analyst to TRIAGE"):
        assert token in SKILL, token
