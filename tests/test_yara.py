"""Phase 5B — the YARA project-wide pattern sweep (design §3.3).

YARA is now an ALWAYS-ON static tool (a static match reads bytes and never executes the
target, so it relaxes no boundary), so there is no `features.yara` gate. Layers, matching the
Phase O curation contract:

- the always-on contract: the MCP/agent verbs are ALWAYS advertised (no toggle) and the
  helper always runs;
- the engine-helper contract with a FAKED executor (offline, no Docker): a per-target scan
  records a single `yara_matches` Observation scoped by content_hash, PROMOTES each matched
  rule to ONE project-level `pattern` node + a `matches_rule` edge (deduped across targets),
  carries the rule's declared severity/cve WITHOUT fabricating one, never auto-mints a
  finding, dedups on a repeat call, and errors cleanly without Docker;
- the project SWEEP over a couple of targets + an extracted firmware file;
- the rules story: the bundled rules load + a user-supplied .yar in the rules dir is picked up;
- a Docker-gated probe test that runs real YARA on a committed fixture and asserts the match
  shape + promotion (skips when the YARA-enabled sandbox image is absent).
"""

import pytest

from hexgraph.db.models import Edge, EdgeType, Node, NodeType, Observation
from hexgraph.db.session import session_scope
from hexgraph.engine.filesystem import persistent_base, record_manifest
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.yara import available_rulesets, scan_target, sweep_project
from hexgraph import config

from conftest import fixture_path

HASH = "deadbeef"

# A representative probe payload (the shape yara_probe emits), for the offline engine-helper
# tests via a faked executor so they need no Docker. Two rules: one carrying a CVE, one not.
_FACTS = {
    "tool": "yara_probe",
    "rule_files": ["bundled/hexgraph_embedded_creds.yar", "bundled/hexgraph_known_bad_lib.yar"],
    "rule_file_count": 2,
    "match_count": 2,
    "matches": [
        {"rule": "hexgraph_default_admin_creds", "namespace": "bundled/hexgraph_embedded_creds.yar",
         "tags": [], "meta": {"severity": "medium", "category": "embedded_credential",
                              "description": "default admin creds"},
         "strings": [{"identifier": "$admin_admin", "offset": 12, "value": "admin:admin"}]},
        {"rule": "hexgraph_dropbear_old_banner", "namespace": "bundled/hexgraph_known_bad_lib.yar",
         "tags": [], "meta": {"severity": "medium", "category": "known_bad_library",
                              "cve": "CVE-2016-7406", "description": "old dropbear"},
         "strings": [{"identifier": "$b3", "offset": 40, "value": "Dropbear sshd v2015"}]},
    ],
}

_NO_MATCH = {"tool": "yara_probe", "rule_files": ["bundled/x.yar"], "rule_file_count": 1,
             "match_count": 0, "matches": []}


class _FakeExec:
    """Returns a fixed probe payload and records how the probe was invoked."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def run_json_probe(self, probe, path, **kw):
        self.calls.append((probe, path, kw.get("extra_args"), kw.get("extra_ro_mounts")))
        return self.result


def _wire(monkeypatch, result=_FACTS):
    fake = _FakeExec(result)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


def _seed(s, name="ya"):
    p = create_project(s, name=name)
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": HASH}
    s.flush()
    return p, t


# --- always-on: the verbs are ALWAYS advertised (no gate) --------------------

def test_no_yara_gate_in_settings(hg_home):
    """YARA is always-on: there is NO features.yara settings key (it was removed when the tool
    went ungated). Attempting to write it is rejected by the settings schema."""
    from hexgraph import settings as st

    with pytest.raises(st.SettingsError):
        st.update_settings({"features.yara.enabled": True})


def test_verbs_always_advertised(hg_home):
    """The MCP read verb (yara_scan) + write verb (yara_sweep) are ALWAYS in the catalog (no
    gate), typed — always-on contract."""
    from hexgraph.engine import mcp_tools as M

    def _present(group, name):
        return any(t["name"] == name for t in M.catalog({group}))

    assert _present("read", "re_yara_scan") is True
    assert _present("write", "re_yara_sweep") is True
    spec = next(t for t in M.catalog({"read"}) if t["name"] == "re_yara_scan")
    assert callable(spec["fn"])
    assert spec["schema"]["properties"].keys() >= {"target_id", "ruleset"}


def test_agent_tool_always_advertised(hg_home):
    """The in-process agent loop ALWAYS advertises yara_scan (always-on static tool)."""
    from hexgraph.engine.agent_tools import ToolContext, available_tools

    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        names = {spec.name for spec in available_tools(ctx)}
        assert "yara_scan" in names


# --- engine helper: one Observation, promotes patterns, dedups (offline) -----

def test_scan_records_observation_and_promotes_patterns(hg_home, monkeypatch):
    fake = _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        out = scan_target(s, p, t, source="agent")
        s.flush()
        assert fake.calls[-1][0] == "yara_probe.py"
        # the rules dir was mounted read-only and passed as --rules-dir
        extra_args, mounts = fake.calls[-1][2], fake.calls[-1][3]
        assert "--rules-dir" in extra_args
        assert mounts and all(len(m) == 2 for m in mounts)
        assert out["observation_id"] and out["cached"] is False and out["reuse_hint"]

        # one Observation, scoped to the analyzed bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "yara_matches").all()
        assert len(obs) == 1 and obs[0].content_hash == HASH and obs[0].tool == "yara_matches"

        # each matched rule -> ONE project-level pattern node (target_id=None) + a matches_rule edge
        patterns = s.query(Node).filter(Node.node_type == NodeType.pattern.value).all()
        assert {n.name for n in patterns} == {"hexgraph_default_admin_creds",
                                              "hexgraph_dropbear_old_banner"}
        assert all(n.target_id is None for n in patterns)
        # the rule's DECLARED severity/cve is surfaced — never fabricated
        dropbear = next(n for n in patterns if n.name == "hexgraph_dropbear_old_banner")
        assert dropbear.attrs_json.get("severity") == "medium"
        assert dropbear.attrs_json.get("cve") == "CVE-2016-7406"
        assert dropbear.attrs_json.get("source") == "yara"

        edges = s.query(Edge).filter(Edge.type == EdgeType.matches_rule.value).all()
        assert len(edges) == 2
        for e in edges:
            assert e.src_kind == "target" and e.src_id == t.id and e.dst_kind == "node"
            assert e.attrs_json.get("by") == "yara"

        # the Observation back-references the promoted pattern nodes
        assert set(obs[0].node_refs or []) == {n.id for n in patterns}

        # NEVER auto-mints a finding (the matcher fabricates no severity claim)
        from hexgraph.db.models import Finding
        assert s.query(Finding).count() == 0


def test_same_rule_dedups_to_one_pattern_across_targets(hg_home, monkeypatch):
    """The cross-target shape: the SAME rule matched in two targets resolves to ONE project-
    level pattern node, with a matches_rule edge from each target (the corpus-wide hunt)."""
    _wire(monkeypatch)
    with session_scope() as s:
        p, t1 = _seed(s, name="ya-multi")
        t2 = ingest_file(s, p, fixture_path("libupnp.so"), name="libupnp")
        t2.metadata_json = {**(t2.metadata_json or {}), "sha256": "cafef00d"}
        s.flush()
        scan_target(s, p, t1)
        s.flush()
        scan_target(s, p, t2)
        s.flush()
        # two rules in the payload, but two targets matching them -> still 2 pattern nodes
        patterns = s.query(Node).filter(Node.node_type == NodeType.pattern.value).all()
        assert len(patterns) == 2
        # each pattern now has TWO matches_rule edges (one per target)
        for n in patterns:
            srcs = {(e.src_kind, e.src_id) for e in
                    s.query(Edge).filter(Edge.type == EdgeType.matches_rule.value,
                                         Edge.dst_id == n.id).all()}
            assert srcs == {("target", t1.id), ("target", t2.id)}


def test_scan_dedups_on_repeat_call(hg_home, monkeypatch):
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        out1 = scan_target(s, p, t)
        s.flush()
        out2 = scan_target(s, p, t)
        s.flush()
        assert out1["cached"] is False and out2["cached"] is True
        assert out1["observation_id"] == out2["observation_id"]
        assert s.query(Observation).filter(Observation.result_kind == "yara_matches").count() == 1
        # re-running does not duplicate pattern nodes or edges (idempotent promotion)
        assert s.query(Node).filter(Node.node_type == NodeType.pattern.value).count() == 2
        assert s.query(Edge).filter(Edge.type == EdgeType.matches_rule.value).count() == 2


def test_ruleset_knob_is_validated(hg_home, monkeypatch):
    """The single agent knob (ruleset) is validated against the bundled set — a bad id is a
    clean error, never a raw command line."""
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s)
        out = scan_target(s, p, t, ruleset="../etc/passwd")
        assert "error" in out and "unknown ruleset" in out["error"]
        # a valid bundled id passes and is echoed back
        out2 = scan_target(s, p, t, ruleset="hexgraph_packers")
        assert out2.get("error") is None and out2["ruleset"] == "hexgraph_packers"


def test_no_match_records_observation_but_no_patterns(hg_home, monkeypatch):
    _wire(monkeypatch, result=_NO_MATCH)
    with session_scope() as s:
        p, t = _seed(s)
        out = scan_target(s, p, t)
        s.flush()
        assert out.get("error") is None and out["facts"]["match_count"] == 0
        assert s.query(Observation).filter(Observation.result_kind == "yara_matches").count() == 1
        assert s.query(Node).filter(Node.node_type == NodeType.pattern.value).count() == 0


def test_scan_reports_error_without_docker(hg_home, monkeypatch):
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: False)
    with session_scope() as s:
        p, t = _seed(s)
        out = scan_target(s, p, t)
        assert "error" in out and "Docker" in out["error"]
        assert s.query(Observation).filter(Observation.result_kind == "yara_matches").count() == 0


def test_scan_surfaces_probe_error_json(hg_home, monkeypatch):
    _wire(monkeypatch, result={"error": "no YARA rule files found"})
    with session_scope() as s:
        p, t = _seed(s)
        out = scan_target(s, p, t)
        assert "error" in out and "no YARA rule files" in out["error"]
        assert s.query(Observation).filter(Observation.result_kind == "yara_matches").count() == 0


# --- the project sweep over targets + an extracted firmware file -------------

def _firmware_with_fs(s, p):
    """A firmware target with one extracted file laid down on disk + a manifest."""
    fw = ingest_file(s, p, fixture_path("synthetic_fw.bin"), name="fw")
    fw.metadata_json = {**(fw.metadata_json or {}), "sha256": "fwhash"}
    base = persistent_base(p, fw.id) / "root"
    (base / "usr" / "sbin").mkdir(parents=True, exist_ok=True)
    binpath = base / "usr" / "sbin" / "httpd"
    with open(fixture_path("vuln_httpd"), "rb") as src:
        binpath.write_bytes(src.read())
    record_manifest(fw, method="unsquashfs", root_rel="root", files=[
        {"rel": "usr/sbin/httpd", "size": binpath.stat().st_size, "is_elf": True},
    ])
    s.flush()
    return fw


def test_sweep_covers_targets_and_firmware_files(hg_home, monkeypatch):
    """sweep_project scans every non-archived byte target AND each extracted firmware file,
    recording an Observation per artifact and promoting matches to shared pattern nodes."""
    fake = _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s, name="ya-sweep")
        fw = _firmware_with_fs(s, p)
        res = sweep_project(s, p)
        s.flush()
        assert res.get("error") is None
        # scanned: the httpd target's bytes + the firmware's bytes + the extracted httpd file
        # (firmware target also has its own path, so 3 artifacts)
        assert res["scanned"] == 3
        assert res["targets"] == 2
        # each scanned artifact recorded its own Observation
        assert s.query(Observation).filter(Observation.result_kind == "yara_matches").count() == 3
        # the extracted firmware file was scanned via a path override (an extra_ro_mount each call)
        scanned_paths = [c[1] for c in fake.calls]
        assert any("usr/sbin/httpd" in str(pp) for pp in scanned_paths)
        # matches promoted to the shared pattern nodes
        assert res["promoted_count"] >= 2
        assert s.query(Node).filter(Node.node_type == NodeType.pattern.value).count() == 2


def test_sweep_skips_archived_targets(hg_home, monkeypatch):
    _wire(monkeypatch)
    with session_scope() as s:
        p, t = _seed(s, name="ya-arch")
        t.archived = True
        s.flush()
        res = sweep_project(s, p)
        assert res.get("error") is None and res["scanned"] == 0 and res["targets"] == 0
        # nothing scannable is not a clean scan either — say so plainly, never as match_count 0 clean
        assert res["status"] == "empty"
        assert res["scanned_ok"] == 0 and res["errored"] == 0


def test_sweep_all_errored_does_not_look_clean(hg_home, monkeypatch):
    """The honesty fix: when EVERY scanned artifact errored (e.g. the runtime YARA dep was
    missing so each probe raised ModuleNotFoundError), the sweep must NOT present as a clean
    match_count 0 scan — it must be an explicit error outcome with the reason bubbled up, not
    buried only in errors[]."""
    # the probe payload is a per-file error every time (the all-errored case)
    _wire(monkeypatch, result={"error": "ModuleNotFoundError: No module named 'yara'"})
    with session_scope() as s:
        p, t = _seed(s, name="ya-all-err")
        t2 = ingest_file(s, p, fixture_path("libupnp.so"), name="libupnp")
        t2.metadata_json = {**(t2.metadata_json or {}), "sha256": "cafef00d"}
        s.flush()
        res = sweep_project(s, p)
        s.flush()
        # match_count 0 alone would be a dangerous false all-clear — it must carry an error
        assert res["match_count"] == 0
        assert res["status"] == "error"
        assert "error" in res and res["error"]
        # the representative per-file reason is surfaced in the summary, not only in errors[]
        assert "ModuleNotFoundError" in res["error"]
        # counts make the outcome legible: nothing scanned cleanly, everything errored
        assert res["scanned_ok"] == 0
        assert res["errored"] == res["scanned"] == 2
        # the underlying per-file errors are still listed
        assert len(res["errors"]) == 2
        # nothing was promoted (no fabricated clean result)
        assert s.query(Node).filter(Node.node_type == NodeType.pattern.value).count() == 0


def test_sweep_partial_reports_both_ok_and_errored(hg_home, monkeypatch):
    """A partial outcome (some artifacts scanned cleanly, some errored) reports both, so
    '0 found in the N we COULD scan, but M errored' is distinguishable from a clean sweep."""

    class _FlakyExec:
        """Errors on the first artifact, scans clean (0 matches) on the rest."""

        def __init__(self):
            self.calls = []

        def run_json_probe(self, probe, path, **kw):
            self.calls.append(path)
            if len(self.calls) == 1:
                return {"error": "boom on the first artifact"}
            return _NO_MATCH

    flaky = _FlakyExec()
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: flaky)
    with session_scope() as s:
        p, t = _seed(s, name="ya-partial")
        t2 = ingest_file(s, p, fixture_path("libupnp.so"), name="libupnp")
        t2.metadata_json = {**(t2.metadata_json or {}), "sha256": "cafef00d"}
        s.flush()
        res = sweep_project(s, p)
        s.flush()
        assert res["scanned"] == 2
        assert res["scanned_ok"] == 1 and res["errored"] == 1
        assert res["status"] == "partial"
        assert res["match_count"] == 0  # the one clean scan found nothing
        # a partial is NOT a flat error, but it MUST advertise the errored count up top
        assert res.get("error") is None
        assert "partial_note" in res and "1 errored" in res["partial_note"]


# --- the rules story: bundled rules load + a user .yar is picked up ----------

def test_bundled_rulesets_listed(hg_home):
    rulesets = available_rulesets()
    assert "all" in rulesets
    # the four bundled high-signal rule files
    assert "hexgraph_embedded_creds" in rulesets
    assert "hexgraph_weak_crypto" in rulesets
    assert "hexgraph_packers" in rulesets
    assert "hexgraph_known_bad_lib" in rulesets


def test_bundled_rules_compile_and_fire():
    """The bundled rules are valid YARA and a known sample fires (compiled with the same
    yara-python the probe uses, in-process — no Docker)."""
    yara = pytest.importorskip("yara")
    from hexgraph.paths import bundled_yara_rules_dir

    d = bundled_yara_rules_dir()
    files = {f"bundled/{pth.name}": str(pth) for pth in d.iterdir() if pth.suffix == ".yar"}
    rules = yara.compile(filepaths=files)
    sample = (b"login admin:admin\nUPX!\x00UPX0UPX1\nDropbear sshd v2015.1\n"
              b"BusyBox v1.2.0\nMD5_Init\n")
    fired = {m.rule for m in rules.match(data=sample)}
    assert "hexgraph_default_admin_creds" in fired
    assert "hexgraph_upx_packed" in fired
    assert "hexgraph_dropbear_old_banner" in fired
    # the dropbear rule cites its CVE in meta (the rule-meta convention)
    drop = next(m for m in rules.match(data=sample) if m.rule == "hexgraph_dropbear_old_banner")
    assert dict(drop.meta).get("cve") == "CVE-2016-7406"


def test_user_rule_dir_is_picked_up(hg_home):
    """A user-supplied .yar in the HEXGRAPH_HOME rules dir is mounted alongside the bundled
    set — the drop-in rules path the design requires."""
    from hexgraph.engine.yara import _resolve_rule_mounts, _USER_MOUNT

    user_dir = config.yara_rules_dir()
    user_dir.mkdir(parents=True, exist_ok=True)
    (user_dir / "my.yar").write_text(
        'rule my_user_rule { strings: $a = "PWNED" condition: $a }\n'
    )
    mounts, rules_dir_args, _eff, _cleanup = _resolve_rule_mounts("all")
    # the user dir is mounted at the fixed user mount point and passed as a rules dir
    assert any(host == str(user_dir) and cont == _USER_MOUNT for host, cont in mounts)
    assert _USER_MOUNT in rules_dir_args


# --- the agent tool renders the matches --------------------------------------

def test_agent_tool_renders_matches(hg_home, monkeypatch):
    _wire(monkeypatch)
    from hexgraph.engine.agent_tools import ToolContext, run_tool

    with session_scope() as s:
        p, t = _seed(s)
        ctx = ToolContext(session=s, project=p, target=t)
        out = run_tool(ctx, "yara_scan", {})
        assert "YARA matches" in out
        assert "hexgraph_dropbear_old_banner" in out
        assert "CVE-2016-7406" in out
        assert "promoted 2 pattern node(s)" in out


# --- the probe's pure parsing logic (offline, no sandbox) --------------------

def test_probe_rule_file_discovery_and_bounds():
    from hexgraph.sandbox.probes import yara_probe as Y
    from hexgraph.paths import bundled_yara_rules_dir

    namespaces = Y._iter_rule_files([str(bundled_yara_rules_dir())])
    # one namespace per .yar, prefixed by the dir basename for collision-safety
    assert len(namespaces) == 4
    assert all(ns.startswith("yara/") for ns in namespaces)


def test_probe_str_entry_renders_text_and_hex():
    from hexgraph.sandbox.probes import yara_probe as Y

    txt = Y._str_entry("$a", 10, b"admin:admin")
    assert txt == {"identifier": "$a", "offset": 10, "value": "admin:admin"}
    binv = Y._str_entry("$b", 20, b"\xff\x00\xfe")
    assert binv["value"] == "ff00fe"  # non-utf8 falls back to hex


# --- Docker-gated: real YARA on the committed fixture ------------------------

def test_yara_probe_on_real_fixture(hg_home, yara_sandbox):
    """Real YARA runs in the sandbox over the committed fixture and matches the bundled rules,
    promoting them to pattern nodes (skips without the YARA-enabled sandbox image)."""
    with session_scope() as s:
        p = create_project(s, name="ya-real")
        t = ingest_file(s, p, fixture_path("yara_fixture.bin"), name="yara_fixture")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "yara-fixture-hash"}
        s.flush()
        out = scan_target(s, p, t, runner=yara_sandbox)
        s.flush()
        assert "error" not in out, out
        rules = {m["rule"] for m in out["facts"]["matches"]}
        # the fixture carries strings firing these bundled rules
        assert "hexgraph_default_admin_creds" in rules, rules
        assert "hexgraph_upx_packed" in rules, rules
        assert "hexgraph_dropbear_old_banner" in rules, rules
        # one durable Observation, scoped to the bytes
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "yara_matches").all()
        assert len(obs) == 1 and obs[0].content_hash == "yara-fixture-hash"
        # matches promoted to pattern nodes + matches_rule edges
        patterns = {n.name for n in
                    s.query(Node).filter(Node.node_type == NodeType.pattern.value).all()}
        assert "hexgraph_dropbear_old_banner" in patterns
        dropbear_edge = s.query(Edge).filter(Edge.type == EdgeType.matches_rule.value).first()
        assert dropbear_edge is not None and dropbear_edge.src_kind == "target"


def test_yara_probe_single_ruleset(hg_home, yara_sandbox):
    """Scoping to a single bundled ruleset only fires that file's rules (the agent knob)."""
    with session_scope() as s:
        p = create_project(s, name="ya-one")
        t = ingest_file(s, p, fixture_path("yara_fixture.bin"), name="yara_fixture")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "yara-one-hash"}
        s.flush()
        out = scan_target(s, p, t, ruleset="hexgraph_packers", runner=yara_sandbox)
        s.flush()
        assert "error" not in out, out
        rules = {m["rule"] for m in out["facts"]["matches"]}
        # only packer rules — the cred/library/crypto rules are NOT in this set
        assert rules <= {"hexgraph_upx_packed", "hexgraph_generic_packer_banner"}
        assert "hexgraph_upx_packed" in rules
