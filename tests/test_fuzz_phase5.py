"""Phase 5 — binary-only (AFL++ qemu/frida) + network (boofuzz / desock+AFL++) fuzzing,
behind the Fuzzer seam. Offline ($0): the seam, the surface×engine matrix, prepare()
launch descriptions, the network bounded-egress gate + audit (NO new gate), the
network-crash assurance ladder, and the engines endpoint. The real-toolchain e2e (qemu
crash, network service-death, desock) is Docker-gated in test_fuzz_phase5_e2e.py.
"""

import json

import pytest

from hexgraph.db.models import (
    EgressEvent, Finding, FuzzArtifact, FuzzCampaign, Target, TargetKind,
)
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.fuzzers import FuzzerError, get_fuzzer, resolve_engine, SURFACE_ENGINES
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.fuzzers.binary_only import BinaryOnlyFuzzer, FridaFuzzer
from hexgraph.engine.fuzzers.network import BoofuzzFuzzer, DesockAflFuzzer
from hexgraph.engine.fuzzing import crash_finding
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.policy import PolicyViolation
from hexgraph import settings as st

from conftest import fixture_path


def _mock_env(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_FUZZER", "mock")


def _enable(flag):
    st.update_settings({flag: True})


def _binary_target(s):
    p = create_project(s, name="ph5")
    t = ingest_file(s, project=p, src_path=fixture_path("vuln_httpd"), name="vuln_httpd")
    return p, t


# ── The surface×engine matrix (Phase 5 additions, fail-closed) ────────────────────

def test_binary_only_defaults_qemu_frida_alt():
    assert SURFACE_ENGINES["binary_only"] == ("qemu", "frida")
    assert resolve_engine("binary_only") == "qemu"          # qemu-mode is the DEFAULT
    assert resolve_engine("binary_only", "frida") == "frida"
    assert get_fuzzer("binary_only").name == "qemu"
    assert get_fuzzer("binary_only", "frida").name == "frida"


def test_network_defaults_boofuzz_desock_alt():
    assert SURFACE_ENGINES["network"] == ("boofuzz", "desock")
    assert resolve_engine("network") == "boofuzz"           # boofuzz is the DEFAULT
    assert resolve_engine("network", "desock") == "desock"
    assert get_fuzzer("network").name == "boofuzz"
    assert get_fuzzer("network", "desock").name == "desock"


def test_fail_closed_on_phase5_nonsensical_pairs():
    with pytest.raises(FuzzerError):
        resolve_engine("network", "qemu")        # qemu is not a network engine
    with pytest.raises(FuzzerError):
        resolve_engine("binary_only", "boofuzz")  # boofuzz is not a binary engine
    with pytest.raises(FuzzerError):
        resolve_engine("source_lib", "qemu")     # qemu-mode needs no source → binary_only


# ── prepare(): the launch descriptions ────────────────────────────────────────────

def test_binary_only_prepare_qemu_with_sysroot(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="binary_only", engine="qemu",
                                target_binary=t.path, sysroot="/some/rootfs",
                                dictionary=["GET", "POST"])
        prep = BinaryOnlyFuzzer("qemu").prepare(spec, p, t)
        assert prep.probe == "afl_qemu_probe.py"
        assert prep.engine == "qemu"
        assert prep.coverage_instrumented is True       # coverage via QEMU TCG
        assert prep.requires_egress is False            # binary-only stays --network none
        assert any(a == "--mode=qemu" for a in prep.extra_args)
        assert any(a.startswith("--sysroot=") for a in prep.extra_args)
        assert ("/some/rootfs", "/sysroot") in prep.extra_ro_mounts
        assert prep.artifact == t.path


def test_frida_mode_override(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="binary_only", engine="frida",
                                target_binary=t.path)
        prep = FridaFuzzer().prepare(spec, p, t)
        assert prep.engine == "frida"
        assert any(a == "--mode=frida" for a in prep.extra_args)


def test_network_boofuzz_prepare_requires_egress(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                host="127.0.0.1", port=9999)
        prep = BoofuzzFuzzer().prepare(spec, p, t)
        assert prep.probe == "boofuzz_probe.py"
        assert prep.requires_egress is True              # the ONLY campaign egress relaxation
        assert prep.egress_host == "127.0.0.1" and prep.egress_port == 9999
        assert prep.artifact is None                     # live socket, no bytes at rest
        # the proto-spec is carried (a default one-block request when none supplied)
        assert "--proto-spec" in prep.extra_args


def test_network_boofuzz_needs_host_port(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        with pytest.raises(ValueError):
            BoofuzzFuzzer().prepare(spec, p, t)


def test_desock_prepare_no_egress(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="desock",
                                target_binary=t.path, port=8080)
        prep = DesockAflFuzzer().prepare(spec, p, t)
        assert prep.probe == "desock_probe.py"
        assert prep.requires_egress is False             # desock feeds stdin → --network none
        assert prep.artifact == t.path


# ── Network campaign gate: features.network (NOT the exec gate), bounded + audited ─

class _FakeExecutor:
    """Records the start_detached call so we can assert the network launch flags."""
    def __init__(self):
        self.calls = []

    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None,
                       allow_network=False, net_container=None):
        from hexgraph.sandbox.runner import DetachedHandle
        self.calls.append({"probe": probe, "allow_network": allow_network,
                           "net_container": net_container, "extra_args": extra_args})
        return DetachedHandle(name=name, outdir=str(outdir))

    def poll_detached(self, name):
        return {"exists": True, "running": True, "exit_code": None}

    def stop_detached(self, name, *, remove=True, timeout=10):
        pass


def _net_target(s, host="127.0.0.1", port=9000):
    p = create_project(s, name="net")
    t = Target(project_id=p.id, name=f"svc {host}:{port}", path="", kind=TargetKind.web_app,
               metadata_json={"channel": {"kind": "tcp", "host": host, "port": port}})
    s.add(t)
    s.flush()
    return p, t


def test_network_campaign_blocked_without_features_network(hg_home):
    """A live-socket boofuzz campaign rides features.network. With it OFF, the bounded-
    egress assert fails closed (no exec gate involved) and the EgressEvent records a denial."""
    with session_scope() as s:
        p, t = _net_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                host="127.0.0.1", port=9000)
        with pytest.raises(C.CampaignError):
            C.start_campaign(s, p, t, spec=spec, executor=_FakeExecutor())
        # the denial was audited
        ev = s.query(EgressEvent).filter(EgressEvent.project_id == p.id,
                                         EgressEvent.allowed.is_(False)).all()
        assert ev and ev[0].tool == "boofuzz"


def test_network_campaign_refuses_non_local_host(hg_home):
    """Even WITH features.network, a campaign can never reach a non-loopback/private host
    (local_tcp_scope refuses it) — the structural containment of the local-network tier."""
    _enable("features.network.enabled")
    with session_scope() as s:
        p, t = _net_target(s, host="8.8.8.8", port=53)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                host="8.8.8.8", port=53)
        with pytest.raises(C.CampaignError) as ei:
            C.start_campaign(s, p, t, spec=spec, executor=_FakeExecutor())
        assert "loopback" in str(ei.value) or "private" in str(ei.value)


def test_network_campaign_launches_bounded_and_audited(hg_home):
    """With features.network on + a loopback target, the campaign launches on the bounded-
    egress path: allow_network=True, the EgressEvent is audited ALLOW, and the container
    joins the rehosted device's netns when present."""
    _enable("features.network.enabled")
    fake = _FakeExecutor()
    with session_scope() as s:
        p, t = _net_target(s, host="127.0.0.1", port=9001)
        # mark it rehosted so the netns join is exercised
        t.metadata_json = {"channel": {"kind": "tcp", "host": "127.0.0.1", "port": 9001,
                                       "rehost": {"ip": "127.0.0.1", "container": "firmae-xyz"}}}
        s.flush()
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        row = C.start_campaign(s, p, t, spec=spec, executor=fake)
        assert row.status == "running" and row.engine == "boofuzz"
        call = fake.calls[-1]
        assert call["allow_network"] is True
        assert call["net_container"] == "firmae-xyz"
        # the channel JSON (host/port/allow) was appended to the probe args
        chan = json.loads(call["extra_args"][call["extra_args"].index("--channel") + 1])
        assert chan["host"] == "127.0.0.1" and chan["port"] == 9001
        assert chan["allow"] == ["127.0.0.1:9001"]
        # audited ALLOW
        ev = s.query(EgressEvent).filter(EgressEvent.project_id == p.id,
                                         EgressEvent.allowed.is_(True)).all()
        assert ev and ev[0].dest == "127.0.0.1:9001" and ev[0].tool == "boofuzz"


def test_network_campaign_does_not_require_exec_gate(hg_home):
    """A live-socket campaign must NOT require features.fuzzing/poc — it executes no
    target bytes locally. features.network alone is sufficient (regression guard against
    over-gating)."""
    _enable("features.network.enabled")  # exec stays OFF
    from hexgraph.policy import current_policy
    assert current_policy().allow_execution is False
    with session_scope() as s:
        p, t = _net_target(s, host="127.0.0.1", port=9002)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        row = C.start_campaign(s, p, t, spec=spec, executor=_FakeExecutor())
        assert row.status == "running"


def test_binary_campaign_still_needs_exec_gate(hg_home):
    """A binary-only campaign EXECUTES the target → it still needs the exec gate
    (features.network alone is NOT enough). Fail-closed."""
    _enable("features.network.enabled")  # but NOT fuzzing/poc
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="binary_only", engine="qemu",
                                target_binary=t.path)
        with pytest.raises(PolicyViolation):
            C.start_campaign(s, p, t, spec=spec, executor=_FakeExecutor())


# ── The network-crash assurance ladder (input_reachable/dynamic) ──────────────────

def test_network_crash_is_input_reachable():
    crash = {"kind": "service-crash", "summary": "service died",
             "dedup_key": "k", "reproducer_sha256": "abc", "reproducer_size": 10,
             "net_reproducer": {"host": "127.0.0.1", "port": 80, "payload_b64": "QQ=="},
             "exploitability": {"rating": "dos"}}
    f = crash_finding(crash, None, "router-httpd", coverage_instrumented=False,
                      engine="boofuzz", surface="network")
    asr = f.evidence.extra["assurance"]
    assert asr["standard"] == "input_reachable" and asr["method"] == "dynamic"
    assert f.category == "other"  # frozen schema has no DoS literal; rating="dos" carries it
    assert f.evidence.extra["fuzz"]["net_reproducer"]["payload_b64"] == "QQ=="
    assert f.evidence.extra["fuzz"]["surface"] == "network"


def test_binary_crash_is_code_present():
    crash = {"kind": "heap-buffer-overflow", "summary": "ASan",
             "dedup_key": "k", "reproducer_sha256": "abc", "reproducer_size": 10,
             "exploitability": {"rating": "likely_exploitable"}}
    f = crash_finding(crash, "parse", "fw-bin", coverage_instrumented=True,
                      engine="qemu", surface="binary_only")
    asr = f.evidence.extra["assurance"]
    assert asr["standard"] == "code_present" and asr["method"] == "dynamic"


# ── Surface inference + input resolution ──────────────────────────────────────────

def test_infer_surface_binary_only_for_plain_binary(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        assert C.infer_surface(t) == "binary_only"


def test_resolve_surface_inputs_binary_sets_target_binary(hg_home):
    with session_scope() as s:
        p, t = _binary_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="binary_only", engine="qemu")
        C.resolve_surface_inputs(s, p, t, spec)
        assert spec.target_binary == t.path


def test_resolve_surface_inputs_network_sets_host_port(hg_home):
    with session_scope() as s:
        p, t = _net_target(s, host="192.168.1.1", port=8080)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        C.resolve_surface_inputs(s, p, t, spec)
        assert spec.host == "192.168.1.1" and spec.port == 8080


# ── The engines endpoint advertises the Phase-5 surfaces/engines ──────────────────

def test_fuzz_engines_endpoint_advertises_phase5():
    from fastapi.testclient import TestClient
    from hexgraph.api.app import create_app

    c = TestClient(create_app())
    r = c.get("/api/fuzz/engines", params={"surface": "binary_only"})
    assert r.status_code == 200
    assert r.json()["engines"] == ["qemu", "frida"] and r.json()["default"] == "qemu"
    r = c.get("/api/fuzz/engines", params={"surface": "network"})
    assert r.json()["engines"] == ["boofuzz", "desock"] and r.json()["default"] == "boofuzz"
    # the whole matrix
    r = c.get("/api/fuzz/engines")
    surfaces = r.json()["surfaces"]
    assert surfaces["binary_only"]["default"] == "qemu"
    assert surfaces["network"]["default"] == "boofuzz"
