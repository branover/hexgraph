"""Launch-and-join for LOCAL-service network fuzzing (design §5.8b, Decision 1 / Option B).

When a boofuzz network campaign targets a service HexGraph can LAUNCH itself (a launchable
server binary, no externally-reachable host), HexGraph (a) starts the service in its OWN
detached, hardened sandbox container listening on that container's loopback, then (b) joins
the fuzzer container to its netns (`net_container=<service-container>`) so `127.0.0.1:port`
is reachable WITHOUT --network host — same isolation, no host networking.

Offline ($0): the launch-and-join wiring (the fuzzer's `net_container` = the launched
service container), the gate mapping (the service launch hits the EXEC tier; the fuzz egress
hits features.network + is audited; non-local refused), and the reaper/stop teardown of BOTH
containers. The real-container e2e (fuzz a launched local service end-to-end finding a planted
bug) is Docker-gated in test_fuzz_phase5_e2e.py.
"""

import json

import pytest

from hexgraph.db.models import EgressEvent, FuzzCampaign, Target, TargetKind
from hexgraph.db.session import session_scope
from hexgraph.engine import campaigns as C
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.fuzzers.network import BoofuzzFuzzer
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.policy import PolicyViolation
from hexgraph import settings as st

from conftest import fixture_path


def _enable(flag):
    st.update_settings({flag: True})


class _RecordingExecutor:
    """Records every start_detached / stop_detached call so we can assert the launch-and-join
    wiring and the teardown. Mirrors the real Executor signature (incl. requires_execution +
    disable_aslr added by PR #66)."""

    def __init__(self, *, service_exits=False):
        self.starts = []
        self.stops = []
        self._exits = service_exits

    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None,
                       allow_network=False, net_container=None, disable_aslr=False):
        from hexgraph.sandbox.runner import DetachedHandle
        self.starts.append({
            "probe": probe, "artifact": artifact, "name": name, "outdir": str(outdir),
            "requires_execution": requires_execution, "allow_network": allow_network,
            "net_container": net_container, "extra_args": extra_args,
            "extra_ro_mounts": extra_ro_mounts,
        })
        return DetachedHandle(name=name, outdir=str(outdir))

    def poll_detached(self, name):
        return {"exists": True, "running": True, "exit_code": None}

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stops.append(name)

    # the service-launch probe call (a `service` start) — same start_detached path

    def _service_call(self):
        return next((c for c in self.starts if c["probe"] == "service_launch_probe.py"), None)

    def _fuzz_call(self):
        return next((c for c in self.starts if c["probe"] == "boofuzz_probe.py"), None)


def _launchable_net_target(s, *, host=None, port=9100, binary=None):
    """A network `service` target with NO externally-reachable host (so launch-and-join is
    auto-selected) and a launchable server binary on its path."""
    p = create_project(s, name="loopback-fuzz")
    binary = binary or fixture_path("vuln_httpd")
    ch = {"kind": "tcp", "port": port}
    if host:
        ch["host"] = host
    t = Target(project_id=p.id, name=f"svc :{port}", path=binary,
               kind=TargetKind.service, metadata_json={"channel": ch})
    s.add(t)
    s.flush()
    return p, t


# ── Auto-detection of the launch-and-join trigger (no identity branching) ─────────

def test_host_is_launchable_local_classification():
    f = C._host_is_launchable_local
    assert f(None) is True and f("") is True            # unset → we must launch
    assert f("127.0.0.1") is True and f("localhost") is True and f("::1") is True
    assert f("192.168.1.1") is False                    # a reachable private IP → honour it
    assert f("10.0.0.5") is False
    assert f("8.8.8.8") is False                        # public is never launchable-local


def test_prepare_launch_and_join_sets_launch_fields(hg_home):
    """The boofuzz fuzzer carries the launch_binary onto PreparedFuzz when launch is on,
    and defaults the host to the shared-netns loopback for a bare-port launch."""
    with session_scope() as s:
        p, t = _launchable_net_target(s)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                port=9100, launch=True, launch_binary=t.path)
        prep = BoofuzzFuzzer().prepare(spec, p, t)
        assert prep.requires_egress is True
        assert prep.egress_host == "127.0.0.1" and prep.egress_port == 9100
        assert prep.launch_binary == t.path


def test_resolve_autoenables_launch_for_loopback_service(hg_home):
    """resolve_surface_inputs auto-enables launch-and-join for a service with a launchable
    binary and no externally-reachable host."""
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9101)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        C.resolve_surface_inputs(s, p, t, spec)
        assert spec.launch is True
        assert spec.launch_binary == t.path
        assert spec.host == "127.0.0.1" and spec.port == 9101


def test_resolve_does_not_launch_for_reachable_private_host(hg_home):
    """A reachable PRIVATE host (e.g. a rehosted device / a service bound to a bridgeable
    IP) is NOT launchable-local — we honour it and do NOT launch a service container."""
    with session_scope() as s:
        p, t = _launchable_net_target(s, host="192.168.7.7", port=80)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        C.resolve_surface_inputs(s, p, t, spec)
        assert spec.launch is False
        assert spec.host == "192.168.7.7"


# ── The launch-and-join launch wiring ─────────────────────────────────────────────

def test_launch_and_join_starts_service_then_joins_fuzzer(hg_home):
    """With features.network + the exec tier on, a launchable-local campaign launches TWO
    containers: a SERVICE container (executes the target → requires_execution=True) and a
    FUZZER container joined to its netns (net_container=<service>, allow_network=True)."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")  # the exec tier (launch-and-join executes the service)
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9102)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        assert row.status == "running" and row.engine == "boofuzz"
        svc = ex._service_call()
        fuzz = ex._fuzz_call()
        assert svc is not None, "the service container must be launched"
        assert fuzz is not None, "the fuzzer container must be launched"
        # the service EXECUTES the target → the exec gate; --network none holds for it
        assert svc["requires_execution"] is True
        assert svc["allow_network"] is False
        assert svc["artifact"] == t.path
        assert any(a.startswith("--port=") for a in svc["extra_args"])
        # the fuzzer joins the SERVICE container's netns + rides the egress path
        assert fuzz["allow_network"] is True
        assert fuzz["net_container"] == svc["name"]
        assert fuzz["requires_execution"] is False
        # the service container name is recorded on the durable row (for teardown)
        assert row.config_json.get("service_container") == svc["name"]
        # the fuzz egress was audited ALLOW to the loopback service
        ev = s.query(EgressEvent).filter(EgressEvent.project_id == p.id,
                                         EgressEvent.allowed.is_(True)).all()
        assert ev and ev[0].dest == "127.0.0.1:9102"
        # the fuzzer gets a generous STARTUP GRACE so the just-launched service has time to
        # bind its port before boofuzz declares it unreachable (no false 'not reachable').
        ch = json.loads(fuzz["extra_args"][fuzz["extra_args"].index("--channel") + 1])
        assert ch["startup_grace"] >= 10


def test_launch_and_join_needs_exec_tier(hg_home):
    """The launched SERVICE executes the target, so launch-and-join requires the EXEC tier
    even though the fuzz egress only needs features.network. With features.network but NOT
    the exec tier, the campaign fails closed (no service container leaks)."""
    _enable("features.network.enabled")  # exec tier OFF
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9103)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        with pytest.raises(C.CampaignError):
            C.start_campaign(s, p, t, spec=spec, executor=ex)
        # the row was marked failed; no fuzzer container was started (fail closed)
        assert ex._fuzz_call() is None


def test_launch_and_join_refuses_non_local_via_explicit_host(hg_home):
    """Even via launch-and-join, the fuzz egress can never reach a non-local host: an
    explicit external host (which disables auto-launch) is refused by local_tcp_scope."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, host="8.8.8.8", port=53)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        with pytest.raises(C.CampaignError) as ei:
            C.start_campaign(s, p, t, spec=spec, executor=ex)
        assert "loopback" in str(ei.value) or "private" in str(ei.value)


# ── Teardown: the reaper / stop tear down BOTH containers ─────────────────────────

def test_reaper_tears_down_both_containers(hg_home):
    """When the campaign finishes, the reaper stops BOTH the fuzzer container AND the
    launched service container (the launched server never outlives its fuzzer)."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9104)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        svc_name = row.config_json["service_container"]
        fuzz_name = row.container_name
        # signal completion: drop the DONE marker the reaper checks
        from pathlib import Path
        Path(row.outdir).mkdir(parents=True, exist_ok=True)
        (Path(row.outdir) / "DONE").write_text("done")
        C.reap_campaign(s, row, executor=ex)
        assert fuzz_name in ex.stops, "the fuzzer container must be torn down"
        assert svc_name in ex.stops, "the launched service container must be torn down too"


def test_stop_tears_down_both_containers(hg_home):
    """Stopping a running launch-and-join campaign tears down BOTH containers."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9105)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        row = C.start_campaign(s, p, t, spec=spec, executor=ex)
        svc_name = row.config_json["service_container"]
        fuzz_name = row.container_name
        C.stop_campaign(s, row, executor=ex)
        assert row.status == "stopped"
        assert fuzz_name in ex.stops and svc_name in ex.stops


def test_spec_roundtrips_launch_fields():
    """The launch-and-join fields survive to_dict (so a resume re-launches the service)."""
    spec = FuzzCampaignSpec(target_id="t", surface="network", engine="boofuzz",
                            port=80, launch=True, launch_binary="/x/srv",
                            launch_command=["/x/srv", "-p", "80"])
    d = spec.to_dict()
    assert d["launch"] is True and d["launch_binary"] == "/x/srv"
    assert d["launch_command"] == ["/x/srv", "-p", "80"]


# ── boofuzz startup-grace (the launch-and-join readiness race, review finding #1) ──

def test_boofuzz_wait_alive_tolerates_slow_bind():
    """`_wait_alive` polls within the grace window, so a service that binds a beat AFTER
    the fuzzer starts (the launch-and-join race) is NOT spuriously declared unreachable —
    while a service that never comes up still returns False once the grace elapses."""
    import socket
    import threading
    import time as _t
    from hexgraph.sandbox.probes import boofuzz_probe as B

    # Pre-pick a free port, then bind it ~0.6s LATE in a thread: a single connect would
    # miss it, but the grace-window poll catches it.
    probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_sock.bind(("127.0.0.1", 0))
    port = probe_sock.getsockname()[1]
    probe_sock.close()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def _serve_late():
        _t.sleep(0.6)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)

    th = threading.Thread(target=_serve_late, daemon=True)
    th.start()
    try:
        assert B._wait_alive("127.0.0.1", port, "tcp", grace=5, interval=0.2) is True
    finally:
        srv.close()
        th.join(timeout=2)

    # A port nothing ever binds: the grace elapses and we report unreachable (fail honestly).
    dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()  # closed → nothing is listening on dead_port
    assert B._wait_alive("127.0.0.1", dead_port, "tcp", grace=0.5, interval=0.2) is False
