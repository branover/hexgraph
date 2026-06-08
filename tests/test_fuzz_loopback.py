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
from hexgraph.engine.fuzz import campaigns as C
from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
from hexgraph.engine.fuzzers.network import BoofuzzFuzzer
from hexgraph.engine.targets.ingest import create_project, ingest_file
from hexgraph.policy import PolicyViolation
from hexgraph import settings as st

from conftest import fixture_path


def _enable(flag):
    st.update_settings({flag: True})


class _RecordingExecutor:
    """Records every start_detached / stop_detached call so we can assert the launch-and-join
    wiring and the teardown. Mirrors the real Executor signature (incl. requires_execution +
    disable_aslr added by PR #66)."""

    def __init__(self, *, service_exits=False, liveness=None):
        self.starts = []
        self.stops = []
        self._exits = service_exits
        # The successive run_tcp_probe liveness verdicts (UP/DOWN) for the verify path:
        # [baseline-UP, post-replay-DOWN] confirms a re-kill. The crashing-message send
        # itself (payload_hex present) is a no-op DoS request.
        self._liveness = list(liveness or [])
        self._probe_i = 0
        self.channel_probes = []

    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None,
                       allow_network=False, net_container=None, disable_aslr=False):
        from hexgraph.sandbox.runner import DetachedHandle
        self.starts.append({
            "probe": probe, "artifact": artifact, "name": name, "outdir": str(outdir),
            "requires_execution": requires_execution, "allow_network": allow_network,
            "net_container": net_container, "extra_args": extra_args,
            "extra_ro_mounts": extra_ro_mounts, "disable_aslr": disable_aslr,
        })
        return DetachedHandle(name=name, outdir=str(outdir))

    def poll_detached(self, name):
        return {"exists": True, "running": True, "exit_code": None}

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stops.append(name)

    def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
        self.channel_probes.append({"probe": probe, "channel": dict(channel),
                                    "net_container": net_container})
        if channel.get("payload_hex") is not None:  # the crashing message (DoS send) — no-op
            return {"ok": True, "response": "(payload sent)"}
        up = self._liveness[self._probe_i] if self._probe_i < len(self._liveness) else False
        self._probe_i += 1
        return {"ok": True, "response": ""} if up else {"ok": False, "error": "ConnectionRefusedError"}

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


# ── Verify: re-confirming a launch-and-join NETWORK crash relaunches the service (F6) ─

def _net_crash_artifact(s, p, t, *, port, launch=True, launch_binary=None):
    """A finished network campaign + a fuzz_crash finding carrying a re-runnable crashing
    MESSAGE + the linked FuzzArtifact — the inputs verify_artifact replays. `launch` records
    that the campaign used launch-and-join (so verify must relaunch the service)."""
    import base64

    from hexgraph.db.models import Finding, FuzzArtifact, FuzzCampaign
    from hexgraph.engine.tasks import create_task

    task = create_task(s, project=p, target_id=t.id, type="fuzzing", params={"campaign": True})
    cfg = {"surface": "network", "engine": "boofuzz", "port": port,
           "launch": launch, "launch_binary": launch_binary or t.path,
           "launch_command": None, "sysroot": None, "host": None}
    from pathlib import Path
    outdir = str(Path(p.data_dir) / "campaigns" / f"net-{port}")
    camp = FuzzCampaign(project_id=p.id, target_id=t.id, name="net fuzz", surface="network",
                        engine="boofuzz", task_id=task.id, status="completed",
                        outdir=outdir, config_json=cfg, resources_json={})
    s.add(camp)
    s.flush()
    payload = b"CRASH\x00\xff\r\n"  # non-ASCII bytes → must round-trip via payload_hex
    f = Finding(project_id=p.id, target_id=t.id, task_id=task.id, title="svc crash",
                severity="high", confidence="high", category="dos", summary="boofuzz crash",
                reasoning="service died", finding_type="fuzz_crash",
                evidence_json={"extra": {"fuzz": {"net_reproducer": {
                    "payload_b64": base64.b64encode(payload).decode(), "port": port}}}})
    s.add(f)
    s.flush()
    art = FuzzArtifact(project_id=p.id, campaign_id=camp.id, kind="crash",
                       content_cas="deadbeef", size=len(payload), finding_id=f.id)
    s.add(art)
    s.flush()
    return camp, art, payload


def test_verify_relaunches_launch_and_join_service(hg_home):
    """F6: re-verifying a launch-and-join network crash RELAUNCHES the service (the service
    container is gone by verify time) into a fresh netns, replays the crashing message on
    127.0.0.1 inside it, then tears it down — instead of failing with 'no live device host'."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")  # the exec tier (relaunching the service executes the target)
    # baseline UP, then DOWN after the replay ⇒ the re-kill is confirmed.
    ex = _RecordingExecutor(liveness=[True, False])
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9200)
        camp, art, payload = _net_crash_artifact(s, p, t, port=9200)

        res = C.verify_artifact(s, art, executor=ex)

        # The service was RELAUNCHED (the §5.8b service-launch probe ran, executing the target).
        svc = ex._service_call()
        assert svc is not None, "verify must relaunch the launch-and-join service"
        assert svc["requires_execution"] is True and svc["allow_network"] is False
        assert svc["artifact"] == t.path
        # …and TORN DOWN afterward — a verify must never leak the relaunched container.
        assert svc["name"] in ex.stops, "the relaunched service must be torn down after verify"
        # The replay targeted 127.0.0.1 INSIDE the relaunched service's netns (not the target,
        # which has no live host) — banner grab, the crashing message, and the liveness re-probe.
        replay = [c for c in ex.channel_probes if c["probe"] == "tcp_probe.py"]
        assert replay and all(c["net_container"] == svc["name"] for c in replay)
        assert all(c["channel"]["host"] == "127.0.0.1" for c in replay)
        assert any(c["channel"].get("payload_hex") == payload.hex() for c in replay), \
            "the crashing message must replay BYTE-EXACT via payload_hex"
        # The liveness transition (UP→DOWN) is the unforgeable verdict.
        assert res["verified"] is True
        assert res["assurance"]["standard"] == "input_reachable"
        # Every replay connection is audited egress to the loopback service (the SAME gate).
        ev = s.query(EgressEvent).filter(EgressEvent.project_id == p.id,
                                         EgressEvent.tool == "tcp_probe").all()
        assert ev and all(e.dest == "127.0.0.1:9200" for e in ev)


def test_verify_relaunch_always_tears_down_on_replay_error(hg_home):
    """Even if the replay blows up mid-verify, the relaunched service container is still torn
    down (the finally) — a verify can never strand a launched container."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")

    class _BoomRunner(_RecordingExecutor):
        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            raise RuntimeError("probe exploded")

    ex = _BoomRunner()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9201)
        camp, art, _ = _net_crash_artifact(s, p, t, port=9201)
        with pytest.raises(RuntimeError):
            C.verify_artifact(s, art, executor=ex)
        svc = ex._service_call()
        assert svc is not None and svc["name"] in ex.stops, \
            "the relaunched service must be torn down even when the replay errors"


def test_verify_non_launch_network_crash_does_not_relaunch(hg_home):
    """A network crash on an ALREADY-LIVE host (rehost/remote/base_url — config.launch off)
    must NOT relaunch a service: the existing already-live replay path is unchanged."""
    _enable("features.network.enabled")
    ex = _RecordingExecutor(liveness=[True, False])
    with session_scope() as s:
        # A target with a live device host recorded on its channel (no launch-and-join).
        p, t = _launchable_net_target(s, host="192.168.5.5", port=9202)
        camp, art, _ = _net_crash_artifact(s, p, t, port=9202, launch=False)

        res = C.verify_artifact(s, art, executor=ex)

        assert ex._service_call() is None, "an already-live host must not relaunch a service"
        assert res["verified"] is True
        replay = [c for c in ex.channel_probes if c["probe"] == "tcp_probe.py"]
        # host/netns came from the TARGET (the live device IP), not a 127.0.0.1 override.
        assert replay and all(c["channel"]["host"] == "192.168.5.5" for c in replay)


# ── Verify: the launch-and-join DOWN oracle is the SERVICE CONTAINER's exit (round-3 N6) ─

def test_verify_launch_and_join_container_exit_is_verified_down(hg_home):
    """N6: for a launch-and-join service, "down" means the relaunched service CONTAINER
    exited. A TCP re-probe can't attach to a dead container's netns (docker `exit 125:
    cannot join network namespace … is exited`) — so the unforgeable DOWN oracle is the
    container EXIT CODE read directly via poll_detached. An ASan crash signal (SIGABRT 134
    / SIGSEGV 139) ⇒ verified:true, WITHOUT the third (impossible) TCP re-probe."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")

    class _CrashExitExecutor(_RecordingExecutor):
        """The relaunched service container ABORTS on the crashing message: poll_detached
        reports it exited with SIGABRT (134). The post-send liveness TCP re-probe must NOT
        even be attempted — the container-exit oracle decides the verdict."""

        def __init__(self, exit_code=134):
            # liveness=[True] → the banner grab confirms the service is UP before the replay.
            super().__init__(liveness=[True])
            self._exit_code = exit_code
            self.polled = []

        def poll_detached(self, name):
            self.polled.append(name)
            return {"exists": True, "running": False, "exit_code": self._exit_code}

    ex = _CrashExitExecutor(exit_code=134)  # 128 + SIGABRT(6) — the ASan abort
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9210)
        camp, art, payload = _net_crash_artifact(s, p, t, port=9210)

        res = C.verify_artifact(s, art, executor=ex)

        # The service was relaunched AND its exit code consulted as the oracle.
        svc = ex._service_call()
        assert svc is not None and svc["name"] in ex.polled, \
            "verify must read the relaunched service container's exit code as the DOWN oracle"
        assert res["verified"] is True
        assert "SIGABRT" in res["detail"]
        assert res["assurance"]["standard"] == "input_reachable"
        # Only TWO TCP probes happened (banner grab + the crashing-message send) — the third
        # "is it down now?" re-probe is replaced by the container-exit oracle.
        tcp = [c for c in ex.channel_probes if c["probe"] == "tcp_probe.py"]
        assert len(tcp) == 2, "the post-send liveness re-probe must be skipped for a dead container"
        # …and the container is still torn down (the finally), never leaked.
        assert svc["name"] in ex.stops


def test_verify_launch_and_join_clean_exit_zero_is_not_verified(hg_home):
    """Defensive: if the relaunched container exited with status 0 (a graceful shutdown, not
    a crash) the replay did NOT reproduce a crash — verified must be False."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")

    class _CleanExitExecutor(_RecordingExecutor):
        def __init__(self):
            super().__init__(liveness=[True])  # banner grab UP, then the container exits 0
        def poll_detached(self, name):
            return {"exists": True, "running": False, "exit_code": 0}

    ex = _CleanExitExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9211)
        camp, art, _ = _net_crash_artifact(s, p, t, port=9211)
        res = C.verify_artifact(s, art, executor=ex)
        assert res["verified"] is False
        assert ex._service_call()["name"] in ex.stops


def test_verify_launch_and_join_netns_join_failure_maps_to_down(hg_home):
    """N6 (fallback): when poll_detached can't confirm the exit (the executor still reports
    the container as running), the post-send TCP re-probe attaches the dead container's netns
    and docker fails `exit 125: cannot join network namespace … is exited`. That SandboxError
    must be MAPPED to DOWN (verified) rather than propagating as a hard verify error."""
    from hexgraph.sandbox.runner import SandboxError
    _enable("features.network.enabled")
    _enable("features.poc.enabled")

    class _NetnsFailExecutor(_RecordingExecutor):
        """poll_detached is inconclusive (reports running) so the code falls back to the TCP
        re-probe; the post-send re-probe then hits the dead-container netns-join 125 error."""

        def __init__(self):
            super().__init__()
            self._sent = False

        def poll_detached(self, name):
            return {"exists": True, "running": True, "exit_code": None}

        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            self.channel_probes.append({"probe": probe, "channel": dict(channel),
                                        "net_container": net_container})
            if channel.get("payload_hex") is not None:  # the crashing message send
                self._sent = True
                return {"ok": True, "response": "(payload sent)"}
            if not self._sent:  # banner grab — service is UP
                return {"ok": True, "response": ""}
            # post-send liveness re-probe: the container died, docker can't join its netns.
            raise SandboxError(
                "probe tcp_probe.py failed (exit 125): Error response from daemon: cannot "
                "join network namespace of a non running container: container ... is exited")

    ex = _NetnsFailExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9212)
        camp, art, _ = _net_crash_artifact(s, p, t, port=9212)
        res = C.verify_artifact(s, art, executor=ex)  # must NOT raise
        assert res["verified"] is True, "a dead-container netns-join (125) must be DOWN, not an error"
        assert ex._service_call()["name"] in ex.stops


def test_verify_launch_and_join_unrelated_probe_error_still_propagates(hg_home):
    """A non-netns-join probe error (e.g. an unrelated docker failure) on the post-send
    re-probe must STILL propagate — only the dead-container 125 is special-cased to DOWN."""
    from hexgraph.sandbox.runner import SandboxError
    _enable("features.network.enabled")
    _enable("features.poc.enabled")

    class _OtherErrExecutor(_RecordingExecutor):
        def __init__(self):
            super().__init__()
            self._sent = False

        def poll_detached(self, name):
            return {"exists": True, "running": True, "exit_code": None}

        def run_channel_probe(self, probe, *, channel, net_container=None, secret=None):
            self.channel_probes.append({"probe": probe, "channel": dict(channel),
                                        "net_container": net_container})
            if channel.get("payload_hex") is not None:
                self._sent = True
                return {"ok": True, "response": "(payload sent)"}
            if not self._sent:
                return {"ok": True, "response": ""}
            raise SandboxError("probe tcp_probe.py did not emit valid JSON: boom")

    ex = _OtherErrExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9213)
        camp, art, _ = _net_crash_artifact(s, p, t, port=9213)
        with pytest.raises(SandboxError):
            C.verify_artifact(s, art, executor=ex)
        # teardown still happened despite the propagating error.
        assert ex._service_call()["name"] in ex.stops


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


# ── F2: launch_command must NEVER be char-split into single characters ─────────────

def test_coerce_launch_argv_does_not_char_split_a_string():
    """A bare str launch_command must be shlex.split into argv TOKENS, never list()'d into
    single characters (bug F2 — `['9','9','9','9']` reaching the service)."""
    f = C._coerce_launch_argv
    assert f("netd 9999") == ["netd", "9999"]
    assert f("9999") == ["9999"]
    # a JSON-array STRING (the exact F2 repro: launch_command='["9999"]') → ['9999'],
    # NOT ['[','"','9','9','9','9','"',']'].
    assert f('["9999"]') == ["9999"]
    assert f('["netd", "9999"]') == ["netd", "9999"]
    # an already-correct list/tuple passes through verbatim (stringified), never re-split.
    assert f(["9999"]) == ["9999"]
    assert f(["netd", "9999"]) == ["netd", "9999"]
    assert f(("-f", "-p", "9999")) == ["-f", "-p", "9999"]
    assert f(None) == [] and f("") == []
    # shell-quoted tokens survive as ONE token (no naive .split(" ")).
    assert f("daemon '--name=my svc'") == ["daemon", "--name=my svc"]


def test_launch_service_passes_intact_argv_not_chars(hg_home):
    """End-to-end through _launch_service: a string launch_command reaches the service probe
    as `--cmd=["9999"]` (the intended argv), NOT a per-character JSON array (bug F2). The
    launched service container also gets disable_aslr=True (bug F3 plumbing)."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9120)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz",
                                launch=True, launch_binary=t.path, launch_command="9999")
        C.start_campaign(s, p, t, spec=spec, executor=ex)
        svc = ex._service_call()
        assert svc is not None
        cmd_arg = next(a for a in svc["extra_args"] if a.startswith("--cmd="))
        argv = json.loads(cmd_arg[len("--cmd="):])
        assert argv == ["9999"], f"launch_command was corrupted: {argv!r}"
        # F3: the launched ASan service container disables ASLR (setarch -R in the probe).
        assert svc["disable_aslr"] is True


def test_launch_service_disables_aslr_for_asan_service(hg_home):
    """The launched-service container always opts into disable_aslr=True so the probe's
    setarch -R can keep an ASan-instrumented daemon from SIGSEGV-ing at init (bug F3)."""
    _enable("features.network.enabled")
    _enable("features.poc.enabled")
    ex = _RecordingExecutor()
    with session_scope() as s:
        p, t = _launchable_net_target(s, port=9121)
        spec = FuzzCampaignSpec(target_id=t.id, surface="network", engine="boofuzz")
        C.start_campaign(s, p, t, spec=spec, executor=ex)
        svc = ex._service_call()
        assert svc is not None and svc["disable_aslr"] is True


# ── F3: the service-launch PROBE sets ASAN_OPTIONS + the setarch -R wrapper ────────

def test_service_launch_probe_sets_asan_options_and_setarch(monkeypatch, tmp_path):
    """The probe launches the service under `setarch <machine> -R` with ASAN_OPTIONS merged
    into the child env — mirroring afl_probe — so an ASan daemon doesn't die at init (F3)."""
    import os as _os
    from hexgraph.sandbox.probes import service_launch_probe as P

    captured = {}

    class _FakeProc:
        pid = 4321

        def wait(self):
            return 0

    def _fake_popen(cmd, **kw):
        captured["cmd"] = cmd
        captured["env"] = kw.get("env")
        # drop the READY/status markers the caller writes after — emulate a clean exit.
        return _FakeProc()

    monkeypatch.setattr(P.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(P.shutil, "which", lambda name: f"/usr/bin/{name}")
    # The engine granted the personality cap → it set the handshake marker on the container.
    monkeypatch.setenv("HEXGRAPH_SVC_ASLR_RELAXED", "1")
    # a real ELF-shaped artifact path; _qemu_prefix reads its header (host arch → no qemu).
    art = tmp_path / "server"
    art.write_bytes(b"\x7fELF" + b"\x01" * 14 + bytes([62, 0]) + b"\x00" * 20)
    out = tmp_path / "out"

    monkeypatch.setattr(sys := __import__("sys"), "argv",
                        ["service_launch_probe.py", str(art), str(out), "--port=9131",
                         '--cmd=["9999"]'])
    rc = P.main()
    assert rc == 0

    cmd = captured["cmd"]
    env = captured["env"]
    # setarch -R wrapper leads the argv (ASLR off), with the intact extra argv at the tail.
    assert cmd[0] == "/usr/bin/setarch"
    assert cmd[1] == _os.uname().machine
    assert cmd[2] == "-R"
    assert "9999" in cmd, f"the launch argv token was lost: {cmd!r}"
    # ASAN_OPTIONS merged into the child env (not symbolize=0 — the launched service log is
    # read directly, unlike the AFL fuzz child).
    assert env is not None
    assert "abort_on_error=1" in env["ASAN_OPTIONS"]
    assert "detect_leaks=0" in env["ASAN_OPTIONS"]
    # Happy path: setarch ran → the status reports the relaxation took effect.
    status = json.loads((out / "status.json").read_text())
    assert status["aslr_relaxed"] is True
    assert status.get("note") in (None, "")


def test_service_launch_probe_falls_back_without_setarch(monkeypatch, tmp_path):
    """If setarch isn't present the probe still launches (bare invocation, no wrapper) —
    ASLR-off is best-effort, mirroring afl_probe."""
    from hexgraph.sandbox.probes import service_launch_probe as P

    captured = {}

    class _FakeProc:
        pid = 7

        def wait(self):
            return 0

    monkeypatch.setattr(P.subprocess, "Popen",
                        lambda cmd, **kw: (captured.update(cmd=cmd, env=kw.get("env")) or _FakeProc()))
    monkeypatch.setattr(P.shutil, "which", lambda name: None)  # no setarch, no qemu
    art = tmp_path / "server"
    art.write_bytes(b"\x7fELF" + b"\x01" * 14 + bytes([62, 0]) + b"\x00" * 20)
    out = tmp_path / "out"
    monkeypatch.setattr(__import__("sys"), "argv",
                        ["service_launch_probe.py", str(art), str(out), "--port=9132"])
    assert P.main() == 0
    cmd = captured["cmd"]
    assert "setarch" not in cmd[0]
    # ASAN_OPTIONS is still set even without setarch.
    assert "abort_on_error=1" in captured["env"]["ASAN_OPTIONS"]
    status = json.loads((out / "status.json").read_text())
    assert status["aslr_relaxed"] is False


# ── N1: the engine sets the ASLR-relaxed handshake marker ONLY when it grants the cap ──

def test_runner_sets_aslr_marker_only_when_relaxation_granted():
    """The capability handshake: _hardening_args emits HEXGRAPH_SVC_ASLR_RELAXED=1 EXACTLY
    when it also swaps in the personality-allowing seccomp profile (disable_aslr=True), and
    NOT otherwise. That's how the probe knows the engine actually granted the relaxation."""
    from hexgraph.sandbox.runner import SandboxRunner

    r = SandboxRunner(image="x")
    kw = dict(allow_network=False, net_container=None, resources=None, secret=False)
    from hexgraph.sandbox.runner import ResourceSpec
    kw["resources"] = ResourceSpec()

    granted = r._hardening_args(disable_aslr=True, **kw)
    not_granted = r._hardening_args(disable_aslr=False, **kw)
    assert "HEXGRAPH_SVC_ASLR_RELAXED=1" in granted
    # The marker rides alongside the relaxed seccomp profile — same gate, same flag.
    assert any("seccomp=" in a for a in granted)
    assert "HEXGRAPH_SVC_ASLR_RELAXED=1" not in not_granted
    assert not any("seccomp=" in a for a in not_granted)


# ── N3 / N1: setarch EPERM fallback + the stale-engine handshake diagnostic ───────────

def _elf(tmp_path, name="server"):
    art = tmp_path / name
    art.write_bytes(b"\x7fELF" + b"\x01" * 14 + bytes([62, 0]) + b"\x00" * 20)
    return art


def test_service_launch_probe_falls_back_when_setarch_epermed(monkeypatch, tmp_path):
    """N3: setarch is PRESENT and the engine granted the cap (marker set), but personality()
    is still denied at runtime (hardened host / older Docker) — setarch exits non-zero before
    exec'ing the target. The probe RETRIES the launch WITHOUT setarch so the service comes up,
    and the status reflects aslr_relaxed=False with a clear host-forbids note."""
    from hexgraph.sandbox.probes import service_launch_probe as P

    calls = []

    class _FakeProc:
        def __init__(self, pid, rc):
            self.pid = pid
            self._rc = rc

        def wait(self):
            return self._rc

    def _fake_popen(cmd, **kw):
        calls.append({"cmd": cmd, "env": kw.get("env")})
        out = tmp_path / "out"
        if cmd and cmd[0].endswith("setarch"):
            # Emulate setarch failing to set the personality BEFORE exec (EPERM): write the
            # tell-tale line to the service log and exit non-zero.
            with open(out / "service.log", "ab") as fh:
                fh.write(b"setarch: failed to set personality to x86_64: Operation not permitted\n")
            return _FakeProc(100, 1)
        return _FakeProc(200, 0)  # the no-setarch retry runs clean

    monkeypatch.setattr(P.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(P.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setenv("HEXGRAPH_SVC_ASLR_RELAXED", "1")  # engine DID grant the cap
    art = _elf(tmp_path)
    out = tmp_path / "out"
    monkeypatch.setattr(__import__("sys"), "argv",
                        ["service_launch_probe.py", str(art), str(out), "--port=9133"])
    assert P.main() == 0

    # Two spawns: the setarch attempt (EPERM) then the no-setarch retry.
    assert len(calls) == 2
    assert calls[0]["cmd"][0].endswith("setarch")
    assert "setarch" not in calls[1]["cmd"][0]
    # The retry keeps the SAME ASAN_OPTIONS.
    assert "abort_on_error=1" in calls[1]["env"]["ASAN_OPTIONS"]
    # The service still came up (final pid = the retry's), and the status is honest.
    status = json.loads((out / "status.json").read_text())
    assert status["launched"] is True
    assert status["pid"] == 200
    assert status["aslr_relaxed"] is False
    assert "personality() denied" in status["note"]
    # The clear note is also in the service log for an operator.
    assert "could not disable ASLR" in (out / "service.log").read_text()


def test_service_launch_probe_does_not_relaunch_on_bare_eperm(monkeypatch, tmp_path):
    """Regression: a SERVICE that legitimately fails (non-zero) and emits the bare errno
    "Operation not permitted" — e.g. `bind: Operation not permitted` on a privileged port
    under --cap-drop ALL — must NOT be misread as a setarch personality failure. setarch ran
    fine (it exec'd the target), so the probe must record the real exit code and NOT relaunch
    the service a second time. Detection keys on setarch's OWN "failed to set personality"
    signature, which is absent here."""
    from hexgraph.sandbox.probes import service_launch_probe as P

    calls = []

    class _FakeProc:
        def __init__(self, pid, rc):
            self.pid = pid
            self._rc = rc

        def wait(self):
            return self._rc

    def _fake_popen(cmd, **kw):
        calls.append({"cmd": cmd, "env": kw.get("env")})
        out = tmp_path / "out"
        # setarch exec'd the target fine; the SERVICE ITSELF then failed with the generic errno.
        with open(out / "service.log", "ab") as fh:
            fh.write(b"server: bind(0.0.0.0:80): Operation not permitted\n")
        return _FakeProc(100, 1)

    monkeypatch.setattr(P.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(P.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setenv("HEXGRAPH_SVC_ASLR_RELAXED", "1")  # engine DID grant the cap
    art = _elf(tmp_path)
    out = tmp_path / "out"
    monkeypatch.setattr(__import__("sys"), "argv",
                        ["service_launch_probe.py", str(art), str(out), "--port=9135"])
    assert P.main() == 0

    # Exactly ONE spawn (with setarch) — no spurious relaunch.
    assert len(calls) == 1
    assert calls[0]["cmd"][0].endswith("setarch")
    status = json.loads((out / "status.json").read_text())
    # setarch did run, so the relaxation took effect; the honest exit code is recorded.
    assert status["aslr_relaxed"] is True
    assert status["exit_code"] == 1


def test_service_launch_probe_skips_setarch_when_marker_absent(monkeypatch, tmp_path):
    """N1 (compat): setarch is PRESENT but the engine did NOT set the handshake marker — the
    server is running stale code that never granted the personality cap (or a host that forbids
    it). The probe skips setarch UP FRONT (no cryptic EPERM), logs the stale-engine diagnostic,
    and launches the service; status reports aslr_relaxed=False."""
    from hexgraph.sandbox.probes import service_launch_probe as P

    calls = []

    class _FakeProc:
        pid = 55

        def wait(self):
            return 0

    monkeypatch.setattr(P.subprocess, "Popen",
                        lambda cmd, **kw: (calls.append({"cmd": cmd, "env": kw.get("env")}) or _FakeProc()))
    monkeypatch.setattr(P.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.delenv("HEXGRAPH_SVC_ASLR_RELAXED", raising=False)  # engine did NOT grant
    art = _elf(tmp_path)
    out = tmp_path / "out"
    monkeypatch.setattr(__import__("sys"), "argv",
                        ["service_launch_probe.py", str(art), str(out), "--port=9134"])
    assert P.main() == 0

    # Only ONE spawn, and it never used setarch (skipped up front, not attempted-and-failed).
    assert len(calls) == 1
    assert "setarch" not in calls[0]["cmd"][0]
    assert "abort_on_error=1" in calls[0]["env"]["ASAN_OPTIONS"]
    status = json.loads((out / "status.json").read_text())
    assert status["launched"] is True
    assert status["aslr_relaxed"] is False
    assert "stale code" in status["note"]
    assert "running stale code" in (out / "service.log").read_text()
