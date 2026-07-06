"""Persistent Ghidra bridge lifecycle + routing (engine.re.bridge), offline with a fake executor.

Covers: the features.network gate (denied when off), the warm-slot requirement (needs_analysis),
single-flight attach, launch-and-record on serving, the metadata registry, target-aware decompiler
routing (a live bridge -> GhidraBridgeDecompiler), the headless-op guard while a bridge is live, and
stop clearing the registry. No Docker/Ghidra: the executor + docker/serving probes are faked.
"""

from __future__ import annotations

import types

import pytest

from hexgraph.engine.re import bridge as B


class _Slot:
    def __init__(self, exists=True, root="/data/ghidra/slot"):
        self._exists = exists
        self.root = root

    def exists(self):
        return self._exists

    def prepare(self):
        pass


class _Project:
    id = "proj-1"
    data_dir = "/data"


class _Target:
    id = "tgt-1"
    path = "/artifact"

    def __init__(self):
        self.metadata_json = {}


class _FakeExec:
    """Records detached launches; answers poll with a fixed state."""

    def __init__(self, poll=None, start_error=None):
        self.started: list = []
        self.stopped: list = []
        self._poll = poll or {"exists": False, "running": False, "exit_code": None}
        self.start_error = start_error

    def poll_detached(self, name):
        return dict(self._poll)

    def start_detached(self, probe, artifact, *, name, outdir, project_mount=None,
                       allow_network=False, resources=None, extra_env=None, **kw):
        if self.start_error:
            raise self.start_error
        self.started.append({"probe": probe, "name": name, "project_mount": project_mount,
                             "allow_network": allow_network, "extra_env": extra_env})
        self._poll = {"exists": True, "running": True, "exit_code": None}  # now up
        return object()

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stopped.append(name)


@pytest.fixture
def env(monkeypatch):
    """A target/project + a warm Ghidra slot; docker up; network ON; server serving at a fake IP."""
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr(B, "_ghidra_slot",
                        lambda project, target, *, runner: (_Slot(), "/artifact", "abc123def4567890"))
    monkeypatch.setattr(B, "_container_ip", lambda name: "172.17.0.9")
    monkeypatch.setattr(B, "_serving", lambda ip, port, timeout=2.0: True)
    monkeypatch.setattr("hexgraph.policy.current_policy",
                        lambda: types.SimpleNamespace(allow_network=True))
    # audit + precise egress gate are exercised in policy/audit tests; keep them no-ops here.
    monkeypatch.setattr("hexgraph.engine.audit.record_egress", lambda *a, **k: None)
    monkeypatch.setattr("hexgraph.policy.assert_allows_egress", lambda *a, **k: None)
    # size-scaled spec resolution needs Docker in prod; stub it offline.
    monkeypatch.setattr("hexgraph.sandbox.resources.resource_spec_for_artifact",
                        lambda *a, **k: None)
    monkeypatch.setattr("tempfile.mkdtemp", lambda *a, **k: "/tmp/bridge-out")
    monkeypatch.setattr(B, "_START_WAIT_S", 0)  # don't block in tests
    return _Session(), _Project(), _Target()


class _Session:
    def flush(self):
        pass


# --- gate + preconditions ------------------------------------------------------

def test_start_denied_without_network(env, monkeypatch):
    s, p, t = env
    monkeypatch.setattr("hexgraph.policy.current_policy",
                        lambda: types.SimpleNamespace(allow_network=False))
    res = B.start_bridge(s, p, t, runner=_FakeExec())
    assert res["state"] == "denied" and "features.network" in res["detail"]


def test_start_needs_analysis_without_warm_slot(env, monkeypatch):
    s, p, t = env
    monkeypatch.setattr(B, "_ghidra_slot",
                        lambda project, target, *, runner: (_Slot(exists=False), "/artifact", "abc123def4567890"))
    res = B.start_bridge(s, p, t, runner=_FakeExec())
    assert res["state"] == "needs_analysis" and "re_analyze" in res["detail"]


# --- launch + record -----------------------------------------------------------

def test_start_launches_records_and_routes(env):
    s, p, t = env
    fake = _FakeExec()  # nothing running -> launches
    res = B.start_bridge(s, p, t, runner=fake)
    assert res["state"] == "running" and res["ip"] == "172.17.0.9" and res["port"] == B.BRIDGE_PORT
    # launched detached with the bridge probe, the project mount, network on, the port env
    assert len(fake.started) == 1
    call = fake.started[0]
    assert call["probe"] == "ghidra_bridge_probe.py"
    assert call["allow_network"] is True
    assert call["project_mount"] and call["extra_env"]["GHIDRA_BRIDGE_PORT"] == str(B.BRIDGE_PORT)
    assert call["name"].startswith("hexgraph-ghidra-bridge-")
    # metadata registry recorded -> routing sees a live endpoint
    assert B.bridge_meta(t) == {"container": call["name"], "ip": "172.17.0.9",
                                "port": B.BRIDGE_PORT, "status": "running"}
    assert B.bridge_endpoint(t) == ("172.17.0.9", B.BRIDGE_PORT)


def test_start_single_flight_attaches(env):
    s, p, t = env
    fake = _FakeExec(poll={"exists": True, "running": True, "exit_code": None})  # already up
    res = B.start_bridge(s, p, t, runner=fake)
    assert res["state"] == "running" and fake.started == []  # attached, no duplicate launch


def test_start_reaps_exited_then_relaunches(env):
    s, p, t = env
    fake = _FakeExec(poll={"exists": True, "running": False, "exit_code": 1})  # a dead prior one
    B.start_bridge(s, p, t, runner=fake)
    assert fake.stopped and fake.started  # reaped the exited container, launched fresh


def test_start_starting_when_not_yet_serving(env, monkeypatch):
    s, p, t = env
    monkeypatch.setattr(B, "_serving", lambda ip, port, timeout=2.0: False)  # port not up yet
    res = B.start_bridge(s, p, t, runner=_FakeExec())
    assert res["state"] == "starting" and B.bridge_meta(t) is None  # not recorded until serving


# --- routing + guard -----------------------------------------------------------

def test_get_decompiler_routes_to_live_bridge(env, monkeypatch):
    s, p, t = env
    B.start_bridge(s, p, t, runner=_FakeExec())  # records the endpoint
    # The managed bridge routes via connect_managed (HexGraph's own JSON RPC); stub it so routing
    # returns the bridge decompiler without a live server.
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    from hexgraph.sandbox.decompiler import get_decompiler
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler

    dec = get_decompiler(target=t)
    assert isinstance(dec, GhidraBridgeDecompiler)
    # no target / no bridge -> NOT the bridge
    assert not isinstance(get_decompiler(), GhidraBridgeDecompiler)


def test_blocking_message_only_when_live(env):
    s, p, t = env
    assert B.blocking_message(t, "xrefs") is None          # no bridge yet
    B.start_bridge(s, p, t, runner=_FakeExec())
    assert "re_bridge_stop" in B.blocking_message(t, "rename")  # live -> guard message


def test_endpoint_none_when_bridge_dead(env, monkeypatch):
    s, p, t = env
    B.start_bridge(s, p, t, runner=_FakeExec())            # records endpoint
    monkeypatch.setattr(B, "_serving", lambda ip, port, timeout=1.0: False)  # bridge died
    assert B.bridge_endpoint(t) is None                    # -> routing falls back to headless


def test_stop_clears_registry(env):
    s, p, t = env
    fake = _FakeExec(poll={"exists": True, "running": True, "exit_code": None})
    B.start_bridge(s, p, t, runner=fake)
    assert B.bridge_meta(t) is not None
    res = B.stop_bridge(s, p, t, runner=fake)
    assert res["state"] == "stopped" and fake.stopped
    assert B.bridge_meta(t) is None and B.bridge_endpoint(t) is None
