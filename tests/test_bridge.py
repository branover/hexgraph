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


def test_ghidra_op_backend_routes_to_live_bridge(env, monkeypatch):
    """The non-decompile Ghidra ops (xrefs/taint/emulate/rename) route to the live managed bridge via
    ghidra_op_backend — no headless op conflicts on the slot the bridge owns; else headless."""
    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    from hexgraph.sandbox.decompiler import GhidraDecompiler, ghidra_op_backend
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler

    assert isinstance(ghidra_op_backend(t), GhidraDecompiler)   # no bridge yet -> headless
    B.start_bridge(s, p, t, runner=_FakeExec())                 # records the endpoint
    assert isinstance(ghidra_op_backend(t), GhidraBridgeDecompiler)  # live bridge -> bridge ops
    assert isinstance(ghidra_op_backend(), GhidraDecompiler)    # no target -> headless


def test_taint_asks_the_seam_so_a_live_bridge_serves_it(env, monkeypatch):
    """`GhidraTaintAnalyzer`'s OWN backend default must ask `ghidra_op_backend`, not name
    `GhidraDecompiler()`.

    Defence in depth, NOT a live bug: the production path already routed correctly, because
    `_target_taint_analyzer` injects `ghidra_op_backend(target)` and `analyze_taint` is the only
    caller. What was wrong is that the class's own fallback — reachable by constructing
    `GhidraTaintAnalyzer()` directly, as a future caller or a test easily might — named the
    implementation, so it would open the warm slot HEADLESS behind a live bridge's resident
    project — which fails outright (LockException at the project open), not merely contends.
    Every other PER-CALL Ghidra op asks the seam; now this one does too at both layers.
    (`enrich_target` asks it as well — see
    test_enrich_target_asks_the_seam_and_uses_the_bridge_when_one_is_live.)"""
    from hexgraph.engine.re import taint as T
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    seen = []

    def _spy(self, artifact, *, project=None):
        seen.append(type(self))
        return {"taint": {"flows": [], "analyzed": 0}}

    monkeypatch.setattr(GhidraDecompiler, "run_taint", _spy)
    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint", _spy)

    # No bridge: the seam resolves to headless, exactly as before this fix.
    T.GhidraTaintAnalyzer().analyze("/artifact", project=p, target=t)
    assert seen == [GhidraDecompiler]

    # Live bridge: taint must route THERE, not open a second headless view of the same project.
    B.start_bridge(s, p, t, runner=_FakeExec())
    T.GhidraTaintAnalyzer().analyze("/artifact", project=p, target=t)
    assert seen == [GhidraDecompiler, GhidraBridgeDecompiler]


def test_managed_decompile_passes_through_the_whole_inventory():
    """The defect this PR exists to fix: the bridge client DISCARDED `calls` and `structs`.

    The server has always sent them — `bridge_dispatch`'s `decompile` op returns
    `pyghidra_lib.decompile_core`'s result, the same core the headless probe uses — so dropping
    them client-side silently made the bridge a decompile-only backend and locked recon
    enrichment, the one consumer that reads the whole inventory, out of a bridged target."""
    from hexgraph.engine.re import ghidra_bridge as GB

    # The REAL wire shapes: `decompile_core` emits calls as [caller, callee] PAIRS
    # (pyghidra_lib.py `edges.append([f.getName(), callee.getName()])`), not {"from","to"} dicts —
    # a dict here would be silently dropped downstream by ghidra._call_graph_records, so the fake
    # has to match the server or this pins nothing.
    server_payload = {
        "functions": ["main", "parse"], "functions_total": 2,
        "focus": {"name": "main", "pseudocode": "int main(){}"},
        "calls": [["main", "parse"]],
        "structs": [{"name": "hdr", "size": 8, "builtin": False, "fields": []}],
    }
    ops = GB._ManagedOps.__new__(GB._ManagedOps)
    ops._rpc = lambda req: server_payload            # noqa: SLF001 — exercising the client contract

    out = ops.decompile(program=None, function=None)
    assert out["calls"] == server_payload["calls"]       # ...no longer dropped
    assert out["structs"] == server_payload["structs"]
    assert out["functions"] == ["main", "parse"]
    assert out["functions_total"] == 2


def test_managed_decompile_propagates_a_server_error_instead_of_an_empty_program():
    """A bridge-side failure must NOT read as "this binary has no functions".

    `bridge_dispatch` returns {"error": ...} for any exception inside `decompile_core`, and the
    whole-program inventory is the expensive JVM-heavy call. Dropping that key was survivable while
    the bridge was decompile-only, but enrichment's ONLY guard is `if "error" in data` — so a
    swallowed error would record 0 functions / 0 calls / 0 structs as authoritative substrate facts
    and return ok=True, after which the worker marks the target `ghidra_enriched` and
    `reveal._needs_ghidra_enrichment` never retries it again. Not even re_bridge_stop recovers."""
    from hexgraph.engine.re import ghidra_bridge as GB

    ops = GB._ManagedOps.__new__(GB._ManagedOps)
    ops._rpc = lambda req: {"error": "bridge op decompile failed: boom", "tb": "..."}  # noqa: SLF001

    out = ops.decompile(program=None, function=None)
    assert out["error"] == "bridge op decompile failed: boom"   # surfaced, not swallowed
    assert out["focus"] is None
    # ...which is what lets enrich_target's `if "error" in data` guard fire at all.
    assert "error" in out


def test_enrich_target_asks_the_seam_and_uses_the_bridge_when_one_is_live(env, monkeypatch):
    """Enrichment is no longer the one Ghidra op that can't run against a bridged target.

    It used to name `GhidraDecompiler()` directly, so with a bridge holding the project its open
    failed outright (LockException). Now it asks `ghidra_op_backend` like every other op.

    Asserts BOTH halves: which backend is asked, AND that a real bridge payload is actually
    CONSUMABLE — the payload here carries the shapes `pyghidra_lib.decompile_core` really emits
    (function NAMES, calls as [caller, callee] PAIRS, struct dicts), so a shape drift shows up as
    an empty call_graph record rather than passing silently."""
    from hexgraph.engine.re import ghidra as G
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    # The env fixture's session is a stub, so capture the Observation writes instead of doing them.
    recorded: list[dict] = []
    monkeypatch.setattr(
        "hexgraph.engine.observations.record_observation",
        lambda *a, **k: (recorded.append(k), (types.SimpleNamespace(id="obs"), False))[1])
    seen = []
    payload = {"functions": ["main"], "calls": [["main", "parse"]],
               "structs": [{"name": "hdr", "size": 8, "builtin": False, "fields": []}]}
    for cls in (GhidraDecompiler, GhidraBridgeDecompiler):
        monkeypatch.setattr(cls, "decompile",
                            lambda self, *a, **k: (seen.append(type(self)), payload)[1])

    out = G.enrich_target(s, p, t)
    assert seen == [GhidraDecompiler]                    # no bridge -> headless, as before

    recorded.clear()
    B.start_bridge(s, p, t, runner=_FakeExec())
    out = G.enrich_target(s, p, t)
    assert seen == [GhidraDecompiler, GhidraBridgeDecompiler]   # live bridge -> served by it

    # ...and the bridge's payload really enriches: counted, and reshaped into call-graph records.
    assert out == {"ok": True, "recorded": True, "functions": 1, "calls": 1, "structs": 1}
    by_kind = {k["result_kind"]: k["payload"] for k in recorded}
    assert by_kind["function_list"] == {"functions": [{"name": "main"}]}
    assert by_kind["call_graph"] == {"functions": [{"name": "main", "callees": ["parse"]}]}
    assert by_kind["structs"] == {"structs": payload["structs"]}


def test_enrich_target_refuses_when_the_bridge_returns_an_error(env, monkeypatch):
    """A bridge fault must leave the target RETRYABLE, not marked enriched with nothing recorded.

    `enrich_target` returning ok=True is what makes engine.worker stamp `ghidra_enriched` on the
    target, and reveal._needs_ghidra_enrichment then skips it forever. So an errored bridge has to
    come back ok=False with the detail — the same contract the headless path has always had."""
    from hexgraph.engine.re import ghidra as G
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    recorded: list[dict] = []
    monkeypatch.setattr(
        "hexgraph.engine.observations.record_observation",
        lambda *a, **k: (recorded.append(k), (types.SimpleNamespace(id="obs"), False))[1])
    # What _ManagedOps.decompile returns when bridge_dispatch reports a server-side failure.
    monkeypatch.setattr(GhidraBridgeDecompiler, "decompile",
                        lambda self, *a, **k: {"functions": [], "functions_total": None,
                                               "focus": None, "calls": [], "structs": [],
                                               "tool": "ghidra_bridge",
                                               "error": "bridge op decompile failed: boom"})

    B.start_bridge(s, p, t, runner=_FakeExec())
    out = G.enrich_target(s, p, t)
    assert out["ok"] is False and "boom" in out["detail"]
    assert not recorded          # no empty "0 functions" facts written to the substrate


def test_run_ghidra_op_retries_headless_when_a_bridge_is_UNREACHABLE(env, monkeypatch):
    """A bridge that RAISES holds nothing, so headless is safe — and better than failing an op
    whose warm slot is sitting right there."""
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    calls = []

    def _dead(self, *a, **k):
        calls.append("bridge"); raise ConnectionRefusedError("container gone")

    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint", _dead)
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: calls.append("headless") or {"taint": {"flows": []}})

    out = run_ghidra_op(t, "run_taint", "/artifact")
    assert calls == ["bridge", "headless"]          # tried the bridge, degraded to headless
    assert out == {"taint": {"flows": []}}


def test_run_ghidra_op_does_NOT_retry_when_a_live_bridge_returns_an_error(env, monkeypatch):
    """The other half, and the one that matters: a bridge that RETURNS an error is ALIVE and still
    owns the project. A headless open behind it collides on the project lock (LockException), so
    the error must propagate untouched — retrying here would corrupt, not recover."""
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    headless = []
    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint",
                        lambda self, *a, **k: {"error": "decompile_core blew up"})
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: headless.append(1) or {"taint": {}})

    out = run_ghidra_op(t, "run_taint", "/artifact")
    assert out == {"error": "decompile_core blew up"}   # propagated verbatim
    assert not headless                                  # never ran behind the live bridge


def test_run_ghidra_op_reraises_when_headless_itself_fails(env, monkeypatch):
    """A headless primary has nothing to degrade to, so its exception is the caller's to handle."""
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env  # no bridge started -> headless primary
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError("docker down")))
    with pytest.raises(RuntimeError, match="docker down"):
        run_ghidra_op(t, "run_taint", "/artifact")


def test_bridge_start_doc_does_not_advertise_a_capability_tradeoff(env):
    """The advertised description is what an agent reads before deciding to start a bridge. It used
    to say re_xrefs falls back to radare2 and emulation/rename are unavailable — true once, but the
    'later release' it promised had already shipped, so the text was deterring agents from the fast
    path with a cost that no longer exists. Pin the corrected claim."""
    from hexgraph.agent.mcp_catalog import catalog

    doc = {x["name"]: x for x in catalog()}["re_bridge_start"]["description"]
    assert "falls back to radare2" not in doc
    assert "later release" not in doc
    assert "re_xrefs" in doc                    # ...it names the ops the bridge DOES serve
    assert "taint" in doc
    assert "re_reanalyze" in doc                # ...and the one genuine exception (cold re-import)


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
