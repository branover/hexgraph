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

_REAL_STATE = B._container_state
from hexgraph.engine.re.ghidra_bridge import BridgeUnavailable as B_UNAVAILABLE


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
    # Routing asks `_container_state` (one inspect: liveness + current ip); the degrade path's
    # `_container_not_running` delegates to it, so this one stub covers both.
    monkeypatch.setattr(B, "_container_state", lambda name: (False, "172.17.0.9"))
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


def test_start_starting_records_the_entry_but_is_not_yet_an_endpoint(env, monkeypatch):
    """A container that is up but not yet serving is RECORDED as `starting`, and is deliberately
    NOT an endpoint.

    Both halves matter, and they are the two different questions this module keeps separate.
    `open_target` takes the Ghidra project lock BEFORE it binds the socket, so a starting bridge
    already OWNS the project — routing must see it (`bridge_route`) or a concurrent op goes headless
    into that lock. But it can't answer an RPC yet, so anything asking "is it live right now?"
    (`bridge_endpoint`, and the search_code nudge's `_bridge_live`) must still say no."""
    s, p, t = env
    monkeypatch.setattr(B, "_serving", lambda ip, port, timeout=2.0: False)  # port not up yet
    res = B.start_bridge(s, p, t, runner=_FakeExec())
    assert res["state"] == "starting"
    meta = B.bridge_meta(t)
    assert meta and meta["status"] == "starting"       # recorded, so routing knows the lock is held
    assert B.bridge_route(t)                           # ...and routes there rather than headless
    assert B.bridge_endpoint(t) is None                # ...but it is not answering yet


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

    This is now the production path itself: `_target_taint_analyzer` injects nothing, so every
    `analyze_taint` lands here (see test_production_taint_path_degrades_a_gone_bridge). Naming the
    implementation instead would open the warm slot HEADLESS behind a live bridge's resident
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


def test_run_ghidra_op_retries_headless_when_a_bridge_is_GONE(env, monkeypatch):
    """A bridge whose container is GONE holds nothing, so headless is safe — and better than
    failing an op whose warm slot is sitting right there. The realistic sequence: routing saw the
    bridge alive, and by the time the op ran the container had been reaped."""
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    # Alive when routing picks it, GONE by the time the post-failure probe runs — a bridge that
    # dies mid-flight, which is the only way the degrade path is reachable now that routing sends a
    # confirmed-gone bridge straight to headless.
    _probe = {"n": 0}

    def _state(name):
        _probe["n"] += 1
        return (False, "172.17.0.9") if _probe["n"] == 1 else (True, None)

    monkeypatch.setattr(B, "_container_state", _state)
    calls, gone = [], []
    # A gone container yields no ip, so bridge_endpoint stops reporting an endpoint (bridge.py).
    monkeypatch.setattr(B, "_container_ip", lambda name: None if gone else "172.17.0.9")

    def _dead(self, *a, **k):
        calls.append("bridge"); gone.append(1); raise ConnectionRefusedError("container gone")

    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint", _dead)
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: calls.append("headless") or {"taint": {"flows": []}})

    out = run_ghidra_op(t, "run_taint", "/artifact")
    assert calls == ["bridge", "headless"]          # tried the bridge, degraded to headless
    assert out == {"taint": {"flows": []}}


def test_run_ghidra_op_does_NOT_retry_when_a_raising_bridge_is_STILL_SERVING(env, monkeypatch):
    """An exception is NOT evidence the bridge is dead, and this is the case that proves it.

    `serve_bridge` is single-threaded behind a listen backlog, so a bridge BUSY inside one op still
    ACCEPTS the next connection; the host read then trips `_ManagedOps`' 600s timeout and `_rpc`
    reports `BridgeUnavailable("... unreachable: timed out")` — from a bridge that is very much
    alive and still owns the project. Degrading there would run a headless op (for `rename`, a
    WRITE) on the project it holds, which is the exact collision this helper exists to prevent. So
    liveness is OBSERVED after the failure, never inferred from the exception — and observed as
    POSITIVE evidence of death (docker no longer has the container) rather than "the port didn't
    answer within a second", which under exactly this load is the reading most likely to be wrong.
    """
    from hexgraph.engine.re.ghidra_bridge import BridgeUnavailable, GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    monkeypatch.setattr(B, "_container_state", lambda name: (False, "172.17.0.9"))  # still there — busy, not gone
    headless = []
    monkeypatch.setattr(GhidraBridgeDecompiler, "rename_function",
                        lambda self, *a, **k: (_ for _ in ()).throw(
                            BridgeUnavailable("managed Ghidra bridge at 172.17.0.9:4768 "
                                              "unreachable: timed out")))
    monkeypatch.setattr(GhidraDecompiler, "rename_function",
                        lambda self, *a, **k: headless.append(1) or {"focus": {}})

    with pytest.raises(BridgeUnavailable):
        run_ghidra_op(t, "rename_function", "/artifact", address="0x401000", new_name="parse")
    assert not headless          # NO headless WRITE behind a bridge that still owns the project


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


def test_production_taint_path_degrades_a_gone_bridge(env, monkeypatch):
    """The degradation has to reach the PRODUCTION taint path, not just `run_ghidra_op` in isolation.

    `analyze_taint` always selects through `_target_taint_analyzer`, which used to INJECT
    `ghidra_op_backend(target)`. That pinned instance routes to a live bridge perfectly well but
    cannot degrade a gone one — the injected object short-circuits the seam — so the whole taint
    call site silently kept the old no-degradation behaviour. Selection now injects nothing and
    `analyze` re-asks the seam per call. Asserting this at the SELECTOR (not on a hand-built
    analyzer) is the point: that is the layer that regressed."""
    from hexgraph.engine.re import taint as T
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    monkeypatch.setattr(T, "get_taint_analyzer", lambda: T.GhidraTaintAnalyzer())
    B.start_bridge(s, p, t, runner=_FakeExec())
    # Alive when routing picks it, GONE by the time the post-failure probe runs — a bridge that
    # dies mid-flight, which is the only way the degrade path is reachable now that routing sends a
    # confirmed-gone bridge straight to headless.
    _probe = {"n": 0}

    def _state(name):
        _probe["n"] += 1
        return (False, "172.17.0.9") if _probe["n"] == 1 else (True, None)

    monkeypatch.setattr(B, "_container_state", _state)
    calls, gone = [], []
    monkeypatch.setattr(B, "_container_ip", lambda name: None if gone else "172.17.0.9")

    def _dead(self, *a, **k):
        calls.append("bridge"); gone.append(1); raise ConnectionRefusedError("container gone")

    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint", _dead)
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: calls.append("headless") or {
                            "taint": {"flows": [], "analyzed": 7}})

    out = T._target_taint_analyzer(t).analyze("/artifact", project=p, target=t)
    assert calls == ["bridge", "headless"]   # the SELECTED analyzer degraded, not just the helper
    assert out["available"] and out["analyzed"] == 7 and out["error"] is None


def test_uncertain_liveness_does_NOT_degrade(env, monkeypatch):
    """The guard asks for POSITIVE evidence of death, because uncertainty here is dangerous.

    The failure that reaches the degrade path is typically a timeout from a bridge under LOAD —
    exactly when a short connect probe misses and a `docker inspect` is slowest. A guard that read
    "couldn't tell" as "gone" would therefore be weakest precisely when it matters, and its failure
    mode is a second writer on a live Ghidra project."""
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, run_ghidra_op

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    monkeypatch.setattr(GhidraBridgeDecompiler, "run_taint",
                        lambda self, *a, **k: (_ for _ in ()).throw(
                            B_UNAVAILABLE("unreachable: timed out")))
    headless = []
    monkeypatch.setattr(GhidraDecompiler, "run_taint",
                        lambda self, *a, **k: headless.append(1) or {})

    # docker can't answer -> "couldn't tell" -> must NOT degrade
    monkeypatch.setattr(B, "_container_state", lambda name: (None, "172.17.0.9"))
    with pytest.raises(B_UNAVAILABLE):     # the ORIGINAL error, not merely "something raised"
        run_ghidra_op(t, "run_taint", "/artifact")
    assert not headless

    # docker says the container is still running -> definitely must NOT degrade
    monkeypatch.setattr(B, "_container_state", lambda name: (False, "172.17.0.9"))
    with pytest.raises(B_UNAVAILABLE):
        run_ghidra_op(t, "run_taint", "/artifact")
    assert not headless

    # only a POSITIVE "no such container" degrades
    monkeypatch.setattr(B, "_container_state", lambda name: (True, None))
    run_ghidra_op(t, "run_taint", "/artifact")
    assert headless == [1]


def test_container_not_running_resolves_every_unknown_to_None(monkeypatch):
    """The PARSING, which the contract tests stub past. Polarity is this function's whole risk, so
    pin each docker shape — and especially that a zero-exit reply we can't read is `None`
    (couldn't tell) rather than True, since True is the answer that lets a headless op run."""
    import subprocess as _sp

    def _docker(rc=0, out="", err=""):
        monkeypatch.setattr(B.subprocess, "run",
                            lambda *a, **k: _sp.CompletedProcess(a[0], rc, out, err))

    # This covers the STATE half, which is all `_container_not_running` reads ([0]) — so the shapes
    # here deliberately omit the ip field the combined inspect also returns. The real two-field
    # replies (and the truthy NON-address tokens two of them carry) are pinned in
    # test_container_state_parses_the_real_two_field_replies.
    #   running -> rc=0 stdout="true …"   exited -> rc=0 stdout="false …"
    #   missing -> rc=1 stderr="error: no such object: <name>"
    _docker(out="true\n");  assert B._container_not_running("c") is False   # running
    _docker(out="false\n"); assert B._container_not_running("c") is True    # exited — dead JVM
    _docker(rc=1, err="error: no such object: c")
    assert B._container_not_running("c") is True                            # positively absent
    # everything below is "we did not get an answer" -> None -> caller assumes it IS running
    _docker(rc=1, err="permission denied while trying to connect to the Docker daemon")
    assert B._container_not_running("c") is None
    _docker(rc=0, out="")                     ; assert B._container_not_running("c") is None
    _docker(rc=0, out="<no value>")            ; assert B._container_not_running("c") is None
    monkeypatch.setattr(B.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(_sp.TimeoutExpired("docker", 10)))
    assert B._container_not_running("c") is None
    # OSError is what a MISSING docker binary raises — a different except arm from TimeoutExpired.
    monkeypatch.setattr(B.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("No such file: docker")))
    assert B._container_not_running("c") is None
    # docker's other absent-object phrasing, and the normalization the parse leans on
    _docker(rc=1, err="Error: No such container: c")
    assert B._container_not_running("c") is True
    _docker(out=" TRUE \r\n");  assert B._container_not_running("c") is False
    _docker(out="FALSE\r\n");   assert B._container_not_running("c") is True


def test_run_ghidra_op_raises_a_bad_op_name_without_touching_headless(env, monkeypatch):
    """A bad `op` is a programming error, not a dead bridge. Resolving it inside the try made the
    two indistinguishable: it degraded, constructed a headless backend, and raised the same
    AttributeError there with the real cause buried. The exception type is identical either way,
    so assert headless is never CONSTRUCTED."""
    import hexgraph.sandbox.decompiler as D

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    built = []
    real = D.GhidraDecompiler
    monkeypatch.setattr(D, "GhidraDecompiler",
                        lambda *a, **k: built.append(1) or real(*a, **k))

    with pytest.raises(AttributeError):
        D.run_ghidra_op(t, "no_such_op", "/artifact")
    assert not built                                  # never fell through to the headless path


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


# --- routing resolves liveness uncertainty the same safe way the degrade path does -------

def test_routing_prefers_the_bridge_when_liveness_is_UNCERTAIN(env, monkeypatch):
    """Routing used to fall through to headless whenever `bridge_endpoint` returned None — which
    collapses "gone" and "couldn't tell" exactly as the degrade path did before #301, except on
    EVERY call rather than only after a failure.

    A live bridge owns the project, so a headless op behind it collides. When we can't tell, route
    to the bridge: a wrong guess costs one failed RPC, which `run_ghidra_op` then resolves with
    positive evidence. The other way costs a second opener on a live project."""
    from hexgraph.engine.re.ghidra_bridge import GhidraBridgeDecompiler
    from hexgraph.sandbox.decompiler import GhidraDecompiler, ghidra_op_backend

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())

    # docker can't answer -> couldn't tell -> still route to the bridge
    monkeypatch.setattr(B, "_container_state", lambda name: (None, "172.17.0.9"))
    assert isinstance(ghidra_op_backend(t), GhidraBridgeDecompiler)

    # container present, socket NOT answering (starting, or wedged) -> it still owns the project
    monkeypatch.setattr(B, "_serving", lambda ip, port, timeout=1.0: False)
    assert isinstance(ghidra_op_backend(t), GhidraBridgeDecompiler)

    # only POSITIVE evidence of death routes headless
    monkeypatch.setattr(B, "_container_state", lambda name: (True, None))
    assert isinstance(ghidra_op_backend(t), GhidraDecompiler)


def test_routing_costs_one_docker_inspect_not_two(env, monkeypatch):
    """Routing runs on EVERY op, so it can't pay for its safety twice. Liveness and the container's
    current IP come from ONE `docker inspect`; the old path did an inspect for the IP and then a TCP
    connect to decide liveness."""
    from hexgraph.sandbox.decompiler import ghidra_op_backend

    s, p, t = env
    monkeypatch.setattr("hexgraph.engine.re.ghidra_bridge.connect_managed",
                        lambda host, port: types.SimpleNamespace(host=host, port=port))
    B.start_bridge(s, p, t, runner=_FakeExec())
    # Exercise the REAL probe by restoring just THIS function — `monkeypatch.undo()` would drop the
    # whole offline-isolation harness (docker_available, the slot, policy, the executor) and let the
    # test touch the host.
    monkeypatch.setattr(B, "_container_state", B._container_state.__wrapped__
                        if hasattr(B._container_state, "__wrapped__") else _REAL_STATE)
    inspects = []
    monkeypatch.setattr(B.subprocess, "run",
                        lambda *a, **k: inspects.append(a[0]) or
                        types.SimpleNamespace(returncode=0, stdout="true 172.17.0.9\n", stderr=""))
    ghidra_op_backend(t)
    assert len(inspects) == 1, inspects
    # ...and that the ONE call really asks both questions — a single inspect that fetched only the
    # state (leaving a second call for the ip) would satisfy a bare count.
    fmt = inspects[0][inspects[0].index("-f") + 1]
    assert "{{.State.Running}}" in fmt and ".IPAddress" in fmt


def test_container_state_parses_the_real_two_field_replies(monkeypatch):
    """The combined reply, captured from Docker 29.6.1 — the shape the OLD single-field template
    could not produce, so nothing pinned it until now.

    The trap is that two real replies carry a TRUTHY non-address in the ip slot. An unvalidated
    `parts[1]` therefore doesn't merely fail, it SHADOWS the fallback to the recorded ip (which is
    the trustworthy one: `_finalize` writes it only after `_serving` accepted a connection). Both
    must read as "no fresh address"."""
    import subprocess as _sp

    def _docker(out, rc=0, err=""):
        monkeypatch.setattr(B.subprocess, "run",
                            lambda *a, **k: _sp.CompletedProcess(a[0], rc, out, err))

    _docker("true 172.17.0.5\n")                   # running, one network — the everyday reply
    assert B._container_state("c") == (False, "172.17.0.5")
    _docker("true invalid IP\n")                   # running, NO usable address: docker >=26 renders
    assert B._container_state("c") == (False, None)  # the zero .IPAddress as the token `invalid`
    _docker("true 172.18.0.2172.19.0.2\n")        # TWO networks: {{range}} has no separator
    assert B._container_state("c") == (False, None)
    _docker("true \n")                             # older docker's empty render
    assert B._container_state("c") == (False, None)
    _docker("false invalid IP\n")                  # exited — the STATE still decides, ip is moot
    assert B._container_state("c") == (True, None)
    _docker("", rc=1, err="error: no such object: c")
    assert B._container_state("c") == (True, None)  # positively absent


def test_routing_prefers_the_RECORDED_ip_over_a_GARBAGE_docker_token(monkeypatch):
    """End to end through the REAL parse, because this is the failure a stubbed `_container_state`
    can't show: a truthy non-address must neither become the destination nor shadow the recorded ip.

    The fresh address still WINS when it is one — a dead bridge's Docker ip can be recycled, which is
    why routing re-reads it at all. It only yields to the registry when docker gave us no address."""
    import subprocess as _sp

    class _T:
        metadata_json = {"bridge": {"container": "c", "ip": "172.17.0.5",
                                    "port": B.BRIDGE_PORT, "status": "running"}}

    def _docker(out):
        monkeypatch.setattr(B.subprocess, "run",
                            lambda *a, **k: _sp.CompletedProcess(a[0], 0, out, ""))

    _docker("true 172.17.0.9\n")                   # re-read address wins over the stale registry
    assert B.bridge_route(_T()) == ("172.17.0.9", B.BRIDGE_PORT)
    _docker("true invalid IP\n")                   # garbage -> fall back, do NOT route to 'invalid'
    assert B.bridge_route(_T()) == ("172.17.0.5", B.BRIDGE_PORT)
    _docker("true 172.18.0.2172.19.0.2\n")        # concatenated pair -> same
    assert B.bridge_route(_T()) == ("172.17.0.5", B.BRIDGE_PORT)
