"""Explicit detached analysis (`re_analyze`) — single-flight + state transitions, BOTH backends.

Engine-layer coverage with a FAKE executor (offline, no Docker/Ghidra/r2): the analysis lifecycle
(analyzed | running | started | failed | none | unavailable), single-flight dedup (a 2nd start
attaches instead of launching a duplicate — including the name-conflict race), the detached launch
argv (`--analyze`, project_mount, the size-scaled spec, the generous budget env), reap-then-retry of
a failed run, and that the ACTIVE backend (Ghidra vs radare2) picks the probe + slot + container name.
"""

import pytest

from hexgraph.engine.re import analysis as A
from hexgraph.engine.re import ghidra_project as gp
from hexgraph.engine.re import r2_project as rp
from hexgraph.sandbox.runner import SandboxError


class _Project:
    def __init__(self, data_dir):
        self.data_dir = str(data_dir)


class _Target:
    def __init__(self, path):
        self.path = str(path)


class _FakeExec:
    """Records detached launches/reaps; answers poll with a fixed state; can force a start error."""

    def __init__(self, poll=None, start_error=None):
        self.started: list = []
        self.stopped: list = []
        self._poll = poll or {"exists": False, "running": False, "exit_code": None}
        self.start_error = start_error

    def run_json_probe(self, probe, artifact, *, extra_args=None, **kw):
        # Serves both version probes: ghidra_version_for_image reads `version`, r2 reads `r2_version`.
        return {"present": True, "version": "12.1", "r2_version": "6.1.4"}

    def poll_detached(self, name):
        return dict(self._poll)

    def start_detached(self, probe, artifact, *, name, outdir, project_mount=None,
                       extra_args=None, extra_env=None, resources=None, **kw):
        if self.start_error:
            raise self.start_error
        self.started.append({"probe": probe, "name": name, "project_mount": project_mount,
                             "extra_args": extra_args, "extra_env": extra_env, "outdir": outdir,
                             "resources": resources})
        return object()

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stopped.append(name)


def _set_backend(monkeypatch, backend):
    monkeypatch.setattr(A, "_active_backend", lambda: backend)


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Default env: headless Ghidra is the active backend."""
    _set_backend(monkeypatch, "ghidra")
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    gp._VERSION_CACHE.clear()
    rp._VERSION_CACHE.clear()
    art = tmp_path / "bin"
    art.write_bytes(b"binary bytes to hash")
    return _Project(tmp_path / "data"), _Target(art), art


def _make_warm(project, art):
    """Fabricate a committed warm Ghidra slot for the target (so slot.exists() is True)."""
    slot = gp.resolve(project.data_dir, gp.content_hash(str(art)), "12.1")
    slot.prepare()
    (slot.project_dir / "hexgraph.gpr").write_text("project")
    slot.write_meta()
    return slot


def _make_warm_r2(project, art):
    """Fabricate a committed warm radare2 slot (named project + marker)."""
    slot = rp.resolve(project.data_dir, rp.content_hash(str(art)), "6.1.4")
    slot.prepare()
    slot.named_project_dir.mkdir(parents=True)
    (slot.named_project_dir / "rc.r2").write_text("project")
    slot.write_meta()
    return slot


# --- analysis_state (read-only) ------------------------------------------------

def test_state_none_when_no_analysis(env):
    project, target, _art = env
    assert A.analysis_state(project, target, runner=_FakeExec())["state"] == "none"


def test_state_analyzed_when_warm(env):
    project, target, art = env
    _make_warm(project, art)
    assert A.analysis_state(project, target, runner=_FakeExec())["state"] == "analyzed"


def test_state_running_when_container_up(env):
    project, target, _art = env
    fake = _FakeExec(poll={"exists": True, "running": True, "exit_code": None})
    assert A.analysis_state(project, target, runner=fake)["state"] == "running"


def test_state_failed_when_container_exited_not_warm(env):
    project, target, _art = env
    fake = _FakeExec(poll={"exists": True, "running": False, "exit_code": 1})
    assert A.analysis_state(project, target, runner=fake)["state"] == "failed"


def test_state_unavailable_when_no_persistent_backend(env, monkeypatch):
    """ghidra_bridge / unknown backend ⇒ no on-disk warm slot to build ⇒ unavailable."""
    project, target, _art = env
    _set_backend(monkeypatch, None)
    assert A.analysis_state(project, target, runner=_FakeExec())["state"] == "unavailable"


# --- start_analysis (start-or-attach, single-flight) --------------------------

def test_start_launches_detached_with_analyze_and_budget(env):
    project, target, _art = env
    fake = _FakeExec()  # none → launches
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "started"
    assert len(fake.started) == 1
    call = fake.started[0]
    assert call["probe"] == "ghidra_probe.py"
    assert call["extra_args"] == ["--analyze"]              # no focus, ignores /out
    assert call["project_mount"]                            # writes into the persistent slot
    assert call["name"].startswith("hexgraph-analyze-ghidra-")  # backend-scoped single-flight name
    assert "HEXGRAPH_PROBE_TIMEOUT_S" in (call["extra_env"] or {})  # generous analysis budget


def test_start_passes_size_scaled_resource_spec(env, monkeypatch):
    """Regression: re_analyze must launch the detached analysis with the SIZE-SCALED spec
    (resource_spec_for_artifact), NOT start_detached's 2 GB base default — a ~500 MB monolith OOMs
    the decompiler DB buffer at 2 GB. Assert the artifact-derived spec is threaded through verbatim,
    derived from THIS target's artifact."""
    project, target, _art = env
    from hexgraph.sandbox import resources as R

    sentinel = R.ResourceSpec(mem="13579m")  # a distinctive spec no default would produce
    seen = {}

    def _fake_spec(artifact, container_type="sandbox"):
        seen["artifact"], seen["ct"] = artifact, container_type
        return sentinel

    monkeypatch.setattr("hexgraph.sandbox.resources.resource_spec_for_artifact", _fake_spec)
    fake = _FakeExec()  # none → launches
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "started"
    assert fake.started[0]["resources"] is sentinel            # NOT the 2 GB base default
    assert seen == {"artifact": target.path, "ct": "sandbox"}  # scaled from this target's bytes


def test_start_is_noop_when_already_warm(env):
    project, target, art = env
    _make_warm(project, art)
    fake = _FakeExec()
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "analyzed" and fake.started == []  # single-flight: nothing launched


def test_start_reaps_lingering_container_when_analyzed(env):
    """Housekeeping: a completed analysis's exit-0 container is reaped on the next re_analyze so a
    done analysis doesn't leave a stopped container behind — and nothing new is launched."""
    project, target, art = env
    _make_warm(project, art)
    fake = _FakeExec(poll={"exists": True, "running": False, "exit_code": 0})  # lingering exit-0
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "analyzed"
    assert fake.stopped and fake.started == []


def test_start_attaches_when_already_running(env):
    project, target, _art = env
    fake = _FakeExec(poll={"exists": True, "running": True, "exit_code": None})
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "running" and fake.started == []   # attach, no duplicate analysis


def test_start_attaches_on_name_conflict_race(env):
    """Two starts racing for the deterministic name: the loser's start_detached hits docker's
    'name already in use' — that's the single-flight WIN, so it attaches (running), not errors."""
    project, target, _art = env
    fake = _FakeExec(start_error=SandboxError(
        "detached container start failed: The container name \"hexgraph-analyze-x\" is already in use"))
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "running"


def test_start_reaps_failed_then_relaunches(env):
    project, target, _art = env
    fake = _FakeExec(poll={"exists": True, "running": False, "exit_code": 1})  # a failed prior run
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "started"
    assert fake.stopped and fake.started        # reaped the exited-not-warm container, relaunched


# --- radare2 backend: the analyze path resolves the r2 slot + probe ------------

def test_r2_backend_state_none_then_analyzed(env, monkeypatch):
    """With radare2 the active backend, analysis_state reads the r2 slot: none until a warm r2
    project exists, analyzed once it does."""
    project, target, art = env
    _set_backend(monkeypatch, "radare2")
    assert A.analysis_state(project, target, runner=_FakeExec())["state"] == "none"
    _make_warm_r2(project, art)
    assert A.analysis_state(project, target, runner=_FakeExec())["state"] == "analyzed"


def test_r2_backend_launches_decompile_probe(env, monkeypatch):
    """re_analyze on the radare2 backend launches decompile_probe --analyze into the r2 slot with an
    r2-scoped single-flight name (never ghidra_probe / the ghidra slot)."""
    project, target, _art = env
    _set_backend(monkeypatch, "radare2")
    fake = _FakeExec()
    st = A.start_analysis(project, target, runner=fake)
    assert st["state"] == "started"
    call = fake.started[0]
    assert call["probe"] == "decompile_probe.py"
    assert call["extra_args"] == ["--analyze"]
    assert call["name"].startswith("hexgraph-analyze-radare2-")   # distinct from the ghidra name
    assert call["resources"] is not None                          # size-scaled for r2 too


def test_backend_names_never_collide(env, monkeypatch):
    """The SAME target under the two backends resolves to DIFFERENT container names (different
    slots) — so a Ghidra and an r2 analysis of one binary can't clobber each other's single-flight."""
    project, target, _art = env
    _set_backend(monkeypatch, "ghidra")
    g = A.start_analysis(project, target, runner=_FakeExec())["container"]
    _set_backend(monkeypatch, "radare2")
    r = A.start_analysis(project, target, runner=_FakeExec())["container"]
    assert g != r and "ghidra" in g and "radare2" in r
