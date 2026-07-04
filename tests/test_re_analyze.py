"""Explicit detached analysis (`re_analyze`) — single-flight + state transitions.

Engine-layer coverage with a FAKE executor (offline, no Docker/Ghidra): the analysis lifecycle
(analyzed | running | started | failed | none | unavailable), single-flight dedup (a 2nd start
attaches instead of launching a duplicate — including the name-conflict race), the detached launch
argv (`--analyze`, project_mount, the generous budget env), and reap-then-retry of a failed run.
"""

import pytest

from hexgraph.engine.re import analysis as A
from hexgraph.engine.re import ghidra_project as gp
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
        return {"present": True, "version": "12.1"}  # for ghidra_version_for_image(--check)

    def poll_detached(self, name):
        return dict(self._poll)

    def start_detached(self, probe, artifact, *, name, outdir, project_mount=None,
                       extra_args=None, extra_env=None, **kw):
        if self.start_error:
            raise self.start_error
        self.started.append({"probe": probe, "name": name, "project_mount": project_mount,
                             "extra_args": extra_args, "extra_env": extra_env, "outdir": outdir})
        return object()

    def stop_detached(self, name, *, remove=True, timeout=10):
        self.stopped.append(name)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "_ghidra_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    gp._VERSION_CACHE.clear()
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


def test_state_unavailable_when_ghidra_off(env, monkeypatch):
    project, target, _art = env
    monkeypatch.setattr(A, "_ghidra_active", lambda: False)
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
    assert call["name"].startswith("hexgraph-analyze-")     # deterministic single-flight name
    assert "HEXGRAPH_PROBE_TIMEOUT_S" in (call["extra_env"] or {})  # generous analysis budget


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
