"""One-shot probe ownership and cleanup when an MCP/client launcher disappears.

`docker run --rm` does not stop a running container when the Docker CLI or its parent process dies.
For a warm Ghidra probe that means a cancelled agent session can leave the project locked until the
container's long size-scaled timeout. These tests cover launcher labels, unwind cleanup, and the
conservative next-call reaper without requiring Docker.
"""

import os
from types import SimpleNamespace

import pytest

from hexgraph.sandbox import runner as R


def _labels_from_run(cmd):
    labels = {}
    for i, arg in enumerate(cmd):
        if arg == "--label":
            key, value = cmd[i + 1].split("=", 1)
            labels[key] = value
    return labels


def test_run_probe_labels_launcher_and_exact_project(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"x")
    project = tmp_path / "warm-project"
    captured = {}
    monkeypatch.setattr(R, "_process_start_token", lambda pid: "boot-id:1234")

    def _run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(R.subprocess, "run", _run)
    R.SandboxRunner(image="image").run_probe(
        "ghidra_probe.py", artifact, project_mount=project, extra_args=["--script"])

    labels = _labels_from_run(captured["cmd"])
    assert labels[R._ONESHOT_LABEL] == R._ONESHOT_VALUE
    assert labels[R._PROBE_LABEL] == "ghidra_probe.py"
    assert labels[R._PROJECT_LABEL] == R._project_label_value(project)
    assert labels[R._OWNER_PID_LABEL] == str(os.getpid())
    assert labels[R._OWNER_START_LABEL] == "boot-id:1234"
    assert str(project) not in labels.values()  # path identity is hashed, never disclosed


class _ClientCancelled(BaseException):
    pass


def test_run_probe_stops_exact_container_when_caller_unwinds(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"x")
    calls = []

    def _run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "run"]:
            raise _ClientCancelled()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(R.subprocess, "run", _run)
    with pytest.raises(_ClientCancelled):
        R.SandboxRunner(image="image").run_probe("ghidra_probe.py", artifact)

    name = calls[0][calls[0].index("--name") + 1]
    assert ["docker", "kill", name] in calls


def test_run_probe_stops_container_when_docker_cli_returns_failure(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"x")
    calls = []

    def _run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:2] == ["docker", "run"]:
            return SimpleNamespace(returncode=130, stdout="", stderr="docker client interrupted")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(R.subprocess, "run", _run)
    with pytest.raises(R.SandboxError, match="docker client interrupted"):
        R.SandboxRunner(image="image").run_probe("ghidra_probe.py", artifact)

    name = calls[0][calls[0].index("--name") + 1]
    assert ["docker", "kill", name] in calls


def test_reconcile_reaps_only_positively_dead_owner(tmp_path, monkeypatch):
    project = tmp_path / "warm-project"
    rows = [
        {"Id": "dead-id", "Name": "/hexgraph-dead",
         "Config": {"Labels": {R._OWNER_PID_LABEL: "10"}}},
        {"Id": "live-id", "Name": "/hexgraph-live",
         "Config": {"Labels": {R._OWNER_PID_LABEL: "20"}}},
        {"Id": "unknown-id", "Name": "/hexgraph-unknown",
         "Config": {"Labels": {R._OWNER_PID_LABEL: "30"}}},
    ]
    calls = []

    def _run(cmd, **kwargs):
        calls.append(list(cmd))
        if cmd[:3] == ["docker", "ps", "--quiet"]:
            return SimpleNamespace(returncode=0, stdout="dead-id\nlive-id\nunknown-id\n", stderr="")
        if cmd[:2] == ["docker", "inspect"]:
            import json

            return SimpleNamespace(returncode=0, stdout=json.dumps(rows), stderr="")
        if cmd[:2] == ["docker", "kill"]:
            return SimpleNamespace(returncode=0, stdout=cmd[2], stderr="")
        raise AssertionError(cmd)

    states = {"10": False, "20": True, "30": None}
    monkeypatch.setattr(R.subprocess, "run", _run)
    monkeypatch.setattr(
        R, "_owner_process_alive", lambda labels: states[labels[R._OWNER_PID_LABEL]])

    result = R.reconcile_oneshot_project_probes(project)

    assert result == {
        "reaped": ["hexgraph-dead"],
        "active": ["hexgraph-live"],
        "uncertain": ["hexgraph-unknown"],
        "error": None,
    }
    assert ["docker", "kill", "dead-id"] in calls
    assert ["docker", "kill", "live-id"] not in calls
    ps = calls[0]
    assert f"label={R._PROJECT_LABEL}={R._project_label_value(project)}" in ps


def test_owner_identity_detects_pid_reuse_and_process_exit(monkeypatch):
    pid = os.getpid()
    token = R._process_start_token(pid)
    if token is None:
        pytest.skip("requires Linux /proc process identity")
    assert R._owner_process_alive({
        R._OWNER_PID_LABEL: str(pid), R._OWNER_START_LABEL: token,
    }) is True
    assert R._owner_process_alive({
        R._OWNER_PID_LABEL: str(pid), R._OWNER_START_LABEL: token + "-different",
    }) is False

    def _gone(probe_pid, signal):
        raise ProcessLookupError

    monkeypatch.setattr(R.os, "kill", _gone)
    assert R._owner_process_alive({R._OWNER_PID_LABEL: "999999"}) is False
