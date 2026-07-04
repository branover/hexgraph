"""The sandbox's wall-clock budget must hold even when the LAUNCHING process dies.

The host-side timeout (`subprocess.run(timeout=)` + `docker kill`) only fires while the launcher
is alive. If it crashes / is OOM-killed / the agent session closes, a `docker run --rm` container is
orphaned by the Docker daemon and — with no in-container enforcement — runs UNBOUNDED (an operator
hit a multi-hour radare2 `aaa` zombie exactly this way). run_probe now wraps the probe in coreutils
`timeout(1)` so the container self-terminates at its budget regardless of the host.

The unit tests lock the wiring offline (no Docker); the SANDBOX_READY test proves the mechanism end
to end on the real image — an orphaned container nobody manages stops itself.
"""

import types
import uuid

import pytest

from hexgraph.sandbox import runner as R

from conftest import SANDBOX_READY


def _capture_docker_run(monkeypatch):
    """Replace subprocess.run so run_probe builds+"launches" a container without Docker; capture
    the argv and the host-side timeout it was given. Returns a dict populated on the call."""
    calls: dict = {}

    def fake_run(cmd, **kw):
        calls["cmd"] = list(cmd)
        calls["host_timeout"] = kw.get("timeout")
        return types.SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(R.subprocess, "run", fake_run)
    return calls


def _wrapper_index(cmd):
    """Index of the image argv element (the container command starts right after it)."""
    return cmd.index("img")


def test_run_probe_wraps_probe_in_container_timeout(tmp_path, monkeypatch):
    art = tmp_path / "bin"
    art.write_bytes(b"hello")
    calls = _capture_docker_run(monkeypatch)

    R.SandboxRunner(image="img").run_probe("decompile_probe.py", str(art))

    cmd = calls["cmd"]
    i = _wrapper_index(cmd)
    # image → timeout -k <kill-after> <budget>s → python3 <probe> …
    assert cmd[i + 1] == "timeout"
    assert cmd[i + 2] == "-k" and cmd[i + 3] == R.CONTAINER_TIMEOUT_KILL_AFTER
    assert cmd[i + 4].endswith("s")
    assert cmd[i + 5] == "python3"
    assert cmd[i + 6].endswith("decompile_probe.py")

    # The container budget is the host budget + grace, so the host-side kill wins (clean
    # SandboxTimeout) when the launcher is alive; the container timeout is only the orphan backstop.
    container_budget = int(cmd[i + 4][:-1])
    assert container_budget == int(calls["host_timeout"]) + R.CONTAINER_TIMEOUT_GRACE_S
    assert container_budget > calls["host_timeout"]


def test_container_timeout_can_be_opted_out(tmp_path, monkeypatch):
    """HEXGRAPH_NO_CONTAINER_TIMEOUT=1 drops the wrapper for an image without coreutils `timeout`."""
    art = tmp_path / "bin"
    art.write_bytes(b"x")
    monkeypatch.setenv("HEXGRAPH_NO_CONTAINER_TIMEOUT", "1")
    calls = _capture_docker_run(monkeypatch)

    R.SandboxRunner(image="img").run_probe("decompile_probe.py", str(art))

    cmd = calls["cmd"]
    i = _wrapper_index(cmd)
    assert cmd[i + 1] == "python3"          # probe invoked directly, no wrapper
    assert "timeout" not in cmd


def test_explicit_resources_timeout_drives_the_container_budget(tmp_path, monkeypatch):
    """A caller-supplied ResourceSpec timeout (fuzz/poc/build set theirs deliberately) is the base
    the container budget scales from — not the runner default."""
    art = tmp_path / "bin"
    art.write_bytes(b"x")
    calls = _capture_docker_run(monkeypatch)

    R.SandboxRunner(image="img").run_probe(
        "poc_probe.py", str(art), resources=R.ResourceSpec(timeout=120))

    cmd = calls["cmd"]
    i = _wrapper_index(cmd)
    assert calls["host_timeout"] == 120
    assert cmd[i + 4] == f"{120 + R.CONTAINER_TIMEOUT_GRACE_S}s"


@pytest.mark.skipif(not SANDBOX_READY, reason="requires the sandbox image + docker")
def test_orphaned_container_self_terminates(tmp_path):
    """End to end: a container wrapped exactly as run_probe wraps it, launched detached and left
    UNMANAGED (nothing docker-kills it), must stop itself at its budget. Proves the orphan backstop
    with the real image's coreutils `timeout`, killing the whole process tree via PID-namespace
    teardown."""
    import subprocess
    import time

    from hexgraph.sandbox.runner import sandbox_image

    name = f"hexgraph-selftimeout-{uuid.uuid4().hex[:8]}"
    # Mirror run_probe's wrapper: `timeout -k 5s 3s <long op>`. The op (sleep 3600) far outlives the
    # 3s budget, so ONLY the container-side timeout can end it. --rm so a clean exit removes it.
    start = subprocess.run(
        ["docker", "run", "-d", "--rm", "--init", "--name", name, sandbox_image(),
         "timeout", "-k", "5s", "3s", "sleep", "3600"],
        capture_output=True, text=True)
    assert start.returncode == 0, start.stderr
    try:
        deadline = time.time() + 25  # must stop by ~3s (+5s kill-after); 25s is generous slack
        stopped = False
        while time.time() < deadline:
            probe = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True, text=True)
            # Non-zero (already removed by --rm) OR Running=false ⇒ it self-terminated.
            if probe.returncode != 0 or probe.stdout.strip() != "true":
                stopped = True
                break
            time.sleep(0.5)
        assert stopped, "orphaned container did not self-terminate within its budget + grace"
    finally:
        subprocess.run(["docker", "kill", name], capture_output=True)
