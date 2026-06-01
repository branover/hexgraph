import os
import subprocess

import pytest

# Tests run against the mock backend: zero key, zero network (SPEC §1).
os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")
# Keep LLM-task unit tests fast + docker-free; the decompiler/harness-build have
# their own sandbox-gated tests that opt back in.
os.environ.setdefault("HEXGRAPH_DISABLE_DECOMPILE", "1")
os.environ.setdefault("HEXGRAPH_DISABLE_SANDBOX_BUILD", "1")


def _sandbox_ready() -> bool:
    """True if Docker is up AND the hexgraph-sandbox image is built."""
    from hexgraph.sandbox.runner import docker_available, sandbox_image

    if not docker_available():
        return False
    r = subprocess.run(
        ["docker", "image", "inspect", sandbox_image()], capture_output=True
    )
    return r.returncode == 0


SANDBOX_READY = _sandbox_ready()


@pytest.fixture(autouse=True)
def _restore_socket_guard():
    """The egress probes' `_egress.install_socket_guard` monkeypatches global stdlib socket
    state. In the sandbox each probe is a fresh process, but in-process tests share the
    interpreter — so restore the original connect path after every test so a probe test can't
    leak its allowlist into an unrelated test's network connect."""
    yield
    import sys

    # Reuse the SAME _egress module object the probes imported (cached in sys.modules via the
    # probes-dir sys.path insert) so we restore the state THEY mutated, not a fresh copy.
    mod = sys.modules.get("_egress")
    if mod is None:
        import importlib.util

        path = os.path.join(os.path.dirname(__file__), "..", "src", "hexgraph",
                            "sandbox", "probes", "_egress.py")
        spec = importlib.util.spec_from_file_location("_egress", path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_egress"] = mod
        spec.loader.exec_module(mod)
    mod.uninstall_socket_guard()


@pytest.fixture
def sandbox():
    """A SandboxRunner; skips the test if the sandbox isn't available."""
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image (just sandbox-build)")
    from hexgraph.sandbox.runner import SandboxRunner

    return SandboxRunner()


def fixture_path(name: str) -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures", name)


def container_ip(name: str) -> str:
    """The single network IP of a running container. The naive
    `{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}` template silently CONCATENATES
    every attached network's IP (e.g. '172.17.0.2172.18.0.3'), yielding an unconnectable
    address if a container is on >1 network. Emit a SPACE between each, then assert there's
    exactly one non-empty dotted-quad and return it. (`.NetworkSettings.IPAddress` is unreliable
    across Docker setups — empty or absent under rootless/custom networks — so we read Networks.)"""
    import subprocess as _sp

    ips = _sp.run(
        ["docker", "inspect", "-f",
         "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
        check=True, capture_output=True, text=True,
    ).stdout.split()
    ips = [ip for ip in ips if ip]
    assert len(ips) == 1, f"expected exactly one container IP for {name!r}, got {ips!r}"
    ip = ips[0]
    assert len(ip.split(".")) == 4, f"expected a dotted-quad IP for {name!r}, got {ip!r}"
    return ip


def wait_for_port(host: str, port: int, timeout: float = 30.0) -> None:
    """Block until `host:port` accepts a TCP connection (bounded), instead of a blind
    time.sleep — removes timing flakiness from the live-container fixtures without changing
    what the tests prove. Raises if it never comes up within `timeout`."""
    import socket
    import time as _time

    deadline = _time.monotonic() + timeout
    last_err: Exception | None = None
    while _time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return
        except OSError as exc:  # refused / unreachable while the service boots
            last_err = exc
            _time.sleep(0.25)
    raise TimeoutError(f"{host}:{port} not ready within {timeout}s (last: {last_err})")


# ── Loud no-Docker visibility (review #5) ───────────────────────────────────────────────
# The highest-value SECURITY round-trips (live vulnrouter RCE/auth-bypass, web_discover, SSH
# remote ops, qemu/FirmAE rehost) are Docker-gated and SILENTLY skip when the sandbox image
# is absent — so a no-Docker run can report "all green" while validating NONE of the live
# egress/exec/rehost/remote paths. This hook makes that loud: it counts how many tests
# skipped for lack of Docker and prints a clear summary line. `just test-ci` additionally
# FAILS when Docker is expected but absent, so CI can't pass while skipping the live paths.
def _skipped_for_docker(terminalreporter) -> int:
    n = 0
    for report in terminalreporter.stats.get("skipped", []):
        reason = ""
        lr = getattr(report, "longrepr", None)
        if isinstance(lr, tuple) and len(lr) == 3:  # (path, lineno, message)
            reason = lr[2] or ""
        else:
            reason = str(lr or "")
        if "Docker" in reason or "sandbox image" in reason:
            n += 1
    return n


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    n = _skipped_for_docker(terminalreporter)
    if n and not SANDBOX_READY:
        terminalreporter.write_sep(
            "!", f"DOCKER ABSENT: {n} security-critical/live test(s) SKIPPED "
                 "(live vulnrouter RCE/auth-bypass, web_discover, SSH remote, rehost). "
                 "A green OFFLINE run validates NONE of these egress/exec/rehost/remote "
                 "paths — run `just test-ci` (or build the sandbox image) to exercise them.",
            yellow=True, bold=True)
    elif n:
        terminalreporter.write_sep(
            "-", f"{n} Docker-gated live test(s) skipped despite SANDBOX_READY "
                 "(check Docker / the hexgraph-sandbox image).", yellow=True)


@pytest.fixture
def hg_home(tmp_path, monkeypatch):
    """Isolate HEXGRAPH_HOME + the SQLite engine in a tmp dir for a test."""
    home = tmp_path / "hg"
    monkeypatch.setenv("HEXGRAPH_HOME", str(home))
    monkeypatch.delenv("HEXGRAPH_DB_PATH", raising=False)

    from hexgraph.config import _load_toml
    from hexgraph.db.session import init_db, reset_engine_for_tests

    _load_toml.cache_clear()
    reset_engine_for_tests()
    init_db()
    yield home
    reset_engine_for_tests()
