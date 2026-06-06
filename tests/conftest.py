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


def _build_image_ready() -> bool:
    """True if Docker is up AND the hexgraph-build image is present (the dedicated
    build-from-source image; HEXGRAPH_BUILD_IMAGE overrides the tag for worktrees)."""
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return False
    image = os.environ.get("HEXGRAPH_BUILD_IMAGE", "hexgraph-build:latest")
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
    return r.returncode == 0


BUILD_IMAGE_READY = _build_image_ready()


def _fuzz_image_ready() -> bool:
    """True if Docker is up AND the hexgraph-fuzz image is present (the dedicated
    coverage-guided fuzz image; HEXGRAPH_FUZZ_IMAGE overrides the tag for worktrees)."""
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return False
    image = os.environ.get("HEXGRAPH_FUZZ_IMAGE", "hexgraph-fuzz:latest")
    r = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
    return r.returncode == 0


FUZZ_IMAGE_READY = _fuzz_image_ready()


def _floss_ready() -> bool:
    """True if the sandbox is up AND the ACTIVE sandbox image actually carries FLOSS.

    The flare-floss dependency is added in sandbox.Dockerfile (Phase 5A PR 5A-2) but a
    not-yet-rebuilt local image (or a worktree pointing at the shared `:latest`) won't have
    it, so the Docker-gated FLOSS probe test must skip cleanly there rather than fail. We
    probe the ACTIVE image (HEXGRAPH_SANDBOX_IMAGE-aware via sandbox_image()) for the floss
    CLI."""
    if not SANDBOX_READY:
        return False
    from hexgraph.sandbox.runner import sandbox_image

    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "sh", sandbox_image(),
         "-c", "command -v floss >/dev/null 2>&1"],
        capture_output=True,
    )
    return r.returncode == 0


FLOSS_READY = _floss_ready()


def _yara_ready() -> bool:
    """True if the sandbox is up AND the ACTIVE sandbox image actually carries yara-python.

    yara-python is added in sandbox.Dockerfile (Phase 5B) but a not-yet-rebuilt local image
    (or a worktree pointing at the shared `:latest`) won't have it, so the Docker-gated YARA
    probe test must skip cleanly there rather than fail. We probe the ACTIVE image
    (HEXGRAPH_SANDBOX_IMAGE-aware via sandbox_image()) for the `yara` Python module."""
    if not SANDBOX_READY:
        return False
    from hexgraph.sandbox.runner import sandbox_image

    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python3", sandbox_image(),
         "-c", "import yara"],
        capture_output=True,
    )
    return r.returncode == 0


YARA_READY = _yara_ready()


def _angr_ready() -> bool:
    """True if Docker is up AND the DEDICATED angr image is present and actually carries angr.

    angr ships in its OWN optional image (docker/angr.Dockerfile, `just angr-build`), NOT the base
    sandbox (D10), so the Docker-gated solver e2e must skip cleanly when that image is absent (a
    stock checkout, or a worktree that hasn't built it). HEXGRAPH_ANGR_IMAGE overrides the tag for
    worktrees. We probe the image for the `angr` Python module so a half-built image also skips."""
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        return False
    image = os.environ.get("HEXGRAPH_ANGR_IMAGE", "hexgraph-angr:latest")
    if subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
        return False
    r = subprocess.run(
        ["docker", "run", "--rm", "--entrypoint", "python3", image, "-c", "import angr"],
        capture_output=True,
    )
    return r.returncode == 0


ANGR_READY = _angr_ready()


@pytest.fixture
def angr_image():
    """Skips unless the dedicated angr image is present and carries angr — the Docker-gated
    solver e2e gate (like floss/yara/fuzz image fixtures). Returns the image tag."""
    if not ANGR_READY:
        pytest.skip("requires the dedicated angr image (`just angr-build`, docker/angr.Dockerfile)")
    return os.environ.get("HEXGRAPH_ANGR_IMAGE", "hexgraph-angr:latest")


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


@pytest.fixture(autouse=True)
def _reset_policy_ceiling():
    """`policy._ceiling` is a process-global frozen at server / MCP-session startup
    (`snapshot_ceiling`). In production each process snapshots once; in-process tests
    share the interpreter, so a test that runs the app lifespan (which snapshots an
    all-off ceiling) would otherwise clamp execution OFF for every later test that
    enables fuzzing/poc/etc. Reset to the no-ceiling (read-live) default around every
    test — the same discipline as `_restore_socket_guard`."""
    from hexgraph import policy

    policy.reset_ceiling()
    yield
    policy.reset_ceiling()


@pytest.fixture
def sandbox():
    """A SandboxRunner; skips the test if the sandbox isn't available."""
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image (just sandbox-build)")
    from hexgraph.sandbox.runner import SandboxRunner

    return SandboxRunner()


@pytest.fixture
def floss_sandbox():
    """A SandboxRunner whose ACTIVE image carries FLOSS; skips otherwise. The flare-floss
    dependency requires a sandbox-image rebuild (Phase 5A PR 5A-2), so this skips cleanly on
    a stock/not-yet-rebuilt image — like the fuzz/build image fixtures."""
    if not FLOSS_READY:
        pytest.skip("requires the flare-floss dependency in the sandbox image "
                    "(rebuild docker/sandbox.Dockerfile)")
    from hexgraph.sandbox.runner import SandboxRunner

    return SandboxRunner()


@pytest.fixture
def yara_sandbox():
    """A SandboxRunner whose ACTIVE image carries yara-python; skips otherwise. The
    yara-python dependency requires a sandbox-image rebuild (Phase 5B), so this skips cleanly
    on a stock/not-yet-rebuilt image — like the floss/fuzz/build image fixtures."""
    if not YARA_READY:
        pytest.skip("requires the yara-python dependency in the sandbox image "
                    "(rebuild docker/sandbox.Dockerfile)")
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


def _dind_image() -> str:
    """The docker-in-docker image used to stand up a SELF-PROVISIONED separate daemon for
    the remote-fuzz e2e (overridable for an offline mirror)."""
    return os.environ.get("HEXGRAPH_DIND_IMAGE", "docker:27-dind")


@pytest.fixture(scope="session")
def dind_remote():
    """A genuinely SEPARATE Docker daemon on a loopback TCP port, simulating a user-owned
    remote fuzz host WITHOUT a hand-configured DOCKER_HOST — so the Phase-6 remote-fuzz e2e
    is self-runnable instead of a permanent skip.

    Why dind (not unix:// or socat): a docker-in-docker daemon has its OWN image store and
    filesystem, so bind-mounts genuinely cannot cross — this is the highest-fidelity proof
    that the CAS-staged named-VOLUME transfer + `docker cp` stream-back path is exercised for
    real (a same-daemon unix:// endpoint would let a bind-mount "work" and mask a regression).
    Binds ONLY to 127.0.0.1, no TLS (loopback). The fuzz image required by a campaign is loaded
    into the dind daemon's separate store. Tears the daemon (and its anonymous state) down at
    session end.

    Yields the `tcp://127.0.0.1:<port>` DOCKER_HOST string. Skips cleanly if Docker, the dind
    image, or the fuzz image is unavailable (offline-safe), and skips if the daemon never comes
    up within the boot budget."""
    import time
    import uuid

    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        pytest.skip("requires Docker to stand up a docker-in-docker remote endpoint")
    if not FUZZ_IMAGE_READY:
        pytest.skip("requires the hexgraph-fuzz image (just fuzz-build) to load into the dind remote")

    dind_img = _dind_image()
    fuzz_img = os.environ.get("HEXGRAPH_FUZZ_IMAGE", "hexgraph-fuzz:latest")
    # Ensure the dind image is present (pull once; offline-safe — skip if it can't be fetched).
    if subprocess.run(["docker", "image", "inspect", dind_img], capture_output=True).returncode != 0:
        if subprocess.run(["docker", "pull", dind_img], capture_output=True).returncode != 0:
            pytest.skip(f"could not obtain the dind image {dind_img} (offline?) — skipping the dind remote")

    name = f"hexgraph-dind-{uuid.uuid4().hex[:8]}"
    # Pick a free loopback port for the dind daemon's insecure (loopback-only) TCP socket.
    import socket as _socket
    with _socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    dh = f"tcp://127.0.0.1:{port}"
    # --privileged is required for an inner dockerd; bind ONLY to loopback, no TLS (the control
    # plane stays loopback — a private compute backend the test owns, torn down at session end).
    up = subprocess.run(
        ["docker", "run", "-d", "--privileged", "--name", name,
         "-p", f"127.0.0.1:{port}:2375", "-e", "DOCKER_TLS_CERTDIR=",
         dind_img, "--host=tcp://0.0.0.0:2375", "--tls=false"],
        capture_output=True, text=True)
    if up.returncode != 0:
        pytest.skip(f"could not start the dind remote daemon: {up.stderr.strip()[:200]}")
    try:
        # Wait for the inner daemon to accept the Docker API (bounded).
        deadline = time.monotonic() + 60
        ready = False
        while time.monotonic() < deadline:
            v = subprocess.run(["docker", "-H", dh, "version", "--format", "{{.Server.Version}}"],
                               capture_output=True)
            if v.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            pytest.skip("the dind remote daemon did not come up within 60s")
        # Load the fuzz image into the SEPARATE store (`docker save | docker -H <dind> load`).
        save = subprocess.Popen(["docker", "save", fuzz_img], stdout=subprocess.PIPE)
        load = subprocess.run(["docker", "-H", dh, "load"], stdin=save.stdout,
                              capture_output=True, text=True, timeout=300)
        save.stdout.close()
        save.wait()
        if load.returncode != 0:
            pytest.skip(f"could not load {fuzz_img} into the dind remote: {load.stderr.strip()[:200]}")
        yield dh
    finally:
        # `-v` reaps the anonymous volume `docker:dind` declares for /var/lib/docker
        # (the dind daemon's whole image store — incl. the loaded fuzz image, easily GBs).
        # Without it that volume is orphaned every run; over CI it leaks unboundedly.
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


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
