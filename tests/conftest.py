import os
import subprocess

import pytest

# Tests run against the mock backend: zero key, zero network (SPEC §1).
os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")


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


@pytest.fixture
def sandbox():
    """A SandboxRunner; skips the test if the sandbox isn't available."""
    if not SANDBOX_READY:
        pytest.skip("requires Docker + the hexgraph-sandbox image (make sandbox-build)")
    from hexgraph.sandbox.runner import SandboxRunner

    return SandboxRunner()


def fixture_path(name: str) -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures", name)


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
