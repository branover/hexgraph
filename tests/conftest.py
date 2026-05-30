import os

import pytest

# Tests run against the mock backend: zero key, zero network (SPEC §1).
os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")


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
