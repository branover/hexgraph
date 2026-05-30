"""Configuration + secret handling (SPEC §1, §6, §7).

Reads `~/.hexgraph/config.toml` and environment. The Anthropic API key is read
from env or config on demand and **never logged or stored** by HexGraph — there
is no field for it on any persisted object, and it is never written to a task
log. BYOK only; no bundled keys.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def hexgraph_home() -> Path:
    """Root for all runtime data: ~/.hexgraph (override with HEXGRAPH_HOME)."""
    return Path(os.environ.get("HEXGRAPH_HOME", Path.home() / ".hexgraph")).expanduser()


def config_path() -> Path:
    return hexgraph_home() / "config.toml"


def projects_dir() -> Path:
    return hexgraph_home() / "projects"


def db_path() -> Path:
    return hexgraph_home() / "hexgraph.db"


@dataclass
class Config:
    llm_backend: str = "mock"
    model_pref: str | None = None
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT

    @property
    def data_root(self) -> Path:
        return hexgraph_home()


@lru_cache(maxsize=1)
def _load_toml() -> dict:
    path = config_path()
    if not path.exists():
        return {}
    with path.open("rb") as fh:
        return tomllib.load(fh)


def load_config() -> Config:
    """Resolve config: env overrides TOML overrides defaults."""
    toml = _load_toml()
    llm = toml.get("llm", {})
    api = toml.get("api", {})
    return Config(
        llm_backend=os.environ.get("HEXGRAPH_LLM_BACKEND", llm.get("backend", "mock")),
        model_pref=os.environ.get("HEXGRAPH_MODEL", llm.get("model")),
        host=os.environ.get("HEXGRAPH_HOST", api.get("host", DEFAULT_HOST)),
        port=int(os.environ.get("HEXGRAPH_PORT", api.get("port", DEFAULT_PORT))),
    )


def get_anthropic_api_key() -> str | None:
    """Return the API key from env or config, or None. Never log the return value."""
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env
    return _load_toml().get("anthropic", {}).get("api_key")


def ensure_dirs() -> None:
    """Create the runtime directories if missing (idempotent)."""
    hexgraph_home().mkdir(parents=True, exist_ok=True)
    projects_dir().mkdir(parents=True, exist_ok=True)
