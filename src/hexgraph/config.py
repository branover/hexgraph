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


def yara_rules_dir() -> Path:
    """User YARA rules directory under HEXGRAPH_HOME (Phase 5B).

    The drop-in directory the operator adds their own `.yar` files to; HexGraph's
    bundled rules ship in-package (`paths.bundled_yara_rules_dir`). Both are mounted
    read-only into the sandbox at match time. Rule updates are a manual user act — the
    no-network invariant means HexGraph never fetches rules for you."""
    return hexgraph_home() / "yara_rules"


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
    """Resolve config with precedence: env > managed settings.json > config.toml > defaults.

    The managed layer (settings.json) is what the web Settings UI / `hexgraph
    config` write; config.toml stays the user's hand-authored file + secret store."""
    from hexgraph import settings as _settings

    toml = _load_toml()
    llm = toml.get("llm", {})
    api = toml.get("api", {})

    def layered(env: str, managed_path: str, toml_val, default):
        if env in os.environ:
            return os.environ[env]
        m = _settings.managed_only(managed_path)
        if m is not None:
            return m
        return toml_val if toml_val is not None else default

    return Config(
        llm_backend=layered("HEXGRAPH_LLM_BACKEND", "llm.backend", llm.get("backend"), "mock"),
        model_pref=layered("HEXGRAPH_MODEL", "llm.model", llm.get("model"), None),
        host=layered("HEXGRAPH_HOST", "server.host", api.get("host"), DEFAULT_HOST),
        port=int(layered("HEXGRAPH_PORT", "server.port", api.get("port"), DEFAULT_PORT)),
    )


def get_anthropic_api_key() -> str | None:
    """Return the API key from env or config, or None. Never log the return value."""
    env = os.environ.get("ANTHROPIC_API_KEY")
    if env:
        return env
    return _load_toml().get("anthropic", {}).get("api_key")


def get_hexgraph_api_key() -> str | None:
    """Reserved (v2): the HexGraph account key for future paid/credits features.
    Read from env or config like any provider key; never logged or stored. Unused today."""
    env = os.environ.get("HEXGRAPH_API_KEY")
    if env:
        return env
    return _load_toml().get("hexgraph", {}).get("api_key")


def fuzz_remote_connection(env_id: str) -> dict | None:
    """The SECRET connection details for a registered remote fuzz environment, keyed by
    the environment id (design §5.8b). Read from env first, then `config.toml
    [fuzz_remote.<env_id>]` — NEVER stored in the DB, NEVER logged, reported presence-only
    (same discipline as the SSH/telnet remote creds, get_anthropic_api_key, etc.).

    env vars (UPPER, `-`→`_`): HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST and the optional TLS
    triple HEXGRAPH_FUZZ_REMOTE_<ID>_{TLS_VERIFY,CERT_PATH}. config.toml:
        [fuzz_remote.<env_id>]
        docker_host = "ssh://user@beefybox"        # or "tcp://10.0.0.5:2376"
        tls_verify = true                           # optional (tcp:// + certs)
        cert_path  = "/home/me/.docker/fuzzbox"     # optional

    Returns {docker_host, tls_env} or None when no connection is configured for the id."""
    key = (env_id or "").strip()
    if not key:
        return None
    env_key = key.upper().replace("-", "_").replace(".", "_")
    prefix = f"HEXGRAPH_FUZZ_REMOTE_{env_key}_"
    docker_host = os.environ.get(prefix + "DOCKER_HOST")
    tls_verify = os.environ.get(prefix + "TLS_VERIFY")
    cert_path = os.environ.get(prefix + "CERT_PATH")
    if not docker_host:
        cfg = (_load_toml().get("fuzz_remote", {}) or {}).get(key, {})
        docker_host = cfg.get("docker_host")
        if tls_verify is None and cfg.get("tls_verify") is not None:
            tls_verify = "1" if cfg.get("tls_verify") else None
        if cert_path is None:
            cert_path = cfg.get("cert_path")
    if not docker_host:
        return None
    tls_env: dict = {}
    if tls_verify:
        tls_env["DOCKER_TLS_VERIFY"] = "1"
    if cert_path:
        tls_env["DOCKER_CERT_PATH"] = os.path.expanduser(str(cert_path))
    return {"docker_host": docker_host, "tls_env": tls_env}


def fuzz_remote_has_connection(env_id: str) -> bool:
    """Presence-only check for a remote fuzz environment's secret connection details —
    never returns or logs the value (the Settings UI shows this as a boolean badge)."""
    return fuzz_remote_connection(env_id) is not None


def ensure_dirs() -> None:
    """Create the runtime directories if missing (idempotent)."""
    hexgraph_home().mkdir(parents=True, exist_ok=True)
    projects_dir().mkdir(parents=True, exist_ok=True)
