"""Managed, writable settings — optional features + non-secret preferences.

Two layers, kept deliberately separate:

- **`config.toml`** stays the user's hand-authored file *and* the BYOK secret
  location (`[anthropic].api_key`). HexGraph **never rewrites it**.
- **`settings.json`** is the HexGraph-managed layer the web UI / CLI mutate
  (feature toggles, backend preference, server bind, Ghidra config). It takes
  precedence over `config.toml` for the keys it owns.

**Secrets are never written here and never returned.** API keys come only from
the environment or `config.toml`; `read_settings()` reports presence + source,
never a single character of the value (SPEC §1, §6: never log or store the key).
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any

from hexgraph import config as _cfg

# Resolved view = these defaults deep-merged with whatever settings.json sets.
DEFAULTS: dict[str, Any] = {
    "llm": {"backend": "mock", "model": None},
    "server": {"host": "127.0.0.1", "port": 8765},
    "features": {
        "ghidra": {
            "enabled": False,
            "mode": "headless",          # "headless" (sandbox) | "bridge" (running Ghidra)
            "enrich_recon": False,       # materialize Ghidra function/call-graph/struct nodes
            "timeout": 600,              # headless analyzeHeadless wall-clock budget (s)
            "bridge": {"host": "127.0.0.1", "port": 4768},
        },
        "fuzzing": {
            # OFF by default: enabling this flips the analysis policy to allow
            # execution (still --network none, capped, timed, disposable). The
            # static-only invariant holds unless a user opts in. (engine: libFuzzer)
            "enabled": False,
            "max_total_time": 60,        # seconds of actual fuzzing per run
            "max_len": 4096,             # max generated input size (bytes)
            "max_crashes": 10,           # cap on unique-crash findings per run
            "timeout": 300,              # sandbox wall-clock (>= compile + max_total_time)
        },
    },
}

# Only these dotted paths may be written via update_settings(); everything else
# is rejected. (type, allowed-values|None). No secret ever appears here.
ALLOWED: dict[str, tuple[Any, set | None]] = {
    "llm.backend": (str, {"mock", "anthropic", "claude_code"}),
    "llm.model": ((str, type(None)), None),
    "server.host": (str, None),
    "server.port": (int, None),
    "features.ghidra.enabled": (bool, None),
    "features.ghidra.mode": (str, {"headless", "bridge"}),
    "features.ghidra.enrich_recon": (bool, None),
    "features.ghidra.timeout": (int, None),
    "features.ghidra.bridge.host": (str, None),
    "features.ghidra.bridge.port": (int, None),
    "features.fuzzing.enabled": (bool, None),
    "features.fuzzing.max_total_time": (int, None),
    "features.fuzzing.max_len": (int, None),
    "features.fuzzing.max_crashes": (int, None),
    "features.fuzzing.timeout": (int, None),
}


class SettingsError(ValueError):
    """A settings write was rejected (unknown key, bad type, illegal value)."""


def settings_path() -> Path:
    return _cfg.hexgraph_home() / "settings.json"


def _read_raw() -> dict:
    """The managed layer exactly as stored (no defaults merged in)."""
    p = settings_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _deep_merge(base: dict, over: dict) -> dict:
    out = deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = deepcopy(v)
    return out


def resolved() -> dict:
    """DEFAULTS with the managed layer applied — the full non-secret view."""
    return _deep_merge(DEFAULTS, _read_raw())


def _walk(d: dict, path: str, default: Any = None) -> Any:
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def get(path: str, default: Any = None) -> Any:
    """Resolved value at a dotted path (managed over defaults)."""
    val = _walk(resolved(), path, _SENTINEL)
    return default if val is _SENTINEL else val


def managed_only(path: str) -> Any:
    """Value explicitly set in settings.json, or None if not set (no defaults).
    Used for layering against config.toml so a user's TOML isn't shadowed by a
    default."""
    val = _walk(_read_raw(), path, _SENTINEL)
    return None if val is _SENTINEL else val


_SENTINEL = object()


def _flatten(d: dict, prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        else:
            out[key] = v
    return out


def _set_path(d: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur = d
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def update_settings(patch: dict) -> dict:
    """Validate `patch` (nested or dotted) against ALLOWED, merge into the managed
    layer, persist, and return the redacted full view. Rejects unknown/secret keys."""
    flat = _flatten(patch)
    raw = _read_raw()
    for path, value in flat.items():
        if path not in ALLOWED:
            raise SettingsError(f"unknown or read-only setting {path!r}")
        typ, choices = ALLOWED[path]
        if isinstance(typ, tuple):
            ok = isinstance(value, typ)
        else:
            # bool is a subclass of int — guard so port:int doesn't accept True.
            ok = isinstance(value, typ) and not (typ is int and isinstance(value, bool))
        if not ok:
            raise SettingsError(f"{path} expects {getattr(typ, '__name__', typ)}, got {type(value).__name__}")
        if choices is not None and value not in choices:
            raise SettingsError(f"{path} must be one of {sorted(choices)}")
        _set_path(raw, path, value)
    _cfg.ensure_dirs()
    settings_path().write_text(json.dumps(raw, indent=2))
    return read_settings()


def secret_status() -> dict:
    """Presence + source of provider keys — NEVER the value (SPEC §1)."""
    def status(env_var: str, getter) -> dict:
        present = bool(getter())
        source = "env" if os.environ.get(env_var) else ("config.toml" if present else None)
        return {"present": present, "source": source}

    return {
        "anthropic_api_key": status("ANTHROPIC_API_KEY", _cfg.get_anthropic_api_key),
        "hexgraph_api_key": status("HEXGRAPH_API_KEY", _cfg.get_hexgraph_api_key),
    }


def feature_availability() -> dict:
    """What optional integrations can actually run right now (best-effort probes)."""
    from hexgraph.sandbox.runner import docker_available

    g = resolved()["features"]["ghidra"]
    bridge_installed = False
    try:
        import ghidra_bridge  # noqa: F401

        bridge_installed = True
    except Exception:  # noqa: BLE001
        pass
    return {
        "docker": docker_available(),
        "ghidra": {
            "enabled": g["enabled"],
            "mode": g["mode"],
            "bridge_client_installed": bridge_installed,
        },
    }


def read_settings() -> dict:
    """Full redacted view for the API/UI: resolved non-secret settings + secret
    presence status + live feature availability."""
    return {
        "settings": resolved(),
        "secrets": secret_status(),
        "availability": feature_availability(),
        "paths": {"config_toml": str(_cfg.config_path()), "settings_json": str(settings_path())},
    }
