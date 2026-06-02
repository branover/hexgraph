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
            # static-only invariant holds unless a user opts in. Phase 3 makes
            # fuzzing coverage-guided + first-class: AFL++ (afl-clang-lto + CmpLog +
            # persistent mode) on the Phase-2 instrumented derived target, or libFuzzer.
            "enabled": False,
            "max_total_time": 60,        # seconds of actual fuzzing per run
            "max_len": 4096,             # max generated input size (bytes)
            "max_crashes": 10,           # cap on unique-crash findings per run
            "timeout": 300,              # sandbox wall-clock (>= compile + max_total_time)
            # The DEDICATED fuzz image (AFL++/libFuzzer/llvm-symbolizer/afl-cov/gdb +
            # an exploitable-style classifier, design §5.4 D4). NEVER the shared sandbox
            # image; set HEXGRAPH_FUZZ_IMAGE to override (worktree: a private tag).
            "image": "hexgraph-fuzz:latest",
            # The user-tunable ResourceSpec DEFAULT (design §5.8a) — a global default a
            # campaign inherits unless it carries a per-campaign override. `unconstrained`
            # lifts mem/cpu/pids ONLY so a campaign can use the whole machine; it is a
            # RESOURCE knob, NOT a security/policy relaxation (the sandbox security flags
            # — --network none, cap-drop, no-new-privileges, read-only, user — always
            # hold, regardless of the ResourceSpec; ResourceSpec NEVER touches policy.py).
            "resources": {
                "mem": "2g", "cpus": 2.0, "pids": 256, "tmpfs": "512m",
                "timeout": 300, "unconstrained": False,
            },
        },
        "poc": {
            # OFF by default. Like fuzzing, enabling this relaxes the static-only
            # policy to allow execution — but only to run an attacker-style PoC
            # against the target IN THE SANDBOX (--network none, capped, timed,
            # disposable) and verify it via an unforgeable nonce oracle.
            "enabled": False,
            "timeout": 20,
        },
        "build": {
            # OFF by default. Enabling this turns on the build gate (D5): HexGraph
            # may compile a managed SOURCE tree into an instrumented artifact inside
            # the sandbox (the Builder seam) via a recorded, reproducible recipe.
            # Building runs untrusted third-party code (configure/make), so it has its
            # OWN policy gate — separate from executing the TARGET (which still needs
            # features.fuzzing/poc). VENDORED/OFFLINE ONLY this phase: the build phase
            # runs --network none (the audited fetch tier is a later phase). The
            # dedicated `hexgraph-build` image carries clang/LLVM + sanitizers + SanCov
            # + AFL++ compilers; set HEXGRAPH_BUILD_IMAGE to override the tag.
            "enabled": False,
            "image": "hexgraph-build:latest",
            "timeout": 1800,            # build wall-clock budget (s)
        },
        "mcp": {
            # Which `hexgraph mcp` tool groups are exposed to a connected coding
            # agent. Trim these so the agent's tool list (its context) stays small
            # when you only want part of HexGraph (e.g. write-only to populate the
            # graph from a UI-driven session). read=inspect, write=graph/findings,
            # run=execute sandboxed tasks.
            "read": True,
            "write": True,
            "run": True,
        },
        "agent": {
            # Delegate a task to a coding agent from the UI (HexGraph launches the
            # agent CLI headless, wired to the MCP server + skill, restricted to
            # HexGraph tools). OFF by default. Register the server first with
            # `hexgraph mcp install`.
            "enabled": False,
            "cli": "claude",            # claude | codex | gemini
            "binary": "",               # override the executable name/path (optional)
            "timeout": 900,
        },
        "network": {
            # OFF by default. Enabling this relaxes --network none for the
            # bounded-egress LOCAL-network tier: a sandboxed probe may reach a
            # web-surface target, but ONLY a loopback/private destination on a
            # per-target deny-all-but-this allowlist, and every outbound action is
            # audited (EgressEvent). External/public hosts require the deferred,
            # separately-gated live-remote tier. (docs/design-dynamic-surfaces.md)
            "enabled": False,
            "timeout": 30,
        },
        "rehost": {
            # OFF by default. Enabling this permits FULL-SYSTEM emulation of a
            # firmware image (boot its kernel + userland + web server under
            # qemu-system via FirmAE) so its live web surface can be assessed. The
            # strongest execution capability, so it has its own gate. Assessing the
            # booted device still needs features.network (it's a private-IP surface).
            # (docs/design-rehosting.md)
            "enabled": False,
            "image": "hexgraph-firmae:latest",      # FirmAE image (vendor firmware blobs)
            "qemu_image": "hexgraph-qemu:latest",    # qemu+KVM image (full-OS disk images)
            # Boot wall-clock budget. FirmAE on a MIPS/ARM vendor image needs an extract +
            # an initial boot + a 360s network-inference pass; ~525s observed on real DVRF,
            # so the marginal 600s default is bumped to 900s. (qemu disk images boot in ~60s
            # and return as soon as the web port answers, so this never penalizes them.)
            "timeout": 900,
        },
        "remote": {
            # OFF by default. The LIVE-REMOTE tier: connect to ONE operator-authorized device
            # over SSH/telnet (a physical box on the bench, a rehosted device) and run the
            # SAME read-only analysis we'd run on a static/rehosted image — enumerate the
            # filesystem, read files, run a fixed allowlist of recon tools. Egress is pinned
            # to that host (remote_scope) + audited. Credentials are SECRETS: never stored in
            # the DB — read at connect from env (HEXGRAPH_REMOTE_PASSWORD / HEXGRAPH_REMOTE_KEY)
            # or config.toml [remote]. (docs/design-rehosting.md / vr-feedback.md)
            "enabled": False,
            "timeout": 30,
            "max_file_bytes": 262144,   # cap on a remote read_file (256 KiB)
        },
        "fuzz_remote": {
            # OFF by default. Run a fuzz CAMPAIGN on a user-owned REMOTE Docker host
            # (design §5.8b) — beefier/unconstrained compute. A registered "fuzz
            # environment" (the fuzz_environment table) points at the remote via
            # DOCKER_HOST (ssh:// over an SSH control socket, or tcp:// + TLS certs);
            # because the Builder/Fuzzer call the Executor seam, building + fuzzing run on
            # the remote with NO code change. The SAME sandbox boundary applies there
            # (--network none except the gated net-fuzz tier, cap-drop, no-new-privileges,
            # read-only, user, resource caps) — a host the user chose is not a weaker box,
            # and the control plane (API/UI) stays bound to 127.0.0.1. Connection details
            # are SECRETS: read from env (HEXGRAPH_FUZZ_REMOTE_<ID>_DOCKER_HOST) or
            # config.toml [fuzz_remote.<id>], NEVER stored in the DB or logged, reported
            # presence-only. This is the ONLY gate for remote campaigns
            # (policy.assert_allows_fuzz_remote, fail-closed). Register + health-check
            # environments in Settings; a campaign selects one (defaulting `local`).
            "enabled": False,
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
    "features.fuzzing.image": (str, None),
    # The user-tunable ResourceSpec default (design §5.8a). `unconstrained` lifts
    # mem/cpu/pids ONLY — never a security/policy relaxation (see DEFAULTS comment).
    "features.fuzzing.resources.mem": (str, None),
    "features.fuzzing.resources.cpus": ((int, float), None),
    "features.fuzzing.resources.pids": (int, None),
    "features.fuzzing.resources.tmpfs": (str, None),
    "features.fuzzing.resources.timeout": (int, None),
    "features.fuzzing.resources.unconstrained": (bool, None),
    "features.poc.enabled": (bool, None),
    "features.poc.timeout": (int, None),
    "features.build.enabled": (bool, None),
    "features.build.image": (str, None),
    "features.build.timeout": (int, None),
    "features.mcp.read": (bool, None),
    "features.mcp.write": (bool, None),
    "features.mcp.run": (bool, None),
    "features.agent.enabled": (bool, None),
    "features.agent.cli": (str, {"claude", "codex", "gemini"}),
    "features.agent.binary": (str, None),
    "features.agent.timeout": (int, None),
    "features.network.enabled": (bool, None),
    "features.network.timeout": (int, None),
    "features.rehost.enabled": (bool, None),
    "features.rehost.image": (str, None),
    "features.rehost.qemu_image": (str, None),
    "features.rehost.timeout": (int, None),
    "features.remote.enabled": (bool, None),
    "features.remote.timeout": (int, None),
    "features.remote.max_file_bytes": (int, None),
    # Remote fuzz environments (design §5.8b, Phase 6). The toggle is the ONLY policy
    # gate; the environments themselves (non-secret metadata) live in the
    # fuzz_environment table, their secret connections in env/config.toml.
    "features.fuzz_remote.enabled": (bool, None),
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
