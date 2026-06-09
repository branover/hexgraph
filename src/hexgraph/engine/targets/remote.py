"""Remote live-device targets (SSH/telnet) — the live-remote tier (docs/dynamic-surfaces-rehosting-remote.md).

When you have a PHYSICAL box on the bench (or a rehosted device) but not its firmware, point
HexGraph at it over SSH/telnet and run the SAME read-only analysis we'd run on a static or
rehosted image — enumerate the filesystem, read files, run a fixed allowlist of recon tools —
recording everything into the graph. Opt-in (`features.remote` → `policy.assert_allows_remote`),
egress pinned to the one operator-authorized host (`remote_scope`) and audited (`EgressEvent`).

Credentials are SECRETS: never stored in the DB or returned. They're read at connect time
from env (`HEXGRAPH_REMOTE_PASSWORD` / `HEXGRAPH_REMOTE_KEY`) or `config.toml [remote]`. The
target only records the non-secret channel (transport/host/port/username).
"""

from __future__ import annotations

import os

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, Target, TargetKind


def _channel(target: Target) -> dict:
    return (target.metadata_json or {}).get("channel") or {}


def register_remote_target(session: Session, project: Project, host: str, *, port: int | None = None,
                           username: str = "root", transport: str = "ssh",
                           name: str | None = None, parent: Target | None = None,
                           net_container: str | None = None) -> Target:
    """Register a live remote device as a `remote` Target (no bytes; reached via an SSH/telnet
    Channel). Credentials are NOT taken here — they're read from env/config at connect time.

    `parent` makes it a child of (e.g.) a rehosted firmware; `net_container` pins the probe to
    that emulator's network namespace (a rehosted device's SSH/telnet lives on a private IP
    reachable only inside the FirmAE container) instead of the default bridge."""
    transport = (transport or "ssh").lower()
    if transport not in ("ssh", "telnet"):
        raise ValueError("transport must be 'ssh' or 'telnet'")
    if not (host or "").strip():
        raise ValueError("a remote target needs a host")
    port = int(port or (22 if transport == "ssh" else 23))
    channel = {"kind": transport, "host": host, "port": port,
               "username": username, "transport": transport}
    if net_container:
        channel["net_container"] = net_container
    target = Target(
        project_id=project.id, parent_id=parent.id if parent else None,
        name=name or f"{username}@{host}:{port} ({transport})",
        path="", kind=TargetKind.remote,
        metadata_json={"channel": channel},
    )
    session.add(target)
    session.flush()
    return target


def _remote_secret() -> dict:
    """SSH/telnet credentials, from env first then config.toml [remote]. Never stored/returned."""
    from hexgraph.config import _load_toml

    out: dict = {}
    if os.environ.get("HEXGRAPH_REMOTE_PASSWORD"):
        out["password"] = os.environ["HEXGRAPH_REMOTE_PASSWORD"]
    if os.environ.get("HEXGRAPH_REMOTE_KEY"):
        out["key"] = os.environ["HEXGRAPH_REMOTE_KEY"]
    if not out:
        cfg = (_load_toml() or {}).get("remote", {})
        if cfg.get("password"):
            out["password"] = cfg["password"]
        if cfg.get("key_path"):
            try:
                with open(os.path.expanduser(cfg["key_path"])) as fh:
                    out["key"] = fh.read()
            except OSError:
                pass
    return out


def run_remote(session: Session, project: Project, target: Target, *, op: str,
               path: str | None = None, tool: str | None = None, args: list | None = None,
               max_bytes: int | None = None, runner=None, task_id=None) -> dict:
    """Run ONE bounded op against the remote device in the sandbox: read-only
    list_files / read_file / run_tool, or the bounded non-read-only `launch` (start a
    not-auto-started service by binary path + args, so its socket can be tested live). Gated by
    features.remote, egress pinned to the target's host:port and audited. Each op maps to a
    fixed command template in remote_probe (no arbitrary shell)."""
    from hexgraph import settings
    from hexgraph.engine.audit import record_egress
    from hexgraph.policy import (PolicyViolation, assert_allows_egress, assert_allows_remote,
                                 current_policy, remote_scope)
    from hexgraph.sandbox.executor import get_executor

    ch = _channel(target)
    host, port = ch.get("host"), int(ch.get("port") or 22)
    if not host:
        raise ValueError("target has no remote channel (host)")

    assert_allows_remote()                       # opt-in: features.remote (live-remote tier)
    scope = remote_scope(host, port)
    dest = next(iter(scope.allow))
    try:
        assert_allows_egress(dest, scope, current_policy())
    except PolicyViolation:
        record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                      dest=dest, allowed=False, tool=f"remote:{op}",
                      detail="blocked: remote access not permitted by policy", durable=True)
        raise
    record_egress(session, project_id=project.id, target_id=target.id, task_id=task_id,
                  dest=dest, allowed=True, tool=f"remote:{op}", detail=scope.rationale)

    runner = runner or get_executor()
    timeout = int(settings.get("features.remote.timeout", 30) or 30)
    cap = int(max_bytes or settings.get("features.remote.max_file_bytes", 262144) or 262144)
    # NON-secret connection descriptor → goes in `--channel` (and thus the docker argv).
    channel = {"transport": ch.get("transport", "ssh"), "host": host, "port": port,
               "username": ch.get("username", "root"), "timeout": timeout,
               "allow": sorted(scope.allow), "op": op, "path": path, "tool": tool,
               "args": args or [], "max_bytes": cap}
    # Credentials (password/key) are delivered out-of-band via HG_CHANNEL_SECRET (env var,
    # not argv) so they can't leak through `ps`/`/proc/<pid>/cmdline`. The probe merges them.
    secret = _remote_secret() or None
    # net_container: a rehosted device's SSH/telnet lives in the emulator's netns (set on the
    # channel when the remote target was derived from a rehost); a physical box uses the bridge.
    net_container = ch.get("net_container")
    result = runner.run_channel_probe("remote_probe.py", channel=channel,
                                      net_container=net_container, secret=secret)
    result.pop("password", None); result.pop("key", None)  # never echo secrets back
    return result
