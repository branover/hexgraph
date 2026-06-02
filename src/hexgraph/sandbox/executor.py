"""The Executor seam (v2 P0-2).

All sandboxed work goes through an `Executor`. Implementations: `LocalDockerExecutor`
(the existing `SandboxRunner`) and — as of Phase 6 — `RemoteDockerExecutor`, which runs
the SAME hardened containers on a user-owned remote Docker host over `DOCKER_HOST`
(ssh:// or tcp:// + TLS), so building/fuzzing run on beefier hardware with NO
fuzzer/builder code change (design §5.8b; gated by features.fuzz_remote, normally
selected per-campaign via a registered fuzz environment). This seam is also where a
future k8s/job executor or a `DynamicExecutor` drops in **without touching task code**.
Selection is via `HEXGRAPH_EXECUTOR` (default `local_docker`) or per-campaign.

Rule: engine/task code calls `get_executor()`; it never names a concrete class.
"""

from __future__ import annotations

import os
from typing import Protocol, runtime_checkable

from hexgraph.sandbox.runner import DetachedHandle, RunResult, SandboxRunner


@runtime_checkable
class Executor(Protocol):
    def run_probe(self, probe, artifact, *, outdir=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, allow_network=False, net_container=None, secret=None, resources=None) -> RunResult: ...
    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, allow_network=False, resources=None) -> dict: ...
    # Dynamic-surface verb: run a probe that talks to a live Channel (no artifact file
    # mounted) — bounded egress when the policy permits. (docs/design-dynamic-surfaces.md)
    # `secret` carries sensitive channel fields (e.g. SSH/telnet creds) out-of-band via env,
    # never on the argv; `net_container` joins an emulator's netns for a rehosted device.
    def run_channel_probe(self, probe, *, channel, outdir=None, extra_args=None, net_container=None, secret=None) -> dict: ...
    # Long-lived campaign verbs (design §5.5): launch a DETACHED container for a
    # multi-hour fuzz campaign, poll its status, and stop it. The reaper (a periodic
    # worker job) re-attaches by the durable handle name across a serve restart, so a
    # campaign survives process restarts. A future RemoteExecutor implements the same
    # verbs over DOCKER_HOST. `resources` carries the per-campaign ResourceSpec ceilings.
    # `allow_network`/`net_container` opt a NETWORK-FUZZ campaign (boofuzz) onto the
    # bounded-egress path — the single place a detached campaign relaxes --network none
    # (policy-checked here; the engine already asserted egress + audited the EgressEvent).
    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, resources=None, allow_network=False, net_container=None) -> DetachedHandle: ...
    def poll_detached(self, name) -> dict: ...
    def stop_detached(self, name, *, remove=True, timeout=10) -> None: ...


# The local Docker sandbox is the v1 executor. Alias keeps a forward-looking name
# while reusing the proven implementation.
LocalDockerExecutor = SandboxRunner

DEFAULT_EXECUTOR = "local_docker"


def get_executor(name: str | None = None) -> Executor:
    name = (name or os.environ.get("HEXGRAPH_EXECUTOR") or DEFAULT_EXECUTOR).lower()
    if name in ("local_docker", "local", "docker"):
        return LocalDockerExecutor()
    if name in ("remote_docker", "remote"):
        # A user-owned remote Docker host via DOCKER_HOST (design §5.8b, Phase 6). Gated
        # by features.fuzz_remote and normally selected PER-CAMPAIGN via a registered fuzz
        # environment (engine.fuzz_env.get_campaign_executor); this env override is for a
        # blanket remote executor (e.g. HEXGRAPH_EXECUTOR=remote_docker + the ambient
        # DOCKER_HOST). The SAME sandbox boundary applies on the remote.
        from hexgraph.sandbox.remote_executor import RemoteDockerExecutor
        dh = os.environ.get("DOCKER_HOST")
        if not dh:
            raise ValueError("HEXGRAPH_EXECUTOR=remote_docker requires DOCKER_HOST to be set")
        return RemoteDockerExecutor(dh)
    # Future: "k8s" (a real RemoteExecutor / job executor), "dynamic" (policy-gated).
    raise ValueError(f"unknown executor {name!r}; expected 'local_docker' or 'remote_docker'")
