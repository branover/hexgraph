"""The Executor seam (v2 P0-2).

All sandboxed work goes through an `Executor`. Today the only implementation is
`LocalDockerExecutor` (the existing `SandboxRunner`). This seam is where a future
`RemoteExecutor` (Kubernetes / horizontal scale) or a `DynamicExecutor` (emulated
execution / fuzzing — gated by the analysis policy) drops in **without touching
task code**. Selection is via `HEXGRAPH_EXECUTOR` (default `local_docker`).

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
    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, resources=None) -> DetachedHandle: ...
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
    # Future: "remote"/"k8s" (RemoteExecutor), "dynamic" (DynamicExecutor, policy-gated).
    raise ValueError(f"unknown executor {name!r}; expected 'local_docker'")
