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

from hexgraph.sandbox.runner import RunResult, SandboxRunner


@runtime_checkable
class Executor(Protocol):
    def run_probe(self, probe, artifact, *, outdir=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, allow_network=False) -> RunResult: ...
    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None, requires_execution=False, extra_ro_mounts=None, allow_network=False) -> dict: ...
    # Dynamic-surface verb: run a probe that talks to a live Channel (no artifact file
    # mounted) — bounded egress when the policy permits. (docs/design-dynamic-surfaces.md)
    def run_channel_probe(self, probe, *, channel, outdir=None, extra_args=None) -> dict: ...


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
