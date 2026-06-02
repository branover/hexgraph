"""The user-tunable `ResourceSpec` (design §5.8a, Phase 3).

Fuzzing is the one genuinely resource-hungry workload in HexGraph, so the user
must be able to lift the per-container resource ceilings on their own box. A
`ResourceSpec` carries `{mem, cpus, pids, tmpfs, timeout, unconstrained}` — defaulted
from Settings (a global default) with a per-campaign override — and is threaded into
the docker flags by the `Executor`.

**CRUCIAL — this is NOT a policy/gate relaxation.** The policy seam (`policy.py`)
governs *what the sandbox may do* (execute / reach the network / rehost / remote);
resource ceilings are orthogonal. `unconstrained=True` drops ONLY the
`--memory`/`--cpus`/`--pids-limit` flags (and raises the wall-clock/disk ceilings) so
a campaign can use the whole machine — it NEVER touches `--network none` (except the
already-gated net-fuzz tier), `--cap-drop ALL`, `--no-new-privileges`, `--read-only`,
or `--user`. A bigger or busier box is not a weaker box. `ResourceSpec` therefore lives
in Settings/the spec, NEVER in `policy.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

# The shipped per-container defaults (historically hardcoded in sandbox/runner.py).
# These are the FLOOR a normal probe runs under and the DEFAULT a campaign inherits
# unless Settings or the per-campaign override raises them.
DEFAULT_MEM = "2g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS = 256
DEFAULT_TMPFS = "512m"
DEFAULT_TIMEOUT = 300


@dataclass(frozen=True)
class ResourceSpec:
    """Per-container resource ceilings. `unconstrained` lifts mem/cpu/pids ONLY (a
    resource decision, never a security one — see the module docstring)."""

    mem: str = DEFAULT_MEM            # docker --memory (e.g. "2g", "8g")
    cpus: float = DEFAULT_CPUS        # docker --cpus
    pids: int = DEFAULT_PIDS          # docker --pids-limit
    tmpfs: str = DEFAULT_TMPFS        # size of the /scratch + /tmp tmpfs mounts
    timeout: int = DEFAULT_TIMEOUT    # wall-clock budget (s); a detached campaign uses it as a HARD cap
    unconstrained: bool = False       # drop mem/cpu/pids ceilings (resource only — NEVER a gate)

    def docker_resource_args(self) -> list[str]:
        """The docker resource flags for this spec. Under `unconstrained` we emit
        NONE of `--memory`/`--cpus`/`--pids-limit` so the container can use the whole
        host. The SECURITY flags are added by the runner unconditionally and are NOT
        part of this list — they hold regardless of the ResourceSpec."""
        if self.unconstrained:
            return []
        return [
            "--memory", str(self.mem),
            "--cpus", str(self.cpus),
            "--pids-limit", str(int(self.pids)),
        ]

    def tmpfs_arg(self) -> str:
        """The tmpfs size token (e.g. '512m'). Under `unconstrained` the tmpfs is
        widened so a coverage corpus/compile scratch doesn't hit the default ceiling."""
        return "2g" if self.unconstrained else str(self.tmpfs)

    def to_dict(self) -> dict:
        return {
            "mem": self.mem, "cpus": self.cpus, "pids": self.pids, "tmpfs": self.tmpfs,
            "timeout": int(self.timeout), "unconstrained": bool(self.unconstrained),
        }

    @classmethod
    def from_dict(cls, d: dict | None) -> "ResourceSpec":
        d = d or {}
        return cls(
            mem=str(d.get("mem", DEFAULT_MEM)),
            cpus=float(d.get("cpus", DEFAULT_CPUS)),
            pids=int(d.get("pids", DEFAULT_PIDS)),
            tmpfs=str(d.get("tmpfs", DEFAULT_TMPFS)),
            timeout=int(d.get("timeout", DEFAULT_TIMEOUT)),
            unconstrained=bool(d.get("unconstrained", False)),
        )


def default_resource_spec() -> ResourceSpec:
    """The global default ResourceSpec from Settings (`features.fuzzing.resources`),
    falling back to the shipped per-container floor. A campaign inherits this unless
    it carries a per-campaign override."""
    try:
        from hexgraph import settings

        d = settings.get("features.fuzzing.resources") or {}
        return ResourceSpec.from_dict(d)
    except Exception:  # noqa: BLE001 — a settings problem must never widen resources
        return ResourceSpec()
