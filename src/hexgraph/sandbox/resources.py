"""The user-tunable `ResourceSpec` (design §5.8a, Phase 3).

Every container HexGraph spawns runs under a per-container resource ceiling, and the
user must be able to tune those ceilings on their own box (fuzzing especially is
resource-hungry). A `ResourceSpec` carries `{mem, cpus, pids, tmpfs, timeout,
unconstrained}` and is threaded into the docker flags by the `Executor`.

**One shared default, optionally specialized per container type.** The ceilings are
configured under the `resources` settings section: a SHARED `resources.default` that
every container type inherits, plus per-type sections (`resources.sandbox` for the
analysis sandbox, `resources.build` for the build image, `resources.fuzzing` for fuzz
campaigns) that override only the keys they set. Leave the per-type sections empty and
every container shares the same ceilings; set one and that type alone diverges.
`resource_spec_for(<type>)` resolves `default` ← `<type>` into a concrete spec. A fuzz
campaign then layers its own per-campaign override on top of `resources.fuzzing`.

**Memory-derived ceilings follow `mem`, not a second constant.** A few sizes are tied to
the memory limit rather than configured on their own. The `unconstrained` tmpfs size is
DERIVED from `mem` here (`tmpfs_arg`), so raising `mem` widens it in lockstep (it was a
hardcoded `2g` — exactly `mem`'s default). libFuzzer's `-rss_limit_mb` and AFL's per-exec
cap are derived in the probes from the container's LIVE cgroup `--memory` cap (which IS
`mem`), so they track it automatically too. No probe carries its own 2-GB literal as a real
ceiling — the only remaining `2048` is a fallback used solely when no cgroup cap exists.

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
# unless Settings or the per-campaign override raises them. They mirror the shipped
# `resources.default` in settings.py — change both together (a test asserts they agree).
DEFAULT_MEM = "2g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS = 256
DEFAULT_TMPFS = "512m"
DEFAULT_TIMEOUT = 300

# The container types that can carry their own per-type override under `resources.<type>`
# (each inherits `resources.default` for any key it doesn't set). Rehosting containers are
# privileged full-system emulators and are deliberately NOT resource-capped here.
CONTAINER_TYPES = ("sandbox", "build", "fuzzing")


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
        """The tmpfs size token (e.g. '512m'). Under `unconstrained` the tmpfs is widened
        so a coverage corpus / compile scratch doesn't hit the default ceiling — sized to
        the `mem` value (DERIVED, not a separate constant), so raising `mem` widens it too.
        Historically this was a hardcoded '2g', which is exactly `mem`'s 2g default."""
        return str(self.mem) if self.unconstrained else str(self.tmpfs)

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


def resource_spec_for(container_type: str = "default") -> ResourceSpec:
    """The resolved ResourceSpec for a container type, from Settings.

    Merges the shipped floor ← the SHARED `resources.default` ← the per-type
    `resources.<container_type>` override (each layer overriding only the keys it
    sets). So leaving the per-type section empty makes that container share the common
    default; setting a key there diverges that type alone.

    For `"fuzzing"` it ALSO folds in any USER-SET legacy `features.fuzzing.resources`
    (the pre-`resources`-section location) so an existing settings.json keeps working —
    only keys the user actually wrote (`managed_only`, never the old defaults) override,
    so a value moved to `resources.default` still reaches fuzzing.

    Fails CLOSED to the shipped floor if Settings is unreadable — a settings problem
    must never silently WIDEN a ceiling."""
    try:
        from hexgraph import settings

        res = settings.get("resources") or {}
        merged = ResourceSpec().to_dict()
        merged.update({k: v for k, v in (res.get("default") or {}).items() if v is not None})
        if container_type in CONTAINER_TYPES:
            merged.update({k: v for k, v in (res.get(container_type) or {}).items() if v is not None})
        if container_type == "fuzzing":
            legacy = settings.managed_only("features.fuzzing.resources") or {}
            merged.update({k: v for k, v in legacy.items() if v is not None})
        return ResourceSpec.from_dict(merged)
    except Exception:  # noqa: BLE001 — a settings problem must never widen resources
        return ResourceSpec()


def default_resource_spec() -> ResourceSpec:
    """Back-compat alias: the global default a fuzz campaign inherits — now resolved
    through the unified `resources` section (`resources.default` ← `resources.fuzzing`).
    A campaign layers its own per-campaign override on top of this."""
    return resource_spec_for("fuzzing")
