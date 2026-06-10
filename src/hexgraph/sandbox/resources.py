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

import os
from dataclasses import dataclass, replace

# The shipped per-container defaults (historically hardcoded in sandbox/runner.py).
# These are the FLOOR a normal probe runs under and the DEFAULT a campaign inherits
# unless Settings or the per-campaign override raises them. They mirror the shipped
# `resources.default` in settings.py — change both together (a test asserts they agree).
DEFAULT_MEM = "2g"
DEFAULT_CPUS = 2.0
DEFAULT_PIDS = 256
DEFAULT_TMPFS = "512m"
DEFAULT_TIMEOUT = 300

# F13: a probe's wall-clock budget scales UP for a large artifact so the FIRST whole-binary
# analysis of a 100 MB+ ELF (a monolithic router-firmware service daemon can run well past that)
# isn't killed at the 300 s default before it can finish — the persistent Ghidra project means that first pass is paid
# once and reused, and the same bump lets the strings/recon probe reach the full table instead
# of falling back to the dynsym sample. A normal-size artifact (≤ the threshold) keeps the base
# timeout EXACTLY; the size budget is a pure widening for big inputs, never a narrowing, and is
# bounded by a hard cap so a multi-GB image can't request an unbounded budget. Tunable here only
# (not user-facing) — a user who needs more sets `resources.sandbox.timeout`, which becomes the
# base this scales up from.
SIZE_TIMEOUT_THRESHOLD_BYTES = 32 * 1024 * 1024   # below this, no scaling at all
SIZE_TIMEOUT_SECONDS_PER_MIB = 5                  # added per MiB of artifact above the threshold
SIZE_TIMEOUT_CAP_SECONDS = 3600                   # size-scaling alone never pushes the budget past 1 h

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

    For `"fuzzing"` a USER-SET legacy `features.fuzzing.resources` (the pre-`resources`-
    section location) is folded in as the LOWEST user layer — below `resources.default`
    and `resources.fuzzing` — so an existing settings.json still takes effect, but anything
    the user later sets through the new section (or the UI) cleanly overrides it. (It must be
    lowest: the legacy key was retired from the writable schema, so a higher-precedence live
    overlay could never be cleared and would silently shadow the new config on upgrades.)

    Every layer reads `managed_only` (only keys the user actually wrote, never the shipped
    defaults), so an unset section contributes nothing and the layer below shows through —
    the shipped floor is the base. Fails CLOSED to that floor if Settings is unreadable —
    a settings problem must never silently WIDEN a ceiling."""
    try:
        from hexgraph import settings

        def _set(path: str) -> dict:
            return {k: v for k, v in (settings.managed_only(path) or {}).items() if v is not None}

        merged = ResourceSpec().to_dict()                  # shipped floor
        if container_type == "fuzzing":                    # legacy: lowest user layer
            merged.update(_set("features.fuzzing.resources"))
        merged.update(_set("resources.default"))           # the shared default
        if container_type in CONTAINER_TYPES:              # the per-type override
            merged.update(_set(f"resources.{container_type}"))
        return ResourceSpec.from_dict(merged)
    except Exception:  # noqa: BLE001 — a settings problem must never widen resources
        return ResourceSpec()


def default_resource_spec() -> ResourceSpec:
    """Back-compat alias: the global default a fuzz campaign inherits — now resolved
    through the unified `resources` section (`resources.default` ← `resources.fuzzing`).
    A campaign layers its own per-campaign override on top of this."""
    return resource_spec_for("fuzzing")


def size_scaled_timeout(size_bytes: int | None, base_timeout: int) -> int:
    """The wall-clock budget for a probe over an artifact of `size_bytes`, scaled up from
    `base_timeout` for a large artifact (F13). Returns `base_timeout` UNCHANGED for a small
    or unknown artifact (≤ `SIZE_TIMEOUT_THRESHOLD_BYTES`, or `None`/0), so the normal probe
    path is bit-for-bit untouched. Above the threshold the budget grows linearly
    (`SIZE_TIMEOUT_SECONDS_PER_MIB` per MiB over it), capped at
    `max(base_timeout, SIZE_TIMEOUT_CAP_SECONDS)` — the size bonus is bounded, but a user who
    configured a base above the cap is never shrunk below it. Monotonic in size and never
    below `base_timeout`: scaling can only widen the budget, never narrow it."""
    if not size_bytes or size_bytes <= SIZE_TIMEOUT_THRESHOLD_BYTES:
        return base_timeout
    over_mib = (size_bytes - SIZE_TIMEOUT_THRESHOLD_BYTES) / (1024 * 1024)
    scaled = base_timeout + int(over_mib * SIZE_TIMEOUT_SECONDS_PER_MIB)
    return min(scaled, max(base_timeout, SIZE_TIMEOUT_CAP_SECONDS))


def resource_spec_for_artifact(artifact, container_type: str = "sandbox") -> ResourceSpec:
    """The resolved ResourceSpec for a probe over `artifact`, with a size-aware `timeout` (F13).

    Starts from `resource_spec_for(container_type)` — so a user's `resources.<type>.timeout`
    override is the base/floor this scales up from — and raises ONLY `timeout`, and only when
    `artifact` is a large file (per `size_scaled_timeout`). A small file, a `None` artifact (a
    path-less Channel surface that mounts no bytes), or an unreadable path yields the base spec
    verbatim: the size budget is a pure widening for big inputs and changes nothing else
    (mem/cpu/pids/tmpfs are exactly the configured ceilings). Use this for the analysis probes
    (recon/decompile/strings/binutils/…); the detached fuzz path keeps its own hard-cap timeout."""
    base = resource_spec_for(container_type)
    try:
        size = os.path.getsize(artifact) if artifact is not None else None
    except OSError:
        return base
    scaled = size_scaled_timeout(size, base.timeout)
    if scaled <= base.timeout:
        return base
    return replace(base, timeout=scaled)
