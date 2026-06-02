"""The `Fuzzer` seam (design §2.2, Phase 3).

The seam dispatches on **attack surface**, not engine identity (the seam rule):
`get_fuzzer(surface, engine=None)` picks the right SOTA engine for the surface; an
explicit `engine` override is validated against the surface (fail-closed on a
nonsensical pairing). Feature/campaign code calls the seam and NEVER writes
`if engine == "afl"`.

A fuzzer's job is bounded and pure-ish: `prepare(spec, project, target)` resolves
the harness/target-sources/seeds/dictionary and returns a `PreparedFuzz` describing
HOW to launch the fuzz probe in the sandbox (probe name + image + extra_args +
read-only mounts). The campaign engine (`engine/campaigns.py`) then launches it as a
DETACHED container (`Executor.start_detached`) and a periodic reaper ingests the
streamed artifacts/stats — so a multi-hour campaign never pins a worker thread.

This module is import-light (no heavy deps) so the seam + MockFuzzer drive the
offline tests at $0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

# The attack surfaces (design §2.3). Phase 3 shipped source_lib (the coverage-guided
# headline); Phase 5 wires binary_only (AFL++ qemu-mode/frida) + network (boofuzz /
# desock+AFL++) behind the same seam, so each drops in additively.
SURFACES = ("source_lib", "binary_only", "network", "file_format")

# Which engines are valid for each surface (the surface×engine matrix, §2.3). The
# FIRST entry is the default; an explicit override must be in the surface's set.
SURFACE_ENGINES: dict[str, tuple[str, ...]] = {
    # Source present → coverage-guided. AFL++ (afl-clang-lto + CmpLog, persistent mode)
    # is the default; libFuzzer is the alternative (and the back-compat Phase-0 path).
    "source_lib": ("afl", "libfuzzer"),
    # No source → AFL++ qemu-mode (`-Q`, full edge coverage via QEMU TCG) is the DEFAULT
    # and reuses HexGraph's proven qemu-user foreign-arch path (a MIPS/ARM firmware binary
    # under qemu-user + the parent firmware rootfs as the `-L` sysroot). frida-mode is the
    # opt-in alternative (faster on some native x86, weaker cross-arch) — Phase 5.
    "binary_only": ("qemu", "frida"),
    # Live/rehosted/local service or a server binary (Phase 5). boofuzz (generational,
    # spec'd protocol blocks/checksums/a small state graph) is the DEFAULT live-socket
    # fuzzer — pure-Python, joins the emulator netns cleanly, bounded by local_tcp_scope +
    # features.network + every send audited to EgressEvent. `desock` is the static-by-
    # default tier-1 alternative: LD_PRELOAD preeny/desock turns a LOCAL server binary's
    # socket into stdin so AFL++ coverage-fuzzes it with --network none (no real net).
    "network": ("boofuzz", "desock"),
    # Structured input parser — same as source_lib if source is present (the auto-dict +
    # structure-aware hook ride the AFL/libFuzzer path); else binary_only qemu-mode.
    "file_format": ("afl", "libfuzzer", "qemu"),
}


class FuzzerError(RuntimeError):
    """A fuzzer could not be selected/prepared (bad surface×engine pair, no harness…)."""


@dataclass
class FuzzCampaignSpec:
    """The recorded inputs to a campaign (design §4.5/§5.5). Mirrors how a BuildSpec
    records a build: enough to re-run/resume deterministically."""

    target_id: str
    surface: str = "source_lib"
    engine: str | None = None            # None → the surface default
    harness_source: str | None = None    # the harness .c text (resolved by the engine)
    harness_node_id: str | None = None
    function: str | None = None
    target_sources: list[str] = field(default_factory=list)   # host paths (coverage-guided)
    target_lib: str | None = None        # a prebuilt .so (coverage-blind fallback)
    seeds: list[str] = field(default_factory=list)            # host seed-corpus paths
    dictionary: list[str] = field(default_factory=list)       # auto-derived tokens
    max_total_time: int = 60
    max_len: int = 4096
    max_crashes: int = 10
    instances: int = 1                   # AFL++ master + N-1 secondaries (host-cores, capped)
    build_spec_id: str | None = None
    # ── binary_only (qemu/frida) — Phase 5 ──────────────────────────────────────────
    target_binary: str | None = None     # host path to the prebuilt ELF (qemu-mode fuzzes it directly)
    sysroot: str | None = None           # host path: the parent firmware rootfs (qemu `-L` for foreign-arch)
    # ── network (boofuzz/desock) — Phase 5 ──────────────────────────────────────────
    host: str | None = None              # the live device IP (rehosted/local) the protocol fuzzer targets
    port: int | None = None              # the service port
    protocol: str = "tcp"                # tcp | udp (transport for boofuzz)
    proto_spec: dict | None = None       # the boofuzz request/state spec (generational) — see net fuzzers
    net_container: str | None = None     # an emulator container netns to join (rehosted device)
    # ── launch-and-join (the loopback-reachable LOCAL service path) — §5.8b ──────────
    # When HexGraph can LAUNCH the service itself (a `service`/binary target carrying a
    # server ELF) and there is no externally-reachable host, it starts the service in its
    # OWN detached hardened container (listening on that container's loopback) and points
    # the fuzzer at it via `net_container=<service-container>` — the shared netns makes
    # `127.0.0.1:port` reachable WITHOUT --network host, preserving isolation. `launch_binary`
    # is the host path to the server ELF; `launch_command` overrides the in-container argv.
    # `launch` forces the path on; None auto-detects (a launchable local loopback service).
    launch: bool | None = None
    launch_binary: str | None = None          # host path to the server ELF HexGraph launches
    launch_command: list[str] | None = None   # optional argv override (in-container)
    structured: bool = False             # file_format: enable the structure-aware/grammar hook
    # ── remote fuzz environment (Phase 6) — WHERE the container runs ─────────────────
    # The selected fuzz environment id ("local" / None → the host daemon; a remote env →
    # a RemoteDockerExecutor over its secret DOCKER_HOST, gated by features.fuzz_remote).
    # The SAME sandbox boundary applies on the remote — this only changes the compute host.
    environment_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id, "surface": self.surface, "engine": self.engine,
            "harness_node_id": self.harness_node_id, "function": self.function,
            "target_sources": list(self.target_sources), "target_lib": self.target_lib,
            "seeds": list(self.seeds), "dictionary": list(self.dictionary),
            "max_total_time": self.max_total_time, "max_len": self.max_len,
            "max_crashes": self.max_crashes, "instances": self.instances,
            "build_spec_id": self.build_spec_id,
            "target_binary": self.target_binary, "sysroot": self.sysroot,
            "host": self.host, "port": self.port, "protocol": self.protocol,
            "proto_spec": self.proto_spec, "net_container": self.net_container,
            "launch": self.launch, "launch_binary": self.launch_binary,
            "launch_command": list(self.launch_command) if self.launch_command else None,
            "structured": self.structured, "environment_id": self.environment_id,
            # harness_source is bytes, not recorded in config_json (it lives on the
            # managed harness node / parent finding; resolved at prepare time).
        }


@dataclass
class PreparedFuzz:
    """How to launch the fuzz probe in the sandbox for this campaign. The campaign
    engine turns this into a `start_detached` call; the reaper reads the same outdir."""

    probe: str                                   # the probe script to run
    image: str                                   # the dedicated fuzz image (HEXGRAPH_FUZZ_IMAGE)
    artifact: str | None = None                  # the harness/target file mounted at /artifact (ro)
    extra_args: list[str] = field(default_factory=list)
    extra_ro_mounts: list[tuple[str, str]] = field(default_factory=list)
    coverage_instrumented: bool = False
    engine: str = "libfuzzer"
    # ── ASLR-disable for ASan source fuzzing (the ONLY seccomp relaxation) ───────────
    # The AFL++ source path compiles the target with ASan. On high-ASLR-entropy kernels
    # (vm.mmap_rnd_bits=32 — WSL2 6.6.x, Ubuntu 23.10+, GitHub CI runners) ASan's
    # MAP_FIXED shadow reservation intermittently collides with a randomized mapping and
    # the target SIGSEGVs during ASan init, before AFL's forkserver handshake — so afl
    # reports "Fork server crashed with signal 11" / 0 execs. The fix is to run the
    # target with ASLR off (`setarch -R` = personality(ADDR_NO_RANDOMIZE)); that one
    # personality arg is filtered by Docker's default seccomp profile, so a container
    # that sets this flag swaps in a MINIMAL profile (default + that one personality
    # value). It reduces ONLY the target's own address-space randomization — NOT a
    # sandbox-escape primitive; --network none / --cap-drop ALL / --no-new-privileges /
    # --read-only / --user all stay. Only the ASan source fuzzer sets it.
    disable_aslr: bool = False
    # ── Network-fuzz launch (the ONLY place the campaign relaxes --network none) ─────
    # `requires_egress` flips the detached launch onto the bounded-egress path: the
    # campaign engine asserts assert_allows_egress(dest, local_tcp_scope(host,port)) +
    # audits an EgressEvent BEFORE launch, and the container runs with the bridge (or
    # `net_container` to join a rehosted device's netns) instead of --network none. A
    # desock/qemu/source campaign leaves this False — it stays --network none.
    requires_egress: bool = False
    egress_host: str | None = None               # the live device host (for the scope + audit)
    egress_port: int | None = None
    net_container: str | None = None             # join this container's netns (rehosted device)
    # ── launch-and-join (§5.8b): HexGraph LAUNCHES a local loopback service itself ───
    # When set, the campaign engine first starts the server binary in its OWN detached
    # hardened container (executes the target → exec tier), then points the fuzzer at it
    # via `net_container=<that container>` so the shared netns makes 127.0.0.1:port
    # reachable WITHOUT --network host. `launch_binary` is the host path to the server ELF.
    launch_binary: str | None = None             # the server ELF HexGraph launches in a service container
    launch_command: list[str] | None = None      # optional in-container argv override
    launch_sysroot: str | None = None            # foreign-arch firmware rootfs (qemu `-L`)


@runtime_checkable
class Fuzzer(Protocol):
    name: str
    surfaces: tuple[str, ...]

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        """Resolve inputs + return how to launch the probe (no side effects on the
        environment — the campaign engine runs it in the sandbox)."""
        ...
