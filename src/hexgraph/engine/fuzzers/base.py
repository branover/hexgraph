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

# The attack surfaces (design §2.3). Phase 3 ships source_lib (the coverage-guided
# headline) — binary_only / network / file_format are wired in later phases but the
# seam already dispatches on them so they drop in additively.
SURFACES = ("source_lib", "binary_only", "network", "file_format")

# Which engines are valid for each surface (the surface×engine matrix, §2.3). The
# FIRST entry is the default; an explicit override must be in the surface's set.
SURFACE_ENGINES: dict[str, tuple[str, ...]] = {
    # Source present → coverage-guided. AFL++ (afl-clang-lto + CmpLog, persistent mode)
    # is the default; libFuzzer is the alternative (and the back-compat Phase-0 path).
    "source_lib": ("afl", "libfuzzer"),
    # No source → AFL++ qemu-mode (Phase 5); libFuzzer can't instrument a prebuilt binary.
    "binary_only": ("afl",),
    # Live/rehosted service (Phase 5).
    "network": ("afl", "boofuzz"),
    # Structured input parser — same as source_lib if source is present.
    "file_format": ("afl", "libfuzzer"),
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

    def to_dict(self) -> dict:
        return {
            "target_id": self.target_id, "surface": self.surface, "engine": self.engine,
            "harness_node_id": self.harness_node_id, "function": self.function,
            "target_sources": list(self.target_sources), "target_lib": self.target_lib,
            "seeds": list(self.seeds), "dictionary": list(self.dictionary),
            "max_total_time": self.max_total_time, "max_len": self.max_len,
            "max_crashes": self.max_crashes, "instances": self.instances,
            "build_spec_id": self.build_spec_id,
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


@runtime_checkable
class Fuzzer(Protocol):
    name: str
    surfaces: tuple[str, ...]

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        """Resolve inputs + return how to launch the probe (no side effects on the
        environment — the campaign engine runs it in the sandbox)."""
        ...
