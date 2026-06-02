"""The Fuzzer seam registry (design §2.2).

`get_fuzzer(surface, engine=None)` dispatches on the attack SURFACE (never on engine
identity in task code). An explicit `engine` override is validated against the
surface's allowed set (fail-closed on a nonsensical pair). `HEXGRAPH_FUZZER=mock`
forces the offline MockFuzzer for tests/$0 CI.
"""

from __future__ import annotations

import os

from hexgraph.engine.fuzzers.aflplusplus import AflPlusPlusFuzzer
from hexgraph.engine.fuzzers.base import (
    SURFACE_ENGINES, SURFACES, FuzzCampaignSpec, Fuzzer, FuzzerError, PreparedFuzz,
)
from hexgraph.engine.fuzzers.binary_only import BinaryOnlyFuzzer, FridaFuzzer
from hexgraph.engine.fuzzers.libfuzzer import LibFuzzerFuzzer
from hexgraph.engine.fuzzers.mock import MockFuzzer
from hexgraph.engine.fuzzers.network import BoofuzzFuzzer, DesockAflFuzzer

# Engine name → concrete Fuzzer class. The seam picks by surface; this only maps the
# validated engine choice to its implementation (so adding an engine is one entry).
_ENGINES: dict[str, type[Fuzzer]] = {
    "libfuzzer": LibFuzzerFuzzer,
    "afl": AflPlusPlusFuzzer,
    "qemu": BinaryOnlyFuzzer,      # AFL++ qemu-mode (binary_only default)
    "frida": FridaFuzzer,          # AFL++ frida-mode (binary_only alt)
    "boofuzz": BoofuzzFuzzer,      # generational live-socket protocol fuzzer (network default)
    "desock": DesockAflFuzzer,     # desock+AFL++ coverage-fuzz a local server (network tier 1)
    "mock": MockFuzzer,
}


def resolve_engine(surface: str, engine: str | None = None) -> str:
    """The engine to use for a surface: the explicit override (validated) or the
    surface default. Fail-closed on an unknown surface or a nonsensical surface×engine
    pair (the seam rule's 'fail-closed on a nonsensical pairing')."""
    if surface not in SURFACES:
        raise FuzzerError(f"unknown fuzz surface {surface!r}; expected one of {SURFACES}")
    allowed = SURFACE_ENGINES[surface]
    if engine is None:
        return allowed[0]
    if engine == "mock":
        return "mock"
    if engine not in allowed:
        raise FuzzerError(
            f"engine {engine!r} is not valid for surface {surface!r} "
            f"(allowed: {allowed}) — fail-closed on a nonsensical pairing")
    return engine


def get_fuzzer(surface: str, engine: str | None = None) -> Fuzzer:
    """Select a fuzzer for the attack surface. `HEXGRAPH_FUZZER=mock` forces the
    offline MockFuzzer (tests/$0). Never branch on engine identity in task code — ask
    the seam."""
    forced = os.environ.get("HEXGRAPH_FUZZER")
    if forced == "mock":
        return MockFuzzer()
    name = resolve_engine(surface, engine)
    cls = _ENGINES[name]
    return cls()


__all__ = [
    "get_fuzzer", "resolve_engine", "Fuzzer", "FuzzCampaignSpec", "PreparedFuzz",
    "FuzzerError", "SURFACES", "SURFACE_ENGINES",
]
