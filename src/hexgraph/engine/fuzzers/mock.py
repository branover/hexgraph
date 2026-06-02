"""MockFuzzer — the offline/$0 fuzzer for `just test` (no Docker, no AFL++/libFuzzer).

It produces a deterministic `PreparedFuzz` describing a MOCK launch; the campaign
engine recognizes `probe == "mock_fuzz_probe.py"` and, instead of a detached
container, writes a deterministic crash artifact + stats directly to the outdir (the
same shape the real probes stream). This keeps the WHOLE detached lifecycle — start →
running → reap → finalize, crash-safe re-attach, stop/resume — testable offline.

The crash payload is a function of the harness + config so it is reproducible (the
verify_poc tie-in test re-runs it). A `mock_scenario` in the spec config can request a
clean run (no crash) to test the lifecycle's success path.
"""

from __future__ import annotations

from hexgraph.engine.fuzzers.base import FuzzCampaignSpec, Fuzzer, PreparedFuzz

MOCK_PROBE = "mock_fuzz_probe.py"


class MockFuzzer(Fuzzer):
    name = "mock"
    surfaces = ("source_lib", "binary_only", "network", "file_format")

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        return PreparedFuzz(
            probe=MOCK_PROBE, image="mock", artifact=None,
            extra_args=[f"--max-crashes={spec.max_crashes}",
                        f"--scenario={spec.function or 'crash'}"],
            coverage_instrumented=bool(spec.target_sources),
            engine="mock",
        )
