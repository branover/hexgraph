"""LibFuzzerFuzzer — the existing libFuzzer path, behind the Fuzzer seam.

This is a STRICT SUPERSET of today's `execute_fuzzing` (Phase 0): it resolves the
same harness / target-sources / target-lib / seeds and builds the SAME `fuzz_probe.py`
invocation, so the single-pass libFuzzer behaviour is unchanged (regression-tested).
The only new thing is that `prepare()` returns the launch description instead of
running the probe inline — the campaign engine runs it (detached or one-shot).
"""

from __future__ import annotations

import os
import tempfile

from hexgraph.engine.fuzzers.base import FuzzCampaignSpec, Fuzzer, PreparedFuzz
from hexgraph.engine.fuzzers.shared import fuzz_image, target_source_mounts


class LibFuzzerFuzzer(Fuzzer):
    name = "libfuzzer"
    surfaces = ("source_lib", "file_format")

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        if not spec.harness_source:
            raise ValueError("no fuzz harness available — run a harness_generation task first")

        # Write the harness to a temp .c the runner mounts at /artifact (ro). This
        # mirrors execute_fuzzing exactly. The campaign engine owns cleanup.
        fd, src_path = tempfile.mkstemp(suffix=".c", prefix="hexgraph-harness-")
        with os.fdopen(fd, "w") as fh:
            fh.write(spec.harness_source)

        extra_args = [
            f"--max-total-time={spec.max_total_time}",
            f"--max-len={spec.max_len}",
            f"--max-crashes={spec.max_crashes}",
        ]
        mounts: list[tuple[str, str]] = []

        # Prefer COVERAGE-GUIDED fuzzing (target source present → SanCov+ASan in the
        # target's own objects); else fall back to linking a prebuilt (uninstrumented)
        # .so — a coverage-blind run reported honestly. IDENTICAL to execute_fuzzing.
        coverage_instrumented = False
        if spec.target_sources:
            # Mount each source's directory (preserving layout) so a self-including header
            # compiles, and add each dir to the include path (battle-test L).
            src_mounts, guest_sources, include_dirs = target_source_mounts(spec.target_sources)
            mounts.extend(src_mounts)
            for guest in guest_sources:
                extra_args.append(f"--target-source={guest}")
            for inc in include_dirs:
                extra_args.append(f"--include-dir={inc}")
            coverage_instrumented = bool(guest_sources)
        elif spec.target_lib and os.path.isfile(spec.target_lib):
            mounts.append((spec.target_lib, "/target.so"))
            extra_args.append("--target-lib=/target.so")

        for i, s in enumerate(spec.seeds):
            if s and os.path.isfile(s):
                mounts.append((s, f"/seeds/seed_{i}"))
                extra_args.append(f"--seed=/seeds/seed_{i}")

        return PreparedFuzz(
            probe="fuzz_probe.py", image=fuzz_image(), artifact=src_path,
            extra_args=extra_args, extra_ro_mounts=mounts,
            coverage_instrumented=coverage_instrumented, engine="libfuzzer",
        )
