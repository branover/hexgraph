"""AflPlusPlusFuzzer — coverage-guided source fuzzing with AFL++ (design §2.3, Phase 3).

The headline of Phase 3: AFL++ (afl-clang-lto/fast + CmpLog `-c` + persistent mode)
fuzzes the Phase-2 INSTRUMENTED derived target — real coverage feedback from the code
under test, at last (vs. the coverage-blind black-box libFuzzer fallback). The harness
is compiled WITH the target's own sources under `afl-clang-fast` (SanitizerCoverage +
ASan in the target's objects), CmpLog gates magic-byte / `memcmp` comparisons, and a
seed corpus + an auto-dictionary (derived from the target's strings) jump-start it.

The engine resolves inputs + returns the `afl_probe.py` launch description; the
campaign engine runs it DETACHED in continuous mode and the reaper ingests crashes/
coverage from the AFL++ output dir. The model never runs `afl-fuzz` — HexGraph does.
"""

from __future__ import annotations

import json
import os
import tempfile

from hexgraph.engine.fuzzers.base import FuzzCampaignSpec, Fuzzer, PreparedFuzz
from hexgraph.engine.fuzzers.shared import fuzz_image


class AflPlusPlusFuzzer(Fuzzer):
    name = "afl"
    surfaces = ("source_lib", "file_format")

    def prepare(self, spec: FuzzCampaignSpec, project, target) -> PreparedFuzz:
        if not spec.harness_source:
            raise ValueError("no fuzz harness available — run a harness_generation task first")
        if not spec.target_sources:
            # AFL++ source_lib mode rebuilds the TARGET's own objects with afl-clang-fast
            # for real coverage. With no source there's nothing to instrument here — that
            # is the binary_only qemu-mode path (Phase 5), a different surface.
            raise ValueError(
                "AFL++ source fuzzing needs the target's source (the Phase-2 instrumented "
                "derived target); a binary without source takes the qemu-mode path (Phase 5)")

        fd, src_path = tempfile.mkstemp(suffix=".c", prefix="hexgraph-aflharness-")
        with os.fdopen(fd, "w") as fh:
            fh.write(spec.harness_source)

        extra_args = [
            f"--max-total-time={spec.max_total_time}",
            f"--max-crashes={spec.max_crashes}",
            f"--instances={max(1, int(spec.instances))}",
        ]
        mounts: list[tuple[str, str]] = []
        for i, ts in enumerate(spec.target_sources):
            guest = f"/src/target_{i}{os.path.splitext(ts)[1] or '.c'}"
            mounts.append((ts, guest))
            extra_args.append(f"--target-source={guest}")

        for i, s in enumerate(spec.seeds):
            if s and os.path.isfile(s):
                mounts.append((s, f"/seeds/seed_{i}"))
                extra_args.append(f"--seed=/seeds/seed_{i}")

        # Auto-dictionary tokens (magic bytes / keywords) are passed inline (small,
        # bounded). The probe writes them to an AFL++ .dict file inside the sandbox.
        if spec.dictionary:
            extra_args.append("--dict=" + json.dumps(spec.dictionary[:256]))

        return PreparedFuzz(
            probe="afl_probe.py", image=fuzz_image(), artifact=src_path,
            extra_args=extra_args, extra_ro_mounts=mounts,
            coverage_instrumented=True, engine="afl",
        )
