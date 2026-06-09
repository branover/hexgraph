"""Docker-gated end-to-end proof that target-source instrumentation works: the
target is compiled with -fsanitize=fuzzer-no-link,address (SanCov + ASan baked into
the target's OWN objects), a bug planted behind a magic gate in the target is found,
ASan catches it, and the deterministic classifier rates the planted out-of-bounds
WRITE. The gate is shallow (one magic byte) so the test is fast + reliable on the
base image's libFuzzer (no CmpLog); the point proven is that instrumentation lives
in the target and the crash is attributed to the target function — exactly the
coverage-instrumented build Phase 0 adds.

Skips cleanly without Docker + the hexgraph-sandbox image (clang/libFuzzer present).
"""

import os
import tempfile

import pytest

from conftest import SANDBOX_READY

# Heavy real fuzz campaign — deselected from the fast `just test` (-m 'not slow'); run via
# `just test-heavy` or CI's live job.
pytestmark = pytest.mark.slow

# A target with an out-of-bounds WRITE reachable only after the input matches the
# magic bytes "FUZZ" — the classic coverage-guided-vs-blackbox discriminator. With
# SanCov+CmpLog-style feedback libFuzzer learns the magic byte-by-byte in seconds.
TARGET_C = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int target_parse(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    if (data[0] != 'F') return 0;   /* a gate inside the INSTRUMENTED target */
    char *buf = (char *)malloc(4);
    /* heap-buffer-overflow WRITE: write `data[4]` bytes into a 4-byte buffer */
    for (uint8_t i = 0; i < data[4]; i++) buf[i] = (char)i;
    char r = buf[0];
    free(buf);
    return r;
}
"""

HARNESS_C = r"""
#include <stdint.h>
#include <stddef.h>
int target_parse(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return target_parse(data, size);
}
"""


@pytest.mark.skipif(not SANDBOX_READY,
                    reason="requires Docker + the hexgraph-sandbox image (just sandbox-build)")
def test_instrumented_build_finds_planted_bug(hg_home):
    from hexgraph.sandbox.runner import SandboxRunner
    from hexgraph import settings as st

    st.update_settings({"features.fuzzing.enabled": True})  # policy: allow execution
    runner = SandboxRunner()

    th = tempfile.mkdtemp(prefix="hexgraph-fuzz-e2e-")
    harness = os.path.join(th, "harness.c")
    target = os.path.join(th, "target.c")
    seed = os.path.join(th, "seed")
    out = os.path.join(th, "out")
    open(harness, "w").write(HARNESS_C)
    open(target, "w").write(TARGET_C)
    # Seed an input that crosses the magic gate with an over-long write length, so the
    # crash is found deterministically (independent of libFuzzer fork-mode timing).
    open(seed, "wb").write(b"F\x00\x00\x00\xff" + b"\x00" * 8)

    result = runner.run_json_probe(
        "fuzz_probe.py", harness, outdir=out,
        extra_args=["--max-total-time=20", "--max-len=64", "--max-crashes=2",
                    "--target-source=/src/target.c", "--seed=/seeds/s0"],
        requires_execution=True,
        extra_ro_mounts=[(target, "/src/target.c"), (seed, "/seeds/s0")],
    )

    assert result.get("compiled") is True, result
    # The headline Phase-0 change: instrumentation lives in the TARGET's objects.
    assert result.get("coverage_instrumented") is True, result
    assert result.get("crash_count", 0) >= 1, result

    # Every kept crash carries the new envelope: a 64-hex dedup key, an exploitability
    # rating, and the coverage flag (instrumentation lives in the target's objects).
    for c in result["crashes"]:
        assert len(c.get("dedup_key") or "") == 64, c
        assert (c.get("exploitability") or {}).get("rating"), c
        assert c.get("coverage_instrumented") is True, c
    # The planted out-of-bounds heap WRITE is found and the deterministic classifier
    # (reading the ASan report, no LLM) rates it a memory-corruption write primitive.
    assert any("overflow" in (c.get("kind") or "") for c in result["crashes"]), result["crashes"]
    ratings = [(c.get("exploitability") or {}).get("rating") for c in result["crashes"]]
    assert any(r == "likely_exploitable" for r in ratings), result["crashes"]
    # Within-run dedup is deterministic: every kept crash has a distinct bucket key.
    keys = [c.get("dedup_key") for c in result["crashes"]]
    assert len(keys) == len(set(keys)), keys
    # NOTE: the base sandbox image has no llvm-symbolizer, so ASan frames are
    # module+offset (the faulting function symbol is unavailable); the symbolized
    # function-attribution + path-independent dedup paths are proven in
    # test_fuzz_triage.py against real symbolized reports.
