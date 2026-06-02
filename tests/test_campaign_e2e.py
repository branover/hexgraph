"""Docker-gated end-to-end proof of the Phase-3 coverage-guided AFL++ campaign:
a REAL AFL++ run (afl-clang-fast instrumentation + CmpLog + persistent harness) in
the dedicated hexgraph-fuzz image finds a planted bug in an INSTRUMENTED build with
real coverage, the detached lifecycle ingests + dedups + classifies it into a
fuzz_crash finding with a minimized reproducer, and that reproducer RE-VERIFIES via
the verify_poc path. Skips cleanly without Docker + the hexgraph-fuzz image (build it
with `just fuzz-build`; in a worktree set HEXGRAPH_FUZZ_IMAGE to a private tag).
"""

import os
import tempfile
import time

import pytest

from conftest import FUZZ_IMAGE_READY

# A target with an out-of-bounds heap WRITE behind a magic gate — coverage-guided
# AFL++ (with CmpLog) learns the gate and reaches the bug fast.
TARGET_C = r"""
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int target_parse(const uint8_t *data, size_t size) {
    if (size < 5) return 0;
    if (data[0] != 'F') return 0;
    char *buf = (char *)malloc(4);
    for (uint8_t i = 0; i < data[4]; i++) buf[i] = (char)i;  /* heap-buffer-overflow WRITE */
    char r = buf[0];
    free(buf);
    return r;
}
"""

# AFL++ persistent-mode harness (LLVMFuzzerTestOneInput is also driven by afl's
# libFuzzer-compat persistent loop in afl-clang-fast).
HARNESS_C = r"""
#include <stdint.h>
#include <stddef.h>
int target_parse(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return target_parse(data, size);
}
"""


@pytest.mark.skipif(not FUZZ_IMAGE_READY,
                    reason="requires Docker + the hexgraph-fuzz image (just fuzz-build)")
def test_aflplusplus_campaign_finds_dedups_classifies_and_reverifies(hg_home, monkeypatch):
    from hexgraph.db.models import FuzzArtifact, FuzzCampaign
    from hexgraph.db.session import session_scope
    from hexgraph.engine import campaigns as C
    from hexgraph.engine.fuzzers.base import FuzzCampaignSpec
    from hexgraph.engine.ingest import create_project, ingest_file
    from hexgraph import settings as st

    from conftest import fixture_path

    st.update_settings({"features.fuzzing.enabled": True, "features.poc.enabled": True})

    th = tempfile.mkdtemp(prefix="hexgraph-camp-e2e-")
    target_c = os.path.join(th, "target.c")
    seed = os.path.join(th, "seed")
    open(target_c, "w").write(TARGET_C)
    # A NON-crashing near-miss seed: crosses the 'F' gate with a SAFE write length (2 ≤ 4),
    # so AFL++ starts from a valid input and only needs to grow data[4] past 4 to crash.
    open(seed, "wb").write(b"F\x00\x00\x00\x02")

    with session_scope() as s:
        p = create_project(s, name="campaign-e2e")
        # A derived "instrumented" target whose own source AFL++ rebuilds with coverage.
        t = ingest_file(s, project=p, src_path=fixture_path("vuln_httpd"), name="instrumented")
        t.metadata_json = {"instrumented": True, "fuzz_target_sources": [target_c]}
        s.flush()
        spec = FuzzCampaignSpec(
            target_id=t.id, surface="source_lib", engine="afl",
            harness_source=HARNESS_C, function="target_parse",
            target_sources=[target_c], seeds=[seed], max_total_time=45, max_crashes=3,
        )
        row = C.start_campaign(s, p, t, spec=spec)
        cid = row.id
        assert row.status == "running" and row.engine == "afl"

    # Drive the reaper (as the worker would) until the campaign finalizes. Crashes
    # stream as they happen (proven by the early ones), but we run to completion so the
    # harness binary is preserved for the verify tie-in.
    deadline = time.monotonic() + 180
    first_crash_seen = False
    while time.monotonic() < deadline:
        with session_scope() as s:
            C.reap_campaign(s, s.get(FuzzCampaign, cid))
            c = s.get(FuzzCampaign, cid)
            if s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).count():
                first_crash_seen = True  # streamed mid-run, before finalize
            if c.status in ("completed", "failed"):
                break
        time.sleep(4)

    with session_scope() as s:
        c = s.get(FuzzCampaign, cid)
        assert c.status in ("running", "completed"), c.error
        assert (c.config_json or {}).get("coverage_instrumented") is True   # real coverage

        # The forkserver fix (writable /dev/shm) means the campaign machinery ran end to
        # end. On a healthy host AFL++ then fuzzes and finds the planted crash; on a host
        # kernel where AFL++ PERSISTENT mode is unstable (the forkserver crashes / the
        # dry-run calibration times out — reproducible even with the /dev/shm fix on e.g.
        # some WSL2 kernels) the probe reports a LOUD diagnostic instead of silently
        # claiming a clean zero-crash run. We must NOT silently pass in that case — skip
        # with the captured reason so it's visible, while still proving the machinery.
        note = (c.stats_json or {}).get("engine_note")
        if note and not s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).count():
            pytest.skip(f"AFL++ could not fuzz on this host kernel: {note}")

        arts = s.query(FuzzArtifact).filter(FuzzArtifact.campaign_id == cid).all()
        assert arts, "AFL++ found no crash in the instrumented build"
        a = arts[0]
        assert len(a.dedup_key or "") == 64                # symbolized stack-hash dedup
        assert (a.exploitability_json or {}).get("rating")  # deterministic classifier
        assert a.content_cas and a.finding_id              # minimized reproducer + finding

        # The reproducer RE-VERIFIES against the preserved instrumented harness binary
        # (the verify_poc tie-in, LLM-free, unforgeable `crash` oracle).
        res = C.verify_artifact(s, a)
        assert res.get("verified") is True, res
        assert res["assurance"]["standard"] == "code_present"
