"""`just demo` runs the offline loop (ingest → build → fuzz → verify → graph →
spawn) and exits 0 — the narrated smoke test. Docker-gated (the recon/unpack stage
needs the base sandbox image); the build/fuzz/poc stages are offline mock seams."""

import os


def test_demo_main_exits_zero(sandbox):
    from hexgraph import demo
    from hexgraph.db.session import reset_engine_for_tests

    # The demo mutates env to drive the offline mock seams; it MUST restore it so calling
    # main() in-process (here, in the full suite) leaks nothing onto later tests — a leaked
    # HEXGRAPH_FUZZER/_BUILDER=mock would silently steer real-toolchain tests onto the mock.
    keys = ("HEXGRAPH_HOME", "HEXGRAPH_LLM_BACKEND", "HEXGRAPH_BUILDER", "HEXGRAPH_FUZZER")
    before = {k: os.environ.get(k) for k in keys}
    try:
        assert demo.main() == 0
        assert {k: os.environ.get(k) for k in keys} == before, "demo leaked env into the caller"
    finally:
        reset_engine_for_tests()
