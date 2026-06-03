"""Phase-0 fuzzing improvements — pure-function tests (no Docker).

Covers the three deterministic pieces added to `fuzz_probe.py`:
  - the normalized stack-hash crash dedup (`dedup_key` / `normalized_frames`),
  - the deterministic exploitability classifier (`classify_exploitability`),
plus the engine-side severity merge (`_severity_for`) and target-source resolution.
"""

from hexgraph.sandbox.probes.fuzz_probe import (
    classify_exploitability,
    dedup_key,
    normalized_frames,
    parse_libfuzzer_progress,
    worst_rating,
)
from hexgraph.engine.fuzzing import _severity_for


# ── ASan report fixtures ────────────────────────────────────────────────────────

HEAP_WRITE = """\
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050
WRITE of size 8 at 0x602000000050 thread T0
    #0 0x4a1b2c in parse_header /build/src/httpd.c:142:7
    #1 0x4a0f00 in handle_request /build/src/httpd.c:88:3
    #2 0x4a0a00 in main /build/src/httpd.c:12:5
    #3 0x7f00 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x29d0f)
SUMMARY: AddressSanitizer: heap-buffer-overflow /build/src/httpd.c:142:7 in parse_header
"""

# Same bug, different build path + ASLR addresses + an interceptor frame on top.
HEAP_WRITE_REBUILT = """\
==999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x611000000111
WRITE of size 8 at 0x611000000111 thread T0
    #0 0xdeadbe in __asan_memcpy (/out/fuzzer+0x4a4a4a)
    #1 0x111111 in parse_header /home/ci/work/src/httpd.c:142
    #2 0x222222 in handle_request /home/ci/work/src/httpd.c:88
    #3 0x333333 in main /home/ci/work/src/httpd.c:12
SUMMARY: AddressSanitizer: heap-buffer-overflow in parse_header
"""

HEAP_READ = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000050
READ of size 4 at 0x602000000050 thread T0
    #0 0x4a1b2c in lookup /build/src/db.c:50:7
    #1 0x4a0f00 in query /build/src/db.c:30:3
SUMMARY: AddressSanitizer: heap-buffer-overflow /build/src/db.c:50 in lookup
"""

UAF_WRITE = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000050
WRITE of size 8 at 0x602000000050 thread T0
    #0 0x4a1b2c in set_value /build/src/obj.c:77:7
    #1 0x4a0f00 in update /build/src/obj.c:40:3
SUMMARY: AddressSanitizer: heap-use-after-free /build/src/obj.c:77 in set_value
"""

UAF_READ = """\
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000050
READ of size 4 at 0x602000000050 thread T0
    #0 0x4a1b2c in get_value /build/src/obj.c:60:7
SUMMARY: AddressSanitizer: heap-use-after-free /build/src/obj.c:60 in get_value
"""

DOUBLE_FREE = """\
==1==ERROR: AddressSanitizer: attempting double-free on 0x602000000050
    #0 0x4a1b2c in cleanup /build/src/obj.c:90:7
SUMMARY: AddressSanitizer: double-free /build/src/obj.c:90 in cleanup
"""

SEGV_READ = """\
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x4a1b2c)
The signal is caused by a READ memory access.
    #0 0x4a1b2c in deref /build/src/x.c:5:7
SUMMARY: AddressSanitizer: SEGV /build/src/x.c:5 in deref
"""

SEGV_WRITE = """\
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000001234 (pc 0x4a1b2c)
The signal is caused by a WRITE memory access.
    #0 0x4a1b2c in store /build/src/x.c:9:7
SUMMARY: AddressSanitizer: SEGV /build/src/x.c:9 in store
"""

STACK_OVERFLOW = """\
==1==ERROR: AddressSanitizer: stack-overflow on address 0x7ffd00000000
    #0 0x4a1b2c in recurse /build/src/r.c:3:7
    #1 0x4a1b2c in recurse /build/src/r.c:3:7
SUMMARY: AddressSanitizer: stack-overflow /build/src/r.c:3 in recurse
"""


# ── dedup: normalization + stable hashing ────────────────────────────────────────

def test_normalized_frames_strip_addresses_paths_interceptors():
    frames = normalized_frames(HEAP_WRITE_REBUILT)
    # the __asan_memcpy interceptor frame is dropped; the real chain survives
    assert frames[:3] == ["parse_header", "handle_request", "main"]
    assert all("0x" not in f and "/" not in f and ":" not in f for f in frames)


def test_dedup_key_deterministic_and_path_independent():
    # Same bug, different ASLR/build-path/interceptor noise → SAME bucket.
    k1 = dedup_key("heap-buffer-overflow", HEAP_WRITE)
    k2 = dedup_key("heap-buffer-overflow", HEAP_WRITE_REBUILT)
    assert k1 == k2
    assert len(k1) == 64 and all(c in "0123456789abcdef" for c in k1)
    # Calling twice is stable.
    assert dedup_key("heap-buffer-overflow", HEAP_WRITE) == k1


def test_dedup_key_distinguishes_distinct_bugs():
    over = dedup_key("heap-buffer-overflow", HEAP_WRITE)
    uaf = dedup_key("heap-use-after-free", UAF_WRITE)
    other_fn = dedup_key("heap-buffer-overflow", HEAP_READ)
    assert len({over, uaf, other_fn}) == 3  # different type OR different stack ⇒ different key


def test_dedup_key_falls_back_when_no_symbolized_frame():
    stripped = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n  #0 0x4a (/bin/x+0x4a)\n"
    k = dedup_key("SEGV", stripped)
    # still a stable 64-hex key, distinct from a totally different kind
    assert len(k) == 64
    assert k != dedup_key("heap-buffer-overflow", stripped)


# ── exploitability classifier ────────────────────────────────────────────────────

def test_classify_write_overflow_likely_exploitable():
    r = classify_exploitability(HEAP_WRITE, "heap-buffer-overflow")
    assert r["rating"] == "likely_exploitable" and r["access"] == "WRITE"


def test_classify_read_overflow_info_leak():
    r = classify_exploitability(HEAP_READ, "heap-buffer-overflow")
    assert r["rating"] == "info_leak" and r["access"] == "READ"


def test_classify_uaf_write_vs_read():
    assert classify_exploitability(UAF_WRITE, "heap-use-after-free")["rating"] == "likely_exploitable"
    assert classify_exploitability(UAF_READ, "heap-use-after-free")["rating"] == "info_leak"


def test_classify_double_free_likely_exploitable():
    assert classify_exploitability(DOUBLE_FREE, "double-free")["rating"] == "likely_exploitable"


def test_classify_segv_read_is_dos_write_is_exploitable():
    assert classify_exploitability(SEGV_READ, "SEGV")["rating"] == "dos"
    assert classify_exploitability(SEGV_WRITE, "SEGV")["rating"] == "probably_exploitable"


def test_classify_stack_overflow_is_dos():
    assert classify_exploitability(STACK_OVERFLOW, "stack-overflow")["rating"] == "dos"


def test_classify_resource_exhaustion_is_dos():
    assert classify_exploitability("libFuzzer: out-of-memory\n", "out-of-memory")["rating"] == "dos"
    assert classify_exploitability("libFuzzer: timeout\n", "timeout")["rating"] == "dos"


def test_worst_rating():
    assert worst_rating("dos", "likely_exploitable", "info_leak") == "likely_exploitable"
    assert worst_rating("dos", "info_leak") == "info_leak"
    assert worst_rating() == "unknown"


# ── engine severity merge ────────────────────────────────────────────────────────

def test_severity_merge():
    # write overflow → critical (both type and exploitability agree)
    assert _severity_for("heap-buffer-overflow",
                         {"rating": "likely_exploitable"}) == "critical"
    # read overflow stays at least its type baseline (high) even if exploitability is info_leak
    assert _severity_for("global-buffer-overflow", {"rating": "info_leak"}) == "high"
    # an ambiguous SEGV defers to the report-derived rating
    assert _severity_for("SEGV", {"rating": "dos"}) == "low"
    assert _severity_for("SEGV", {"rating": "probably_exploitable"}) == "high"
    # a stack-overflow recursion DoS settles low (was over-rated 'high' before)
    assert _severity_for("stack-overflow", {"rating": "dos"}) == "low"
    # no exploitability info → bare type baseline
    assert _severity_for("heap-use-after-free", None) == "critical"


# ── libFuzzer progress parsing (Bug A: edge coverage was never collected) ─────────

# A real-shaped fork-mode libFuzzer transcript: periodic `#NNN: cov: C ft: F ...` lines
# (note the colon after the count — fork mode's format) where cov/ft climb monotonically
# and the LAST `#NNN:` is the cumulative exec count.
LIBFUZZER_FORK = """\
INFO: Running with entropic power schedule (0xFF, 100).
#2: cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 28Mb
#512: cov: 17 ft: 21 corp: 4/40b lim: 4 exec/s: 0 rss: 29Mb
#100000: cov: 142 ft: 311 corp: 22/1100b exec/s: 50000 rss: 31Mb
#2500000: cov: 198 ft: 540 corp: 31/2200b exec/s: 80000 rss: 33Mb
"""

# Single-process libFuzzer ends with `#N DONE` + a `number_of_executed_units` stat; its
# progress lines are tab-separated `#NNN\tNEW cov: ...` (no colon).
LIBFUZZER_SINGLE_DONE = """\
#1	INITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 28Mb
#4096	NEW    cov: 33 ft: 60 corp: 8/80b exec/s: 0 rss: 29Mb
#65536	DONE   cov: 41 ft: 77 corp: 9/90b exec/s: 32000 rss: 30Mb
stat::number_of_executed_units: 65536
"""


def test_libfuzzer_progress_fork_mode_extracts_edges_and_execs():
    p = parse_libfuzzer_progress(LIBFUZZER_FORK)
    # LAST #NNN: is the cumulative exec count; MAX cov:/ft: are the (monotonic) edges/features.
    assert p["executions"] == 2500000
    assert p["edges_covered"] == 198
    assert p["features"] == 540


def test_libfuzzer_progress_single_process_done_line():
    p = parse_libfuzzer_progress(LIBFUZZER_SINGLE_DONE)
    assert p["executions"] == 65536      # number_of_executed_units wins over the #N lines
    assert p["edges_covered"] == 41
    assert p["features"] == 77


def test_libfuzzer_progress_empty_is_all_none():
    p = parse_libfuzzer_progress("")
    assert p == {"executions": None, "edges_covered": None, "features": None}


# ── AFL++ fuzzer_stats parsing (Bug A: same edges_covered field for both engines) ──

def test_afl_stats_reads_edges_found(tmp_path):
    """The AFL probe already extracts `edges_found` from afl's `fuzzer_stats` into the same
    `edges_covered` status field libFuzzer now populates — assert that parse directly."""
    from hexgraph.sandbox.probes.afl_probe import _afl_stats

    inst = tmp_path / "fuzzer00"
    inst.mkdir()
    (inst / "fuzzer_stats").write_text(
        "start_time        : 1700000000\n"
        "execs_done        : 1234567\n"
        "edges_found       : 842\n"
        "total_edges       : 5000\n"
        "bitmap_cvg        : 16.84%\n")
    execs, edges = _afl_stats(str(tmp_path))
    assert execs == 1234567
    assert edges == 842


def test_afl_stats_sums_execs_across_instances(tmp_path):
    for name, execs, edges in (("fuzzer00", 1000, 50), ("fuzzer01", 2000, 60)):
        d = tmp_path / name
        d.mkdir()
        (d / "fuzzer_stats").write_text(f"execs_done : {execs}\nedges_found : {edges}\n")
    from hexgraph.sandbox.probes.afl_probe import _afl_stats
    execs, edges = _afl_stats(str(tmp_path))
    assert execs == 3000        # summed across master + secondary
    assert edges == 60          # max edges across instances (shared bitmap)
