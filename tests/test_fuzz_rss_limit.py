"""libFuzzer's `-rss_limit_mb` is set BELOW the container's `--memory` cgroup cap so
libFuzzer's own graceful OOM limiter (which prints a classifiable `out-of-memory` report
and saves the input) trips before the kernel cgroup OOM-killer SIGKILLs the process
opaquely. Historically it was hardcoded to 2048 == the default `--memory 2g`, so the two
fired at the same threshold and the kernel often won. These lock the scaling logic and
verify the real hardened container reads its actual cgroup cap."""

import subprocess

import pytest

from hexgraph.sandbox.probes.fuzz_probe import rss_limit_mb_for_cap

from conftest import SANDBOX_READY

_GIB = 1024 * 1024 * 1024


# ── offline: the RSS limit scales below the memory cap (pure function) ───────────────

def test_rss_limit_is_below_the_memory_cap():
    # 2g cap → 80% = 1638 MB, strictly below the 2048 MB cap → libFuzzer trips first
    # (the historical hardcoded 2048 sat exactly AT the cap).
    assert rss_limit_mb_for_cap(2 * _GIB) == 1638
    assert rss_limit_mb_for_cap(2 * _GIB) < 2 * 1024


def test_rss_limit_scales_with_a_raised_cap():
    # A campaign that raised --memory gets a proportionally larger RSS budget.
    assert rss_limit_mb_for_cap(8 * _GIB) == int(8 * 1024 * 0.8)
    assert rss_limit_mb_for_cap(8 * _GIB) < 8 * 1024


def test_rss_limit_falls_back_when_uncapped():
    # No finite cap (unconstrained / unreadable) → the historical default, never 0/None.
    assert rss_limit_mb_for_cap(None) == 2048
    assert rss_limit_mb_for_cap(0) == 2048


def test_rss_limit_stays_below_even_a_tiny_cap():
    # The invariant that matters: the RSS limit is ALWAYS strictly below the cap (and > 0)
    # so libFuzzer's limiter trips before the cgroup OOM-killer. NO floor that could reach
    # the cap — `mem` is user-tunable (the `resources` settings section), and a 256 MB floor
    # against a mem="256m" cap would re-create the rss>=cap inversion this fixes.
    for cap_mb in (256, 128, 64, 32):
        rss = rss_limit_mb_for_cap(cap_mb * 1024 * 1024)
        assert 0 < rss < cap_mb, f"cap={cap_mb}MB -> rss={rss} must be >0 and below the cap"


def test_rss_limit_below_cap_invariant_holds_across_caps():
    # Sweep a wide range of caps: the limit is below the cap at every size (the property
    # libFuzzer relies on to OOM-report gracefully instead of being SIGKILLed).
    for cap_mb in (16, 64, 256, 512, 2048, 8192, 65536):
        rss = rss_limit_mb_for_cap(cap_mb * 1024 * 1024)
        assert 0 < rss < cap_mb, (cap_mb, rss)


# ── Docker-gated: the real container reads its actual cgroup --memory cap ─────────────

@pytest.mark.skipif(not SANDBOX_READY, reason="requires Docker + the hexgraph-sandbox image")
def test_container_reads_its_cgroup_memory_cap():
    """Run the actual probe module inside a `--memory 1g` container and confirm
    `_memory_cap_bytes` / `libfuzzer_rss_limit_mb` read the real cgroup cap (not the host's
    RAM), yielding an RSS limit comfortably below 1 GiB — the property that keeps libFuzzer's
    limiter ahead of the cgroup OOM-killer. The probe is pure-stdlib, so it imports cleanly
    in the image without HexGraph installed."""
    from hexgraph.sandbox.runner import sandbox_image, PROBES_DIR

    snippet = (
        "import sys; sys.path.insert(0, '/probes'); import fuzz_probe as f; "
        "print(f._memory_cap_bytes(), f.libfuzzer_rss_limit_mb())"
    )
    cmd = [
        "docker", "run", "--rm", "--memory", "1g", "--network", "none",
        "-v", f"{PROBES_DIR}:/probes:ro", sandbox_image(), "python3", "-c", snippet,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    cap_str, rss_str = proc.stdout.split()
    cap, rss = int(cap_str), int(rss_str)
    # cgroup reported ~1 GiB (allow a little slack for runtime rounding), NOT the host RAM.
    assert 0.9 * _GIB <= cap <= 1.1 * _GIB, f"read cap={cap}, expected ~1 GiB"
    # RSS limit is 80% of the cap → ~819 MB, strictly below the 1024 MB cgroup cap.
    assert rss < 1024, f"rss_limit={rss} must be below the 1 GiB cgroup cap"
    assert rss == rss_limit_mb_for_cap(cap)
