"""F13: a sandbox probe over a LARGE artifact gets a size-scaled wall-clock budget so the
first whole-binary analysis of a 100 MB+ ELF isn't killed at the 300 s default — while a
normal-size artifact, a path-less channel, and an explicit (fuzz/poc) ResourceSpec are all
left exactly as before. These run offline with no Docker: the pure scaling helpers are tested
directly, and the `run_probe` wiring is checked by capturing the `timeout` it hands subprocess.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from hexgraph.sandbox import runner as R
from hexgraph.sandbox import resources as RS
from hexgraph.sandbox.resources import (
    DEFAULT_TIMEOUT,
    SIZE_TIMEOUT_CAP_SECONDS,
    SIZE_TIMEOUT_SECONDS_PER_MIB,
    SIZE_TIMEOUT_THRESHOLD_BYTES,
    ResourceSpec,
    resource_spec_for,
    resource_spec_for_artifact,
    size_scaled_timeout,
)

MIB = 1024 * 1024


def _sparse_file(tmp_path, name, size_bytes):
    """A file of the given apparent size, allocated sparsely so a 'large' artifact costs
    no real disk (os.path.getsize reports the truncated length)."""
    p = tmp_path / name
    with open(p, "wb") as fh:
        fh.truncate(size_bytes)
    return p


# ---- size_scaled_timeout: the pure rule -------------------------------------------------

def test_small_or_unknown_artifact_keeps_base_timeout_exactly():
    assert size_scaled_timeout(None, 300) == 300
    assert size_scaled_timeout(0, 300) == 300
    assert size_scaled_timeout(SIZE_TIMEOUT_THRESHOLD_BYTES, 300) == 300       # boundary: inclusive
    assert size_scaled_timeout(SIZE_TIMEOUT_THRESHOLD_BYTES - 1, 300) == 300


def test_large_artifact_scales_linearly_above_the_threshold():
    size = SIZE_TIMEOUT_THRESHOLD_BYTES + 100 * MIB
    expected = 300 + 100 * SIZE_TIMEOUT_SECONDS_PER_MIB
    assert size_scaled_timeout(size, 300) == expected
    assert expected > 300                                                       # it really widened


def test_scaling_is_monotonic_in_size():
    base = 300
    budgets = [size_scaled_timeout(SIZE_TIMEOUT_THRESHOLD_BYTES + n * MIB, base)
               for n in (0, 50, 200, 600, 5000)]
    assert budgets == sorted(budgets)
    assert all(b >= base for b in budgets)                                      # never narrows


def test_size_bonus_is_capped():
    huge = SIZE_TIMEOUT_THRESHOLD_BYTES + 100_000 * MIB
    assert size_scaled_timeout(huge, 300) == SIZE_TIMEOUT_CAP_SECONDS


def test_user_base_above_the_cap_is_never_shrunk():
    # A user who set resources.sandbox.timeout above the cap keeps their floor; the size
    # bonus can still add on top but the cap can never pull them DOWN.
    high = SIZE_TIMEOUT_CAP_SECONDS + 1000
    assert size_scaled_timeout(SIZE_TIMEOUT_THRESHOLD_BYTES + 10 * MIB, high) >= high


# ---- resource_spec_for_artifact: applied to the resolved spec ---------------------------

def test_spec_unchanged_for_small_artifact(tmp_path):
    base = resource_spec_for("sandbox")
    small = _sparse_file(tmp_path, "small.bin", 4 * MIB)
    assert resource_spec_for_artifact(small, "sandbox") == base                 # identical, timeout incl.


def test_spec_widens_only_timeout_in_the_medium_band(tmp_path):
    # Between the 32 MiB timeout threshold and the (higher) 64 MiB mem/tmpfs threshold, ONLY the
    # timeout widens — a medium binary gets more wall-clock but not the heavier mem/tmpfs bump
    # (those are reserved for genuinely large artifacts, F13 heap-half). 48 MiB sits in that band.
    base = resource_spec_for("sandbox")
    size = SIZE_TIMEOUT_THRESHOLD_BYTES + 16 * MIB        # 48 MiB: > timeout threshold, < ram threshold
    med = _sparse_file(tmp_path, "med.bin", size)
    spec = resource_spec_for_artifact(med, "sandbox")
    assert spec.timeout == size_scaled_timeout(size, base.timeout)
    assert spec.timeout > base.timeout
    # mem/cpu/pids/tmpfs are all byte-for-byte the configured ceiling in this band.
    assert (spec.mem, spec.cpus, spec.pids, spec.tmpfs, spec.unconstrained) == (
        base.mem, base.cpus, base.pids, base.tmpfs, base.unconstrained)


def test_none_and_missing_artifacts_yield_the_base_spec(tmp_path):
    base = resource_spec_for("sandbox")
    assert resource_spec_for_artifact(None, "sandbox") == base                  # path-less channel surface
    assert resource_spec_for_artifact(tmp_path / "does-not-exist", "sandbox") == base


def test_user_timeout_override_is_the_base_it_scales_from(tmp_path, monkeypatch):
    # resources.sandbox.timeout=600 → a small artifact stays 600, a big one scales UP from 600.
    monkeypatch.setattr(RS, "resource_spec_for",
                        lambda ct="default": ResourceSpec(timeout=600))
    small = _sparse_file(tmp_path, "s.bin", 1 * MIB)
    big = _sparse_file(tmp_path, "b.bin", SIZE_TIMEOUT_THRESHOLD_BYTES + 40 * MIB)
    assert resource_spec_for_artifact(small, "sandbox").timeout == 600
    assert resource_spec_for_artifact(big, "sandbox").timeout == 600 + 40 * SIZE_TIMEOUT_SECONDS_PER_MIB


# ---- run_probe wiring: the default it hands to subprocess --------------------------------

def _capture_probe_timeout(monkeypatch, runner, artifact, **kw):
    """Drive run_probe with subprocess faked so the docker-run call records its timeout and
    raises TimeoutExpired (surfaced as SandboxTimeout) — no Docker needed."""
    captured = {}

    def fake_run(cmd, *a, **k):
        if len(cmd) > 1 and cmd[1] == "run":
            captured["timeout"] = k.get("timeout")
            raise subprocess.TimeoutExpired(cmd, k.get("timeout"))
        return SimpleNamespace(returncode=0, stdout="", stderr="")             # the docker-kill call

    monkeypatch.setattr(R.subprocess, "run", fake_run)
    with pytest.raises(R.SandboxTimeout):
        runner.run_probe("recon_probe.py", artifact, **kw)
    return captured["timeout"]


def test_run_probe_default_is_size_aware(tmp_path, monkeypatch):
    runner = R.SandboxRunner(image="hexgraph-bogus:nope")
    base = resource_spec_for("sandbox").timeout

    small = _sparse_file(tmp_path, "small.bin", 8 * MIB)
    assert _capture_probe_timeout(monkeypatch, runner, small) == base          # unchanged for normal binaries

    big = _sparse_file(tmp_path, "big.bin", SIZE_TIMEOUT_THRESHOLD_BYTES + 120 * MIB)
    got = _capture_probe_timeout(monkeypatch, runner, big)
    assert got == size_scaled_timeout(SIZE_TIMEOUT_THRESHOLD_BYTES + 120 * MIB, base)
    assert got > base


def test_run_probe_explicit_resources_are_not_size_scaled(tmp_path, monkeypatch):
    # An explicit ResourceSpec (fuzz/poc/build set their budget deliberately) is honored verbatim,
    # even over a huge artifact — size scaling applies ONLY to the None default.
    runner = R.SandboxRunner(image="hexgraph-bogus:nope")
    big = _sparse_file(tmp_path, "huge.bin", SIZE_TIMEOUT_THRESHOLD_BYTES + 500 * MIB)
    got = _capture_probe_timeout(monkeypatch, runner, big, resources=ResourceSpec(timeout=123))
    assert got == 123
