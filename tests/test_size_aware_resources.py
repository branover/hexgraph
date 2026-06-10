"""F13 (the heap half): a sandbox probe over a LARGE artifact gets more container `--memory` and a
bigger `/scratch` tmpfs (so Ghidra's import/auto-analysis of a 100 MB+ ELF doesn't exhaust the heap
or fill the DB/recovery tmpfs — the "DB buffer" failure), while a normal-size artifact, a path-less
channel, and an explicit (fuzz/poc) spec are untouched. Offline: the scaling helpers are pure, and
the run_probe wiring is checked by capturing the docker flags it builds.
"""

from __future__ import annotations

import subprocess
from types import SimpleNamespace

import pytest

from hexgraph.sandbox import runner as R
from hexgraph.sandbox.resources import (
    SIZE_MEM_BYTES_PER_BYTE,
    SIZE_RAM_THRESHOLD_BYTES,
    SIZE_TMPFS_MEM_FRACTION,
    ResourceSpec,
    _fmt_mb,
    _parse_bytes,
    resource_spec_for,
    resource_spec_for_artifact,
    size_scaled_mem,
    size_scaled_tmpfs,
)
import hexgraph.sandbox.resources as RS

MIB = 1024 * 1024
GIB = 1024 * 1024 * 1024


@pytest.fixture(autouse=True)
def _big_host(monkeypatch):
    # Pin host RAM large + deterministic so the host-fraction cap doesn't make tests depend on the box.
    monkeypatch.setattr(RS, "_host_mem_total_bytes", lambda: 64 * GIB)


# ---- size string parsing ----------------------------------------------------------------

def test_parse_and_format_bytes():
    assert _parse_bytes("2g") == 2 * GIB
    assert _parse_bytes("512m") == 512 * MIB
    assert _parse_bytes("2048") == 2048
    assert _parse_bytes("garbage") == 0          # lenient: unparseable -> 0 (caller keeps base)
    assert _fmt_mb(6 * GIB) == "6144m"
    assert _fmt_mb(1) == "1m"                     # floors at 1m, never '0m' (docker rejects 0)


# ---- mem / tmpfs scaling ----------------------------------------------------------------

def test_mem_unchanged_below_threshold():
    assert size_scaled_mem(SIZE_RAM_THRESHOLD_BYTES, "2g") == "2g"
    assert size_scaled_mem(None, "2g") == "2g"
    assert size_scaled_mem(8 * MIB, "2g") == "2g"


def test_mem_scales_above_threshold():
    size = SIZE_RAM_THRESHOLD_BYTES + 100 * MIB
    got = _parse_bytes(size_scaled_mem(size, "2g"))
    assert got == 2 * GIB + 100 * MIB * SIZE_MEM_BYTES_PER_BYTE
    assert got > 2 * GIB


def test_mem_capped_by_host_fraction(monkeypatch):
    monkeypatch.setattr(RS, "_host_mem_total_bytes", lambda: 8 * GIB)   # small box
    huge = SIZE_RAM_THRESHOLD_BYTES + 4 * GIB
    assert _parse_bytes(size_scaled_mem(huge, "2g")) <= int(8 * GIB * 0.75)   # never over-commit


def test_tmpfs_scales_but_stays_under_mem():
    size = SIZE_RAM_THRESHOLD_BYTES + 200 * MIB
    mem = _parse_bytes(size_scaled_mem(size, "2g"))
    tmpfs = _parse_bytes(size_scaled_tmpfs(size, "512m", mem))
    assert tmpfs > 512 * MIB
    assert tmpfs <= int(mem * SIZE_TMPFS_MEM_FRACTION)     # tmpfs counts against mem -> leave heap room


def test_tmpfs_unchanged_below_threshold():
    assert size_scaled_tmpfs(8 * MIB, "512m", 2 * GIB) == "512m"


# ---- resource_spec_for_artifact: composes timeout + mem + tmpfs --------------------------

def test_spec_unchanged_for_small_artifact(tmp_path):
    base = resource_spec_for("sandbox")
    f = tmp_path / "small.bin"
    f.write_bytes(b"\x00" * (4 * MIB))
    assert resource_spec_for_artifact(f, "sandbox") == base


def test_spec_widens_mem_and_tmpfs_for_large_artifact(tmp_path):
    base = resource_spec_for("sandbox")
    f = tmp_path / "big.bin"
    with open(f, "wb") as fh:
        fh.truncate(SIZE_RAM_THRESHOLD_BYTES + 150 * MIB)   # sparse — no real disk
    spec = resource_spec_for_artifact(f, "sandbox")
    assert _parse_bytes(spec.mem) > _parse_bytes(base.mem)
    assert _parse_bytes(spec.tmpfs) > _parse_bytes(base.tmpfs)
    assert spec.timeout > base.timeout
    assert (spec.cpus, spec.pids, spec.unconstrained) == (base.cpus, base.pids, base.unconstrained)


def test_unconstrained_spec_is_left_alone(tmp_path, monkeypatch):
    monkeypatch.setattr(RS, "resource_spec_for",
                        lambda ct="default": ResourceSpec(unconstrained=True))
    f = tmp_path / "big.bin"
    with open(f, "wb") as fh:
        fh.truncate(SIZE_RAM_THRESHOLD_BYTES + 200 * MIB)
    spec = resource_spec_for_artifact(f, "sandbox")
    assert spec.mem == ResourceSpec().mem and spec.tmpfs == ResourceSpec().tmpfs   # ceilings already dropped


# ---- run_probe wiring: the scaled mem/tmpfs reach the docker flags -----------------------

def _capture_docker_cmd(monkeypatch, runner, artifact, **kw):
    captured = {}

    def fake_run(cmd, *a, **k):
        if len(cmd) > 1 and cmd[1] == "run":
            captured["cmd"] = cmd
            raise subprocess.TimeoutExpired(cmd, k.get("timeout"))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(R.subprocess, "run", fake_run)
    with pytest.raises(R.SandboxTimeout):
        runner.run_probe("ghidra_probe.py", artifact, **kw)
    return captured["cmd"]


def test_run_probe_passes_scaled_mem_and_tmpfs_for_a_large_artifact(tmp_path, monkeypatch):
    runner = R.SandboxRunner(image="hexgraph-bogus:nope")
    f = tmp_path / "mono.elf"
    with open(f, "wb") as fh:
        fh.truncate(SIZE_RAM_THRESHOLD_BYTES + 150 * MIB)
    cmd = _capture_docker_cmd(monkeypatch, runner, f)
    joined = " ".join(cmd)
    mem = cmd[cmd.index("--memory") + 1]
    assert _parse_bytes(mem) > 2 * GIB                       # widened past the 2g default
    assert "size=" in joined and "/scratch" in joined        # tmpfs present
    tmpfs_tok = next(p for p in cmd if p.startswith("/scratch:"))
    assert _parse_bytes(tmpfs_tok.split("size=")[1]) > 512 * MIB


def test_run_probe_small_artifact_keeps_base_mem(tmp_path, monkeypatch):
    runner = R.SandboxRunner(image="hexgraph-bogus:nope")
    base_mem = resource_spec_for("sandbox").mem
    f = tmp_path / "small.elf"
    f.write_bytes(b"\x00" * (8 * MIB))
    cmd = _capture_docker_cmd(monkeypatch, runner, f)
    assert cmd[cmd.index("--memory") + 1] == base_mem        # unchanged for a normal binary


def test_run_probe_advertises_its_deadline_to_the_probe(tmp_path, monkeypatch):
    # F13: run_probe exposes its wall-clock budget (-e HEXGRAPH_PROBE_TIMEOUT_S) so a long-running
    # probe (Ghidra) can stop+save just before the external kill instead of dying with nothing.
    runner = R.SandboxRunner(image="hexgraph-bogus:nope")
    f = tmp_path / "x.elf"
    f.write_bytes(b"\x00" * (8 * MIB))
    cmd = _capture_docker_cmd(monkeypatch, runner, f)
    assert f"HEXGRAPH_PROBE_TIMEOUT_S={resource_spec_for('sandbox').timeout}" in cmd
