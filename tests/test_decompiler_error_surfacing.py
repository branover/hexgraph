"""A failing decompiler probe must surface its REAL reason, not a bare `exit N`. Guards:

1. The runner's swallow point (`_probe_failure_message`) must lift the probe's stdout JSON
   `{error: ...}` on a non-zero exit, not surface only the (often empty) stderr.
2. The pyghidra ghidra_probe must always emit STRUCTURED JSON on failure (deps missing -> exit 3,
   in-process Ghidra fault -> exit 4), never a silent bare exit.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hexgraph.sandbox.runner import (
    SandboxError,
    SandboxRunner,
    _probe_failure_message,
)

PROBE_DIR = Path("src/hexgraph/sandbox/probes")
GHIDRA_PROBE = PROBE_DIR / "ghidra_probe.py"


class _FakeCompleted:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ── _probe_failure_message: the surfacing helper ────────────────────────────────


def test_failure_message_uses_probe_json_error():
    msg = _probe_failure_message(
        "ghidra_probe.py", 3,
        stdout=json.dumps({"error": "Ghidra not installed — rebuild with WITH_GHIDRA=1"}),
        stderr="",
    )
    assert "Ghidra not installed" in msg
    assert "WITH_GHIDRA=1" in msg
    assert "exit 3" in msg  # exit code is never lost


def test_failure_message_picks_error_from_last_line():
    # analyzeHeadless logs noise to stdout, then the probe prints the error JSON last.
    stdout = "INFO some log line\nWARN another\n" + json.dumps({"error": "analyzeHeadless produced no output"})
    msg = _probe_failure_message("ghidra_probe.py", 4, stdout=stdout, stderr="")
    assert "analyzeHeadless produced no output" in msg


def test_failure_message_falls_back_to_stderr_when_no_json():
    msg = _probe_failure_message("decompile_probe.py", 1, stdout="not json at all", stderr="segfault in r2")
    assert "segfault in r2" in msg
    assert "exit 1" in msg


def test_failure_message_falls_back_to_stdout_when_no_stderr():
    msg = _probe_failure_message("p.py", 1, stdout="raw traceback text", stderr="")
    assert "raw traceback text" in msg


def test_failure_message_bare_when_nothing_captured():
    msg = _probe_failure_message("p.py", 5, stdout="", stderr="")
    assert msg == "probe p.py failed (exit 5)"


# ── run_probe: the swallow point now surfaces the real reason ────────────────────


def test_run_probe_surfaces_probe_json_error(monkeypatch, tmp_path):
    """A probe that exits non-zero with `{error}` on STDOUT must reach the caller as
    a SandboxError carrying that reason — not a bare `exit N` from the empty stderr."""
    artifact = tmp_path / "target.bin"
    artifact.write_bytes(b"\x7fELF")

    real_reason = "Ghidra not installed in this sandbox image — rebuild it with WITH_GHIDRA=1"

    def fake_run(cmd, **kwargs):
        # The probe wrote its error to stdout; stderr is empty (the old bug).
        return _FakeCompleted(3, stdout=json.dumps({"error": real_reason}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(SandboxError) as ei:
        SandboxRunner().run_probe("ghidra_probe.py", artifact)
    text = str(ei.value)
    assert real_reason in text
    assert "exit 3" in text
    # NOT a bare exit with empty detail.
    assert not text.endswith("exit 3)")


def test_run_json_probe_propagates_real_reason(monkeypatch, tmp_path):
    artifact = tmp_path / "target.bin"
    artifact.write_bytes(b"\x7fELF")

    def fake_run(cmd, **kwargs):
        return _FakeCompleted(4, stdout=json.dumps({"error": "analyzeHeadless produced no output (exit 1)"}), stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(SandboxError) as ei:
        SandboxRunner().run_json_probe("ghidra_probe.py", artifact)
    assert "analyzeHeadless produced no output" in str(ei.value)


# ── the pyghidra probe always emits STRUCTURED JSON, never a silent failure ───────


def test_ghidra_probe_never_fails_silently(tmp_path):
    """Run the real (pyghidra) probe against a Ghidra dir that LOOKS present (a Ghidra/ subtree +
    version file) but isn't a working install. Whether pyghidra is host-importable or not, the probe
    must exit with a structured JSON error carrying an actionable reason — never a bare non-zero exit
    with empty output (the old undiagnosable failure). Since the re-platform there is no
    analyzeHeadless subprocess: a missing dependency is exit 3, an in-process Ghidra fault is exit 4,
    and BOTH print `{error: ...}` to stdout."""
    ghidra_dir = tmp_path / "ghidra"
    props_dir = ghidra_dir / "Ghidra"
    props_dir.mkdir(parents=True)
    (props_dir / "application.properties").write_text("application.version=12.1\n")

    artifact = tmp_path / "fw.bin"
    artifact.write_bytes(b"\x7fELF binary")
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    env = {**os.environ, "GHIDRA_INSTALL_DIR": str(ghidra_dir), "TMPDIR": str(scratch)}
    r = subprocess.run(
        [sys.executable, str(GHIDRA_PROBE), str(artifact)],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode in (3, 4)          # deps missing (3) or in-process Ghidra fault (4)
    out = json.loads(r.stdout)             # structured — NOT a silent bare exit
    assert out.get("error")               # carries a reason, always


def test_ghidra_probe_missing_ghidra_actionable(tmp_path):
    """exit 3 carries the actionable rebuild hint on stdout."""
    artifact = tmp_path / "x.bin"
    artifact.write_bytes(b"\x7fELF")
    r = subprocess.run(
        [sys.executable, str(GHIDRA_PROBE), str(artifact)],
        capture_output=True, text=True,
        env={"GHIDRA_INSTALL_DIR": "/nonexistent"},
    )
    assert r.returncode == 3
    out = json.loads(r.stdout)
    assert "WITH_GHIDRA=1" in out["error"]
