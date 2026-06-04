"""Phase 0: a failing decompiler probe must surface its REAL reason, not a bare
`exit N`. Two defects this guards against:

1. The runner's swallow point dropped the probe's stdout JSON `{error: ...}` on a
   non-zero exit and surfaced only the (often empty) stderr.
2. ghidra_probe's exit-4 path read `proc.stderr`, but analyzeHeadless logs to
   STDOUT, so the captured reason was blank.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
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


# ── ghidra_probe exit-4 reads STDOUT (where analyzeHeadless logs), not stderr ─────


def test_ghidra_probe_exit4_captures_stdout_log(tmp_path, monkeypatch):
    """Run the real probe against a FAKE analyzeHeadless that logs to stdout then
    exits without producing the output file. The probe must capture that stdout log
    in its error JSON (the old code read the empty stderr)."""
    # A fake Ghidra install: support/analyzeHeadless that logs to stdout + a version file.
    ghidra_dir = tmp_path / "ghidra"
    support = ghidra_dir / "support"
    support.mkdir(parents=True)
    fake_headless = support / "analyzeHeadless"
    fake_headless.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import sys
        # analyzeHeadless logs to STDOUT, not stderr.
        print("INFO  HeadlessAnalyzer - REPORT: load failed: unknown ELF arch MIPS-R6")
        print("ERROR HeadlessAnalyzer - Import failed for file")
        sys.exit(1)
    """))
    fake_headless.chmod(0o755)
    # application.properties for _version()
    props_dir = ghidra_dir / "Ghidra"
    props_dir.mkdir()
    (props_dir / "application.properties").write_text("application.version=12.0\n")

    artifact = tmp_path / "fw.bin"
    artifact.write_bytes(b"\x7fELF binary")

    scratch = tmp_path / "scratch"
    scratch.mkdir()

    env = {
        **os.environ,
        "GHIDRA_INSTALL_DIR": str(ghidra_dir),
        "TMPDIR": str(scratch),
    }
    r = subprocess.run(
        [sys.executable, str(GHIDRA_PROBE), str(artifact)],
        capture_output=True, text=True, env=env,
    )
    assert r.returncode == 4
    out = json.loads(r.stdout)
    # The captured reason carries the analyzeHeadless STDOUT log tail — the fix.
    assert "analyzeHeadless produced no output" in out["error"]
    assert "load failed" in out["error"]
    assert "MIPS-R6" in out["error"]


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
