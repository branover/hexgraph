"""Compile a generated fuzz harness in the sandbox (best-effort).

The LLM (or mock) emits harness C source on the finding's evidence; we actually
compile it in the disposable sandbox and record the real build result, replacing
any claimed result. No fuzzing is run in v1 (SPEC §5, §12).
"""

from __future__ import annotations

import os
import tempfile

from hexgraph.sandbox.runner import SandboxRunner


def compile_harness_source(source: str, runner: SandboxRunner | None = None) -> dict:
    """Compile harness C source in the sandbox; return the build-result dict."""
    runner = runner or SandboxRunner()
    fd, path = tempfile.mkstemp(suffix=".c", prefix="hexgraph-harness-")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(source)
        return runner.run_json_probe("compile_probe.py", path)
    finally:
        os.unlink(path)
