"""The sandbox runner — the container boundary for ALL target-byte handling (SPEC §7).

Every probe runs in a fresh, disposable container with no network, a read-only
root filesystem, resource caps, a tmpfs scratch, the target mounted read-only,
and a hard wall-clock timeout. The target is NEVER executed — only our probe
scripts run, over the target's bytes (static/RE only in v1).
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

DEFAULT_IMAGE = "hexgraph-sandbox:latest"
DEFAULT_TIMEOUT = 300  # seconds
PROBES_DIR = Path(__file__).resolve().parent / "probes"
CONTAINER_PROBES = "/opt/hexgraph"


class SandboxError(RuntimeError):
    """The sandbox run failed (non-zero exit, docker error, bad output)."""


class SandboxTimeout(SandboxError):
    """The sandbox run exceeded its wall-clock budget and was killed."""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    outdir: str | None


def sandbox_image() -> str:
    return os.environ.get("HEXGRAPH_SANDBOX_IMAGE", DEFAULT_IMAGE)


def docker_available() -> bool:
    try:
        subprocess.run(["docker", "version"], capture_output=True, timeout=10, check=True)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


class SandboxRunner:
    def __init__(self, image: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.image = image or sandbox_image()
        self.timeout = timeout

    def run_probe(
        self,
        probe: str,
        artifact: str | Path,
        *,
        outdir: str | Path | None = None,
        extra_args: list[str] | None = None,
        requires_execution: bool = False,
    ) -> RunResult:
        """Run a probe script over `artifact` inside the sandbox.

        `outdir` (host dir) is bind-mounted read-write at /out when a probe needs
        to write extracted files; otherwise only stdout is captured.
        `requires_execution` is the policy hook for future dynamic probes; in the
        static-only v1 policy it raises, so the target is never executed.
        """
        if requires_execution:
            from hexgraph.policy import assert_allows_execution

            assert_allows_execution()
        artifact = Path(artifact).resolve()
        if not artifact.is_file():
            raise SandboxError(f"artifact not found: {artifact}")

        name = f"hexgraph-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only",
            "--memory", "2g",
            "--cpus", "2",
            "--pids-limit", "256",
            "--tmpfs", "/scratch:rw,size=512m",
            "--workdir", "/scratch",
            # Point HOME/TMP at the tmpfs so tools needing a writable home work
            # under the read-only rootfs.
            "-e", "HOME=/scratch",
            "-e", "TMPDIR=/scratch",
            "-e", "XDG_CACHE_HOME=/scratch",
            "-e", "XDG_CONFIG_HOME=/scratch",
            "-v", f"{artifact}:/artifact:ro",
        ]

        probe_args = ["/artifact"]
        if outdir is not None:
            outdir = Path(outdir).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            cmd += ["-v", f"{outdir}:/out:rw"]
            probe_args.append("/out")
        if extra_args:
            probe_args += extra_args

        # Dev convenience: mount local probes so edits don't require a rebuild.
        if os.environ.get("HEXGRAPH_SANDBOX_DEV") == "1":
            cmd += ["-v", f"{PROBES_DIR}:{CONTAINER_PROBES}:ro"]

        cmd += [self.image, "python3", f"{CONTAINER_PROBES}/{probe}", *probe_args]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "kill", name], capture_output=True)
            raise SandboxTimeout(f"probe {probe} exceeded {self.timeout}s on {artifact.name}") from exc
        except OSError as exc:
            raise SandboxError(f"failed to launch docker: {exc}") from exc

        if proc.returncode != 0:
            raise SandboxError(
                f"probe {probe} failed (exit {proc.returncode}): {proc.stderr.strip()[:500]}"
            )
        return RunResult(proc.returncode, proc.stdout, proc.stderr, str(outdir) if outdir else None)

    def run_json_probe(
        self,
        probe: str,
        artifact: str | Path,
        *,
        outdir: str | Path | None = None,
        extra_args: list[str] | None = None,
        requires_execution: bool = False,
    ) -> dict:
        """Run a probe whose stdout is a single JSON object, and parse it."""
        result = self.run_probe(
            probe, artifact, outdir=outdir, extra_args=extra_args, requires_execution=requires_execution
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc
