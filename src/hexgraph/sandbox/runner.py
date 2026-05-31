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
        extra_ro_mounts: list[tuple[str, str]] | None = None,
        allow_network: bool = False,
        net_container: str | None = None,
    ) -> RunResult:
        """Run a probe script over `artifact` inside the sandbox.

        `outdir` (host dir) is bind-mounted read-write at /out when a probe needs
        to write extracted files; otherwise only stdout is captured.
        `requires_execution` is the policy hook for dynamic probes (raises unless the
        policy permits execution). `allow_network` is the egress hook: by default the
        container runs `--network none`; only when the caller passes True AND the
        policy permits network does it get the bridge network. `net_container` (only
        meaningful with allow_network) joins the probe to ANOTHER container's network
        namespace (`--network container:<name>`) instead of the bridge — used to reach a
        rehosted firmware's device IP, which lives on a tap inside the FirmAE container.
        The caller is responsible for the per-destination allowlist + audit (engine.audit)
        — this is the single, explicit place `--network none` is relaxed.
        """
        if requires_execution:
            from hexgraph.policy import assert_allows_execution

            assert_allows_execution()
        if allow_network:
            from hexgraph.policy import PolicyViolation, current_policy

            if not current_policy().allow_network:
                raise PolicyViolation("network egress is not permitted by the active policy")
        if artifact is not None:
            artifact = Path(artifact).resolve()
            if not artifact.is_file():
                raise SandboxError(f"artifact not found: {artifact}")

        name = f"hexgraph-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            # Egress is OFF by default; `allow_network` (policy-checked above) swaps in
            # the bridge so a probe can reach an allowlisted local target — or joins a
            # rehosted firmware's container netns to reach its emulated device IP.
            *(["--network", f"container:{net_container}" if net_container else "bridge"]
              if allow_network else ["--network", "none"]),
            "--read-only",
            # Defense-in-depth at the hostile-target boundary: no Linux capabilities,
            # no privilege escalation (blocks setuid-root re-escalation), and pin the
            # unprivileged uid even if the image's USER is overridden. The probes run
            # as the non-root analyst (uid 1000) and need none of these.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "1000:1000",
            "--memory", "2g",
            "--cpus", "2",
            "--pids-limit", "256",
            # mode=1777 (world-writable + sticky, like /tmp) so the non-root probe
            # user can create files/dirs; exec so compiled PoCs/JVM scratch can run.
            "--tmpfs", "/scratch:rw,exec,mode=1777,size=512m",
            # Writable /tmp too: tools (Ghidra's java.io.tmpdir, mktemp callers)
            # assume it, and the rootfs is read-only.
            "--tmpfs", "/tmp:rw,exec,mode=1777,size=512m",
            "--workdir", "/scratch",
            # Point HOME/TMP at the tmpfs so tools needing a writable home work
            # under the read-only rootfs.
            "-e", "HOME=/scratch",
            "-e", "TMPDIR=/scratch",
            "-e", "XDG_CACHE_HOME=/scratch",
            "-e", "XDG_CONFIG_HOME=/scratch",
            # A channel probe (live target, no bytes at rest) mounts no artifact.
            *(["-v", f"{artifact}:/artifact:ro"] if artifact is not None else []),
        ]

        probe_args = ["/artifact"] if artifact is not None else []
        if outdir is not None:
            outdir = Path(outdir).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            cmd += ["-v", f"{outdir}:/out:rw"]
            probe_args.append("/out")
        # Extra read-only inputs (e.g. the target library a fuzz harness links against).
        for host, cont in (extra_ro_mounts or []):
            cmd += ["-v", f"{Path(host).resolve()}:{cont}:ro"]
        if extra_args:
            probe_args += extra_args

        # Mount the installed probe scripts read-only, overlaying the image's baked
        # copy, so probes stay in sync with the package and ADDING a probe never
        # requires rebuilding the image (only toolchain changes do). Probes are our
        # own trusted code; the target is still only at /artifact (ro) + /out.
        # Set HEXGRAPH_SANDBOX_NO_MOUNT=1 to force the baked-in copy instead.
        if PROBES_DIR.is_dir() and os.environ.get("HEXGRAPH_SANDBOX_NO_MOUNT") != "1":
            cmd += ["-v", f"{PROBES_DIR}:{CONTAINER_PROBES}:ro"]

        cmd += [self.image, "python3", f"{CONTAINER_PROBES}/{probe}", *probe_args]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "kill", name], capture_output=True)
            target = artifact.name if artifact is not None else "live channel"
            raise SandboxTimeout(f"probe {probe} exceeded {self.timeout}s on {target}") from exc
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
        extra_ro_mounts: list[tuple[str, str]] | None = None,
        allow_network: bool = False,
    ) -> dict:
        """Run a probe whose stdout is a single JSON object, and parse it."""
        result = self.run_probe(
            probe, artifact, outdir=outdir, extra_args=extra_args,
            requires_execution=requires_execution, extra_ro_mounts=extra_ro_mounts,
            allow_network=allow_network,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc

    def run_channel_probe(self, probe: str, *, channel: dict, outdir: str | Path | None = None,
                          extra_args: list[str] | None = None, net_container: str | None = None) -> dict:
        """Run a probe that talks to a live Channel — no artifact file is mounted; the
        connection descriptor (incl. the per-run egress allowlist) is passed as
        `--channel <json>`. Runs with bounded egress (policy-checked). `net_container` joins
        a rehosted firmware's container netns to reach its emulated device IP. The CALLER
        must already have asserted `assert_allows_egress` + recorded the audit event."""
        result = self.run_probe(
            probe, None, outdir=outdir,
            extra_args=["--channel", json.dumps(channel), *(extra_args or [])],
            allow_network=True, net_container=net_container,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc
