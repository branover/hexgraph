"""The sandbox runner — the container boundary for ALL target-byte handling (SPEC §7).

Every probe runs in a fresh, disposable container with no network, a read-only
root filesystem, resource caps, a tmpfs scratch, the target mounted read-only,
and a hard wall-clock timeout. The target is NEVER executed — only our probe
scripts run, over the target's bytes (static/RE only in v1).

Phase 3 adds a **detached, long-lived** container lifecycle (`start_detached` +
poll/reap/stop) for multi-hour fuzz campaigns — the SAME hardening, but the
container runs `docker run -d` and is owned by a durable `fuzz_campaign` row + a
periodic reaper, so it never pins a worker thread and survives a `serve` restart.
Per-container resource ceilings are governed by a `ResourceSpec` (user-tunable,
`unconstrained` lifts mem/cpu/pids ONLY — never a security flag).
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from hexgraph.sandbox.resources import ResourceSpec

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


@dataclass
class DetachedHandle:
    """A handle to a detached, long-lived sandbox container (a fuzz campaign). The
    `name` is the durable, content-stable docker container name persisted on the
    `fuzz_campaign` row — so a `serve` restart re-attaches by name (crash-safe). The
    `outdir` is the host bind-mount the reaper polls for streamed artifacts/stats."""
    name: str
    outdir: str


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

    # ── Shared hardening: the docker flags EVERY container gets ────────────────────
    def _hardening_args(self, *, allow_network: bool, net_container: str | None,
                        resources: ResourceSpec, secret: bool) -> list[str]:
        """The security + resource docker flags shared by run_probe and start_detached.

        The SECURITY flags (`--network none` unless an already-gated network tier,
        `--read-only`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`) are
        UNCONDITIONAL — a ResourceSpec NEVER relaxes them. Only the resource ceilings
        (`--memory`/`--cpus`/`--pids-limit`) come from `resources` and are dropped under
        `unconstrained` (a resource decision, not a security one — design §5.8a)."""
        tmpfs = resources.tmpfs_arg()
        return [
            # Egress is OFF by default; `allow_network` (policy-checked by the caller)
            # swaps in the bridge or joins a rehosted firmware's container netns.
            *(["--network", f"container:{net_container}" if net_container else "bridge"]
              if allow_network else ["--network", "none"]),
            "--read-only",
            # Defense-in-depth at the hostile-target boundary: no Linux capabilities,
            # no privilege escalation, pin the unprivileged uid. UNCONDITIONAL.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "1000:1000",
            # Resource ceilings — the ONLY flags a ResourceSpec governs (empty under
            # `unconstrained`, so the container can use the whole host).
            *resources.docker_resource_args(),
            # mode=1777 (world-writable + sticky) so the non-root probe can create
            # files; exec so a compiled fuzzer/PoC can run.
            "--tmpfs", f"/scratch:rw,exec,mode=1777,size={tmpfs}",
            "--tmpfs", f"/tmp:rw,exec,mode=1777,size={tmpfs}",
            "--workdir", "/scratch",
            "-e", "HOME=/scratch",
            "-e", "TMPDIR=/scratch",
            "-e", "XDG_CACHE_HOME=/scratch",
            "-e", "XDG_CONFIG_HOME=/scratch",
            *(["-e", "HG_CHANNEL_SECRET"] if secret else []),
        ]

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
        secret: dict | None = None,
        resources: ResourceSpec | None = None,
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

        `secret` (a JSON-able dict) is delivered to the probe via the `HG_CHANNEL_SECRET`
        env var instead of the argv — so credentials NEVER appear on the docker command
        line (visible via `ps`/`/proc/<pid>/cmdline`). The probe reads + merges it.

        `resources` (a ResourceSpec) overrides the per-container ceilings (mem/cpu/pids/
        tmpfs/timeout); `unconstrained` lifts mem/cpu/pids ONLY (never a security flag).
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

        resources = resources or ResourceSpec()
        timeout = resources.timeout or self.timeout
        name = f"hexgraph-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            *self._hardening_args(allow_network=allow_network, net_container=net_container,
                                  resources=resources, secret=bool(secret)),
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

        run_env = None
        if secret:
            # The secret value lives ONLY in the child docker process's environment,
            # keyed by the name we passed via `-e HG_CHANNEL_SECRET` above. Never on argv.
            run_env = {**os.environ, "HG_CHANNEL_SECRET": json.dumps(secret)}

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  env=run_env)
        except subprocess.TimeoutExpired as exc:
            subprocess.run(["docker", "kill", name], capture_output=True)
            target = artifact.name if artifact is not None else "live channel"
            raise SandboxTimeout(f"probe {probe} exceeded {timeout}s on {target}") from exc
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
        resources: ResourceSpec | None = None,
    ) -> dict:
        """Run a probe whose stdout is a single JSON object, and parse it."""
        result = self.run_probe(
            probe, artifact, outdir=outdir, extra_args=extra_args,
            requires_execution=requires_execution, extra_ro_mounts=extra_ro_mounts,
            allow_network=allow_network, resources=resources,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc

    def run_channel_probe(self, probe: str, *, channel: dict, outdir: str | Path | None = None,
                          extra_args: list[str] | None = None, net_container: str | None = None,
                          secret: dict | None = None) -> dict:
        """Run a probe that talks to a live Channel — no artifact file is mounted; the
        connection descriptor (incl. the per-run egress allowlist) is passed as
        `--channel <json>`. Runs with bounded egress (policy-checked). `net_container` joins
        a rehosted firmware's container netns to reach its emulated device IP. The CALLER
        must already have asserted `assert_allows_egress` + recorded the audit event.

        `secret` carries any sensitive channel fields (e.g. SSH/telnet creds): it is NOT
        put in `--channel`/argv but delivered via the `HG_CHANNEL_SECRET` env var, so it
        cannot leak through the world-readable docker command line. The probe merges it
        back onto the channel."""
        result = self.run_probe(
            probe, None, outdir=outdir,
            extra_args=["--channel", json.dumps(channel), *(extra_args or [])],
            allow_network=True, net_container=net_container, secret=secret,
        )
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc

    # ── Detached, long-lived containers (fuzz campaigns — design §5.5) ─────────────

    def start_detached(
        self,
        probe: str,
        artifact: str | Path | None,
        *,
        name: str,
        outdir: str | Path,
        image: str | None = None,
        extra_args: list[str] | None = None,
        requires_execution: bool = False,
        extra_ro_mounts: list[tuple[str, str]] | None = None,
        resources: ResourceSpec | None = None,
    ) -> DetachedHandle:
        """Launch a probe as a DETACHED, long-lived container (`docker run -d`), same
        hardening as run_probe. The launcher returns IMMEDIATELY with a handle whose
        `name` is durable, so the reaper (a periodic worker job) and a `serve`-restart
        re-attach by name (crash-safe). The container streams artifacts/stats to the
        `/out` bind-mount as it runs; nothing blocks a worker thread.

        Used ONLY for fuzz campaigns: `requires_execution=True` hits the exec gate (a
        fuzz campaign runs the instrumented target), `--network none` still holds.
        Resource ceilings come from `resources` (or the campaign's ResourceSpec)."""
        if requires_execution:
            from hexgraph.policy import assert_allows_execution

            assert_allows_execution()
        if artifact is not None:
            artifact = Path(artifact).resolve()
            if not artifact.is_file():
                raise SandboxError(f"artifact not found: {artifact}")

        resources = resources or ResourceSpec()
        outdir = Path(outdir).resolve()
        outdir.mkdir(parents=True, exist_ok=True)
        cmd = [
            "docker", "run", "-d", "--name", name,
            # NOT --rm: a detached campaign container is reaped explicitly so its exit
            # status is observable. The reaper `docker rm`s it on finalize.
            *self._hardening_args(allow_network=False, net_container=None,
                                  resources=resources, secret=False),
            *(["-v", f"{artifact}:/artifact:ro"] if artifact is not None else []),
            "-v", f"{outdir}:/out:rw",
        ]
        probe_args = (["/artifact"] if artifact is not None else []) + ["/out"]
        for host, cont in (extra_ro_mounts or []):
            cmd += ["-v", f"{Path(host).resolve()}:{cont}:ro"]
        if extra_args:
            probe_args += extra_args
        if PROBES_DIR.is_dir() and os.environ.get("HEXGRAPH_SANDBOX_NO_MOUNT") != "1":
            cmd += ["-v", f"{PROBES_DIR}:{CONTAINER_PROBES}:ro"]
        cmd += [image or self.image, "python3", f"{CONTAINER_PROBES}/{probe}", *probe_args]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            raise SandboxError(f"failed to launch detached container: {exc}") from exc
        if proc.returncode != 0:
            raise SandboxError(f"detached container start failed: {proc.stderr.strip()[:500]}")
        return DetachedHandle(name=name, outdir=str(outdir))

    def poll_detached(self, name: str) -> dict:
        """The status of a detached container by name. Returns
        {exists, running, exit_code} — the reaper uses this to know when a campaign's
        container has finished (so it can finalize)."""
        try:
            proc = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{.State.Running}} {{.State.ExitCode}}", name],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return {"exists": False, "running": False, "exit_code": None}
        if proc.returncode != 0:
            return {"exists": False, "running": False, "exit_code": None}
        parts = proc.stdout.strip().split()
        running = parts[0].lower() == "true" if parts else False
        try:
            exit_code = int(parts[1]) if len(parts) > 1 else None
        except ValueError:
            exit_code = None
        return {"exists": True, "running": running, "exit_code": exit_code}

    def stop_detached(self, name: str, *, remove: bool = True, timeout: int = 10) -> None:
        """Kill (and by default remove) a detached container. Best-effort + idempotent
        — a missing container is fine (the reaper may have already reaped it). The
        corpus on the `/out` bind-mount survives, so a campaign is resumable."""
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=timeout)
        if remove:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=timeout)
