"""The `RemoteDockerExecutor` — run sandboxed work on a user-owned REMOTE Docker host
(design §5.8b, Phase 6).

The Executor seam's docstring always anticipated "a future RemoteExecutor … drops in
without touching task code." This is the lowest-lift route: target a Docker host the
user owns via **DOCKER_HOST** (`ssh://user@beefybox` over an SSH control socket, or
`tcp://host:port` + TLS client certs). Because the Builder/Fuzzer call
`Executor.run_probe`/`start_detached`, building and fuzzing run on the remote with NO
fuzzer/builder code change — the seam is the entire point.

**The one real difference from local Docker: bind-mounts don't cross the connection.**
A `-v /host/path:/in` over a remote DOCKER_HOST refers to the *remote* daemon's
filesystem, not ours. So inputs (the probe scripts, the target artifact, extra RO
inputs, the seed corpus) are **CAS-staged into a per-run named VOLUME on the remote**
via `docker cp` (content-addressed ⇒ dedups, cache-friendly), and the reaper **streams
the `/out` directory back** via `docker cp` from the (detached) container — exactly the
artifact/coverage/stats flow a local detached campaign gets, just over the wire.

**Security boundary is UNCHANGED on the remote.** Every container still runs
`--read-only`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`, the resource
caps, and `--network none` (except the gated net-fuzz tier) — the SAME `_hardening_args`
the local runner builds. Hostile bytes only ever materialize inside the container, now
on a host the user chose. The control plane (API/UI) stays bound to 127.0.0.1; the
remote is purely a compute backend.

**Trust + secrets.** Selecting a remote environment is gated by `features.fuzz_remote`
(the only place — `policy.assert_allows_fuzz_remote`). The connection details
(`DOCKER_HOST`, SSH key/password, TLS certs) are a SECRET read from env/config.toml
keyed by the environment id — NEVER stored in the DB, NEVER logged, reported
presence-only (same discipline as the SSH/telnet remote creds). The connection is
audited.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import uuid
from pathlib import Path

from dataclasses import dataclass, field

from hexgraph.sandbox.resources import resource_spec_for
from hexgraph.sandbox.runner import (
    DEFAULT_TIMEOUT,
    PROBES_DIR,
    DetachedHandle,
    RunResult,
    SandboxError,
    SandboxRunner,
    SandboxTimeout,
)

# Subdir names inside the per-run staging VOLUME (mounted at /stage in the container).
# The probe reads /stage/probes/<probe>.py, /stage/artifact_file, writes /stage/out.
_STAGE_ARTIFACT = "artifact"
_STAGE_OUT = "out"
_STAGE_PROBES = "probes"
_STAGE_EXTRA = "extra"


@dataclass
class _Staged:
    vol: str
    extras: list[tuple[int, str]] = field(default_factory=list)


class RemoteDockerExecutor(SandboxRunner):
    """An Executor that runs probes/campaigns on a remote Docker daemon over DOCKER_HOST.

    Reuses SandboxRunner's `_hardening_args` (so the security/resource flags are
    byte-identical to local) and its `poll`/`stop` shapes; overrides the mount strategy
    to CAS-stage inputs into a remote volume and stream `/out` back via `docker cp`.

    `docker_host` is the SECRET connection string (ssh://… or tcp://…). It is held only
    on the instance, passed to the docker subprocess via the env, and NEVER logged (the
    error paths below scrub it)."""

    def __init__(self, docker_host: str, *, image: str | None = None,
                 timeout: int = DEFAULT_TIMEOUT, tls_env: dict | None = None) -> None:
        super().__init__(image=image, timeout=timeout)
        if not (docker_host or "").strip():
            raise SandboxError("RemoteDockerExecutor needs a DOCKER_HOST connection string")
        self._docker_host = docker_host
        # Optional TLS env (DOCKER_TLS_VERIFY / DOCKER_CERT_PATH) for a tcp:// + certs
        # endpoint — also secret, also only on the instance / subprocess env.
        self._tls_env = dict(tls_env or {})

    # ── connection env (secret — never logged) ─────────────────────────────────────
    def _env(self) -> dict:
        env = {**os.environ, "DOCKER_HOST": self._docker_host}
        env.update(self._tls_env)
        return env

    def _scrub(self, text: str) -> str:
        """Strip the secret connection string out of any text we might surface in an
        error (defense-in-depth: the docker CLI rarely echoes DOCKER_HOST, but never
        leak it through an exception message)."""
        out = text or ""
        if self._docker_host:
            out = out.replace(self._docker_host, "<docker-host>")
        for v in self._tls_env.values():
            if v:
                out = out.replace(str(v), "<redacted>")
        return out

    def _docker(self, args: list[str], *, timeout: int, check: bool = True,
                input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(["docker", *args], capture_output=True,
                                  timeout=timeout, env=self._env(), input=input_bytes)
        except subprocess.TimeoutExpired as exc:
            raise SandboxTimeout(f"remote docker {args[0]} timed out after {timeout}s") from exc
        except OSError as exc:
            raise SandboxError(f"failed to launch docker for remote host: {exc}") from exc
        if check and proc.returncode != 0:
            err = self._scrub((proc.stderr or b"").decode(errors="replace")[:500])
            raise SandboxError(f"remote docker {args[0]} failed: {err}")
        return proc

    # ── health-check (reachable / authorized / image present) ───────────────────────
    def health(self, image: str | None = None) -> dict:
        """Probe the remote: is it reachable + authorized, and is the fuzz image present?
        Returns a NON-SECRET dict for the Settings indicator. Never raises — a failure is
        reported as `ok: False` with a scrubbed detail."""
        img = image or self.image
        out = {"ok": False, "reachable": False, "authorized": False,
               "image_present": False, "docker_version": None, "image": img, "detail": ""}
        try:
            v = self._docker(["version", "--format", "{{.Server.Version}}"],
                             timeout=20, check=False)
            if v.returncode != 0:
                out["detail"] = self._scrub((v.stderr or b"").decode(errors="replace")[:300]) \
                    or "could not reach/authorize the remote docker daemon"
                # A reachable-but-unauthorized daemon still answers TCP/SSH but errors on
                # the API; we can't always distinguish, so report not-reachable+detail.
                return out
            out["reachable"] = True
            out["authorized"] = True
            out["docker_version"] = (v.stdout or b"").decode(errors="replace").strip() or None
            insp = self._docker(["image", "inspect", img], timeout=20, check=False)
            out["image_present"] = insp.returncode == 0
            out["ok"] = out["image_present"]
            out["detail"] = ("ready" if out["image_present"]
                             else f"reachable + authorized, but {img} is not present "
                                  "(run a one-time `docker pull`/`docker build` on the remote)")
        except SandboxError as exc:
            out["detail"] = self._scrub(str(exc))[:300]
        return out

    # ── staging (CAS-staged transfer in / artifact stream-back out) ─────────────────
    def _stage_volume(self, *, artifact, extra_ro_mounts) -> "_Staged":
        """Create a per-run named VOLUME on the remote and populate it via `docker cp`
        through a transient helper container: the probe scripts → /stage/probes, the
        target artifact → /stage/artifact_file, each extra RO input → /stage/extra_<i>,
        and an empty /stage/out for streamed results. The volume is mounted at /stage in
        the probe container — writable even under `--read-only` rootfs (so hostile bytes
        never touch the read-only root, and we never need a host bind-mount, which can't
        cross a remote DOCKER_HOST). `docker cp` is content-cache-friendly. Returns the
        staging descriptor (volume name + the extra-mount container paths)."""
        vol = f"hexgraph-stage-{uuid.uuid4().hex[:12]}"
        self._docker(["volume", "create", vol], timeout=30)
        helper = f"hexgraph-stage-helper-{uuid.uuid4().hex[:12]}"
        # A short-lived holder so `docker cp` can write into the volume (you cp into a
        # container path, not a bare volume). The same image is guaranteed present.
        self._docker(["create", "--name", helper, "-v", f"{vol}:/stage",
                      self.image, "true"], timeout=60)
        try:
            # Pre-create /stage/out so the stream-back always has a directory to copy.
            with tempfile.TemporaryDirectory(prefix="hexgraph-stage-") as tmp:
                out_marker = Path(tmp) / _STAGE_OUT
                out_marker.mkdir()
                self._docker(["cp", f"{out_marker}/.", f"{helper}:/stage/{_STAGE_OUT}"],
                             timeout=60, check=False)
            if PROBES_DIR.is_dir() and os.environ.get("HEXGRAPH_SANDBOX_NO_MOUNT") != "1":
                self._docker(["cp", f"{PROBES_DIR}/.", f"{helper}:/stage/{_STAGE_PROBES}"],
                             timeout=300)
            if artifact is not None:
                self._docker(["cp", str(Path(artifact).resolve()),
                              f"{helper}:/stage/{_STAGE_ARTIFACT}_file"], timeout=600)
            extras: list[tuple[int, str]] = []
            for i, (host, cont) in enumerate(extra_ro_mounts or []):
                self._docker(["cp", str(Path(host).resolve()),
                              f"{helper}:/stage/{_STAGE_EXTRA}_{i}"], timeout=600)
                extras.append((i, cont))
        finally:
            self._docker(["rm", "-f", helper], timeout=30, check=False)
        # `docker cp` lands files owned by root; the probe container runs as --user 1000
        # and must WRITE /stage/out, so world-write the staged tree (a STAGING step on our
        # own trusted inputs — NOT the hostile-bytes container, which still runs as 1000).
        # `/stage/out` becomes 1777 so the non-root probe streams results into it.
        self._docker(["run", "--rm", "--user", "0", "-v", f"{vol}:/stage", self.image,
                      "chmod", "-R", "0777", "/stage"], timeout=120, check=False)
        return _Staged(vol=vol, extras=extras)

    def _tmpfs_for_extras(self, extras: list[tuple[int, str]]) -> list[str]:
        """`--tmpfs` flags for each distinct PARENT dir of an extra-mount destination, so
        the wrapper can copy the staged input there under the `--read-only` rootfs (only
        tmpfs / the /stage volume are writable). e.g. /seeds/seed_0 → `--tmpfs /seeds`."""
        parents = sorted({str(Path(cont).parent) for _i, cont in extras
                          if str(Path(cont).parent) not in ("/", "/scratch", "/tmp", "/out", "/stage")})
        args: list[str] = []
        for p in parents:
            args += ["--tmpfs", f"{p}:rw,exec,mode=1777"]
        return args

    def _wrap_cmd(self, probe: str, *, extras: list[tuple[int, str]],
                  probe_args: list[str]) -> list[str]:
        """The container reads its inputs from the /stage VOLUME and writes results to
        /stage/out. Extra RO inputs the probe expects at a fixed path (e.g. /target.so,
        /seeds/seed_0) are copied from the staged volume into a writable tmpfs we mounted
        at their parent (`_tmpfs_for_extras`). The probe runs from /stage/probes.

        Every interpolated token (probe args like `--channel <json>` / `--spec <json>`,
        the extra-mount paths) is shlex-quoted so a value with spaces/quotes/shell
        metacharacters is passed to the probe as a SINGLE argv token — matching the local
        runner's argv-list semantics exactly (no word-splitting, no injection)."""
        lines = ["set -e"]
        for i, cont in extras:
            lines.append(f"cp -a /stage/extra_{i} {shlex.quote(cont)}")
        argv = " ".join(shlex.quote(tok) for tok in
                        ["python3", f"/stage/{_STAGE_PROBES}/{probe}", *probe_args])
        lines.append(argv)
        return ["sh", "-c", "; ".join(lines)]

    # ── one-shot probe ──────────────────────────────────────────────────────────────
    def run_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                  requires_execution=False, extra_ro_mounts=None, allow_network=False,
                  net_container=None, secret=None, resources=None, network_gate="network",
                  image=None, project_mount=None) -> RunResult:
        if project_mount is not None:
            # The persistent Ghidra project cache (engine.re.ghidra_project) lives on the LOCAL
            # data dir; a writable cross-host project mount is not wired for the staged-volume
            # remote path. Fail loud rather than silently re-analyzing every call on the remote.
            raise SandboxError(
                "the persistent Ghidra project cache (project_mount) is only supported on the "
                "local docker executor; run Ghidra decompilation locally or disable the cache")
        if requires_execution:
            from hexgraph.policy import assert_allows_execution
            assert_allows_execution()
        if allow_network:
            from hexgraph.sandbox.runner import _assert_network_gate
            _assert_network_gate(network_gate)  # "build_fetch" re-checks features.build_fetch, not features.network
        if artifact is not None:
            artifact = Path(artifact).resolve()
            if not artifact.is_file():
                raise SandboxError(f"artifact not found: {artifact}")
        resources = resources or resource_spec_for("sandbox")
        timeout = resources.timeout or self.timeout
        name = f"hexgraph-{uuid.uuid4().hex[:12]}"
        local_out = Path(outdir).resolve() if outdir is not None else None

        staged = self._stage_volume(artifact=artifact, extra_ro_mounts=extra_ro_mounts)
        probe_args = ([f"/stage/{_STAGE_ARTIFACT}_file"] if artifact is not None else []) + \
                     ([f"/stage/{_STAGE_OUT}"] if local_out is not None else []) + list(extra_args or [])
        wrap = self._wrap_cmd(probe, extras=staged.extras, probe_args=probe_args)
        cmd = ["run", "--rm", "--name", name,
               *self._hardening_args(allow_network=allow_network, net_container=net_container,
                                     resources=resources, secret=bool(secret)),
               *self._tmpfs_for_extras(staged.extras),
               "-v", f"{staged.vol}:/stage", image or self.image, *wrap]
        # HG_CHANNEL_SECRET rides the docker subprocess env (the `-e` flag was declared by
        # _hardening_args); it lives ONLY in the child docker process env, never on argv.
        env = self._env()
        if secret:
            env = {**env, "HG_CHANNEL_SECRET": json.dumps(secret)}
        try:
            proc = subprocess.run(["docker", *cmd], capture_output=True, text=True,
                                  timeout=timeout, env=env)
        except subprocess.TimeoutExpired as exc:
            self._docker(["kill", name], timeout=20, check=False)
            if local_out is not None:
                self._stream_back_vol(staged.vol, local_out)
            self._docker(["volume", "rm", "-f", staged.vol], timeout=30, check=False)
            raise SandboxTimeout(f"probe {probe} exceeded {timeout}s on the remote") from exc
        except OSError as exc:
            self._docker(["volume", "rm", "-f", staged.vol], timeout=30, check=False)
            raise SandboxError(f"failed to launch remote docker: {exc}") from exc
        if proc.returncode != 0:
            self._docker(["volume", "rm", "-f", staged.vol], timeout=30, check=False)
            raise SandboxError(
                f"probe {probe} failed on the remote (exit {proc.returncode}): "
                f"{self._scrub(proc.stderr.strip()[:500])}")
        # Stream the results back BEFORE GC'ing the volume (`--rm` already removed the
        # container, so we read /out from the volume via a tiny helper).
        if local_out is not None:
            self._stream_back_vol(staged.vol, local_out)
        self._docker(["volume", "rm", "-f", staged.vol], timeout=30, check=False)
        return RunResult(proc.returncode, proc.stdout, proc.stderr,
                         str(local_out) if local_out else None)

    def run_json_probe(self, probe, artifact, *, outdir=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, allow_network=False,
                       resources=None, project_mount=None) -> dict:
        result = self.run_probe(probe, artifact, outdir=outdir, extra_args=extra_args,
                                requires_execution=requires_execution,
                                extra_ro_mounts=extra_ro_mounts, allow_network=allow_network,
                                resources=resources, project_mount=project_mount)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise SandboxError(f"probe {probe} did not emit valid JSON: {exc}") from exc

    def run_channel_probe(self, probe, *, channel, outdir=None, extra_args=None,
                          net_container=None, secret=None) -> dict:
        # A live-channel probe (no artifact at rest) — supported on the remote too: stage
        # nothing but the probes, run with bounded egress on the remote's network.
        return self.run_json_probe(
            probe, None, outdir=outdir,
            extra_args=["--channel", json.dumps(channel), *(extra_args or [])],
            allow_network=True,
        )

    # ── detached, long-lived campaign container ─────────────────────────────────────
    def start_detached(self, probe, artifact, *, name, outdir, image=None, extra_args=None,
                       requires_execution=False, extra_ro_mounts=None, resources=None,
                       allow_network=False, net_container=None, disable_aslr=False) -> DetachedHandle:
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
        resources = resources or resource_spec_for("sandbox")
        local_out = Path(outdir).resolve()
        local_out.mkdir(parents=True, exist_ok=True)

        staged = self._stage_volume(artifact=artifact, extra_ro_mounts=extra_ro_mounts)
        probe_args = ([f"/stage/{_STAGE_ARTIFACT}_file"] if artifact is not None else []) + \
                     [f"/stage/{_STAGE_OUT}"] + list(extra_args or [])
        wrap = self._wrap_cmd(probe, extras=staged.extras, probe_args=probe_args)
        # Label the container with its staging volume + local outdir so poll/stop are
        # STATELESS — a fresh executor instance (the reaper builds one per call) and a
        # serve restart re-attach by name alone, recovering where to stream + what to GC
        # from the remote daemon's own labels (crash-safe, no in-process state).
        cmd = ["run", "-d", "--name", name,
               "--label", f"hexgraph_stage_vol={staged.vol}",
               "--label", f"hexgraph_outdir={local_out}",
               *self._hardening_args(allow_network=allow_network, net_container=net_container,
                                     resources=resources, secret=False, disable_aslr=disable_aslr),
               *self._tmpfs_for_extras(staged.extras),
               "-v", f"{staged.vol}:/stage", image or self.image, *wrap]
        self._docker(cmd, timeout=120)
        return DetachedHandle(name=name, outdir=str(local_out))

    def _labels(self, name: str) -> dict:
        """The hexgraph_* labels on a detached container (the stateless re-attach handle:
        the staging volume + the local outdir to stream results back to)."""
        try:
            proc = self._docker(
                ["inspect", "-f",
                 "{{index .Config.Labels \"hexgraph_stage_vol\"}}|{{index .Config.Labels \"hexgraph_outdir\"}}",
                 name], timeout=30, check=False)
        except SandboxError:
            return {}
        if proc.returncode != 0:
            return {}
        raw = (proc.stdout or b"").decode(errors="replace").strip()
        vol, _, outdir = raw.partition("|")
        return {"vol": vol or None, "outdir": outdir or None}

    def poll_detached(self, name: str) -> dict:
        """Status of a detached remote container, AND stream its `/stage/out` back to the
        local outdir (recovered from the container label) so the reaper ingests artifacts/
        stats exactly as for a local campaign. Idempotent — polled repeatedly."""
        labels = self._labels(name)
        if labels.get("outdir"):
            self._stream_back_container(name, Path(labels["outdir"]))
        try:
            proc = self._docker(["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", name],
                                timeout=30, check=False)
        except SandboxError:
            return {"exists": False, "running": False, "exit_code": None}
        if proc.returncode != 0:
            return {"exists": False, "running": False, "exit_code": None}
        parts = (proc.stdout or b"").decode(errors="replace").strip().split()
        running = parts[0].lower() == "true" if parts else False
        try:
            exit_code = int(parts[1]) if len(parts) > 1 else None
        except ValueError:
            exit_code = None
        return {"exists": True, "running": running, "exit_code": exit_code}

    def stop_detached(self, name: str, *, remove: bool = True, timeout: int = 10) -> None:
        # Recover the outdir + staging volume from the container labels (stateless), final
        # stream-back so a stopped campaign keeps its corpus/artifacts locally, then GC.
        labels = self._labels(name)
        if labels.get("outdir"):
            self._stream_back_container(name, Path(labels["outdir"]))
        self._docker(["kill", name], timeout=timeout + 10, check=False)
        if remove:
            self._docker(["rm", "-f", name], timeout=timeout + 10, check=False)
        if labels.get("vol"):
            self._docker(["volume", "rm", "-f", labels["vol"]], timeout=30, check=False)

    def _stream_back_container(self, name: str, local_out: Path) -> None:
        """Copy a RUNNING/exited container's `/stage/out` back to the local outdir via
        `docker cp` (the artifact/coverage/stats stream-back over the same connection).
        Best-effort + idempotent."""
        try:
            local_out.mkdir(parents=True, exist_ok=True)
            self._docker(["cp", f"{name}:/stage/{_STAGE_OUT}/.", str(local_out)],
                         timeout=300, check=False)
        except SandboxError:
            pass

    def _stream_back_vol(self, vol: str, local_out: Path) -> None:
        """Copy a staging volume's `out/` back to the local outdir via a transient helper
        (used by the one-shot run_probe, whose `--rm` container is already gone)."""
        local_out.mkdir(parents=True, exist_ok=True)
        helper = f"hexgraph-back-{uuid.uuid4().hex[:12]}"
        try:
            self._docker(["create", "--name", helper, "-v", f"{vol}:/stage", self.image, "true"],
                         timeout=60, check=False)
            self._docker(["cp", f"{helper}:/stage/{_STAGE_OUT}/.", str(local_out)],
                         timeout=300, check=False)
        finally:
            self._docker(["rm", "-f", helper], timeout=30, check=False)
