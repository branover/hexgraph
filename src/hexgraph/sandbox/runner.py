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

from hexgraph.sandbox.resources import (
    ResourceSpec,
    resource_spec_for,
    resource_spec_for_artifact,
)

DEFAULT_IMAGE = "hexgraph-sandbox:latest"
DEFAULT_TIMEOUT = 300  # seconds
PROBES_DIR = Path(__file__).resolve().parent / "probes"
CONTAINER_PROBES = "/opt/hexgraph"
# The persistent Ghidra-project bind-mount point inside the container (analyze-once / reuse,
# engine.re.ghidra_project). A single bounded WRITABLE volume of HexGraph's own data — must match
# engine.re.ghidra_project.CONTAINER_PROJECT_DIR.
CONTAINER_PROJECT_DIR = "/ghidra-project"
# The unprivileged uid:gid every sandbox container runs as — UNCONDITIONAL hardening,
# never root. Kept as a constant (not a bare literal) so the host-side `/out` bind-mount
# can be made writable by exactly this uid no matter what the host process's own uid is
# (see _ensure_outdir_writable). The remote executor stages its volume for this same uid.
SANDBOX_UID = 1000
SANDBOX_GID = 1000
# A minimal seccomp profile: byte-for-byte Docker's default deny-by-errno profile PLUS a
# single extra rule allowing `personality(ADDR_NO_RANDOMIZE)`. Used ONLY by the ASan
# source-fuzz path (disable_aslr) so `setarch -R` can turn ASLR off for the instrumented
# target (Docker's default profile filters out exactly that one personality arg value).
# Provenance: github.com/moby/profiles seccomp/default.json + the one personality rule.
SECCOMP_ASLR_PROFILE = Path(__file__).resolve().parent / "seccomp" / "fuzz-aslr.json"


def _seccomp_aslr_profile() -> str:
    """Absolute path to the minimal ASLR-disable seccomp profile (default + one
    personality allow). Fails loudly if it's missing — better than silently running
    seccomp=unconfined."""
    if not SECCOMP_ASLR_PROFILE.is_file():
        raise SandboxError(f"seccomp profile not found: {SECCOMP_ASLR_PROFILE}")
    return str(SECCOMP_ASLR_PROFILE)


def _ensure_outdir_writable(path: Path) -> None:
    """Make the host-side `/out` bind-mount writable by the sandbox container's uid.

    The container always runs as ``--user 1000:1000`` (non-root, UNCONDITIONAL). The host
    process, though, creates the out-dir as ITS OWN uid/gid — which equals 1000 only by
    luck. On any host whose uid != 1000 (a fresh user account, a CI runner, a packaged
    service) the container then can't create ``/out/<file>`` and every extract/exec path
    dies with EACCES. Grant access by uid/gid, WITHOUT weakening the container and WITHOUT
    opening the dir to other local users:

      * effective uid == 1000 → already owned by the container uid; nothing to do.
      * effective uid is root → chown the dir to 1000 (we hold the privilege; tightest).
      * otherwise             → make the dir group-writable at ``0o770`` (owner+group only,
                                no "other"). The dir's group is the host's own gid, and
                                ``_hardening_args`` adds that gid to the container with
                                ``--group-add`` so the container writes via the group.

    The ``0o770`` matters: a bare ``0o777`` would expose the per-run out-dir (extracted
    firmware, PoC/fuzz output) to ANY local user, because the real out-dir roots are not
    private — poc/fuzz/build use ``tempfile.mkdtemp()`` under ``/tmp`` (1777), and
    ``HEXGRAPH_HOME``/``projects/`` are created at 0o755. Group-write keeps access to the
    host user + the container's added gid only. (Caveat: on a host whose effective gid is a
    BROAD shared primary group — uncommon under modern per-user-group defaults — that
    group's members could also reach the per-run dir; a packaged/multi-user deployment
    should run HexGraph under a private group.) Only the host-side bind-mount dir changes;
    the container's ``--user``, dropped caps, read-only rootfs and ``--network none`` are
    untouched.
    """
    if not hasattr(os, "geteuid"):  # non-POSIX host: bind-mount uid semantics don't apply
        return
    euid = os.geteuid()
    if euid == SANDBOX_UID:
        return
    if euid == 0:
        os.chown(path, SANDBOX_UID, SANDBOX_GID)
    else:
        # The dir's group is the host's egid (set at mkdir); the container joins that gid
        # via --group-add (see _hardening_args). Group-write, NO "other" — so no exposure.
        os.chmod(path, 0o770)


def _probe_failure_message(probe: str, returncode: int, stdout: str, stderr: str) -> str:
    """Build a legible failure message for a non-zero probe exit.

    Probes emit a JSON `{"error": "<real reason>"}` on their failure paths (e.g.
    ghidra_probe's "Ghidra not installed … rebuild with WITH_GHIDRA=1" or the
    analyzeHeadless log tail). The old swallow point dropped that and surfaced only
    `stderr` — which for analyzeHeadless is EMPTY (it logs to stdout), so the operator
    got a bare `exit N`. Lead with the probe's own actionable reason when present,
    falling back to a captured-output tail, and always keep the exit code visible.
    """
    reason = ""
    out = (stdout or "").strip()
    if out:
        # The error JSON is usually the whole/last line of stdout; try the last
        # non-empty line first, then the whole buffer.
        for candidate in (out.splitlines()[-1], out):
            try:
                obj = json.loads(candidate)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(obj, dict) and obj.get("error"):
                reason = str(obj["error"]).strip()
                break
    if not reason:
        # No structured reason — fall back to a tail of whatever the probe printed
        # (stderr first, then stdout) so the caller still sees the real cause.
        reason = (stderr or "").strip()[:500] or out[:500]
    base = f"probe {probe} failed (exit {returncode})"
    return f"{base}: {reason}" if reason else base


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


def _image_created_epoch(image: str) -> float | None:
    """The build time of a local docker image as a POSIX timestamp, or None.

    Reads `docker image inspect <image> --format {{.Created}}` (an RFC-3339 / ISO-8601
    timestamp like `2026-06-01T12:34:56.789012345Z`). Returns None when docker is absent,
    the image isn't built, or the date can't be parsed — never raises. Docker reports
    nanosecond precision and a trailing `Z`; Python's `datetime.fromisoformat` only handles
    microseconds (and, before 3.11, not `Z`), so we normalise both before parsing."""
    import shutil
    from datetime import datetime, timezone

    if not shutil.which("docker"):
        return None
    try:
        proc = subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{.Created}}"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    raw = (proc.stdout or "").strip()
    if not raw:
        return None
    # Normalise: trailing 'Z' → '+00:00', and truncate sub-second precision to the
    # 6 digits fromisoformat accepts (docker emits up to 9 / nanoseconds).
    ts = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    if "." in ts:
        head, _, tail = ts.partition(".")
        frac = tail
        tzpart = ""
        for sign in ("+", "-"):
            if sign in tail:
                frac, tzpart = tail.split(sign, 1)
                tzpart = sign + tzpart
                break
        ts = f"{head}.{frac[:6]}{tzpart}"
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _toolchain_source_epoch() -> float | None:
    """When the sandbox image's TOOLCHAIN source last CHANGED, as a POSIX epoch — the git
    COMMIT time of `docker/sandbox.Dockerfile`, NOT its filesystem mtime.

    Filesystem mtime is the wrong signal: a fresh `git clone` / `git worktree add` /
    `git checkout` stamps every file with the CHECKOUT time, which would make a perfectly good
    image read 'stale' the moment you clone. The Dockerfile's last-commit time is
    checkout-independent and is the real 'toolchain changed' moment. The probes baked in by the
    Dockerfile's `COPY` are DELIBERATELY excluded — they mount read-only at run time
    (`PROBES_DIR`), so editing/adding a probe needs no rebuild (CLAUDE.md is explicit).

    Returns None (→ staleness reads 'unknown', never a false alarm) when git isn't available,
    the source isn't a git checkout, or the Dockerfile isn't tracked (e.g. an installed wheel
    with no source). A purely-local UNCOMMITTED Dockerfile edit isn't reflected (it reports the
    last commit) — acceptable: a dev editing the toolchain already knows to rebuild. Never raises."""
    try:
        from hexgraph.paths import repo_root

        root = repo_root()
        dockerfile = root / "docker" / "sandbox.Dockerfile"
        if not dockerfile.is_file():
            return None
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%ct", "--",
             "docker/sandbox.Dockerfile"],
            capture_output=True, text=True, timeout=10,
        )
        ts = proc.stdout.strip()
        if proc.returncode != 0 or not ts:
            return None
        return float(ts)
    except Exception:  # noqa: BLE001 — locating/reading source must never crash a health check
        return None


def sandbox_image_staleness(image: str | None = None) -> bool | None:
    """Is the local sandbox image OLDER than its toolchain source (so a rebuild is due)?

    Compares the image's build time (`docker image inspect … {{.Created}}`) against the
    git COMMIT time of the toolchain source (`docker/sandbox.Dockerfile`). This is the
    PROACTIVE counterpart to `meta_check_features` (which catches a broken/missing dep
    REACTIVELY by probing the image at run time): here we flag, at setup time, that an
    otherwise-present image predates the Dockerfile and silently lacks newer tools.

    Tri-state, never raises:
      * True  — the image is STALE (built before the Dockerfile's last commit); rebuild it.
      * False — the image is FRESH (built at/after the Dockerfile's last commit).
      * None  — UNKNOWN: docker absent, image not built, the date can't be read, or the
                Dockerfile's commit time can't be read (git absent / not a checkout / a wheel).

    The git COMMIT time (not the filesystem mtime) is used deliberately, so a fresh clone or
    worktree doesn't falsely read 'stale'. Probes are NOT part of the comparison (mounted at
    run time, no rebuild needed) — see `_toolchain_source_epoch`."""
    image = image or sandbox_image()
    created = _image_created_epoch(image)
    if created is None:
        return None
    src_epoch = _toolchain_source_epoch()
    if src_epoch is None:
        return None
    return created < src_epoch


def _assert_network_gate(network_gate: str) -> None:
    """The runner's defense-in-depth egress re-check (on top of the caller's assert).
    `"build_fetch"` re-checks the SEPARATE bounded-fetch tier (features.build_fetch) — a
    registry-allowlisted fetch is NOT the local-network tier, so requiring features.network
    here would defeat the separate gate. `"network"` (default) re-checks features.network.
    Both fail closed."""
    if network_gate == "build_fetch":
        from hexgraph.policy import assert_allows_build_fetch

        assert_allows_build_fetch()
        return
    from hexgraph.policy import PolicyViolation, current_policy

    if not current_policy().allow_network:
        raise PolicyViolation("network egress is not permitted by the active policy")


class SandboxRunner:
    def __init__(self, image: str | None = None, timeout: int = DEFAULT_TIMEOUT) -> None:
        self.image = image or sandbox_image()
        self.timeout = timeout

    # ── Shared hardening: the docker flags EVERY container gets ────────────────────
    def _hardening_args(self, *, allow_network: bool, net_container: str | None,
                        resources: ResourceSpec, secret: bool,
                        disable_aslr: bool = False,
                        extra_env: dict[str, str] | None = None) -> list[str]:
        """The security + resource docker flags shared by run_probe and start_detached.

        The SECURITY flags (`--network none` unless an already-gated network tier,
        `--read-only`, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`) are
        UNCONDITIONAL — a ResourceSpec NEVER relaxes them. Only the resource ceilings
        (`--memory`/`--cpus`/`--pids-limit`) come from `resources` and are dropped under
        `unconstrained` (a resource decision, not a security one — design §5.8a).

        `disable_aslr` (set ONLY by the ASan source-fuzz path, via PreparedFuzz) swaps
        Docker's default seccomp profile for a MINIMAL one that is the default PLUS a
        single extra rule allowing `personality(ADDR_NO_RANDOMIZE)`. AFL wraps the
        instrumented target in `setarch -R` to turn ASLR off so ASan's MAP_FIXED shadow
        reservation cannot collide with a randomized mapping (the SIGSEGV-in-ASan-init
        bug on high-`vm.mmap_rnd_bits` kernels — WSL2 6.6.x / Ubuntu 23.10+ / CI runners);
        that one `personality` arg value is the only thing Docker's default profile
        filters out. The relaxation reduces ONLY the target's own address-space
        randomization — it is NOT a sandbox-escape primitive, and every OTHER hardening
        flag below is untouched."""
        tmpfs = resources.tmpfs_arg()
        return [
            # Egress is OFF by default; `allow_network` (policy-checked by the caller)
            # swaps in the bridge or joins a rehosted firmware's container netns.
            *(["--network", f"container:{net_container}" if net_container else "bridge"]
              if allow_network else ["--network", "none"]),
            "--read-only",
            # Run a real PID 1 (Docker's bundled tini) that REAPS orphaned children.
            # Without it the probe's `python3` is PID 1, and a process that is PID 1 does
            # NOT reap reparented orphans. libFuzzer's `-fork=1` / AFL's forkserver kill
            # child fuzzers hard (an ASan abort, or the cgroup OOM-killer) before the child
            # reaps ITS OWN grandchildren (e.g. the `llvm-symbolizer` ASan spawns to
            # symbolize a crash); those grandchildren reparent to PID 1 and, unreaped, pile
            # up as ZOMBIES. Over a crash-dense campaign the zombies exhaust `--pids-limit`
            # until `fork()` returns EAGAIN and the forkserver dies mid-run — the long-
            # observed "fragile forkserver under the hardened sandbox" (empty/truncated
            # crash reports, campaigns wrongly finalized `degraded`). tini reaps them, so
            # the PID table never fills from orphan accumulation. NOT a security relaxation:
            # the daemon injects its own static init, it runs as our `--user`, forwards
            # signals, and propagates the child's exit code (the detached reaper still sees
            # the real status) — every other hardening flag below is untouched.
            "--init",
            # Defense-in-depth at the hostile-target boundary: no Linux capabilities,
            # no privilege escalation, pin the unprivileged uid. UNCONDITIONAL.
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            # Default seccomp UNLESS the ASan source-fuzz path needs ASLR off; then a
            # minimal profile = Docker's default + ONE personality(ADDR_NO_RANDOMIZE)
            # allow (see _seccomp_aslr_profile). The single, narrow, documented relaxation.
            *(["--security-opt", f"seccomp={_seccomp_aslr_profile()}"] if disable_aslr else []),
            "--user", f"{SANDBOX_UID}:{SANDBOX_GID}",
            # When the host uid != 1000 (a fresh account / CI runner / packaged service) the
            # container can't write the host-owned /out bind-mount as uid 1000. Add the host's
            # OWN gid as a supplementary group so it writes a 0o770 group-writable out-dir
            # (see _ensure_outdir_writable) without granting "other" access — and WITHOUT
            # adding the root group (skipped when host is root; that path chowns /out instead).
            *(["--group-add", str(os.getegid())]
              if (hasattr(os, "geteuid") and os.geteuid() not in (0, SANDBOX_UID)) else []),
            # Resource ceilings — the ONLY flags a ResourceSpec governs (empty under
            # `unconstrained`, so the container can use the whole host).
            *resources.docker_resource_args(),
            # mode=1777 (world-writable + sticky) so the non-root probe can create
            # files; exec so a compiled fuzzer/PoC can run.
            "--tmpfs", f"/scratch:rw,exec,mode=1777,size={tmpfs}",
            "--tmpfs", f"/tmp:rw,exec,mode=1777,size={tmpfs}",
            # /dev/shm — POSIX shared memory. Docker's default is a fixed 64 MiB, which is
            # too small for AFL++: an instrumented target maps its coverage bitmap + the
            # SHM testcase region in /dev/shm, and a too-small (or, under some runtimes,
            # absent) /dev/shm makes afl-fuzz's forkserver child segfault before the
            # handshake completes ("Fork server crashed with signal 11"). Sizing it to the
            # scratch ceiling fixes that. This is NOT a security relaxation: the container
            # already has a writable /dev/shm; we only resize it AND add `noexec,nosuid,
            # nodev` (data-only — stricter than docker's default), so it cannot host code.
            # The read-only rootfs, dropped caps, no-new-privileges and --user are all
            # untouched. Other fuzzers (libFuzzer/qemu/desock) are unaffected.
            "--tmpfs", f"/dev/shm:rw,noexec,nosuid,nodev,mode=1777,size={tmpfs}",
            "--workdir", "/scratch",
            "-e", "HOME=/scratch",
            "-e", "TMPDIR=/scratch",
            "-e", "XDG_CACHE_HOME=/scratch",
            "-e", "XDG_CONFIG_HOME=/scratch",
            # Capability handshake (NOT a security flag): when this container gets the
            # personality-allowing seccomp profile (disable_aslr), tell the probe so it KNOWS
            # the relaxation was actually granted. A probe that intends `setarch -R` but does
            # NOT see this marker is running against a STALE engine (probes hot-load from disk;
            # engine code is process-cached) that didn't grant the cap — it can then log a clear
            # diagnostic and skip setarch instead of hitting a cryptic EPERM. See
            # service_launch_probe.py / afl_probe.py.
            *(["-e", "HEXGRAPH_SVC_ASLR_RELAXED=1"] if disable_aslr else []),
            *(["-e", "HG_CHANNEL_SECRET"] if secret else []),
            # Caller-supplied probe env (e.g. the AFL source-fuzz knobs). NOT a security
            # relaxation: these are HexGraph-set tuning vars (the engine builds the dict from
            # the validated campaign spec, never raw user/attacker input), passed as separate
            # argv (`-e`, `K=V`) so there is no shell interpolation. The hardening flags above
            # are untouched. Skip any malformed key (a `=` in the name would split wrong).
            *[arg
              for k, v in (extra_env or {}).items() if k and "=" not in k
              for arg in ("-e", f"{k}={v}")],
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
        network_gate: str = "network",
        image: str | None = None,
        project_mount: str | Path | None = None,
    ) -> RunResult:
        """Run a probe script over `artifact` inside the sandbox.

        `image` overrides the runner's default sandbox image for THIS probe run (the
        same per-run override `start_detached` accepts) — e.g. the build probe runs in
        the dedicated `hexgraph-build` image (clang + AFL++ toolchain), not the shared
        analysis sandbox. Defaults to `self.image`.

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

        `network_gate` selects WHICH policy gate authorizes the egress (the runner's
        defense-in-depth re-check, on top of the caller's assert): `"network"` (default)
        re-checks the bounded local-network tier (`features.network`); `"build_fetch"`
        re-checks the SEPARATE bounded dependency-fetch tier (`features.build_fetch`) — a
        registry-allowlisted fetch is NOT the local-network tier, so it must NOT require
        `features.network` (that would defeat the separate gate). Both fail closed.

        `secret` (a JSON-able dict) is delivered to the probe via the `HG_CHANNEL_SECRET`
        env var instead of the argv — so credentials NEVER appear on the docker command
        line (visible via `ps`/`/proc/<pid>/cmdline`). The probe reads + merges it.

        `resources` (a ResourceSpec) overrides the per-container ceilings (mem/cpu/pids/
        tmpfs/timeout); `unconstrained` lifts mem/cpu/pids ONLY (never a security flag).

        `project_mount` (host dir) is bind-mounted READ-WRITE at /ghidra-project so the
        persistent Ghidra project (analyze-once / reuse, engine.re.ghidra_project) survives
        across container runs. This is HexGraph's OWN data dir, NOT target bytes — the target
        artifact stays read-only at /artifact. It is the single bounded writable volume the
        ghidra path adds; EVERY other hardening flag (`--read-only` rootfs, `--network none`,
        `--cap-drop ALL`, `--no-new-privileges`, `--user 1000:1000`) is unchanged. The dir is
        made writable for the container uid exactly like /out (`_ensure_outdir_writable`).
        """
        if requires_execution:
            from hexgraph.policy import assert_allows_execution

            assert_allows_execution()
        if allow_network:
            _assert_network_gate(network_gate)
        if artifact is not None:
            # Defense-in-depth: an empty/whitespace artifact path is a path-less SURFACE
            # target (web_app/service/remote, `path=""`) accidentally routed onto the byte
            # path. `Path("").resolve()` is the cwd, so the old check produced a baffling
            # "artifact not found: <repo root>". Refuse it with a clear, actionable error.
            if not str(artifact).strip():
                raise SandboxError(
                    "this target has no byte artifact — it's a Channel-reached surface "
                    "(web_app/service/remote); use surface recon / a network probe, not the "
                    "byte sandbox")
            artifact = Path(artifact).resolve()
            if not artifact.is_file():
                raise SandboxError(f"artifact not found: {artifact}")

        # F13: when the caller passes no explicit ResourceSpec, the default's wall-clock
        # `timeout` scales up for a LARGE artifact so the first whole-binary analysis of a
        # 100 MB+ ELF isn't killed at 300 s (a normal-size artifact is unchanged; only the
        # timeout widens, never mem/cpu/pids). An explicit `resources=` (fuzz/poc/build) is
        # honored verbatim with NO size scaling — those set their budget deliberately. The
        # detached path (`start_detached`) keeps `resource_spec_for("sandbox")` for the same
        # reason: its timeout is a hard campaign cap, not a per-analysis budget.
        resources = resources or resource_spec_for_artifact(artifact, "sandbox")
        timeout = resources.timeout or self.timeout
        name = f"hexgraph-{uuid.uuid4().hex[:12]}"
        cmd = [
            "docker", "run", "--rm", "--name", name,
            # Expose THIS run's wall-clock budget to the probe so a long-running tool can stop
            # itself GRACEFULLY a little before the external kill and save partial work, rather
            # than being torn down with nothing (Ghidra's `-analysisTimeoutPerFile` uses this on a
            # huge ELF whose full auto-analysis would outrun the budget — F13). Informational only.
            "-e", f"HEXGRAPH_PROBE_TIMEOUT_S={timeout}",
            *self._hardening_args(allow_network=allow_network, net_container=net_container,
                                  resources=resources, secret=bool(secret)),
            # A channel probe (live target, no bytes at rest) mounts no artifact.
            *(["-v", f"{artifact}:/artifact:ro"] if artifact is not None else []),
        ]

        probe_args = ["/artifact"] if artifact is not None else []
        if outdir is not None:
            outdir = Path(outdir).resolve()
            outdir.mkdir(parents=True, exist_ok=True)
            _ensure_outdir_writable(outdir)  # so the --user 1000 container can write /out
            cmd += ["-v", f"{outdir}:/out:rw"]
            probe_args.append("/out")
        if project_mount is not None:
            # The persistent Ghidra project: a single bounded writable bind-mount of HexGraph's
            # OWN data (not target bytes). Made writable for the --user 1000 container exactly
            # like /out; the target artifact stays read-only at /artifact and every other
            # hardening flag is untouched (see the docstring + _ensure_outdir_writable).
            project_mount = Path(project_mount).resolve()
            project_mount.mkdir(parents=True, exist_ok=True)
            _ensure_outdir_writable(project_mount)
            cmd += ["-v", f"{project_mount}:{CONTAINER_PROJECT_DIR}:rw"]
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

        cmd += [image or self.image, "python3", f"{CONTAINER_PROBES}/{probe}", *probe_args]

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
                _probe_failure_message(probe, proc.returncode, proc.stdout, proc.stderr)
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
        project_mount: str | Path | None = None,
    ) -> dict:
        """Run a probe whose stdout is a single JSON object, and parse it."""
        result = self.run_probe(
            probe, artifact, outdir=outdir, extra_args=extra_args,
            requires_execution=requires_execution, extra_ro_mounts=extra_ro_mounts,
            allow_network=allow_network, resources=resources, project_mount=project_mount,
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
        allow_network: bool = False,
        net_container: str | None = None,
        disable_aslr: bool = False,
        extra_env: dict[str, str] | None = None,
    ) -> DetachedHandle:
        """Launch a probe as a DETACHED, long-lived container (`docker run -d`), same
        hardening as run_probe. `disable_aslr` (the ASan source-fuzz path only) swaps in
        the minimal default+personality seccomp profile so `setarch -R` can disable ASLR
        for the instrumented target — see `_hardening_args`. The launcher returns IMMEDIATELY with a handle whose
        `name` is durable, so the reaper (a periodic worker job) and a `serve`-restart
        re-attach by name (crash-safe). The container streams artifacts/stats to the
        `/out` bind-mount as it runs; nothing blocks a worker thread.

        Used ONLY for fuzz campaigns: `requires_execution=True` hits the exec gate (a
        fuzz campaign runs the instrumented target). `--network none` holds for a
        binary-only / desock campaign. A NETWORK-FUZZ campaign (boofuzz) opts into
        `allow_network=True` — the SINGLE place a detached campaign relaxes the network
        flag — which is policy-checked here (`current_policy().allow_network`) and joins
        `net_container`'s netns (a rehosted device) when given; the CALLER (the campaign
        engine) has already asserted assert_allows_egress to the bounded local scope +
        audited the EgressEvent. Resource ceilings come from `resources`."""
        if requires_execution:
            from hexgraph.policy import assert_allows_execution

            assert_allows_execution()
        if allow_network:
            from hexgraph.policy import PolicyViolation, current_policy

            if not current_policy().allow_network:
                raise PolicyViolation("network egress is not permitted by the active policy")
        if artifact is not None:
            # Defense-in-depth: an empty/whitespace artifact path is a path-less SURFACE
            # target (web_app/service/remote, `path=""`) accidentally routed onto the byte
            # path. `Path("").resolve()` is the cwd, so the old check produced a baffling
            # "artifact not found: <repo root>". Refuse it with a clear, actionable error.
            if not str(artifact).strip():
                raise SandboxError(
                    "this target has no byte artifact — it's a Channel-reached surface "
                    "(web_app/service/remote); use surface recon / a network probe, not the "
                    "byte sandbox")
            artifact = Path(artifact).resolve()
            if not artifact.is_file():
                raise SandboxError(f"artifact not found: {artifact}")

        resources = resources or resource_spec_for("sandbox")
        outdir = Path(outdir).resolve()
        outdir.mkdir(parents=True, exist_ok=True)
        _ensure_outdir_writable(outdir)  # so the --user 1000 container can write /out
        cmd = [
            "docker", "run", "-d", "--name", name,
            # NOT --rm: a detached campaign container is reaped explicitly so its exit
            # status is observable. The reaper `docker rm`s it on finalize.
            *self._hardening_args(allow_network=allow_network, net_container=net_container,
                                  resources=resources, secret=False, disable_aslr=disable_aslr,
                                  extra_env=extra_env),
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
