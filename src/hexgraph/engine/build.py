"""The `Builder` seam + build-as-API (design §2.1, §3, Phase 2).

Turn a managed `source_tree` into an **instrumented artifact** via a *recorded,
reproducible recipe* the API/tool layer executes IN THE SANDBOX. This is the
analogue of the rehoster/executor/decompiler seams: feature code calls
`get_builder()` and never names a concrete builder. `SandboxBuilder` (the default)
runs a new `build_probe.py` in the `hexgraph-build` image; `MockBuilder` keeps
`just test` offline/$0 (no Docker) for the seam/persistence/derived-target tests.

The governing principle (build-as-API): nobody runs `make` by hand. The user/LLM
authors or approves a `BuildSpec` (itself source) and *requests* a build; HexGraph
runs the recorded recipe, reproducibly, gated at the policy seam
(`assert_allows_build()` — the ONLY place the build gate is relaxed).

**Reproducibility is the contract.** `recipe_sha` = sha256 over
{phases, env, base_image, instrumentation, arch}. Same recipe_sha + same source
`content_hash` + same `toolchain_digest` ⇒ the same build, recorded.

**Supply-chain containment (§3.5/§8).** Vendored/offline ONLY this phase: the
compile phase runs `--network none` (the bounded, audited fetch tier is Phase 7).
Source is mounted READ-ONLY (non-root), output only to `/out`, the container is
ephemeral. A malicious `configure` can burn CPU and exit; it cannot persist or
exfiltrate. The LLM never sees raw bytes — only the bounded build log / CAS hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

# Build systems we recognise (detection + recipe authoring). `custom` = the recipe
# fully specifies the phases (no implied defaults).
BUILD_SYSTEMS = ("make", "cmake", "autotools", "meson", "cargo", "go", "custom")

DEFAULT_BUILD_IMAGE = "hexgraph-build:latest"
DEFAULT_BUILD_TIMEOUT = 1800


class BuildError(RuntimeError):
    """A build was attempted but failed (compile error, bad recipe, no artifact)."""


class BuildUnavailable(BuildError):
    """The builder can't run here (no Docker / build image) — handle gracefully."""


@dataclass(frozen=True)
class Instrumentation:
    """How the target's own objects get instrumented (design §3.1 base-image
    contract). The recipe stays the same; only this profile changes to swap an
    ASan+libFuzzer build for an AFL++ build for a coverage build."""
    sanitizers: tuple[str, ...] = ("address",)   # address | undefined | memory | …
    coverage: tuple[str, ...] = ("sancov",)       # sancov (-fsanitize=fuzzer-no-link) | afl_pcguard
    engine: str = "libfuzzer"                     # libfuzzer | afl | none
    extra_cflags: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"sanitizers": list(self.sanitizers), "coverage": list(self.coverage),
                "engine": self.engine, "extra_cflags": list(self.extra_cflags)}

    @classmethod
    def from_dict(cls, d: dict | None) -> "Instrumentation":
        d = d or {}
        return cls(
            sanitizers=tuple(d.get("sanitizers") or ()),
            coverage=tuple(d.get("coverage") or ()),
            engine=d.get("engine", "none"),
            extra_cflags=tuple(d.get("extra_cflags") or ()),
        )


@dataclass(frozen=True)
class BuildPhase:
    """One ordered, explicit-argv build step — RECORDED verbatim (never a free-text
    shell string unless `shell=True`, used only for a recorded build.sh script)."""
    argv: tuple[str, ...]
    shell: bool = False

    def to_dict(self) -> dict:
        return {"argv": list(self.argv), "shell": bool(self.shell)}

    @classmethod
    def from_dict(cls, d: dict) -> "BuildPhase":
        if isinstance(d, (list, tuple)):
            return cls(argv=tuple(str(a) for a in d))
        return cls(argv=tuple(str(a) for a in (d.get("argv") or [])), shell=bool(d.get("shell")))


# Cross-compile target triples per recorded `arch` (design §3.4). clang IS a
# cross-compiler (`--target=<triple> --sysroot=<firmware-rootfs>`), so a cross build
# only needs the right triple + the firmware's extracted rootfs as the sysroot. A
# missing/unknown arch falls back to the native build (which then degrades to
# qemu-mode binary-only fuzzing per §3.4 if the binary can't run natively).
CROSS_TRIPLES = {
    "x86_64": None, "amd64": None,            # native
    "mips": "mipsel-linux-gnu", "mipsel": "mipsel-linux-gnu",
    "mipseb": "mips-linux-gnu", "mipsbe": "mips-linux-gnu",
    "arm": "arm-linux-gnueabi", "armel": "arm-linux-gnueabi",
    "armhf": "arm-linux-gnueabihf",
    "aarch64": "aarch64-linux-gnu", "arm64": "aarch64-linux-gnu",
}


@dataclass(frozen=True)
class BuildSpec:
    """A recorded, reproducible build recipe (design §2.1). Feature code asks the
    seam with this; the Builder never names a concrete tool."""
    source_tree_id: str
    system: str = "make"
    phases: tuple[BuildPhase, ...] = ()
    instrumentation: Instrumentation = field(default_factory=Instrumentation)
    artifacts: tuple[str, ...] = ()                 # rel paths under the build dir to capture
    env: dict[str, str] = field(default_factory=dict)   # NON-secret build env (CC/CXX/CFLAGS injected per the contract)
    arch: str = "x86_64"                            # host or a cross target (firmware arch, §3.4)
    base_image: str = DEFAULT_BUILD_IMAGE           # RECORDED — part of reproducibility
    network: str = "none"                           # "none" (default) | "fetch" (bounded, audited deps phase — features.build_fetch)
    timeout: int = DEFAULT_BUILD_TIMEOUT
    name: str = "build"
    # The bounded-fetch FETCH phase (design §3.5, features.build_fetch): ordered explicit-
    # argv commands run with network ON (allowlisted) in a SEPARATE sandbox run BEFORE the
    # compile phase, which then runs --network none against the snapshotted deps. Empty ⇒
    # no fetch (vendored/offline — the default; the compile is fully offline-reproducible).
    fetch_phases: tuple[BuildPhase, ...] = ()
    # Cross-compile: the firmware's extracted rootfs to use as the clang `--sysroot`, so
    # the cross-built binary is binary-compatible with the device userland (§3.4). Resolved
    # by the orchestrator from the parent firmware; recorded for replay. NOT part of
    # recipe_sha (it's a host path; the arch + injected --target is the reproducible part).
    sysroot: str | None = None

    def recipe_sha(self) -> str:
        """sha256 over {phases, fetch_phases, env, base_image, instrumentation, arch} —
        the recipe identity. Deterministic: sorted keys, canonical JSON, so the SAME
        recipe always hashes the same regardless of dict/tuple ordering. The fetch phase
        is part of the recipe identity (a different dep set ⇒ a different recipe)."""
        basis = {
            "phases": [p.to_dict() for p in self.phases],
            "fetch_phases": [p.to_dict() for p in self.fetch_phases],
            "env": self.env,
            "base_image": self.base_image,
            "instrumentation": self.instrumentation.to_dict(),
            "arch": self.arch,
        }
        return hashlib.sha256(json.dumps(basis, sort_keys=True).encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "source_tree_id": self.source_tree_id, "system": self.system,
            "phases": [p.to_dict() for p in self.phases],
            "fetch_phases": [p.to_dict() for p in self.fetch_phases],
            "instrumentation": self.instrumentation.to_dict(),
            "artifacts": list(self.artifacts), "env": dict(self.env),
            "arch": self.arch, "base_image": self.base_image, "network": self.network,
            "sysroot": self.sysroot, "timeout": self.timeout, "name": self.name,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BuildSpec":
        return cls(
            source_tree_id=d["source_tree_id"],
            system=d.get("system", "make"),
            phases=tuple(BuildPhase.from_dict(p) for p in (d.get("phases") or [])),
            fetch_phases=tuple(BuildPhase.from_dict(p) for p in (d.get("fetch_phases") or [])),
            instrumentation=Instrumentation.from_dict(d.get("instrumentation")),
            artifacts=tuple(d.get("artifacts") or ()),
            env={str(k): str(v) for k, v in (d.get("env") or {}).items()},
            arch=d.get("arch", "x86_64"),
            base_image=d.get("base_image", DEFAULT_BUILD_IMAGE),
            network=d.get("network", "none"),
            sysroot=d.get("sysroot"),
            timeout=int(d.get("timeout", DEFAULT_BUILD_TIMEOUT)),
            name=d.get("name", "build"),
        )


@dataclass
class BuildResult:
    """What a build produced. The reproducibility triple (recipe_sha /
    source_content_hash / toolchain_digest) + the artifacts + the log make the build
    replayable + auditable. The Builder reports artifacts as ON-DISK paths
    (`artifact_paths`, rel → host path) and the raw `log_text`; the engine
    orchestrator (`build_source`) ingests those into the per-project CAS and fills
    `artifacts` (rel → cas_sha) + `log_sha`. This keeps the Builder seam free of
    project/CAS concerns (it just produces bytes)."""
    ok: bool
    artifact_paths: dict[str, str] = field(default_factory=dict)   # rel → host path (builder side)
    log_text: str = ""                                             # full build log (builder side)
    artifacts: dict[str, str] = field(default_factory=dict)        # rel → cas_sha (filled by the engine)
    log_sha: str | None = None                                     # CAS sha (filled by the engine)
    recipe_sha: str | None = None
    source_content_hash: str | None = None
    toolchain_digest: str | None = None
    instrumentation: dict | None = None
    duration: float = 0.0
    returncode: int | None = None
    error: str | None = None
    # Phase 7 supply-chain provenance (filled by the fetch phase; {} / [] for a
    # vendored/offline build). `lockfile` is the hash-pinned dependency map
    # {name→{version,sha256,url}}; `sbom` is the SBOM-lite list of fetched dep records.
    lockfile: dict | None = None
    sbom: list | None = None
    # The recorded build arch (host or a cross triple's arch) + whether a cross-build was
    # actually performed (False if it fell back to native — degrade-to-qemu path, §3.4).
    arch: str = "x86_64"
    cross: bool = False


@runtime_checkable
class Builder(Protocol):
    name: str

    def build(self, spec: BuildSpec, *, source_root: str, content_hash: str | None = None,
              fetch_session=None, project=None, target_id=None, task_id=None) -> BuildResult:
        # `fetch_session`/`project`/`target_id`/`task_id` are passed ONLY for the bounded
        # fetch tier's egress audit (design §3.5); they are unused for vendored/offline builds.
        ...


# ── Secret hygiene: build env is NON-secret by contract ─────────────────────────
# A BuildSpec.env carries CC/CXX/CFLAGS-style knobs only. We refuse anything that
# looks like a credential so a secret can never flow through it onto the recorded
# recipe (which is durable + displayed). The injected instrumentation env is set by
# the probe, never by the LLM.
_SECRETISH = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH")


def assert_env_nonsecret(env: dict[str, str]) -> None:
    for k in env or {}:
        up = k.upper()
        if any(s in up for s in _SECRETISH):
            raise BuildError(
                f"build env var {k!r} looks like a secret — build env is NON-secret by contract; "
                "credentials must never flow through a recorded recipe")


def assert_artifacts_contained(artifacts) -> None:
    """An artifact rel is operator/LLM-authored; reject absolute paths and traversal
    so a build can only capture a file INSIDE its own build dir (defense-in-depth on
    top of the probe's own check + the sandbox boundary). The recorded recipe — and
    so every replay — is then guaranteed contained."""
    for rel in artifacts or ():
        r = str(rel)
        if os.path.isabs(r) or r.startswith("~"):
            raise BuildError(f"artifact path must be relative to the build dir, not {rel!r}")
        # Normalize and ensure it stays at/under the root (no leading ../ after norm).
        norm = os.path.normpath(r)
        if norm == ".." or norm.startswith(".." + os.sep) or os.path.isabs(norm):
            raise BuildError(f"artifact path escapes the build dir: {rel!r}")


# ── The base-image contract (design §3.1) ───────────────────────────────────────
# The orchestrator (build_probe) sets CC/CXX/CFLAGS/SANITIZER/FUZZING_ENGINE from
# the instrumentation profile — NEVER the recipe author. We compute the toolchain
# *intent* here so the probe and the recorded recipe agree; the probe also stamps
# the actual compiler version into the toolchain_digest.

def instrumentation_env(instr: Instrumentation, *, arch: str = "x86_64",
                        sysroot: str | None = None) -> dict[str, str]:
    """The injected toolchain env for an instrumentation profile (the OSS-Fuzz
    lesson: separate 'what to build' from 'how it's instrumented'). Returns the env the
    probe exports before running the recipe phases.

    Cross-compile (design §3.4): a non-native `arch` resolves to a clang target triple
    that is appended to CC/CXX/CFLAGS (`--target=<triple>`), and when a `sysroot` is given
    (the firmware's extracted rootfs, mounted at /sysroot in the probe) `--sysroot=/sysroot`
    is added so the cross-built binary is binary-compatible with the device userland.
    clang is the SAME cross-compiler for every arch — only the triple/sysroot change — so
    instrumentation (SanCov/ASan) is preserved across arches."""
    cflag_bits: list[str] = ["-g", "-O1"]
    sans = list(instr.sanitizers)
    triple = CROSS_TRIPLES.get((arch or "x86_64").lower())
    cross_bits: list[str] = []
    if triple:
        cross_bits.append(f"--target={triple}")
        if sysroot:
            # The probe mounts the recorded sysroot RO at /sysroot (a fixed container path).
            cross_bits.append("--sysroot=/sysroot")
    if instr.engine == "afl":
        cc, cxx = "afl-clang-lto", "afl-clang-lto++"
        # AFL++'s LTO instrumentation provides coverage; sanitizers still add ASan/UBSan.
        if sans:
            cflag_bits.append("-fsanitize=" + ",".join(sans))
        fuzzing_engine = "afl"
    else:
        cc, cxx = "clang", "clang++"
        cov_bits = []
        if "sancov" in instr.coverage:
            cov_bits.append("fuzzer-no-link")
        cov_bits.extend(sans)
        if cov_bits:
            cflag_bits.append("-fsanitize=" + ",".join(cov_bits))
        fuzzing_engine = "libfuzzer" if instr.engine == "libfuzzer" else "none"
    cflag_bits.extend(cross_bits)
    cflag_bits.extend(instr.extra_cflags)
    cc = (cc + " " + " ".join(cross_bits)).strip() if cross_bits else cc
    cxx = (cxx + " " + " ".join(cross_bits)).strip() if cross_bits else cxx
    cflags = " ".join(cflag_bits)
    sanitizer = sans[0] if sans else "none"
    env = {
        "CC": cc, "CXX": cxx, "CFLAGS": cflags, "CXXFLAGS": cflags,
        "SANITIZER": sanitizer, "FUZZING_ENGINE": fuzzing_engine,
    }
    if triple:
        env["ARCH"] = arch
        env["CROSS"] = triple
    return env


def determinism_env(*, source_date_epoch: int | None = None, ccache: bool = False) -> dict[str, str]:
    """Reproducible-build + incrementality knobs (design §3, Phase 7), injected by the
    orchestrator (NOT the recipe author). `SOURCE_DATE_EPOCH` pins embedded timestamps so
    a rebuild is byte-identical run-to-run; ccache caches object files (`CCACHE_DIR` on the
    persistent host cache mounted by the probe) so an incremental rebuild reuses them. Both
    are reproducibility/speed knobs, never security — they don't touch the sandbox flags."""
    env: dict[str, str] = {}
    if source_date_epoch is not None:
        env["SOURCE_DATE_EPOCH"] = str(int(source_date_epoch))
    if ccache:
        # The probe prepends ccache to CC/CXX and points CCACHE_DIR at a writable cache
        # mounted into /scratch (per-tree, content-keyed by ccache itself).
        env["USE_CCACHE"] = "1"
        env["CCACHE_DIR"] = "/scratch/ccache"
    return env


class SandboxBuilder(Builder):
    """Default builder — runs `build_probe.py` in the `hexgraph-build` sandbox image.

    Source is mounted READ-ONLY (copied to a writable scratch by the probe, so the
    immutable snapshot is never corrupted), output only to `/out`, the compile phase
    `--network none`, same hardening as every other probe (`--read-only` rootfs +
    tmpfs `/scratch` rw,exec, `--cap-drop ALL`, `--no-new-privileges`, `--user 1000`,
    mem/cpu/pids caps, hard timeout). Probes are mounted from the install at run time
    — editing build_probe.py needs no image rebuild."""

    name = "sandbox"

    def __init__(self, image: str | None = None) -> None:
        from hexgraph import settings

        self.image = (image or os.environ.get("HEXGRAPH_BUILD_IMAGE")
                      or settings.get("features.build.image", DEFAULT_BUILD_IMAGE)
                      or DEFAULT_BUILD_IMAGE)

    def build(self, spec: BuildSpec, *, source_root: str, content_hash: str | None = None,
              fetch_session=None, project=None, target_id=None, task_id=None) -> BuildResult:
        from hexgraph.policy import assert_allows_build
        from hexgraph.sandbox.executor import get_executor
        from hexgraph.sandbox.runner import SandboxError, docker_available

        assert_allows_build()  # opt-in gate — the ONLY place the build gate is relaxed
        assert_env_nonsecret(spec.env)
        assert_artifacts_contained(spec.artifacts)
        if spec.network not in ("none", "fetch"):
            raise BuildError(f"unknown build network mode {spec.network!r} (expected 'none' or 'fetch')")
        if not docker_available():
            raise BuildUnavailable("Docker is not running — building needs it.")

        root = Path(source_root).resolve()
        if not root.is_dir():
            raise BuildError(f"source root not found: {root}")

        recipe_sha = spec.recipe_sha()
        from hexgraph import settings
        sde = settings.get("features.build.source_date_epoch")
        ccache = bool(settings.get("features.build.ccache", True))
        # Cross-compile env (clang --target/--sysroot) when arch != native (§3.4); the
        # sysroot is mounted RO at /sysroot below. instrumentation_env injects ARCH/CROSS.
        inj_env = instrumentation_env(spec.instrumentation, arch=spec.arch, sysroot=spec.sysroot)
        det_env = determinism_env(source_date_epoch=sde, ccache=ccache)
        merged_env = {**inj_env, **det_env, **dict(spec.env)}  # recipe env can override (rare)
        cross_requested = bool(CROSS_TRIPLES.get((spec.arch or "x86_64").lower()))

        import tempfile
        executor = get_executor()
        extra_ro = [(str(root), "/src")]
        if spec.sysroot and Path(spec.sysroot).is_dir() and cross_requested:
            extra_ro.append((str(Path(spec.sysroot).resolve()), "/sysroot"))

        # ── Phase F (FETCH) — bounded, audited, allowlisted; DROPS NETWORK before compile.
        # A SEPARATE sandbox run from the compile, so a build script can't exfiltrate during
        # compile (which is --network none). Produces a lockfile + SBOM-lite + a vendor dir
        # snapshotted into /out/vendor, then mounted RO into the compile phase.
        lockfile: dict = {}
        sbom: list = []
        vendor_dir: str | None = None
        outdir = tempfile.mkdtemp(prefix="hexgraph-build-out-")
        if spec.network == "fetch" and spec.fetch_phases:
            lockfile, sbom, vendor_dir = self._run_fetch(
                spec, root, merged_env, executor,
                fetch_session=fetch_session, project=project,
                target_id=target_id, task_id=task_id)
            if vendor_dir:
                extra_ro.append((vendor_dir, "/vendor"))

        probe_payload = {
            "phases": [p.to_dict() for p in spec.phases],
            "env": merged_env,
            "artifacts": list(spec.artifacts),
            "system": spec.system,
            "vendor": "/vendor" if vendor_dir else None,
        }
        # Source mounted READ-ONLY at /src; the probe copies it into /scratch to build.
        try:
            result = executor.run_probe(
                "build_probe.py", None, outdir=outdir,
                extra_args=["--spec", json.dumps(probe_payload)],
                extra_ro_mounts=extra_ro,
                # The dedicated build image (clang/LLVM + the AFL++ toolchain), NOT the
                # shared analysis sandbox — an AFL++ instrumentation profile compiles with
                # afl-clang-lto, which only the build image carries (the sandbox image has
                # plain clang, so a libFuzzer build happened to work there but an AFL build
                # could never find its compiler).
                image=self.image,
                # The COMPILE phase runs --network none (requires_execution=False keeps the
                # exec gate independent of the build gate, and never opts into network — so
                # even with features.build_fetch on, compile has NO network). A malicious dep
                # fetched in Phase F cannot run/exfiltrate here.
                requires_execution=False,
            )
        except SandboxError as exc:
            # A non-zero probe exit (e.g. a compile failure surfaced as an exception by
            # the runner). The probe is written to emit JSON + exit 0 even on a failed
            # build; this path is for an infra failure.
            raise BuildError(f"build probe failed: {exc}") from exc

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise BuildError(f"build probe did not emit JSON: {exc}") from exc
        res = self._finalize(spec, recipe_sha, content_hash, data, outdir)
        res.lockfile = lockfile
        res.sbom = sbom
        res.cross = bool(cross_requested and spec.sysroot)
        return res

    def _run_fetch(self, spec, root, merged_env, executor, *, fetch_session, project,
                   target_id, task_id):
        """Phase F (design §3.5): a SEPARATE, audited, ALLOWLISTED sandbox run with network
        ON. Asserts the bounded-fetch gate + builds the registry-allowlist egress scope +
        AUDITS the EgressEvent BEFORE the run, fetches declared deps into /out/vendor, and
        produces a hash-pinned lockfile + SBOM-lite. Returns (lockfile, sbom, vendor_dir).
        After it returns, the caller runs the COMPILE phase --network none against the
        snapshot — fetch-then-offline."""
        import tempfile

        from hexgraph import settings
        from hexgraph.policy import assert_allows_build_fetch, build_fetch_scope

        assert_allows_build_fetch()  # fail-closed — the ONLY place the fetch gate is relaxed
        allowlist = settings.get("features.build_fetch.allowlist") or None
        scope = build_fetch_scope(allowlist)
        # Audit the allowlist the fetch was permitted to reach (one allowed EgressEvent per
        # registry). We can't enumerate every download host up-front, so we record the scope
        # the probe's per-host egress guard confines the fetch to (the gate itself was asserted
        # above; reaching here means it passed, so every entry is `allowed=True`).
        from hexgraph.engine.audit import record_egress
        if fetch_session is not None and project is not None:
            for dest in sorted(scope.allow):
                record_egress(fetch_session, project_id=project.id, target_id=target_id,
                              task_id=task_id, dest=dest, allowed=True, tool="build_fetch",
                              detail=scope.rationale)

        fetch_out = tempfile.mkdtemp(prefix="hexgraph-fetch-out-")
        fetch_payload = {
            "phases": [p.to_dict() for p in spec.fetch_phases],
            "env": merged_env,
            "allow": sorted(scope.allow),
            "system": spec.system,
        }
        timeout = int(settings.get("features.build_fetch.timeout", 600) or 600)
        from hexgraph.sandbox.resources import ResourceSpec
        try:
            # network ON, bounded to the allowlist (the probe enforces per-host). A SEPARATE
            # sandbox run — its container is torn down before the compile run starts.
            result = executor.run_probe(
                "build_fetch_probe.py", None, outdir=fetch_out,
                extra_args=["--spec", json.dumps(fetch_payload)],
                extra_ro_mounts=[(str(root), "/src")],
                image=self.image,  # the dedicated build image (package managers + toolchain)
                allow_network=True, network_gate="build_fetch",  # the SEPARATE fetch gate, NOT features.network
                resources=ResourceSpec(timeout=timeout),
            )
        except Exception as exc:  # noqa: BLE001
            raise BuildError(f"dependency fetch failed: {exc}") from exc
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, AttributeError) as exc:
            raise BuildError(f"fetch probe did not emit JSON: {exc}") from exc
        if not data.get("ok"):
            raise BuildError(f"dependency fetch failed: {data.get('error') or 'unknown'}")
        vendor = str(Path(fetch_out) / "vendor")
        return data.get("lockfile") or {}, data.get("sbom") or [], vendor if Path(vendor).is_dir() else None

    def _finalize(self, spec, recipe_sha, content_hash, data, outdir) -> BuildResult:
        # The probe wrote captured artifacts under /out/artifacts/<rel> + the log at
        # /out/build.log (both bound to `outdir`). We hand the engine the on-disk paths
        # + the log text; it CAS-ingests them into the per-project store (CAS is
        # project-scoped, the Builder seam is not).
        art_root = Path(outdir) / "artifacts"
        artifact_paths: dict[str, str] = {}
        for rel in (data.get("artifacts") or {}):
            p = art_root / rel
            if p.is_file():
                artifact_paths[rel] = str(p)
        log_text = ""
        log_path = Path(outdir) / "build.log"
        if log_path.is_file():
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        return BuildResult(
            ok=bool(data.get("ok")),
            artifact_paths=artifact_paths,
            log_text=log_text,
            recipe_sha=recipe_sha,
            source_content_hash=content_hash,
            toolchain_digest=data.get("toolchain_digest"),
            instrumentation=spec.instrumentation.to_dict(),
            duration=float(data.get("duration") or 0.0),
            returncode=data.get("returncode"),
            error=data.get("error"),
            arch=spec.arch,
        )


class MockBuilder(Builder):
    """Offline builder for tests/$0 CI — never touches Docker. Produces a deterministic
    fake artifact + log so the seam, persistence, reproducibility hashing, and
    derived-target registration are all testable without the build image. It still
    asserts the policy gate (so the gate test exercises the real seam path)."""

    name = "mock"

    def build(self, spec: BuildSpec, *, source_root: str, content_hash: str | None = None,
              fetch_session=None, project=None, target_id=None, task_id=None) -> BuildResult:
        import tempfile

        from hexgraph.policy import assert_allows_build

        assert_allows_build()
        assert_env_nonsecret(spec.env)
        assert_artifacts_contained(spec.artifacts)
        recipe_sha = spec.recipe_sha()
        # A deterministic toolchain digest so the reproducibility triple is stable in tests.
        toolchain = "mock-clang-18.0.0"
        # If a fetch tier was requested, assert the (fail-closed) gate + audit the allowlist,
        # then synthesize a DETERMINISTIC lockfile + SBOM-lite from the recipe so the
        # fetch-then-offline path is testable at $0. The gate is asserted even in the mock
        # (so the fail-closed test exercises the real seam path).
        lockfile: dict = {}
        sbom: list = []
        if spec.network == "fetch":
            from hexgraph.policy import assert_allows_build_fetch, build_fetch_scope
            assert_allows_build_fetch()
            scope = build_fetch_scope(None)
            if fetch_session is not None and project is not None:
                from hexgraph.engine.audit import record_egress
                for dest in sorted(scope.allow):
                    record_egress(fetch_session, project_id=project.id, target_id=target_id,
                                  task_id=task_id, dest=dest, allowed=True, tool="build_fetch",
                                  detail=scope.rationale)
            # Deterministic fake deps keyed off the recipe so a rebuild produces the same lock.
            for i, ph in enumerate(spec.fetch_phases or (BuildPhase(("vendor",)),)):
                name = (ph.argv[-1] if ph.argv else f"dep{i}")
                ds = hashlib.sha256(f"{name}|{recipe_sha}".encode()).hexdigest()
                lockfile[f"{name}"] = {"version": "0.0.0", "sha256": ds,
                                       "url": f"https://example.invalid/{name}"}
                sbom.append({"name": name, "version": "0.0.0", "sha256": ds,
                             "url": f"https://example.invalid/{name}"})
        # Fabricate one artifact per requested rel path with DETERMINISTIC content
        # (a function of the recipe + source hash), so reproducibility holds: the same
        # recipe_sha + content_hash yields byte-identical artifacts ⇒ the same cas_sha.
        outdir = Path(tempfile.mkdtemp(prefix="hexgraph-mockbuild-"))
        art_root = outdir / "artifacts"
        artifact_paths: dict[str, str] = {}
        for rel in spec.artifacts:
            p = art_root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            body = f"MOCK-ARTIFACT\nrecipe_sha={recipe_sha}\nsource={content_hash}\nrel={rel}\n"
            p.write_text(body, encoding="utf-8")
            artifact_paths[rel] = str(p)
        log_text = (f"[mock-builder] system={spec.system} recipe_sha={recipe_sha}\n"
                    f"[mock-builder] toolchain={toolchain} instrumentation={spec.instrumentation.to_dict()}\n"
                    f"[mock-builder] phases={[p.to_dict() for p in spec.phases]}\n"
                    f"[mock-builder] OK — produced {len(artifact_paths)} artifact(s)\n")
        return BuildResult(
            ok=True, artifact_paths=artifact_paths, log_text=log_text, recipe_sha=recipe_sha,
            source_content_hash=content_hash, toolchain_digest=toolchain,
            instrumentation=spec.instrumentation.to_dict(), duration=0.0, returncode=0, error=None,
            lockfile=lockfile, sbom=sbom, arch=spec.arch,
            cross=bool(CROSS_TRIPLES.get((spec.arch or "x86_64").lower()) and spec.sysroot),
        )


def cache_key(recipe_sha: str | None, source_content_hash: str | None,
              toolchain_digest: str | None, lockfile: dict | None = None) -> str | None:
    """The reproducibility cache key (design §3 determinism). Same recipe_sha + source
    content_hash + toolchain_digest (+ a hash-pinned lockfile digest) ⇒ the same build,
    so a prior build's CAS artifact can be REUSED. None when any leg is missing (no reuse
    without a complete, recorded provenance)."""
    if not (recipe_sha and source_content_hash and toolchain_digest):
        return None
    lock_digest = ""
    if lockfile:
        lock_digest = hashlib.sha256(
            json.dumps(lockfile, sort_keys=True).encode("utf-8")).hexdigest()
    basis = "|".join([recipe_sha, source_content_hash, toolchain_digest, lock_digest])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def is_reproducible(recipe_sha: str | None, source_content_hash: str | None,
                    toolchain_digest: str | None, network: str = "none",
                    lockfile: dict | None = None) -> bool:
    """The reproducibility-BADGE verdict (design §3.5 / §8). A build is 'reproducible' when
    its full provenance is recorded: recipe_sha + source_content_hash + toolchain_digest all
    present, AND a fetch build (network='fetch') carries a hash-pinned lockfile (so the
    deps are pinned, not floating). A vendored/offline build (network='none') is reproducible
    on the triple alone (it had no network). The UI shows this as a badge."""
    if not (recipe_sha and source_content_hash and toolchain_digest):
        return False
    if network == "fetch":
        return bool(lockfile)  # fetch must be hash-pinned to count as reproducible
    return True


def get_builder(name: str | None = None) -> Builder:
    """The builder seam. Default `sandbox`; `mock` for offline tests. Selected by
    `HEXGRAPH_BUILDER`. Future `RemoteBuilder`/`oss_fuzz` adapters drop in here."""
    name = (name or os.environ.get("HEXGRAPH_BUILDER") or "sandbox").lower()
    if name == "sandbox":
        return SandboxBuilder()
    if name == "mock":
        return MockBuilder()
    raise ValueError(f"unknown builder {name!r}; expected 'sandbox' or 'mock'")
