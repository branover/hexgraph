#!/usr/bin/env python3
"""Phase F — the BOUNDED, AUDITED dependency-fetch phase (design §3.5/§8, Phase 7).

  argv: /out (rw — the vendor dir + lockfile + log land here)  --spec <json>
  spec: {phases:[{argv,shell}], env:{...}, allow:["host:port",...], system:str}

This is the SEPARATE sandbox run that fetches declared deps with network ON — but ONLY
to an ALLOWLIST of package-registry host:ports (the `allow` list, built host-side from
the operator-confirmed registry allowlist). It runs BEFORE the compile phase, which is a
DIFFERENT sandbox run with `--network none` against the snapshotted vendor dir. So:

  • fetch-then-offline — the fetch and compile are distinct containers; a build script
    cannot reach the network during compile,
  • allowlisted — `_egress.install_socket_guard(allow)` is a can't-forget BACKSTOP that
    DROPS any TCP connect outside the registry allowlist (the kernel-confinement story is
    deferred; this is the app-layer enforcement HexGraph's other egress probes already use),
  • hash-pinned + audited — after fetching, every file under the vendor dir is sha256'd
    into a LOCKFILE + an SBOM-lite, so a rebuild is auditable + the deps are pinned.

A malicious dependency can be DOWNLOADED (recorded, pinned) but never RUN here (no
compile happens in this phase) and never persists (ephemeral container). The probe
ALWAYS emits JSON {ok, lockfile, sbom, error, phases}.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _egress  # noqa: E402  (sibling import inside the sandbox image)

SRC = "/src"
SCRATCH = os.environ.get("TMPDIR", "/scratch")
WORK = os.path.join(SCRATCH, "fetch")


def _flag(args, name, default=None):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _emit(obj: dict) -> int:
    obj.setdefault("tool", "build_fetch_probe")
    print(json.dumps(obj))
    return 0


def _hash_vendor(vendor_dir: str) -> tuple[dict, list]:
    """Walk the vendor dir, sha256 every file → a hash-pinned lockfile (rel→sha256) + an
    SBOM-lite (list of {name, sha256, size}). The lockfile pins the EXACT bytes fetched, so
    a rebuild against this vendor dir is reproducible + auditable."""
    lockfile: dict = {}
    sbom: list = []
    if not os.path.isdir(vendor_dir):
        return lockfile, sbom
    for root, _dirs, files in os.walk(vendor_dir):
        for f in sorted(files):
            p = os.path.join(root, f)
            rel = os.path.relpath(p, vendor_dir)
            try:
                data = open(p, "rb").read()
            except OSError:
                continue
            sha = hashlib.sha256(data).hexdigest()
            lockfile[rel] = {"sha256": sha, "size": len(data)}
            sbom.append({"name": rel, "sha256": sha, "size": len(data)})
    return lockfile, sbom


def main() -> int:
    if len(sys.argv) < 2:
        return _emit({"ok": False, "error": "usage: build_fetch_probe.py <outdir> --spec <json>"})
    outdir = sys.argv[1]
    spec_raw = _flag(sys.argv[2:], "--spec")
    if not spec_raw:
        return _emit({"ok": False, "error": "missing --spec"})
    try:
        spec = json.loads(spec_raw)
    except json.JSONDecodeError as exc:
        return _emit({"ok": False, "error": f"bad --spec JSON: {exc}"})

    allow = set(spec.get("allow") or [])
    if not allow:
        # Fail-closed: with no allowlist there is no permitted destination — refuse.
        return _emit({"ok": False, "error": "fetch refused: empty registry allowlist (deny-all)"})
    # Install the can't-forget egress backstop: ANY TCP connect outside the registry
    # allowlist is DROPPED (EgressBlocked), even one a package manager makes that we
    # didn't anticipate. This is the structural 'allowlisted' enforcement.
    _egress.install_socket_guard(allow)

    os.makedirs(outdir, exist_ok=True)
    vendor = os.path.join(outdir, "vendor")
    os.makedirs(vendor, exist_ok=True)
    if os.path.exists(WORK):
        import shutil
        shutil.rmtree(WORK, ignore_errors=True)
    import shutil
    try:
        shutil.copytree(SRC, WORK, symlinks=True)
    except OSError as exc:
        return _emit({"ok": False, "error": f"copy source: {exc}"})

    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (spec.get("env") or {}).items()})
    # Point package managers at the vendor dir (best-effort; recipe env can override).
    env.setdefault("CARGO_HOME", os.path.join(vendor, "cargo"))
    env.setdefault("GOPATH", os.path.join(vendor, "go"))
    env.setdefault("GOMODCACHE", os.path.join(vendor, "go", "pkg", "mod"))
    env.setdefault("PIP_TARGET", os.path.join(vendor, "pip"))

    log_path = os.path.join(outdir, "fetch.log")
    log = open(log_path, "w", encoding="utf-8")

    def w(s: str) -> None:
        log.write(s + "\n")
        log.flush()

    w(f"[build_fetch] allowlist: {sorted(allow)}")
    phases = spec.get("phases") or []
    phase_results = []
    ok = True
    err = None
    started = time.monotonic()
    for idx, ph in enumerate(phases):
        argv = list(ph.get("argv") or []) if isinstance(ph, dict) else list(ph)
        shell = bool(ph.get("shell")) if isinstance(ph, dict) else False
        if not argv:
            continue
        w(f"\n[build_fetch] phase {idx}: {argv}")
        try:
            cmd = ["sh", "-e", *argv] if shell else argv
            proc = subprocess.run(cmd, cwd=WORK, env=env, capture_output=True, text=True,
                                  timeout=int(os.environ.get("HG_FETCH_PHASE_TIMEOUT", "300")))
        except (OSError, subprocess.SubprocessError) as exc:
            w(f"[build_fetch] phase {idx} failed: {exc}")
            ok, err = False, f"phase {idx}: {exc}"
            phase_results.append({"argv": argv, "returncode": 127})
            break
        w(proc.stdout or "")
        w(proc.stderr or "")
        phase_results.append({"argv": argv, "returncode": proc.returncode})
        if proc.returncode != 0:
            ok = False
            err = f"fetch phase {idx} exited {proc.returncode} (see log)"
            blob = (proc.stderr or "") + (proc.stdout or "")
            if "EgressBlocked" in blob or "not in allowlist" in blob:
                err += " — a fetch tried to reach a host OUTSIDE the registry allowlist (refused)."
            break

    # Move any vendored caches the package managers populated INTO the vendor dir (they
    # already point there via env); also capture the source tree's own vendor/ if present.
    for cand in ("vendor", "deps"):
        srcv = os.path.join(WORK, cand)
        if os.path.isdir(srcv):
            try:
                shutil.copytree(srcv, os.path.join(vendor, cand), dirs_exist_ok=True)
            except OSError:
                pass

    lockfile, sbom = _hash_vendor(vendor)
    duration = time.monotonic() - started
    w(f"\n[build_fetch] done ok={ok} pinned={len(lockfile)} deps duration={duration:.1f}s")
    log.close()
    return _emit({"ok": ok, "lockfile": lockfile, "sbom": sbom, "error": err,
                  "phases": phase_results, "duration": duration})


if __name__ == "__main__":
    raise SystemExit(main())
