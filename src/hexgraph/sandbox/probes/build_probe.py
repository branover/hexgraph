#!/usr/bin/env python3
"""Build a managed source tree into an INSTRUMENTED artifact inside the sandbox
(design §3, Phase 2 — build-as-API).

  argv: /out (rw — artifacts + log land here)  --spec <json>
  spec: {phases:[{argv:[...], shell:bool}], env:{CC,CXX,CFLAGS,SANITIZER,...},
         artifacts:[rel,...], system:str}

Runs the RECORDED recipe, never a human-typed shell. The source is mounted
READ-ONLY at /src; we copy it into a writable /scratch build dir so the immutable
snapshot is never mutated (a past build's reproducibility is preserved). The
orchestrator injects the toolchain env (CC/CXX/CFLAGS/SANITIZER/FUZZING_ENGINE per
the base-image contract §3.1) so the TARGET's own objects get SanCov+ASan — the
recipe only says "what to build", the env says "how it's instrumented".

Hardening (set by the runner, not here): --network none (vendored/offline only this
phase), --read-only rootfs + tmpfs /scratch (rw,exec for compiling), --cap-drop ALL,
--no-new-privileges, --user 1000, mem/cpu/pids caps, hard timeout. A malicious
configure can burn CPU and exit; it cannot persist or exfiltrate.

Emits JSON {ok, returncode, toolchain_digest, duration, artifacts:{rel:true},
error, phases:[{argv, returncode}]}; the captured artifacts are written to
/out/artifacts/<rel> and the full log to /out/build.log. The probe ALWAYS exits 0
with a JSON verdict (a failed build is `ok:false`, not a probe crash), so the
orchestrator reads the log + surfaces a recipe-iteration signal.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time

SRC = "/src"
SCRATCH = os.environ.get("TMPDIR", "/scratch")
BUILD_DIR = os.path.join(SCRATCH, "build")


def _flag(args, name, default=None):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _toolchain_digest() -> str:
    """A stable identity for the compiler/toolchain in this image — part of the
    reproducibility triple. Prefer `clang --version`'s first line; fall back to a
    fixed token so the digest is never empty."""
    for cc in ("clang", "cc", "gcc"):
        exe = shutil.which(cc)
        if not exe:
            continue
        try:
            out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20)
            line = (out.stdout or out.stderr or "").splitlines()
            if line:
                return line[0].strip()[:80]
        except (OSError, subprocess.SubprocessError):
            continue
    return "unknown-toolchain"


def _emit(obj: dict) -> int:
    obj.setdefault("tool", "build_probe")
    print(json.dumps(obj))
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        return _emit({"ok": False, "error": "usage: build_probe.py <outdir> --spec <json>"})
    outdir = sys.argv[1]
    spec_raw = _flag(sys.argv[2:], "--spec")
    if not spec_raw:
        return _emit({"ok": False, "error": "missing --spec"})
    try:
        spec = json.loads(spec_raw)
    except json.JSONDecodeError as exc:
        return _emit({"ok": False, "error": f"bad --spec JSON: {exc}"})

    os.makedirs(outdir, exist_ok=True)
    art_out = os.path.join(outdir, "artifacts")
    os.makedirs(art_out, exist_ok=True)
    log_path = os.path.join(outdir, "build.log")
    log = open(log_path, "w", encoding="utf-8")

    def w(line: str) -> None:
        log.write(line + "\n")
        log.flush()

    toolchain = _toolchain_digest()
    w(f"[build_probe] toolchain: {toolchain}")

    if not os.path.isdir(SRC):
        w(f"[build_probe] ERROR: source not mounted at {SRC}")
        log.close()
        return _emit({"ok": False, "error": f"source not mounted at {SRC}",
                      "toolchain_digest": toolchain})

    # Copy the READ-ONLY source snapshot into a writable build dir (the snapshot
    # itself is never mutated — reproducibility). /scratch is rw,exec.
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR, ignore_errors=True)
    try:
        shutil.copytree(SRC, BUILD_DIR, symlinks=True)
    except OSError as exc:
        w(f"[build_probe] ERROR copying source: {exc}")
        log.close()
        return _emit({"ok": False, "error": f"copy source: {exc}", "toolchain_digest": toolchain})

    # The injected toolchain env (base-image contract). The recipe author NEVER sets
    # CC/CXX/CFLAGS; the orchestrator does, per the instrumentation profile.
    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (spec.get("env") or {}).items()})
    env.setdefault("SRC", SRC)
    env["OUT"] = art_out
    env["WORK"] = BUILD_DIR
    # Determinism + incrementality (Phase 7): SOURCE_DATE_EPOCH (injected by the
    # orchestrator) pins embedded timestamps; ccache (USE_CCACHE) wraps CC/CXX so an
    # incremental rebuild reuses cached objects. Neither touches the sandbox security flags.
    if env.get("USE_CCACHE") == "1" and shutil.which("ccache"):
        cache_dir = env.get("CCACHE_DIR") or os.path.join(SCRATCH, "ccache")
        os.makedirs(cache_dir, exist_ok=True)
        env["CCACHE_DIR"] = cache_dir
        for var in ("CC", "CXX"):
            val = env.get(var)
            if val and not val.startswith("ccache "):
                env[var] = "ccache " + val
        w("[build_probe] ccache enabled (incremental object reuse)")
    # The bounded-fetch vendor dir (Phase F) is mounted RO at /vendor; point package
    # managers at it for the OFFLINE compile (the recipe env can override).
    if spec.get("vendor"):
        env.setdefault("CARGO_HOME", os.path.join(spec["vendor"], "cargo"))
        env.setdefault("GOPATH", os.path.join(spec["vendor"], "go"))
        env.setdefault("GOMODCACHE", os.path.join(spec["vendor"], "go", "pkg", "mod"))
        w(f"[build_probe] vendor dir mounted at {spec['vendor']} (offline compile)")
    w(f"[build_probe] injected: CC={env.get('CC')} CXX={env.get('CXX')} "
      f"CFLAGS={env.get('CFLAGS')} SANITIZER={env.get('SANITIZER')} "
      f"FUZZING_ENGINE={env.get('FUZZING_ENGINE')} SOURCE_DATE_EPOCH={env.get('SOURCE_DATE_EPOCH')}")

    phases = spec.get("phases") or []
    phase_results = []
    started = time.monotonic()
    ok = True
    returncode = 0
    err = None
    ran_any = False
    for idx, ph in enumerate(phases):
        if isinstance(ph, (list, tuple)):
            argv, shell = list(ph), False
        else:
            argv, shell = list(ph.get("argv") or []), bool(ph.get("shell"))
        if not argv:
            w(f"[build_probe] phase {idx} has empty argv — skipped")
            continue
        ran_any = True
        w(f"\n[build_probe] phase {idx}: {'(shell) ' if shell else ''}{argv}")
        try:
            if shell:
                # A recorded build.sh phase: argv is [path-to-script] run with sh -e.
                proc = subprocess.run(["sh", "-e", *argv], cwd=BUILD_DIR, env=env,
                                      capture_output=True, text=True)
            else:
                proc = subprocess.run(argv, cwd=BUILD_DIR, env=env,
                                      capture_output=True, text=True)
        except OSError as exc:
            w(f"[build_probe] phase {idx} could not launch: {exc}")
            ok, returncode, err = False, 127, f"phase {idx}: {exc}"
            phase_results.append({"argv": argv, "returncode": 127})
            break
        w(proc.stdout or "")
        w(proc.stderr or "")
        phase_results.append({"argv": argv, "returncode": proc.returncode})
        if proc.returncode != 0:
            ok, returncode = False, proc.returncode
            err = f"phase {idx} exited {proc.returncode} (see log)"
            # A common cause this phase: a recipe that needs network deps. Say so honestly.
            blob = (proc.stderr or "") + (proc.stdout or "")
            if any(s in blob for s in ("Could not resolve host", "Network is unreachable",
                                       "Temporary failure in name resolution", "Connection refused")):
                err += " — looks like a NETWORK fetch was attempted; builds are vendored/offline " \
                       "only this phase (--network none). Vendor the deps and retry."
            break

    duration = time.monotonic() - started

    # Honesty guard: phases were submitted but NONE actually ran (every one had empty argv).
    # Fail loudly rather than fall through to "succeeded" (or the confusing no-artifact error)
    # — a recipe that ran zero commands never built anything. The host now validates phases
    # up front (normalize_build_phases), so this is the last-line defense against a malformed
    # recipe reporting a fake success.
    if ok and phases and not ran_any:
        ok = False
        err = "no build phases ran — every submitted phase had empty argv (malformed recipe)"

    # Capture the requested artifacts (rel paths under the build dir → /out/artifacts/<rel>).
    # Defense-in-depth: an artifact rel is operator/LLM-authored, so refuse absolute paths
    # and traversal — a build may only capture a file that resolves INSIDE the build dir
    # (and the kept `rel` key is the contained path, so the engine reading /out/artifacts/
    # <rel> back agrees). The sandbox already contains this (RO rootfs, no secrets,
    # --network none), but a build has no business reading outside its own tree.
    build_root = os.path.realpath(BUILD_DIR)
    art_root = os.path.realpath(art_out)
    captured: dict[str, bool] = {}
    if ok:
        for rel in spec.get("artifacts") or []:
            if os.path.isabs(rel):
                w(f"[build_probe] refusing absolute artifact path: {rel}")
                continue
            # An artifact may resolve under the BUILD dir ($WORK) — the common case — OR
            # already be in $OUT (= art_out): an OSS-Fuzz build.sh copies its fuzz targets to
            # $OUT, so `out/<name>` resolves there, not under $WORK. Try $OUT first (where a
            # script intentionally placed it), then the build dir. Both are contained roots.
            cand_out = os.path.realpath(os.path.join(art_out, rel))
            cand_work = os.path.realpath(os.path.join(BUILD_DIR, rel))
            srcp = None
            if (cand_out == art_root or cand_out.startswith(art_root + os.sep)) and os.path.isfile(cand_out):
                # Already in /out/artifacts (placed by the script) — keep it as-is.
                captured[rel] = True
                continue
            if cand_work == build_root or cand_work.startswith(build_root + os.sep):
                srcp = cand_work
            else:
                w(f"[build_probe] refusing artifact outside the build dir / $OUT: {rel}")
                continue
            if os.path.isfile(srcp):
                dstp = os.path.join(art_out, rel)
                # The dst must also stay within /out/artifacts (rel is contained per the
                # check above, so this holds; keep the guard explicit).
                if not os.path.realpath(dstp).startswith(os.path.realpath(art_out) + os.sep):
                    w(f"[build_probe] refusing artifact dst outside /out: {rel}")
                    continue
                os.makedirs(os.path.dirname(dstp) or art_out, exist_ok=True)
                try:
                    shutil.copyfile(srcp, dstp)
                    captured[rel] = True
                except OSError as exc:
                    w(f"[build_probe] could not capture {rel}: {exc}")
            else:
                w(f"[build_probe] requested artifact not found: {rel}")
        if spec.get("artifacts") and not captured:
            ok = False
            err = "build succeeded but produced none of the requested artifacts (check rel paths)"

    w(f"\n[build_probe] done ok={ok} returncode={returncode} duration={duration:.1f}s "
      f"artifacts={list(captured)}")
    log.close()
    return _emit({
        "ok": ok, "returncode": returncode, "toolchain_digest": toolchain,
        "duration": duration, "artifacts": captured, "error": err, "phases": phase_results,
    })


if __name__ == "__main__":
    raise SystemExit(main())
