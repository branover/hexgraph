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
    w(f"[build_probe] injected: CC={env.get('CC')} CXX={env.get('CXX')} "
      f"CFLAGS={env.get('CFLAGS')} SANITIZER={env.get('SANITIZER')} "
      f"FUZZING_ENGINE={env.get('FUZZING_ENGINE')}")

    phases = spec.get("phases") or []
    phase_results = []
    started = time.monotonic()
    ok = True
    returncode = 0
    err = None
    for idx, ph in enumerate(phases):
        if isinstance(ph, (list, tuple)):
            argv, shell = list(ph), False
        else:
            argv, shell = list(ph.get("argv") or []), bool(ph.get("shell"))
        if not argv:
            continue
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

    # Capture the requested artifacts (rel paths under the build dir → /out/artifacts/<rel>).
    captured: dict[str, bool] = {}
    if ok:
        for rel in spec.get("artifacts") or []:
            srcp = os.path.join(BUILD_DIR, rel)
            if os.path.isfile(srcp):
                dstp = os.path.join(art_out, rel)
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
