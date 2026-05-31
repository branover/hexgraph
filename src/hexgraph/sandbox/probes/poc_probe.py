#!/usr/bin/env python3
"""Verify a proof-of-concept by EXECUTING the target in the sandbox (dynamic).

  argv: /artifact /out --spec <json>

The spec describes how to run the target and how to know the PoC worked:
  {
    "argv":  ["..."],                 # extra args after the program (optional)
    "env":   {"QUERY_STRING": "..."}, # environment for the run (optional)
    "stdin": "...",                   # stdin to feed (optional)
    "timeout": 20,                    # wall-clock seconds (optional)
    "oracle": {"type": "output_contains"|"exit_code"|"exit_nonzero"|"crash", "value": ...}
  }

Emits JSON: {ran, verified, exit_code, signal, output, oracle, detail}.

Runs ONLY when the analysis policy permits execution (PoC/fuzzing enabled) — the
runner gates this via requires_execution=True. Still --network none, capped,
timed, disposable. We copy the target to the writable+exec /out and run it there.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys


def _flag(args, name, default=None):
    if name in args:
        i = args.index(name)
        if i + 1 < len(args):
            return args[i + 1]
    return default


def _check_oracle(oracle: dict, output: str, rc: int) -> tuple[bool, str]:
    t = (oracle or {}).get("type", "output_contains")
    val = (oracle or {}).get("value")
    if t == "output_contains":
        return (str(val) in output, f"output {'contains' if str(val) in output else 'missing'} {val!r}")
    if t == "exit_code":
        return (rc == int(val), f"exit {rc} vs expected {val}")
    if t == "exit_nonzero":
        return (rc != 0, f"exit {rc}")
    if t == "crash":
        # killed by signal (negative rc) or ASan-style abort
        crashed = rc < 0 or rc in (134, 139) or "AddressSanitizer" in output or "Segmentation fault" in output
        return (crashed, f"exit {rc}{' (crash)' if crashed else ''}")
    return (False, f"unknown oracle type {t!r}")


def main() -> int:
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: poc_probe.py <artifact> <outdir> --spec <json>"}))
        return 2
    artifact, outdir, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
    try:
        spec = json.loads(_flag(rest, "--spec", "{}"))
    except json.JSONDecodeError as exc:
        print(json.dumps({"error": f"bad --spec json: {exc}"}))
        return 2

    target = os.path.join(outdir, "poc_target")
    shutil.copyfile(artifact, target)
    os.chmod(target, 0o755)

    env = dict(os.environ)
    env.update({str(k): str(v) for k, v in (spec.get("env") or {}).items()})
    cmd = [target, *[str(a) for a in (spec.get("argv") or [])]]
    timeout = int(spec.get("timeout", 20))

    try:
        proc = subprocess.run(cmd, env=env, cwd=outdir, capture_output=True, text=True,
                              input=spec.get("stdin"), timeout=timeout)
        rc, out = proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except subprocess.TimeoutExpired as exc:
        rc, out = 124, (exc.output or "") if isinstance(exc.output, str) else ""
    except OSError as exc:
        print(json.dumps({"tool": "poc_probe", "ran": False, "verified": False,
                          "detail": f"could not execute target: {exc}"}))
        return 0

    verified, detail = _check_oracle(spec.get("oracle") or {}, out, rc)
    print(json.dumps({"tool": "poc_probe", "ran": True, "verified": verified,
                      "exit_code": rc, "output": out[:8000], "oracle": spec.get("oracle"),
                      "detail": detail}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
