#!/usr/bin/env python3
"""Inspect a mounted source tree and propose a build `system` + default phases
(design §3.2 path 1 — Detected). Deterministic; runs NO project code (it only reads
file names), so it's safe to run in the box before any build is authorized.

  argv: /out (unused)  --src /src  (source mounted read-only)

Emits JSON {system, phases:[{argv:[...]}], evidence:[...]}. The host-side
`engine.builds.detect_build_system` is the fast default; this probe is the deeper
in-sandbox inspection (e.g. recursing for a nested build file) the API can call
when the manifest heuristic is inconclusive.
"""

from __future__ import annotations

import json
import os
import sys

SRC = "/src"


def _flag(args, name, default=None):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _emit(obj: dict) -> int:
    obj.setdefault("tool", "build_detect_probe")
    print(json.dumps(obj))
    return 0


# (marker filename, build system) — checked in priority order at the tree root.
_MARKERS = [
    ("CMakeLists.txt", "cmake"),
    ("meson.build", "meson"),
    ("Cargo.toml", "cargo"),
    ("go.mod", "go"),
    ("configure", "autotools"),
    ("configure.ac", "autotools"),
    ("autogen.sh", "autotools"),
    ("Makefile", "make"),
    ("makefile", "make"),
    ("GNUmakefile", "make"),
]


def main() -> int:
    src = _flag(sys.argv[1:], "--src", SRC)
    if not os.path.isdir(src):
        return _emit({"system": "custom", "phases": [], "evidence": [],
                      "error": f"source not mounted at {src}"})
    try:
        names = set(os.listdir(src))
    except OSError as exc:
        return _emit({"system": "custom", "phases": [], "evidence": [], "error": str(exc)})

    system = "custom"
    evidence = []
    for marker, sysname in _MARKERS:
        if marker in names:
            system, evidence = sysname, [marker]
            break

    j = ["-j", str(max(1, os.cpu_count() or 2))]
    phases_map = {
        "cmake": [["cmake", "-S", ".", "-B", "build"], ["cmake", "--build", "build", *j]],
        "meson": [["meson", "setup", "build"], ["meson", "compile", "-C", "build"]],
        "autotools": [["./configure"], ["make", *j]],
        "cargo": [["cargo", "build", "--release", "--offline"]],
        "go": [["go", "build", "./..."]],
        "make": [["make", *j]],
        "custom": [],
    }
    phases = [{"argv": p} for p in phases_map.get(system, [])]
    return _emit({"system": system, "phases": phases, "evidence": evidence})


if __name__ == "__main__":
    raise SystemExit(main())
