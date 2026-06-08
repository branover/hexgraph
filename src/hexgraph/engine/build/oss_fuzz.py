"""Import an OSS-Fuzz-style `build.sh` / project layout into a HexGraph `BuildSpec`
(design §3.1/§7, Phase 7).

OSS-Fuzz's durable lesson is the base-image CONTRACT: a project ships a `build.sh`
that relies on `$CC`/`$CXX`/`$CFLAGS`/`$CXXFLAGS`/`$LIB_FUZZING_ENGINE`/`$SRC`/`$OUT`
set by the orchestrator. HexGraph's build-image contract sets the SAME variables
(`engine/build.py: instrumentation_env` + the build probe), so an existing
`build.sh` runs essentially unchanged — referenced by a single `shell:true` phase
(design §3.2 path 3). This module:

  • stores the `build.sh` as a `source_file(role=script)` in the tree,
  • adds `$LIB_FUZZING_ENGINE` to the injected env (the one var our contract didn't
    already expose — it points at the fuzzing-engine driver the harness links),
  • produces a `BuildSpec` whose single phase runs `build.sh` and whose `artifacts`
    capture the fuzz targets the script drops in `$OUT`.

No project code runs here — this is a deterministic mapping. The build itself still
runs in the sandbox via the Builder seam, gated by features.build.
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from hexgraph.db.models import Project, SourceTree
from hexgraph.engine.build.build import BuildPhase, BuildSpec, Instrumentation

# The OSS-Fuzz → HexGraph instrumentation default: ASan + libFuzzer (their most common
# sanitizer/engine pairing). The recorded recipe is editable; the operator can swap to
# AFL++ by changing only the instrumentation profile (the base-image contract).
_DEFAULT_INSTR = {"sanitizers": ["address"], "coverage": ["sancov"], "engine": "libfuzzer"}

# Heuristic: pull `$OUT/<name>` targets out of a build.sh so we can capture them. In the
# OSS-Fuzz contract `$OUT` IS the artifact-output dir (HexGraph maps it to the capture
# root), so a target written to `$OUT/<name>` is captured as the BARE `<name>` (the probe
# accepts an artifact rel resolving under either $WORK or $OUT).
_OUT_TARGET = re.compile(r"\$\{?OUT\}?/([A-Za-z0-9._-]+)")


def parse_build_sh_artifacts(build_sh: str) -> list[str]:
    """Best-effort: the fuzz-target names a build.sh writes into `$OUT` (so we capture
    them as build artifacts, by their BARE name — `$OUT` is the capture root).
    Deterministic regex over the script text — runs nothing."""
    names: list[str] = []
    for m in _OUT_TARGET.finditer(build_sh or ""):
        n = m.group(1)
        if n and n not in names and not n.endswith((".o", ".a", ".options", ".dict")):
            names.append(n)
    return names


def import_oss_fuzz(session: Session, project: Project, tree: SourceTree, *,
                    build_sh: str, rel: str = "build.sh",
                    instrumentation: dict | None = None,
                    artifacts: list[str] | None = None) -> BuildSpec:
    """Ingest an OSS-Fuzz `build.sh` into a recorded `BuildSpec`. Stores the script as a
    `source_file(role=script)` in `tree` (the tree must be editable to accept the write),
    maps the OSS-Fuzz env contract to ours (adding `$LIB_FUZZING_ENGINE`), and returns a
    BuildSpec whose single `shell:true` phase runs the script with the SAME `$CC/$CXX/
    $CFLAGS/$OUT/$SRC` the orchestrator injects. `artifacts` overrides the auto-detected
    `$OUT/<name>` capture list. Returns the spec (not persisted — the caller records it)."""
    from hexgraph.engine.build.source import SourceError, write_source_file

    if not (build_sh or "").strip():
        raise SourceError("empty build.sh")
    # Store the script in the tree (role=script). Requires an editable tree.
    write_source_file(session, project, tree, rel, build_sh, role="script")
    instr = Instrumentation.from_dict(instrumentation or _DEFAULT_INSTR)
    caps = artifacts if artifacts is not None else parse_build_sh_artifacts(build_sh)
    spec = BuildSpec(
        source_tree_id=tree.id,
        system="custom",  # the script fully specifies the build (no implied phases)
        phases=(BuildPhase((rel,), shell=True),),
        instrumentation=instr,
        artifacts=tuple(caps),
        # The one OSS-Fuzz var our base-image contract doesn't already set: the path to the
        # fuzzing-engine driver the harness links (`$LIB_FUZZING_ENGINE`). libFuzzer ships
        # in clang's compiler-rt; AFL++ uses its own driver. The probe expands it.
        env={"LIB_FUZZING_ENGINE": _lib_fuzzing_engine(instr)},
        name=f"{tree.name} (oss-fuzz build.sh)",
    )
    return spec


def _lib_fuzzing_engine(instr: Instrumentation) -> str:
    """The `$LIB_FUZZING_ENGINE` value per the engine (OSS-Fuzz contract). libFuzzer is
    `-fsanitize=fuzzer` (clang links its driver); AFL++ uses its own driver lib. A flag,
    not a secret — recorded on the recipe."""
    if instr.engine == "afl":
        return "/usr/local/lib/afl/libAFLDriver.a"
    return "-fsanitize=fuzzer"
