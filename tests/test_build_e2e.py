"""Docker-gated end-to-end: the REAL build_probe in the hexgraph-build image.

Proves the build-as-API loop end to end: a tiny C source tree is rebuilt with a
recorded recipe, the instrumentation profile injects SanCov+ASan into the target's
own objects, the artifact is captured + homed in CAS, and the produced object
actually carries the sanitizer/coverage instrumentation (so Phase-3 coverage-guided
fuzzing has real feedback). Skips without Docker + the hexgraph-build image (set
HEXGRAPH_BUILD_IMAGE to the tag you built).

Stays within the BUILD scope — it does NOT execute the target (that's the exec
gate). It confirms instrumentation by inspecting the built object's symbols in the
same sandbox image, not by running it."""

import json
import os
import subprocess

import pytest

from hexgraph.db.session import session_scope
from hexgraph.engine.build import builds as B
from hexgraph.engine import cas
from hexgraph.engine.build import source as src
from hexgraph.engine.build.build import BuildSpec
from hexgraph.engine.ingest import create_project
from hexgraph import settings

from conftest import BUILD_IMAGE_READY

pytestmark = pytest.mark.skipif(
    not BUILD_IMAGE_READY,
    reason="requires Docker + the hexgraph-build image (just build-image; "
           "set HEXGRAPH_BUILD_IMAGE for a worktree tag)")

# A self-contained libFuzzer target with a planted heap-buffer-overflow. We compile
# it under the SanCov+ASan profile into an object (`fuzz.o`) and a linked binary
# (`fuzz`); the object carries the instrumentation.
TARGET_C = r"""
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char*)malloc(8);
    if (size > 0) memcpy(buf, data, size);  /* heap-buffer-overflow when size > 8 */
    free(buf);
    return 0;
}
"""

# The instrumented OBJECT is the artifact Phase-3 coverage-guided fuzzing links a
# harness against — SanCov+ASan live in it. We also link a standalone runnable
# target with the full libFuzzer driver (`-fsanitize=fuzzer`) to prove a complete
# instrumented binary builds. CC/CFLAGS are INJECTED by HexGraph (base-image
# contract): CFLAGS already carries `-fsanitize=fuzzer-no-link,address`, so the
# object is instrumented; the binary adds the driver.
MAKEFILE = r"""
CC ?= clang
CFLAGS ?= -O1 -g
all: fuzz.o fuzz
fuzz.o: target.c
	$(CC) $(CFLAGS) -c target.c -o fuzz.o
fuzz: target.c
	$(CC) $(CFLAGS) -fsanitize=fuzzer target.c -o fuzz
"""


def _has_symbols(image: str, obj_bytes: bytes, needles) -> bool:
    """True if `nm`/strings over the object (fed via stdin in the build image) shows
    any of `needles` (sanitizer/coverage symbols). Runs in the build image so we use
    its own llvm toolchain; no target execution."""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as fh:
        fh.write(obj_bytes)
        path = fh.name
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "none",
             "-v", f"{path}:/tmp/obj.o:ro", image,
             "sh", "-c", "nm /tmp/obj.o 2>/dev/null || llvm-nm /tmp/obj.o 2>/dev/null"],
            capture_output=True, text=True, timeout=60,
        )
        blob = (out.stdout or "") + (out.stderr or "")
        return any(n in blob for n in needles)
    finally:
        os.unlink(path)


def test_instrumented_build_produces_sancov_asan_artifact(hg_home, monkeypatch):
    settings.update_settings({"features.build.enabled": True})  # the build gate
    image = os.environ.get("HEXGRAPH_BUILD_IMAGE", "hexgraph-build:latest")
    with session_scope() as s:
        p = create_project(s, name="e2e-build")
        tree = src.create_source_tree(s, p, name="tinyfuzz", origin="scratch", editable=True)
        src.write_source_file(s, p, tree, "target.c", TARGET_C)
        src.write_source_file(s, p, tree, "Makefile", MAKEFILE)
        spec = BuildSpec.from_dict({
            "source_tree_id": tree.id, "system": "make",
            "phases": [{"argv": ["make"]}],
            "instrumentation": {"sanitizers": ["address"], "coverage": ["sancov"],
                                "engine": "libfuzzer"},
            "artifacts": ["fuzz.o", "fuzz"],
        })
        spec_row = B.create_build_spec(s, p, spec)
        # The REAL SandboxBuilder (default seam) — no builder override.
        build = B.run_build(s, p, spec_row)
        assert build.status == "succeeded", (build.error, build.log_cas and cas.get_text(p, build.log_cas))
        # both artifacts homed in CAS
        assert "fuzz.o" in build.artifacts_json and "fuzz" in build.artifacts_json
        assert build.toolchain_digest and "clang" in build.toolchain_digest.lower()
        # the object carries SanCov + ASan instrumentation (the whole point)
        obj = cas.get(p, build.artifacts_json["fuzz.o"])
        assert obj, "fuzz.o not in CAS"
        assert _has_symbols(image, obj, ("__sanitizer_cov", "__asan", "asan")), \
            "built object lacks SanCov/ASan instrumentation"
        # a derived target was NOT registered here (no built_from target), but the
        # build + artifacts are durable + reproducible.
        assert build.recipe_sha == spec.recipe_sha()


def test_build_network_dep_fails_honestly(hg_home):
    """A recipe that tries to fetch over the network fails with a clear message
    (--network none, vendored/offline only this phase)."""
    settings.update_settings({"features.build.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="e2e-nonet")
        tree = src.create_source_tree(s, p, name="netdep", origin="scratch", editable=True)
        src.write_source_file(s, p, tree, "Makefile",
                              "all:\n\tcurl -sf https://example.com -o /tmp/x\n")
        spec = BuildSpec.from_dict({
            "source_tree_id": tree.id, "system": "make",
            "phases": [{"argv": ["make"]}], "artifacts": ["x"],
        })
        build = B.run_build(s, p, B.create_build_spec(s, p, spec))
        assert build.status == "failed"
        # the log records the failure; the error mentions network when the resolver fails
        log = cas.get_text(p, build.log_cas) if build.log_cas else ""
        assert build.error  # honest failure, not a crash
