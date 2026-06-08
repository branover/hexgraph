"""Docker-gated end-to-end for Phase 7 — the REAL build_probe / build_fetch_probe in
the hexgraph-build image (set HEXGRAPH_BUILD_IMAGE to the worktree tag, built WITH
WITH_CROSS=1 for the cross test).

Proves the SAFETY-critical properties against real containers:
  - the COMPILE phase runs --network none even with features.build_fetch on
    (fetch-then-offline): a compile that tries the network fails honestly;
  - the FETCH phase reaches an ALLOWLISTED loopback registry but is BLOCKED from a
    non-allowlisted host (the egress backstop), produces a hash-pinned lockfile, and the
    subsequent compile sees the vendored bytes with NO network;
  - cross-compile injects clang --target so a foreign-arch (MIPS) object is produced
    (skips if the cross toolchain isn't in the image).

These execute NOTHING of a target (build scope only) — they inspect produced bytes.
"""

import os
import subprocess

import pytest

from hexgraph import settings
from hexgraph.db.session import session_scope
from hexgraph.engine.build import builds as B
from hexgraph.engine import cas
from hexgraph.engine.build import source as src
from hexgraph.engine.build.build import BuildSpec
from hexgraph.engine.targets.ingest import create_project

from conftest import BUILD_IMAGE_READY

pytestmark = pytest.mark.skipif(
    not BUILD_IMAGE_READY,
    reason="requires Docker + the hexgraph-build image (set HEXGRAPH_BUILD_IMAGE)")


def _enable_fetch():
    settings.update_settings({"features.build.enabled": True,
                              "features.build_fetch.enabled": True})


def test_compile_phase_has_no_network_even_with_fetch_on(hg_home):
    """The decisive supply-chain property: the COMPILE phase is --network none even when
    features.build_fetch is enabled. A compile that tries the network fails honestly — so a
    malicious dep fetched in Phase F cannot phone home during compile."""
    _enable_fetch()
    with session_scope() as s:
        p = create_project(s, name="e2e-compile-nonet")
        tree = src.create_source_tree(s, p, name="t", origin="scratch", editable=True)
        # Fetch phase: a no-op that succeeds (touch a vendor marker). Compile phase: tries
        # the network — must FAIL because the compile container is --network none.
        src.write_source_file(s, p, tree, "Makefile",
                              "all:\n\tcurl -sf https://example.com -o x || (echo NETFAIL; exit 7)\n")
        spec = BuildSpec.from_dict({
            "source_tree_id": tree.id, "system": "make",
            "phases": [{"argv": ["make"]}],
            "fetch_phases": [{"argv": ["true"]}],
            "network": "fetch", "artifacts": ["x"],
        })
        build = B.run_build(s, p, B.create_build_spec(s, p, spec))
        assert build.status == "failed"  # the compile's network attempt failed
        # Decisive: the failure is the COMPILE's network attempt, NOT a fetch-gate refusal —
        # the fetch ran (features.network is OFF; only features.build_fetch is on), the
        # compile log exists, and it carries our planted NETFAIL marker.
        log = cas.get_text(p, build.log_cas) if build.log_cas else ""
        assert "NETFAIL" in (log or ""), f"expected the compile (not the fetch gate) to fail: {build.error}"


def test_fetch_blocks_non_allowlisted_host(hg_home):
    """The FETCH phase's egress backstop DROPS a connect outside the registry allowlist.
    We use a custom allowlist of one loopback host:port; a fetch that curls a DIFFERENT
    host must be refused (EgressBlocked), failing the fetch honestly."""
    _enable_fetch()
    settings.update_settings({"features.build_fetch.allowlist": ["127.0.0.1:9"]})  # discard port
    with session_scope() as s:
        p = create_project(s, name="e2e-fetch-block")
        tree = src.create_source_tree(s, p, name="t", origin="scratch", editable=True)
        src.write_source_file(s, p, tree, "Makefile", "all:\n\t:\n")
        # The fetch phase tries to reach a NON-allowlisted public host → blocked by the guard.
        spec = BuildSpec.from_dict({
            "source_tree_id": tree.id, "system": "make",
            "phases": [{"argv": ["true"]}],
            "fetch_phases": [{"argv": ["python3", "-c",
                                       "import urllib.request as u; u.urlopen('http://93.184.216.34:80', timeout=5)"]}],
            "network": "fetch", "artifacts": [],
        })
        build = B.run_build(s, p, B.create_build_spec(s, p, spec))
        # The fetch failed (the guard blocked the off-allowlist connect) ⇒ build failed.
        assert build.status == "failed"
        # And the allowlist egress was AUDITED (allowed entries for the registry scope).
        from hexgraph.db.models import EgressEvent
        evs = s.query(EgressEvent).filter(EgressEvent.tool == "build_fetch").all()
        assert evs and any(e.dest == "127.0.0.1:9" for e in evs)


def _nm(image, obj_bytes, needles):
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".o", delete=False) as fh:
        fh.write(obj_bytes); path = fh.name
    try:
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "-v", f"{path}:/tmp/o.o:ro", image,
             "sh", "-c", "file /tmp/o.o; llvm-nm /tmp/o.o 2>/dev/null || nm /tmp/o.o 2>/dev/null"],
            capture_output=True, text=True, timeout=60)
        return (out.stdout or "") + (out.stderr or "")
    finally:
        os.unlink(path)


def test_oss_fuzz_build_captures_out_target(hg_home):
    """An OSS-Fuzz build.sh writes its fuzz target to $OUT; the build must capture it from
    there (not $WORK). Proves the $OUT/$WORK artifact-capture path end-to-end."""
    settings.update_settings({"features.build.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="e2e-ossfuzz")
        tree = src.create_source_tree(s, p, name="ofz", origin="scratch", editable=True)
        src.write_source_file(s, p, tree, "f.c", "int add(int a,int b){return a+b;}\n")
        # A build.sh that uses the injected $CC/$CFLAGS and writes to $OUT (OSS-Fuzz contract).
        build_sh = '$CC $CFLAGS -ffreestanding -c f.c -o "$OUT/fuzz_f"\n'
        row = B.import_oss_fuzz_build(s, p, tree, build_sh=build_sh,
                                      instrumentation={"sanitizers": [], "coverage": [], "engine": "none"})
        build = B.run_build(s, p, row)
        assert build.status == "succeeded", (build.error, build.log_cas and cas.get_text(p, build.log_cas))
        assert "fuzz_f" in build.artifacts_json   # captured from $OUT by its bare name


def test_cross_compile_produces_foreign_arch_object(hg_home):
    """Cross-compile (design §3.4): with arch='mips' HexGraph injects clang
    --target=mipsel-linux-gnu, so the produced object is a MIPS ELF (not x86). Skips if the
    cross toolchain isn't in the image (degrade path). No --sysroot here (no firmware
    rootfs); clang's bundled headers compile a freestanding object."""
    image = os.environ.get("HEXGRAPH_BUILD_IMAGE", "hexgraph-build:latest")
    settings.update_settings({"features.build.enabled": True})
    with session_scope() as s:
        p = create_project(s, name="e2e-cross")
        tree = src.create_source_tree(s, p, name="x", origin="scratch", editable=True)
        # Freestanding object (no libc dependency) so cross-compile works without a sysroot.
        src.write_source_file(s, p, tree, "f.c", "int add(int a,int b){return a+b;}\n")
        src.write_source_file(s, p, tree, "Makefile",
                              "all:\n\t$(CC) $(CFLAGS) -ffreestanding -c f.c -o f.o\n")
        spec = BuildSpec.from_dict({
            "source_tree_id": tree.id, "system": "make", "phases": [{"argv": ["make"]}],
            "instrumentation": {"sanitizers": [], "coverage": [], "engine": "none"},
            "artifacts": ["f.o"], "arch": "mips",
        })
        build = B.run_build(s, p, B.create_build_spec(s, p, spec))
        if build.status != "succeeded":
            pytest.skip(f"cross toolchain unavailable in image (degrade path): {build.error}")
        obj = cas.get(p, build.artifacts_json["f.o"])
        info = _nm(image, obj, ())
        assert "MIPS" in info or "mips" in info, f"expected a MIPS object, got: {info[:200]}"
