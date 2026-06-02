"""`just demo` — the full offline loop on bundled fixtures, narrated + asserting.

A zero-token, no-key, no-network smoke test that exercises HexGraph's current
headline capabilities end-to-end and proves the core loop:

    target → task → structured finding → graph → spawn next task

The arc (each step ASSERTS its key outcome, so this doubles as a real smoke test):

  1. Ingest a FIRMWARE image → recon → unpack into child targets + `contains` edges
     (the real-sandbox stage — needs Docker, like every prior `demo`).
  2. Author a SOURCE TREE (C lib + fuzz harness) and BUILD-FROM-SOURCE WITH
     INSTRUMENTATION via the offline MockBuilder → an instrumented derived target
     wired `instrumented_build_of` → the shipped binary (the recorded recipe is
     reproducible: recipe_sha + source content_hash + toolchain_digest).
  3. Run a coverage-guided FUZZ CAMPAIGN on the instrumented target via the offline
     MockFuzzer → a `fuzz_crash` finding with dedup / exploitability / coverage + a
     minimized reproducer (assurance: code_present / dynamic — lab-confirmed).
  4. Run a `poc` task that EXECUTES a standalone target in the sandbox with an
     unforgeable `{{NONCE}}` oracle → a VERIFIED PoC carrying an ASSURANCE TRIPLE;
     print the {standard, method, precondition} ladder.
  5. SPAWN a suggested follow-up off a finding (the target→task→finding→graph→spawn
     loop) and run it.
  6. Build the GRAPH and print the node/edge-type variety (the new edge kinds:
     contains, built_from, instrumented_build_of, fuzzed_by, produced_artifact, …).

Everything but stage 1 is pure offline mock machinery: the MOCK LLM backend, the
MockBuilder, and the MockFuzzer — no API key, no fuzz/build Docker images (only the
base sandbox image stage 1 needs). Exits 0 on success.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from hexgraph.paths import repo_root


def _fixtures() -> Path:
    return repo_root() / "tests" / "fixtures"


def _step(msg: str) -> None:
    print(f"\033[36m▶\033[0m {msg}")


# A small C library + a libFuzzer harness. The source file name matches the
# MockFuzzer's coverage map (`target.c`) so coverage shading and the symbolized
# crash stack line up offline, exactly as `seed_showcase.py` does.
LIB_C = """\
/* httpd.c — the router's embedded CGI handler (trimmed). */
#include <string.h>
#include <stdlib.h>

int cgi_handler(const char *query) {
    char buf[64];
    const char *p = strstr(query, "host=");
    if (!p) return 1;
    strcpy(buf, p + 5);          /* BUG: unbounded copy (CWE-120) */
    return system(buf);          /* command-injection sink (CWE-78) */
}
"""

HARNESS_C = """\
/* fuzz_cgi.c — a libFuzzer harness driving the CGI parser directly. */
#include <stddef.h>
#include <stdint.h>

extern int cgi_handler(const char *query);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char q[512];
    size_t n = size < sizeof(q) - 1 ? size : sizeof(q) - 1;
    __builtin_memcpy(q, data, n);
    q[n] = 0;
    return cgi_handler(q);
}
"""


def main() -> int:
    from hexgraph.sandbox.runner import docker_available

    if not docker_available():
        print("demo requires Docker for the analysis sandbox. Start Docker and retry.", file=sys.stderr)
        return 1

    fixtures = _fixtures()
    for name in ("vuln_httpd", "synthetic_fw.bin"):
        if not (fixtures / name).exists():
            print(f"missing fixture {name}; run tests/fixtures/build.sh first.", file=sys.stderr)
            return 1

    # Snapshot the env we mutate so calling main() (e.g. from the smoke test, in-process)
    # NEVER leaks the mock seams into the caller's environment — a leaked HEXGRAPH_FUZZER/
    # _BUILDER would silently steer later tests onto the mock seam (real-toolchain assertions
    # then break). Restored in the finally below.
    _ENV_KEYS = ("HEXGRAPH_HOME", "HEXGRAPH_LLM_BACKEND", "HEXGRAPH_BUILDER", "HEXGRAPH_FUZZER")
    _saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
    try:
        return _run()
    finally:
        for k, v in _saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _run() -> int:
    fixtures = _fixtures()
    # Isolated, throwaway home so the demo is repeatable and offline.
    os.environ["HEXGRAPH_HOME"] = tempfile.mkdtemp(prefix="hexgraph-demo-")
    os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")
    # Drive the build + fuzz seams offline ($0, no fuzz/build Docker images).
    os.environ["HEXGRAPH_BUILDER"] = "mock"
    os.environ["HEXGRAPH_FUZZER"] = "mock"

    from hexgraph import settings as st
    from hexgraph.db.session import init_db, reset_engine_for_tests, session_scope
    from hexgraph.engine.graph import build_graph
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.pipeline import ingest_and_analyze

    reset_engine_for_tests()
    init_db()
    # Opt into the capabilities the loop exercises (the policy seam — the only place the
    # static-only default is relaxed). build → compile in the sandbox; poc/fuzzing → the
    # dynamic profile that permits the (still --network none, capped, timed) exec path.
    st.update_settings({
        "features.build.enabled": True,
        "features.fuzzing.enabled": True,
        "features.poc.enabled": True,
    })

    print("=== HexGraph demo — mock backend, no key, no network ===\n")

    # ── 1) Ingest firmware → recon → unpack into children + contains edges ──────────
    _step("Ingest a firmware image (synthetic_fw.bin): recon → unpack → child targets + contains edges")
    with session_scope() as s:
        from hexgraph.db.models import Edge, EdgeType, Target

        project = create_project(s, name="demo")
        pid = project.id
        summary = ingest_and_analyze(s, project, str(fixtures / "synthetic_fw.bin"))
        children = summary["children"]
        print(f"   root: {summary['name']} → {len(children)} child target(s):")
        for c in children:
            print(f"      └─ {c['name']}")
        contains = s.query(Edge).filter(
            Edge.project_id == pid, Edge.type == EdgeType.contains, Edge.dst_kind == "target"
        ).count()
        print(f"   contains edges: {contains}")
        assert children, "firmware unpack produced no child targets"
        assert contains >= len(children), "every unpacked child should be joined by a contains edge"
        # The shipped httpd child binary is the one we'll rebuild instrumented.
        httpd = next(t for t in s.query(Target).filter(Target.project_id == pid)
                     if t.name.endswith("httpd"))
        httpd_id = httpd.id

    # ── 2) Source tree + build-from-source WITH INSTRUMENTATION (MockBuilder) ────────
    _step("Author a source tree (C lib + fuzz harness) and build it INSTRUMENTED (MockBuilder)")
    from hexgraph.engine import builds as B
    from hexgraph.engine import source as src
    from hexgraph.engine.build import BuildSpec

    with session_scope() as s:
        from hexgraph.db.models import Edge, EdgeType, Project, Target
        from hexgraph.engine.authoring import create_edge

        project = s.query(Project).filter(Project.id == pid).one()
        tree = src.create_source_tree(s, project, name="acme-httpd (src)", origin="scratch")
        src.write_source_file(s, project, tree, "Makefile", "all:\n\t: build\n")
        src.write_source_file(s, project, tree, "target.c", LIB_C, role="code")
        src.write_source_file(s, project, tree, "fuzz/fuzz_cgi.c", HARNESS_C, role="harness")
        # The shipped httpd binary is built_from this tree, so the instrumented rebuild
        # wires instrumented_build_of → it.
        create_edge(s, project, src_kind="target", src_id=httpd_id,
                    dst_kind="source_tree", dst_id=tree.id, type="built_from",
                    attrs={"system": "make"})

        spec = BuildSpec.from_dict({
            **B.propose_build_spec(tree), "artifacts": ["fuzz_target"],
            "instrumentation": {"sanitizers": ["address"], "coverage": ["sancov"],
                                "engine": "libfuzzer"},
        })
        spec_row = B.create_build_spec(s, project, spec)
        build = B.run_build(s, project, spec_row)  # MockBuilder via HEXGRAPH_BUILDER=mock
        assert build.status == "succeeded", f"build failed: {build.error}"
        assert build.derived_target_id, "instrumented build produced no derived target"
        derived = s.get(Target, build.derived_target_id)
        instr = derived.metadata_json or {}
        print(f"   recorded recipe: system={spec.system}  recipe_sha={build.recipe_sha[:12]}…")
        print(f"   toolchain: {build.toolchain_digest}  "
              f"instrumentation={spec.instrumentation.to_dict()['sanitizers']}+sancov")
        print(f"   reproducible badge: {build.reproducible}  "
              "(recipe_sha + source content_hash + toolchain_digest)")
        print(f"   derived target: {derived.name}  instrumented={instr.get('instrumented')}")
        assert instr.get("instrumented") is True
        assert instr.get("sanitizers") == ["address"]
        ibo = s.query(Edge).filter(
            Edge.project_id == pid, Edge.type == EdgeType.instrumented_build_of,
            Edge.src_id == derived.id, Edge.dst_id == httpd_id,
        ).count()
        print(f"   instrumented_build_of edge (derived → shipped httpd): {ibo}")
        assert ibo == 1
        instr_target_id = derived.id

    # ── 3) Coverage-guided fuzz campaign on the instrumented target (MockFuzzer) ─────
    _step("Run a coverage-guided fuzz campaign on the instrumented target (MockFuzzer, offline)")
    from hexgraph.engine import campaigns as C
    from hexgraph.engine.fuzzers import FuzzCampaignSpec

    with session_scope() as s:
        from hexgraph.db.models import FuzzArtifact, FuzzCampaign, Project, Target

        project = s.query(Project).filter(Project.id == pid).one()
        instr_target = s.get(Target, instr_target_id)
        assert C.infer_surface(instr_target) == "source_lib", "instrumented target should fuzz source_lib"
        cspec = FuzzCampaignSpec(
            target_id=instr_target_id, surface="source_lib", harness_source=HARNESS_C,
            function="cgi_handler", target_sources=["/target.c"], max_total_time=60,
        )
        row = C.start_campaign(s, project, instr_target, spec=cspec)
        # The MockFuzzer launcher wrote /out synchronously; reap drives the full lifecycle
        # (running → ingest crash → finalize) and streams the crash into a fuzz_crash finding.
        created = C.reap_campaign(s, s.get(FuzzCampaign, row.id))
        row = s.get(FuzzCampaign, row.id)
        stats = row.stats_json or {}
        cov = C.coverage_for(s, row)
        print(f"   campaign: {row.name}  surface={row.surface}  engine={row.engine}  status={row.status}")
        print(f"   execs={stats.get('execs')}  edges_covered={stats.get('edges_covered')}  "
              f"crashes={stats.get('crash_count')}  line-coverage={cov.get('percent')}%")
        assert row.status == "completed"
        assert created >= 1, "the mock campaign should surface at least one crash finding"
        art = (s.query(FuzzArtifact)
               .filter(FuzzArtifact.campaign_id == row.id, FuzzArtifact.kind == "crash").first())
        expl = (art.exploitability_json or {}).get("rating")
        print(f"   crash artifact: dedup_key={art.dedup_key[:12]}…  exploitability={expl}  "
              f"minimized={art.size}B")
        assert art.content_cas, "the crash should carry a stored (minimized) reproducer in CAS"

    # ── 4) PoC verification → an assurance triple (the assurance ladder) ─────────────
    _step("Ingest a standalone target + run a `poc` task: execute in the sandbox, verify via {{NONCE}} oracle")
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    with session_scope() as s:
        from hexgraph.db.models import Project

        project = s.query(Project).filter(Project.id == pid).one()
        summary = ingest_and_analyze(s, project, str(fixtures / "vuln_httpd"),
                                     name="vuln_httpd (standalone)")
        elf_id = summary["root_target_id"]
        task = create_task(
            s, project=project, target_id=elf_id, type="poc", backend="mock",
            params={"mock_scenario": "command_injection", "function": "cgi_handler"},
        )
        poc_task_id = task.id
    run_task_sync(poc_task_id)
    with session_scope() as s:
        from hexgraph.db.models import Finding
        from hexgraph.engine import assurance as A

        f = s.query(Finding).filter(Finding.task_id == poc_task_id).one()
        ev = f.evidence_json or {}
        verification = (ev.get("extra") or {}).get("verification") or {}
        asr = A.assurance_of(ev)
        print(f"   finding: [{f.severity}] {f.title}")
        print(f"   verified: {verification.get('verified')}  "
              "(unforgeable {{NONCE}} oracle, executed in the sandbox)")
        print(f"   ASSURANCE TRIPLE: {A.summary_line(asr)}")
        print("   the assurance ladder (weakest → strongest):")
        rung_key = (asr.get("standard"), asr.get("method")) if asr else (None, None)
        for rung in A.LADDER:
            here = bool(asr) and rung.startswith(f"{rung_key[0]} / {rung_key[1]}")
            print(f"     {'→' if here else ' '} {rung.split('—')[0].strip()}")
        assert verification.get("verified") is True, "the command-injection PoC should verify in the sandbox"
        assert asr and asr.get("method") == A.DYNAMIC, "a verified PoC is a dynamic claim"
        poc_finding_id = f.id

    # ── 5) Spawn a suggested follow-up (target → task → finding → graph → spawn-next) ─
    _step("Spawn the PoC's suggested follow-up → a new task anchored to the seed finding")
    from hexgraph.engine.followups import spawn_followup

    with session_scope() as s:
        from hexgraph.db.models import Finding

        seed = s.get(Finding, poc_finding_id)
        followups = seed.suggested_followups_json or []
        print(f"   suggested follow-ups: {[fu['label'] for fu in followups]}")
        assert followups, "the verified PoC should suggest a root-cause follow-up"
        spawned = spawn_followup(s, poc_finding_id, 0)
        spawned_id = spawned.id
    run_task_sync(spawned_id)
    with session_scope() as s:
        from hexgraph.db.models import Task

        spawned_task = s.get(Task, spawned_id)
        print(f"   spawned task: type={spawned_task.type}  parent_finding == PoC finding: "
              f"{spawned_task.parent_finding_id == poc_finding_id}")
        assert spawned_task.parent_finding_id == poc_finding_id

    # ── 6) Build the graph and show the node/edge-type variety ───────────────────────
    _step("Build the project graph and show its node/edge-type variety")
    with session_scope() as s:
        from hexgraph.db.models import Edge, Finding, Target

        graph = build_graph(s, pid)
        targets = s.query(Target).filter(Target.project_id == pid).count()
        findings = s.query(Finding).filter(Finding.project_id == pid).count()
        edge_types = sorted({e.type for e in s.query(Edge).filter(Edge.project_id == pid).all()})
        print(f"   graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges  "
              f"({targets} targets, {findings} findings)")
        print(f"   edge types: {', '.join(edge_types)}")
        # The modernized loop should exhibit the new structural edges, not just contains.
        for kind in ("contains", "built_from", "instrumented_build_of", "fuzzed_by"):
            assert kind in edge_types, f"expected a {kind!r} edge in the graph"

    print("\n\033[32m✓ demo loop complete\033[0m — ingest → build → fuzz → verify → graph → spawn, "
          "zero model calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
