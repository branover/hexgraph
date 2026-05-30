"""`make demo` — the full offline loop on bundled fixtures (SPEC §10).

Ingest a lone ELF and a firmware image with the MOCK backend, no API key, no
network (the sandbox runs --network none). Proves: ingest → recon task →
structured finding → graph, with firmware unpacking into child targets joined by
`contains` edges. Exits 0 on success; doubles as a smoke test.

(The suggested-follow-up *spawn* step is added here in M4 once LLM tasks land.)
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

    # Isolated, throwaway home so the demo is repeatable and offline.
    os.environ["HEXGRAPH_HOME"] = tempfile.mkdtemp(prefix="hexgraph-demo-")
    os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")

    from hexgraph.db.session import init_db, reset_engine_for_tests, session_scope
    from hexgraph.engine.graph import build_graph
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.pipeline import ingest_and_analyze

    reset_engine_for_tests()
    init_db()

    print("=== HexGraph demo — mock backend, no key, no network ===\n")

    _step("Ingest a lone vulnerable ELF (vuln_httpd) and run recon")
    with session_scope() as s:
        project = create_project(s, name="demo-elf")
        summary = ingest_and_analyze(s, project, str(fixtures / "vuln_httpd"))
        from hexgraph.db.models import Finding, Target

        t = s.get(Target, summary["root_target_id"])
        mit = t.metadata_json.get("mitigations", {})
        print(f"   target: {t.name}  kind={t.kind.value} arch={t.arch}")
        print(f"   mitigations: {mit}")
        f = s.query(Finding).filter(Finding.target_id == t.id).first()
        print(f"   recon finding: [{f.severity}] {f.title}")
        assert f.category == "recon"

    _step("Ingest a firmware image (synthetic_fw.bin): unpack → child targets + contains edges")
    with session_scope() as s:
        from hexgraph.db.models import Edge, EdgeType, Finding, Target

        project = create_project(s, name="demo-fw")
        summary = ingest_and_analyze(s, project, str(fixtures / "synthetic_fw.bin"))
        pid = project.id
        children = summary["children"]
        print(f"   root: {summary['name']} → {len(children)} child target(s):")
        for c in children:
            print(f"      └─ {c['name']}")
        contains = s.query(Edge).filter(Edge.project_id == pid, Edge.type == EdgeType.contains).count()
        findings = s.query(Finding).filter(Finding.project_id == pid).count()
        graph = build_graph(s, pid)
        print(f"   contains edges: {contains}   findings: {findings}")
        print(f"   graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")
        assert len(children) == 2
        assert contains == 2
        assert findings == 3

    print("\n\033[32m✓ demo loop complete\033[0m — ingest → recon → finding → graph, zero model calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
