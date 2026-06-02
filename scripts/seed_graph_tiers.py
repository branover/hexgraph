"""Seed the four GRAPH-PRESENTATION complexity tiers (mock, offline, $0, deterministic).

A *reusable A/B fixture* for the graph-presentation redesign (docs/design/design-graph-presentation.md
§9): one isolated project per tier so any phase can shoot before/after Playwright captures
against identical data.

  SMALL         ~15 nodes / ~20 edges   one binary, a few functions + one finding
  MEDIUM        the showcase (~30+)     the rich curated engagement (reuses seed_showcase)
  LARGE         ~178 nodes / ~599 edges firmware ⊃ ~12 binaries, cross-target links,
                                        shared sockets, findings incl. a critical
  PATHOLOGICAL  ~500 / ~2000            dense firmware, high-degree hubs (degree 15–25),
                                        2000+ edges, findings across binaries

All structure is built through the engine/authoring API (no sandbox, no Docker, no LLM),
seeded with a fixed RNG so a re-seed reproduces the same graph. Each tier is its own
project (so a tier renders alone). Idempotent on the project name; `--reset` rebuilds.

Run via `just graph-tiers` (sets a fresh/mock env) or directly. `--tier small|medium|large|
pathological|all` selects which to seed (default all).
"""

from __future__ import annotations

import argparse
import os
import random
import sys

# Mock everything, offline, zero token spend (set BEFORE importing hexgraph).
os.environ.setdefault("HEXGRAPH_LLM_BACKEND", "mock")
os.environ.setdefault("HEXGRAPH_FUZZER", "mock")

from hexgraph.paths import repo_root  # noqa: E402

# Project names — one per tier (stable, used for idempotency).
TIER_NAMES = {
    "small": "Graph tier — SMALL",
    "medium": "Graph tier — MEDIUM (showcase)",
    "large": "Graph tier — LARGE",
    "pathological": "Graph tier — PATHOLOGICAL",
}


def _fixtures():
    return repo_root() / "tests" / "fixtures"


def _step(msg: str) -> None:
    print(f"\033[36m▶\033[0m {msg}")


def _classify(target, *, kind, fmt=None, arch=None, extra=None):
    from hexgraph.db.models import TargetKind

    target.kind = TargetKind(kind)
    if fmt:
        target.format = fmt
    if arch:
        target.arch = arch
    meta = dict(target.metadata_json or {})
    if extra:
        meta.update(extra)
    target.metadata_json = meta


# ── SMALL ──────────────────────────────────────────────────────────────────────────
def seed_small(session, project) -> None:
    """One binary, a handful of functions in a call chain, one finding."""
    from hexgraph.db.models import EdgeType, FindingStatus, NodeType
    from hexgraph.engine.authoring import create_socket
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.nodes import get_or_create_node, materialize_function
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding

    pid = project.id
    httpd_bytes = _fixtures() / "vuln_httpd"
    binr = ingest_file(session, project, str(httpd_bytes), name="sbin/httpd")
    _classify(binr, kind="executable", fmt="ELF", arch="mipsel",
              extra={"imports": ["system", "strcpy", "recv"]})

    fns = {}
    chain = ["main", "handle_request", "auth_check", "parse_query", "get_param",
             "build_cmd", "do_ping", "log_request", "send_response"]
    addr = 0x401000
    for name in chain:
        fns[name] = materialize_function(session, project_id=pid, target_id=binr.id,
                                         name=name, address=hex(addr), created_by="recon")
        addr += 0x80
    # A call chain main → … → do_ping, plus a couple of branches off the spine.
    for a, b in zip(chain, chain[1:]):
        add_edge(session, project_id=pid, src=("node", fns[a].id), dst=("node", fns[b].id),
                 type=EdgeType.calls, origin="tool", confidence=0.9,
                 attrs={"call_sites": [hex(addr)]})
        addr += 0x10
    add_edge(session, project_id=pid, src=("node", fns["handle_request"].id),
             dst=("node", fns["log_request"].id), type=EdgeType.calls, origin="tool", confidence=0.9)
    add_edge(session, project_id=pid, src=("node", fns["handle_request"].id),
             dst=("node", fns["send_response"].id), type=EdgeType.calls, origin="tool", confidence=0.9)
    sink = get_or_create_node(session, project_id=pid, node_type=NodeType.sink, name="system",
                              target_id=binr.id, address="0x402300",
                              attrs={"library": "libc", "danger": "command-exec"})
    add_edge(session, project_id=pid, src=("node", fns["do_ping"].id), dst=("node", sink.id),
             type=EdgeType.calls, origin="tool", confidence=0.9)
    add_edge(session, project_id=pid, src=("node", fns["get_param"].id), dst=("node", sink.id),
             type=EdgeType.taints, origin="llm", confidence=0.8,
             attrs={"via": "host param", "note": "query string → system()"})
    # A shared socket the server listens on, plus a couple of strings.
    sock = create_socket(session, project, kind="tcp", port=80, name="http", bind_addr="0.0.0.0")
    add_edge(session, project_id=pid, src=("node", fns["main"].id), dst=("node", sock.id),
             type=EdgeType.listens_on, origin="tool", confidence=0.9, attrs={"address": "0.0.0.0:80"})
    for s in ("ping -c 1 %s", "GET %s HTTP/1.1"):
        get_or_create_node(session, project_id=pid, node_type=NodeType.string, name=s,
                           target_id=binr.id, attrs={"value": s})

    t = create_task(session, project=project, target_id=binr.id, type="static_analysis", backend="mock")
    persist_finding(session, project_id=pid, target_id=binr.id, task_id=t.id,
                    finding=Finding(
                        title="Command injection in do_ping via host param",
                        severity="critical", confidence="high", category="command-injection",
                        summary="The host parameter flows unsanitized into system().",
                        reasoning="get_param() return reaches system() through do_ping().",
                        evidence=Evidence(function="do_ping", sink="system", file="/sbin/httpd")),
                    status=FindingStatus.confirmed, finding_type="vulnerability")


# ── LARGE / PATHOLOGICAL (procedurally generated firmware) ───────────────────────────
def _seed_firmware(session, project, *, n_bins: int, fns_per_bin: int,
                   hub_degree: int, n_sockets: int, n_findings: int, seed: int) -> None:
    """A firmware image with N binaries, each a call graph, cross-target links, shared
    sockets (the network bus), high-degree hubs, and findings spread across binaries."""
    from hexgraph.db.models import EdgeType, FindingStatus, NodeType
    from hexgraph.engine.authoring import create_socket
    from hexgraph.engine.edges import add_edge
    from hexgraph.engine.findings import persist_finding
    from hexgraph.engine.ingest import ingest_file
    from hexgraph.engine.nodes import get_or_create_node, materialize_function
    from hexgraph.engine.tasks import create_task
    from hexgraph.models.finding import Evidence, Finding

    rng = random.Random(seed)
    pid = project.id
    fw_bytes = _fixtures() / "synthetic_fw.bin"
    httpd_bytes = _fixtures() / "vuln_httpd"
    lib_bytes = _fixtures() / "libupnp.so"

    fw = ingest_file(session, project, str(fw_bytes), name="acme_fw.chk")
    _classify(fw, kind="firmware_image", fmt="TRX → squashfs", arch="mipsel",
              extra={"vendor": "Acme", "model": "MultiBin"})

    # Shared sockets (the network map) — cross-binary endpoints.
    sockets = []  # (node, port)
    for i in range(n_sockets):
        kind = rng.choice(["tcp", "udp"])
        port = rng.choice([80, 443, 1900, 5000, 23, 53, 8080, 8443, 7547, 9000]) + i
        sockets.append((create_socket(session, project, kind=kind, port=port,
                                      name=f"svc{i}", bind_addr="0.0.0.0"), port))

    bins = []
    bin_fns: list[list] = []
    for b in range(n_bins):
        kind = "shared_library" if b % 4 == 3 else "executable"
        src = lib_bytes if kind == "shared_library" else httpd_bytes
        name = (f"lib/lib{b:02d}.so" if kind == "shared_library"
                else f"sbin/svc_{b:02d}")
        binr = ingest_file(session, project, str(src), name=name, parent=fw)
        _classify(binr, kind=kind, fmt="ELF", arch="mipsel",
                  extra={"imports": ["system", "strcpy", "recv", "memcpy"]})
        bins.append(binr)

        # Functions for this binary.
        fns = []
        addr = 0x400000 + b * 0x10000
        for f in range(fns_per_bin):
            fn = materialize_function(session, project_id=pid, target_id=binr.id,
                                      name=f"fn_{b:02d}_{f:03d}", address=hex(addr),
                                      created_by="recon")
            fns.append(fn)
            addr += 0x40
        bin_fns.append(fns)

        # Intra-binary call graph: a couple of hubs that many fns call, plus a chain.
        n_hubs = max(1, fns_per_bin // 12)
        hubs = fns[:n_hubs]
        for hub in hubs:
            # hub is called BY hub_degree random callers (high in-degree hub).
            callers = rng.sample(fns[n_hubs:], min(hub_degree, len(fns) - n_hubs))
            for caller in callers:
                add_edge(session, project_id=pid, src=("node", caller.id),
                         dst=("node", hub.id), type=EdgeType.calls, origin="tool",
                         confidence=0.9, attrs={"call_sites": [hex(rng.randint(0x400000, 0x4fffff))]})
        # A sprinkling of ordinary calls (chain-ish) to fill out the mesh.
        for f in fns[n_hubs:]:
            for _ in range(rng.randint(1, 3)):
                tgt = rng.choice(fns)
                if tgt.id != f.id:
                    add_edge(session, project_id=pid, src=("node", f.id), dst=("node", tgt.id),
                             type=EdgeType.calls, origin="tool", confidence=0.7,
                             attrs={"call_sites": [hex(rng.randint(0x400000, 0x4fffff))]})

        # A sink + a taint edge into it (semantic signal).
        sink = get_or_create_node(session, project_id=pid, node_type=NodeType.sink,
                                  name="system", target_id=binr.id,
                                  address=hex(0x402300 + b),
                                  attrs={"library": "libc", "danger": "command-exec"})
        add_edge(session, project_id=pid, src=("node", rng.choice(fns).id), dst=("node", sink.id),
                 type=EdgeType.taints, origin="llm", confidence=0.8,
                 attrs={"note": "tainted arg → system()"})

        # Bind a couple of this binary's fns to shared sockets (listens_on / connects_to).
        for sock, port in rng.sample(sockets, min(2, len(sockets))):
            etype = EdgeType.listens_on if kind == "executable" else EdgeType.connects_to
            add_edge(session, project_id=pid, src=("node", hubs[0].id), dst=("node", sock.id),
                     type=etype, origin="tool", confidence=0.9,
                     attrs={"address": f"0.0.0.0:{port}"})

    # Cross-target structural links: links_against + references between binaries.
    for binr in bins:
        others = [o for o in bins if o.id != binr.id]
        for other in rng.sample(others, min(2, len(others))):
            add_edge(session, project_id=pid, src=("target", binr.id), dst=("target", other.id),
                     type=EdgeType.links_against, origin="tool", confidence=0.9)
    # A few cross-binary function references (the gray cobweb the redesign pushes back).
    flat_fns = [f for fns in bin_fns for f in fns]
    for _ in range(len(bins) * 6):
        a, b = rng.sample(flat_fns, 2)
        add_edge(session, project_id=pid, src=("node", a.id), dst=("node", b.id),
                 type=EdgeType.references, origin="tool", confidence=0.4)

    # Findings spread across binaries, including one critical.
    sevs = ["critical"] + ["high", "medium", "low", "info"] * 10
    cats = ["command-injection", "memory-safety", "auth", "recon", "hardcoded-secret"]
    for i in range(n_findings):
        binr = rng.choice(bins)
        sev = sevs[i] if i < len(sevs) else rng.choice(sevs[1:])
        t = create_task(session, project=project, target_id=binr.id,
                        type="static_analysis", backend="mock")
        persist_finding(session, project_id=pid, target_id=binr.id, task_id=t.id,
                        finding=Finding(
                            title=f"{rng.choice(cats)} issue #{i} in {binr.name}",
                            severity=sev, confidence=rng.choice(["high", "medium", "low"]),
                            category=rng.choice(cats),
                            summary="Generated finding for the graph-tier fixture.",
                            reasoning="Procedurally generated for density A/B captures.",
                            evidence=Evidence(file=f"/{binr.name}")),
                        status=(FindingStatus.confirmed if sev == "critical" else FindingStatus.new),
                        finding_type="vulnerability")


def seed_large(session, project) -> None:
    _seed_firmware(session, project, n_bins=12, fns_per_bin=13, hub_degree=8,
                   n_sockets=5, n_findings=8, seed=1701)


def seed_pathological(session, project) -> None:
    _seed_firmware(session, project, n_bins=18, fns_per_bin=26, hub_degree=18,
                   n_sockets=8, n_findings=16, seed=8675309)


# ── Driver ───────────────────────────────────────────────────────────────────────────
def _counts(session, pid: str) -> dict:
    from hexgraph.db.models import Edge, Finding as FRow, Node, Target
    return {
        "targets": session.query(Target).filter(Target.project_id == pid).count(),
        "nodes": session.query(Node).filter(Node.project_id == pid).count(),
        "edges": session.query(Edge).filter(Edge.project_id == pid).count(),
        "findings": session.query(FRow).filter(FRow.project_id == pid).count(),
    }


def seed_tier(session, tier: str, *, reset: bool) -> dict:
    """Seed one tier into its own project. Returns {project_id, reused, counts...}."""
    from hexgraph.db.models import Project
    from hexgraph.engine.ingest import create_project

    name = TIER_NAMES[tier]
    existing = session.query(Project).filter(Project.name == name).all()
    if existing and reset:
        from hexgraph.engine.removal import delete_project
        for p in existing:
            delete_project(session, p.id)
        session.flush()
        existing = []
    if existing:
        pid = existing[0].id
        return {"tier": tier, "project_id": pid, "reused": True, **_counts(session, pid)}

    if tier == "medium":
        # MEDIUM is the curated showcase project (reused wholesale, under its own name).
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import seed_showcase
        info = seed_showcase.seed(session, reset=reset)
        pid = info["project_id"]
        # Rename to the tier name so it groups with the other tiers (idempotency key).
        proj = session.get(Project, pid)
        proj.name = name
        session.flush()
        return {"tier": tier, "project_id": pid, "reused": bool(info.get("reused")),
                **_counts(session, pid)}

    _step(f"Seed {tier.upper()} tier")
    project = create_project(session, name=name, llm_backend="mock")
    {"small": seed_small, "large": seed_large, "pathological": seed_pathological}[tier](session, project)
    session.flush()
    return {"tier": tier, "project_id": project.id, "reused": False, **_counts(session, project.id)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed the graph-presentation complexity tiers (mock, offline).")
    ap.add_argument("--tier", choices=[*TIER_NAMES, "all"], default="all")
    ap.add_argument("--reset", action="store_true", help="delete prior tier projects first")
    args = ap.parse_args()

    # MEDIUM (the showcase) exercises optional features; enable them so it seeds identically.
    from hexgraph import settings as st
    st.update_settings({
        "features.fuzzing.enabled": True,
        "features.poc.enabled": True,
        "features.network.enabled": True,
        "features.build.enabled": True,
    })

    # seed_showcase lives next to this script — make it importable for MEDIUM.
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import session_scope

    prepare_database()
    tiers = list(TIER_NAMES) if args.tier == "all" else [args.tier]
    results = []
    with session_scope() as s:
        for tier in tiers:
            results.append(seed_tier(s, tier, reset=args.reset))

    print()
    for r in results:
        tag = "\033[33m↺ reused\033[0m" if r["reused"] else "\033[32m✓ seeded\033[0m"
        print(f"{tag} {r['tier'].upper():13s} — {r['targets']} targets · {r['nodes']} nodes · "
              f"{r['edges']} edges · {r['findings']} findings   (id {r['project_id']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
