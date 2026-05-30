"""HexGraph CLI (SPEC §8).

    hexgraph init
    hexgraph ingest <path> [--name] [--project <id>] [--backend mock|anthropic|claude_code]
    hexgraph targets <project>
    hexgraph run <target> --type <task_type> [--objective] [--model] [--mock-scenario]  (M3)
    hexgraph findings <project> [--status new]                                           (M3)
    hexgraph graph <project> --export graph.json                                         (M2/M5)
    hexgraph serve

Defaults to the mock backend: no key, no network.
"""

from __future__ import annotations

import argparse
import sys

from hexgraph.db.models import Finding, Project, Target
from hexgraph.db.session import init_db, session_scope


def _cmd_init(args: argparse.Namespace) -> int:
    from hexgraph.config import hexgraph_home

    init_db()
    print(f"Initialized HexGraph at {hexgraph_home()}")
    return 0


def _cmd_ingest(args: argparse.Namespace) -> int:
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.pipeline import ingest_and_analyze
    from hexgraph.sandbox.runner import SandboxRunner, docker_available

    init_db()
    if not args.no_recon and not docker_available():
        print(
            "error: Docker is required for the recon sandbox. Start Docker, or pass "
            "--no-recon to register the target without analysis.",
            file=sys.stderr,
        )
        return 1

    with session_scope() as session:
        if args.project:
            project = session.get(Project, args.project)
            if project is None:
                print(f"error: project {args.project} not found", file=sys.stderr)
                return 1
        else:
            project = create_project(
                session,
                name=args.name or args.path.split("/")[-1],
                llm_backend=args.backend,
            )
        project_id = project.id

        if args.no_recon:
            from hexgraph.engine.ingest import ingest_file

            target = ingest_file(session, project, args.path, name=args.name)
            print(f"project {project_id}")
            print(f"target  {target.id}  {target.name}  (recon skipped)")
            return 0

        summary = ingest_and_analyze(
            session, project, args.path, name=args.name, runner=SandboxRunner()
        )
        print(f"project {project_id}")
        print(f"target  {summary['root_target_id']}  {summary['name']}")
        for child in summary["children"]:
            print(f"  child {child['target_id']}  {child['name']}")
        print(
            f"recon complete: {1 + len(summary['children'])} target(s), "
            f"{summary['links_against_edges']} links_against edge(s)"
        )
    return 0


def _cmd_targets(args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        rows = session.query(Target).filter(Target.project_id == args.project).all()
        if not rows:
            print("(no targets)")
            return 0
        for t in rows:
            parent = f"  parent={t.parent_id}" if t.parent_id else ""
            print(f"{t.id}  {t.kind.value:16} {t.name}{parent}")
    return 0


def _cmd_findings(args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        q = session.query(Finding).filter(Finding.project_id == args.project)
        if args.status:
            q = q.filter(Finding.status == args.status)
        rows = q.all()
        if not rows:
            print("(no findings)")
            return 0
        for f in rows:
            print(f"{f.id}  [{f.severity:8}] {f.category:14} {f.title}  ({f.status.value})")
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    from hexgraph.engine.graph import export_graph

    init_db()
    with session_scope() as session:
        out = export_graph(session, args.project, args.export)
    print(f"wrote {out}")
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    from hexgraph.api.app import run_server

    run_server(host=args.host, port=args.port)
    return 0


def _not_yet(milestone: str):
    def _run(args: argparse.Namespace) -> int:
        print(f"`{args._cmd}` lands in {milestone}.", file=sys.stderr)
        return 2

    return _run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hexgraph", description="Local-only vuln-research workbench")
    sub = p.add_subparsers(dest="_cmd", required=True)

    sub.add_parser("init", help="initialize HexGraph (DB + dirs)").set_defaults(func=_cmd_init)

    pi = sub.add_parser("ingest", help="ingest a binary/firmware as a target")
    pi.add_argument("path")
    pi.add_argument("--name")
    pi.add_argument("--project", help="add to an existing project instead of creating one")
    pi.add_argument("--backend", default="mock", choices=["mock", "anthropic", "claude_code"])
    pi.add_argument("--no-recon", action="store_true", help="register the target without running recon")
    pi.set_defaults(func=_cmd_ingest)

    pt = sub.add_parser("targets", help="list targets in a project")
    pt.add_argument("project")
    pt.set_defaults(func=_cmd_targets)

    pr = sub.add_parser("run", help="run an analysis task against a target")
    pr.add_argument("target")
    pr.add_argument("--type", required=True)
    pr.add_argument("--objective")
    pr.add_argument("--model")
    pr.add_argument("--mock-scenario")
    pr.set_defaults(func=_not_yet("M3"))

    pf = sub.add_parser("findings", help="list findings in a project")
    pf.add_argument("project")
    pf.add_argument("--status")
    pf.set_defaults(func=_cmd_findings)

    pg = sub.add_parser("graph", help="export the project graph as JSON")
    pg.add_argument("project")
    pg.add_argument("--export", required=True)
    pg.set_defaults(func=_cmd_graph)

    ps = sub.add_parser("serve", help="start the loopback-only API/UI")
    ps.add_argument("--host", default=None)
    ps.add_argument("--port", type=int, default=None)
    ps.set_defaults(func=_cmd_serve)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
