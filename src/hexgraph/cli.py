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
    from hexgraph.db.migrate import prepare_database

    res = prepare_database()
    print(f"Initialized HexGraph at {hexgraph_home()} (schema {res['action']}, rev {res['revision']})")
    return 0


def _cmd_db_upgrade(args: argparse.Namespace) -> int:
    from hexgraph.db.migrate import prepare_database

    res = prepare_database(backup=not args.no_backup)
    print(f"DB {res['action']} → rev {res['revision']}  ({res['db']})")
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


def _cmd_rehost(args: argparse.Namespace) -> int:
    from hexgraph.engine.rehost import RehostError, rehost_firmware
    from hexgraph.policy import PolicyViolation

    init_db()
    with session_scope() as session:
        target = session.get(Target, args.target)
        if target is None:
            print(f"error: target {args.target} not found", file=sys.stderr)
            return 1
        project = session.get(Project, target.project_id)
        try:
            surface = rehost_firmware(session, project, target, brand=args.brand)
        except PolicyViolation as exc:
            print(f"error: {exc}\n(enable it with: hexgraph config set features.rehost.enabled true)",
                  file=sys.stderr)
            return 1
        except RehostError as exc:
            print(f"rehost failed: {exc}", file=sys.stderr)
            return 1
        ch = (surface.metadata_json or {}).get("channel", {})
        print(f"rehosted → surface {surface.id} at {ch.get('base_url')} "
              f"(container {ch.get('rehost', {}).get('container')})")
        print("assess it: enable features.network, then task_run(surface, 'surface_recon'/'web_recon') "
              "or net_http_request / finding_verify_poc")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    from hexgraph.engine.tasks import create_task
    from hexgraph.engine.worker import run_task_sync

    init_db()
    with session_scope() as session:
        target = session.get(Target, args.target)
        if target is None:
            print(f"error: target {args.target} not found", file=sys.stderr)
            return 1
        project = session.get(Project, target.project_id)
        params = {}
        if args.mock_scenario:
            params["mock_scenario"] = args.mock_scenario
        if getattr(args, "function", None):
            params["function"] = args.function
        task = create_task(
            session, project=project, target_id=target.id, type=args.type,
            objective=args.objective, model=args.model,
            backend=args.backend or project.llm_backend.value, params=params,
        )
        task_id = task.id

    status = run_task_sync(task_id)
    print(f"task {task_id}  [{status}]")
    with session_scope() as session:
        rows = session.query(Finding).filter(Finding.task_id == task_id).all()
        if not rows:
            print("  (no findings)")
        for f in rows:
            print(f"  {f.id}  [{f.severity:8}] {f.category:14} {f.title}")
    return 0 if status in ("succeeded", "needs_triage") else 1


def _cmd_findings(args: argparse.Namespace) -> int:
    init_db()
    with session_scope() as session:
        q = session.query(Finding).filter(Finding.project_id == args.project)
        if args.status:
            q = q.filter(Finding.status == args.status)
        rows = q.all()
        if args.export:
            import json

            from hexgraph.engine.findings import row_to_payload

            payloads = [
                {
                    "id": f.id, "target_id": f.target_id, "task_id": f.task_id,
                    "status": f.status, "created_at": f.created_at.isoformat(),
                    **row_to_payload(f),
                }
                for f in rows
            ]
            with open(args.export, "w") as fh:
                json.dump(payloads, fh, indent=2)
            print(f"wrote {len(payloads)} finding(s) to {args.export}")
            return 0
        if not rows:
            print("(no findings)")
            return 0
        for f in rows:
            print(f"{f.id}  [{f.severity:8}] {f.category:14} {f.title}  ({f.status})")
    return 0


def _cmd_graph(args: argparse.Namespace) -> int:
    from hexgraph.engine.graph import export_graph

    init_db()
    with session_scope() as session:
        out = export_graph(session, args.project, args.export)
    print(f"wrote {out}")
    return 0


def _cmd_prune(args: argparse.Namespace) -> int:
    from hexgraph.engine import cas

    init_db()
    with session_scope() as session:
        project = session.get(Project, args.project)
        if project is None:
            print(f"error: project {args.project} not found", file=sys.stderr)
            return 1
        report = cas.size_report(project)
    print(f"CAS: {report['objects']} objects, {report['bytes']} bytes at {report['dir']}")
    print("(v1: manual review only; no auto-eviction)")
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    """Read/write managed settings (optional features + non-secret prefs).
    Secrets (API keys) are reported as status only and are never written here."""
    import json

    from hexgraph import settings as st

    if args._cfgcmd == "list":
        view = st.read_settings()
        print(json.dumps(view["settings"], indent=2))
        print("\nsecrets (status only — never stored here):")
        for name, s in view["secrets"].items():
            print(f"  {name}: {'present' if s['present'] else 'absent'}"
                  + (f" (from {s['source']})" if s["source"] else ""))
        return 0
    if args._cfgcmd == "get":
        val = st.get(args.path, None)
        print(json.dumps(val))
        return 0
    if args._cfgcmd == "set":
        # Coerce the string value to bool/int where the schema expects it.
        raw = args.value
        typ = st.ALLOWED.get(args.path, (str, None))[0]
        types = typ if isinstance(typ, tuple) else (typ,)
        value: object = raw
        if bool in types or raw.lower() in ("true", "false"):
            if raw.lower() in ("true", "false"):
                value = raw.lower() == "true"
        if int in types and not isinstance(value, bool):
            try:
                value = int(raw)
            except ValueError:
                pass
        if raw == "" and (type(None) in types):
            value = None
        try:
            st.update_settings({args.path: value})  # dotted keys are accepted as-is
        except st.SettingsError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"{args.path} = {json.dumps(value)}")
        return 0
    return 1


def _cmd_mcp(args: argparse.Namespace) -> int:
    if args._mcpcmd == "install":
        from hexgraph.agent.agent_setup import (
            SUBFILES, full_skill_markdown, install_help, write_skill,
        )

        if getattr(args, "print_skill", False):
            # The WHOLE bundle (spine + sub-files) so a Codex/gemini system prompt that
            # can't read on-demand sub-files still gets the complete field manual.
            print(full_skill_markdown())
            return 0
        if getattr(args, "write_skill", None):
            path = write_skill(args.write_skill)
            print(f"wrote VR skill to {path} (+ {len(SUBFILES)} sub-files)")
            return 0
        print(install_help(args.agent))
        return 0
    groups = None
    if getattr(args, "tools", None):
        groups = {g.strip() for g in args.tools.split(",") if g.strip()}

    if getattr(args, "check", False):
        # Human confirmation that the server is wired up, without needing a client.
        from hexgraph.agent.mcp_tools import catalog
        from hexgraph.agent.mcp_server import enabled_groups

        active = enabled_groups(groups)
        tools = catalog(active)
        print(f"HexGraph MCP server OK — {len(tools)} tools exposed [{', '.join(sorted(active))}]:")
        for t in tools:
            print(f"  [{t['group']}] {t['name']}")
        return 0

    from hexgraph.agent.mcp_server import serve_stdio

    serve_stdio(groups)
    return 0


def _cmd_setup(args: argparse.Namespace) -> int:
    """Interactive setup wizard: choose optional features (with their security
    implications) + non-secret config, then build the chosen images. Falls back to the
    static-only baseline without prompting when non-interactive (no TTY / --yes / CI)."""
    from hexgraph.setup_wizard import run_setup

    return run_setup(
        non_interactive=args.non_interactive or args.yes,
        defaults=args.defaults,
        rebuild=args.rebuild,
    )


def _cmd_serve(args: argparse.Namespace) -> int:
    from hexgraph.api.app import run_server

    run_server(host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hexgraph", description="Local-only vuln-research workbench")
    from hexgraph.version import version_string

    p.add_argument("--version", "-V", action="version", version=f"hexgraph {version_string()}")
    sub = p.add_subparsers(dest="_cmd", required=True)

    sub.add_parser("init", help="initialize HexGraph (DB + dirs, via migrations)").set_defaults(func=_cmd_init)

    psw = sub.add_parser("setup", help="interactive setup wizard (optional features + their security implications, builds)")
    psw.add_argument("--non-interactive", action="store_true",
                     help="never prompt; apply the static-only baseline + base build (CI-safe)")
    psw.add_argument("--yes", "-y", action="store_true",
                     help="alias for --non-interactive (accept the static-only defaults)")
    psw.add_argument("--defaults", action="store_true",
                     help="apply the default plan without prompting (same as --yes)")
    psw.add_argument("--rebuild", action="store_true",
                     help="rebuild images even if already present")
    psw.set_defaults(func=_cmd_setup)

    pdb = sub.add_parser("db", help="database maintenance")
    dbsub = pdb.add_subparsers(dest="_dbcmd", required=True)
    pup = dbsub.add_parser("upgrade", help="migrate the project DB to the latest schema (backs up first)")
    pup.add_argument("--no-backup", action="store_true", help="skip the pre-upgrade backup")
    pup.set_defaults(func=_cmd_db_upgrade)

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
    pr.add_argument("--backend", choices=["mock", "anthropic", "claude_code"])
    pr.add_argument("--function", help="focus function (templated into the prompt/mock)")
    pr.add_argument("--mock-scenario", dest="mock_scenario")
    pr.set_defaults(func=_cmd_run)

    prh = sub.add_parser("rehost", help="boot a firmware target under full-system emulation (FirmAE) and register its live web surface")
    prh.add_argument("target", help="firmware target id")
    prh.add_argument("--brand", help="device brand hint for FirmAE (default: auto)")
    prh.set_defaults(func=_cmd_rehost)

    pf = sub.add_parser("findings", help="list findings in a project")
    pf.add_argument("project")
    pf.add_argument("--status")
    pf.add_argument("--export", help="write findings as JSON to this file instead of listing")
    pf.set_defaults(func=_cmd_findings)

    pg = sub.add_parser("graph", help="export the project graph as JSON")
    pg.add_argument("project")
    pg.add_argument("--export", required=True)
    pg.set_defaults(func=_cmd_graph)

    pp = sub.add_parser("prune", help="report the project's content-addressed store size")
    pp.add_argument("project")
    pp.set_defaults(func=_cmd_prune)

    pc = sub.add_parser("config", help="read/write managed settings (optional features, prefs)")
    csub = pc.add_subparsers(dest="_cfgcmd", required=True)
    csub.add_parser("list", help="print all settings + secret status").set_defaults(func=_cmd_config)
    cg = csub.add_parser("get", help="print one setting (dotted path)")
    cg.add_argument("path")
    cg.set_defaults(func=_cmd_config)
    cs = csub.add_parser("set", help="set one setting (e.g. features.ghidra.enabled true)")
    cs.add_argument("path")
    cs.add_argument("value")
    cs.set_defaults(func=_cmd_config)

    ps = sub.add_parser("serve", help="start the loopback-only API/UI")
    ps.add_argument("--host", default=None)
    ps.add_argument("--port", type=int, default=None)
    ps.set_defaults(func=_cmd_serve)

    pm = sub.add_parser("mcp", help="MCP server for coding agents (stdio); `mcp install` prints setup")
    pm.add_argument("--tools", help="comma-separated tool groups to expose: read,write,run (default: Settings)")
    pm.add_argument("--check", action="store_true", help="list the exposed tools and exit (don't serve)")
    msub = pm.add_subparsers(dest="_mcpcmd")  # no subcommand → serve
    mi = msub.add_parser("install", help="print how to register HexGraph with claude/codex/gemini")
    mi.add_argument("--agent", choices=["claude", "codex", "gemini"], default=None)
    mi.add_argument("--write-skill", dest="write_skill", metavar="DIR",
                    help="write the VR skill to DIR/hexgraph-vr/SKILL.md (e.g. .claude/skills)")
    mi.add_argument("--print-skill", dest="print_skill", action="store_true", help="print the VR skill markdown")
    mi.set_defaults(func=_cmd_mcp)
    pm.set_defaults(func=_cmd_mcp, _mcpcmd=None)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
