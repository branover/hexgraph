#!/usr/bin/env python3
"""Stand up the live `vulnrouter` web target and a HexGraph project pointed at it, so
you can hand a Claude Code agent the challenge and let it rip.

What it does (idempotent):
  1. builds + runs the vulnrouter container, reads its docker-bridge IP;
  2. enables `features.network` (bounded, local-only egress — needed for live HTTP);
  3. creates a project and registers the web surface (a `web_app` target) with its routes;
  4. prints the project_id / target_id / base_url and the exact next steps.

Run it with the venv's python so HexGraph is importable, e.g.:
    .venv/bin/python scripts/vulnrouter_engagement.py
or via:  make vulnrouter

Tear down with:  docker rm -f hexgraph-vulnrouter
"""

from __future__ import annotations

import subprocess
import sys

IMAGE = "hexgraph-vulnrouter:latest"
NAME = "hexgraph-vulnrouter"
FIXTURE = "tests/fixtures/vulnrouter"
# A non-trivial flag so the auth-bypass oracle (body_contains the flag) is unforgeable.
FLAG = "ROUTER-FLAG-LIVE-7Q2X"

ENDPOINTS = [
    {"method": "GET", "path": "/", "auth": "none"},
    {"method": "POST", "path": "/api/login", "params": ["token"], "auth": "none"},
    {"method": "GET", "path": "/admin/flag", "auth": "required"},
    {"method": "POST", "path": "/api/diag", "params": ["host"], "auth": "required"},
]


def _sh(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def main() -> int:
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True)
    except Exception:
        print("Docker isn't available — start Docker and retry.", file=sys.stderr)
        return 2

    print(f"• building {IMAGE} …")
    _sh("docker", "build", "-q", "-t", IMAGE, FIXTURE)
    subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)
    print(f"• running {NAME} …")
    _sh("docker", "run", "-d", "--name", NAME, "-e", f"ROUTER_FLAG={FLAG}", IMAGE)
    ip = _sh("docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", NAME)
    base_url = f"http://{ip}:8080"

    # Import HexGraph lazily so the docker steps give a clear error first if it's missing.
    from hexgraph import settings
    from hexgraph.db.migrate import prepare_database
    from hexgraph.db.session import session_scope
    from hexgraph.engine.ingest import create_project
    from hexgraph.engine.surfaces import register_web_surface

    prepare_database()
    settings.update_settings({"features": {"network": {"enabled": True}}})
    with session_scope() as s:
        project = create_project(s, name="vulnrouter (live web)")
        target = register_web_surface(s, project, base_url, name="Orbweaver Router",
                                      endpoints=ENDPOINTS)
        pid, tid = project.id, target.id

    print("\n" + "=" * 72)
    print("vulnrouter engagement is ready.")
    print("=" * 72)
    print(f"  base_url    : {base_url}")
    print(f"  project_id  : {pid}")
    print(f"  target_id   : {tid}  (web_app surface)")
    print(f"  flag (proof): {FLAG}")
    print("  features.network: ENABLED (bounded to the target's private host)")
    print("\nHand it to Claude Code:")
    print("  1. Register the MCP server + skill (once):")
    print("       hexgraph mcp install --agent claude")
    print("       hexgraph mcp install --write-skill .claude/skills")
    print("  2. Start Claude Code and give it docs/engagement-vulnrouter.md as the brief,")
    print(f"     telling it the project_id ({pid}) and base_url ({base_url}).")
    print("  3. Watch the graph fill in at  http://127.0.0.1:8765  (run `make serve`).")
    print("\nTear down when done:  docker rm -f", NAME)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
