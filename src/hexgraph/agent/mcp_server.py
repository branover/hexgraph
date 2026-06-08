"""`hexgraph mcp` — expose HexGraph's sandboxed tools to a coding agent over MCP.

This is *driver mode*: an external agent (Claude Code / Codex / gemini-cli) drives
the investigation and calls these tools instead of touching the target itself.
Every tool runs HexGraph's existing engine/sandbox primitives, so hostile bytes
stay inside the `--network none` sandbox and findings land in the project graph.

Runs over stdio (the transport local agents spawn). The `mcp` SDK is an optional
dependency; this module only imports it when the server is actually started.
"""

from __future__ import annotations

import json

from hexgraph.agent.mcp_tools import GROUPS, catalog


def enabled_groups(override: set[str] | None = None) -> set[str]:
    """Tool groups to expose: an explicit override, else the Settings toggles
    (features.mcp.{read,write,run}); default all."""
    if override is not None:
        return {g for g in override if g in GROUPS}
    from hexgraph import settings

    return {g for g in GROUPS if settings.get(f"features.mcp.{g}", True)}


def serve_stdio(groups: set[str] | None = None) -> None:
    """Run the MCP server on stdio until the client disconnects."""
    try:
        import anyio
        import mcp.types as types
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(
            'MCP support needs the SDK: pip install "hexgraph[mcp]"  (or: pip install mcp)\n'
            f"({exc})"
        )

    # Ensure the persistent DB exists/upgraded (same as the API server lifespan),
    # so an agent connecting to a fresh home doesn't hit missing tables.
    from hexgraph.db.migrate import prepare_database
    from hexgraph import policy

    prepare_database(backup=True)
    # Freeze the policy ceiling for this MCP session: an agent can't widen its own
    # execution/egress by writing settings.json mid-session — the running session
    # honors the gates that were enabled when it started (a new session re-snapshots).
    policy.snapshot_ceiling()

    import sys

    active = enabled_groups(groups)
    tools = {t["name"]: t for t in catalog(active)}
    from hexgraph.version import version_string

    # Confirmation goes to STDERR — stdout is the MCP JSON-RPC channel and must not
    # carry human text. Running this by hand just blocks waiting for a client (it's
    # normally spawned by your coding agent); Ctrl-C to stop.
    print(f"HexGraph MCP server v{version_string()} ready on stdio · {len(tools)} tools "
          f"[{','.join(sorted(active))}] · waiting for a client… "
          f"(normally launched by your agent; running it by hand will just block)",
          file=sys.stderr, flush=True)
    server = Server("hexgraph")

    @server.list_tools()
    async def _list_tools():  # noqa: ANN202
        return [
            types.Tool(name=t["name"], description=t["description"], inputSchema=t["schema"])
            for t in tools.values()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict | None):  # noqa: ANN202
        spec = tools.get(name)
        if spec is None:
            return [types.TextContent(type="text", text=f"error: unknown tool {name!r}")]
        # Tools do blocking DB/sandbox work; run off the event loop.
        result = await anyio.to_thread.run_sync(lambda: spec["fn"](**(arguments or {})))
        text = result if isinstance(result, str) else json.dumps(result, default=str)
        return [types.TextContent(type="text", text=text)]

    async def _main() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    anyio.run(_main)
