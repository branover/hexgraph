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

from hexgraph.engine.mcp_tools import catalog


def serve_stdio() -> None:
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

    tools = {t["name"]: t for t in catalog()}
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
