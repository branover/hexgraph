"""The agent-integration layer: everything about how agents interface with HexGraph.

This package is the *interface* between HexGraph and the agents that drive it — kept
together so the tool surface and the docs that describe it live in one place rather than
scattered across the top-level package and `engine/`:

- **mcp_server** / **mcp_catalog** / **mcp_tools** — the stdio MCP server, the agent-facing
  tool catalog (the `(group, name, fn, description, schema)` tuples), and the thin tool
  implementations that wrap `engine/` primitives. The surface an external coding agent
  (Claude Code / Codex / gemini-cli) drives HexGraph through.
- **agent_tools** — the in-process LLM agent-loop tools (`decompile_function`, …) the BYOK
  agent loop advertises and HexGraph runs in the sandbox (distinct from the MCP surface; the
  mock fixtures hardcode these by name).
- **agent_delegate** — delegate mode: HexGraph launches a coding-agent CLI headless, wired to
  the MCP server, restricted to the sandboxed tools.
- **agent_setup** — MCP-server registration with an agent + the VR-skill emission helpers.
- **vr_skill** / **record_keeping** — the deployed VR skill (spine + capability sub-files) and
  the shared record-keeping rubric that teach the workflow and the hostile-target rules.

These are the *interface*; the implementations they call into stay in `engine/`.
"""
