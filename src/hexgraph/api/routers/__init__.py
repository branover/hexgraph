"""APIRouter modules for the HexGraph loopback API.

`api/app.py:create_app()` mounts each of these. Routers are grouped by the
resource boundaries already visible in the route paths (projects, targets,
graph=nodes/edges/sockets, findings, hypotheses, annotations, settings,
tasks/runs, capabilities, ghidra). Shared response-shaping helpers and the
request models live in `_shared.py`.
"""
