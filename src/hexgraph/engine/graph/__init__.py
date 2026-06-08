"""The curated typed graph — the researcher's map of a target (distinct from the raw,
exhaustive Observation substrate). Modules:
- **nodes** + **edges** — the typed node/edge model + identity/dedup-key logic.
- **node_schemas** + **edge_schemas** — the per-type attribute schemas (+ SOCKET_KINDS).
- **authoring** — deliberately PROMOTE nodes/edges/sockets into the graph.
- **annotations** — agent notes/tags/renames (proposals pending analyst approval).
- **hypotheses** — the falsifiable open-question worklist + evidence links.
- **nodemerge** + **dedup** — fold duplicate nodes by per-type canonical key.
- **crosstarget** — n-day similarity links across binaries.
- **removal** — graduated archive/restore/delete of graph entities.
- **refs** — polymorphic (kind, id) entity references over target|node|finding|task.
- **search** — keyword search over the curated graph.
- **graph** — per-type stats + traversal helpers over the graph.
"""
