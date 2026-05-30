"""Task capability table (P3-2, design §6).

Server-driven map of which task *types* are offered for a given anchor (a node of
some type, an edge, a target, ...). The UI filters the launch dialog from this, so
adding a task type or anchor never means editing the frontend. Task *types* stay
the canonical set; relational work is an anchor, not a new type (ruling #8).
"""

from __future__ import annotations

# task types available per target kind
_TARGET = {
    "firmware_image": ["recon", "unpack"],
    "executable": ["recon", "static_analysis", "reverse_engineering", "harness_generation"],
    "shared_library": ["recon", "static_analysis", "reverse_engineering", "harness_generation"],
    "unknown": ["recon"],
}

# task types available per node type
_NODE = {
    "function": ["static_analysis", "reverse_engineering", "harness_generation"],
    "symbol": ["pattern_sweep"],
    "string": ["pattern_sweep"],
    "struct": ["reverse_engineering"],
    "hypothesis": ["static_analysis", "reverse_engineering"],  # gather evidence
    "pattern": ["pattern_sweep"],
}

# task types available when anchored on an edge (relational interrogation)
_EDGE = {
    "calls": ["static_analysis", "reverse_engineering"],   # trace dataflow / explain
    "links_against": ["reverse_engineering"],              # explain the boundary
    "similar_to": ["static_analysis"],                     # diff / confirm
    "instance_of_pattern": ["pattern_sweep"],
    "_default": ["static_analysis"],
}


def capabilities_for(anchor_kind: str, subtype: str | None = None) -> list[str]:
    if anchor_kind == "target":
        return _TARGET.get(subtype or "unknown", ["recon"])
    if anchor_kind == "node":
        return _NODE.get(subtype or "", [])
    if anchor_kind == "edge":
        return _EDGE.get(subtype or "_default", _EDGE["_default"])
    return []


def capability_table() -> dict:
    """Full table for the UI."""
    return {"target": _TARGET, "node": _NODE, "edge": _EDGE}
