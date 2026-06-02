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


# Task types whose target kind / node type can be fuzzed once a harness exists.
_FUZZABLE_TARGETS = {"executable", "shared_library"}


def _flag(path: str) -> bool:
    try:
        from hexgraph import settings

        return bool(settings.get(path))
    except Exception:  # noqa: BLE001
        return False


def _fuzzing_enabled() -> bool:
    return _flag("features.fuzzing.enabled")


def _agent_enabled() -> bool:
    return _flag("features.agent.enabled")


def _poc_enabled() -> bool:
    return _flag("features.poc.enabled")


def _build_enabled() -> bool:
    return _flag("features.build.enabled")


def _build_fetch_enabled() -> bool:
    # The bounded dependency-fetch tier is a sub-capability of building (Phase 7).
    return _build_enabled() and _flag("features.build_fetch.enabled")


def _source_edit_enabled() -> bool:
    # The editable IDE (Phase 7). A UI/capability flag — never touches policy.
    return _flag("features.source.edit")


def capabilities_for(anchor_kind: str, subtype: str | None = None) -> list[str]:
    if anchor_kind == "target":
        caps = list(_TARGET.get(subtype or "unknown", ["recon"]))
        if _fuzzing_enabled() and subtype in _FUZZABLE_TARGETS:
            caps.append("fuzzing")
        if _agent_enabled() and subtype in _FUZZABLE_TARGETS:
            caps.append("agent_delegate")
        if _poc_enabled() and subtype in _FUZZABLE_TARGETS:
            caps.append("poc")
        return caps
    if anchor_kind == "node":
        caps = list(_NODE.get(subtype or "", []))
        if _fuzzing_enabled() and subtype == "function":
            caps.append("fuzzing")
        if _agent_enabled() and subtype == "function":
            caps.append("agent_delegate")
        if _poc_enabled() and subtype == "function":
            caps.append("poc")
        return caps
    if anchor_kind == "edge":
        return _EDGE.get(subtype or "_default", _EDGE["_default"])
    return []


def capability_table() -> dict:
    """Full table for the UI (fuzzing/agent_delegate folded in when enabled in Settings)."""
    fuzz, agent, poc = _fuzzing_enabled(), _agent_enabled(), _poc_enabled()

    def extra(kind: str, base: list[str]) -> list[str]:
        out = list(base)
        dyn = kind in _FUZZABLE_TARGETS or kind == "function"
        if fuzz and dyn:
            out.append("fuzzing")
        if agent and dyn:
            out.append("agent_delegate")
        if poc and dyn:
            out.append("poc")
        return out

    targets = {k: extra(k, v) for k, v in _TARGET.items()}
    nodes = {k: extra(k, v) for k, v in _NODE.items()}
    # `features` carries non-anchor affordance flags the SPA reads to show/hide UI
    # that isn't keyed to a target/node/edge — e.g. the Source-tab Build button
    # (build is anchored on a source_tree, gated by features.build), the bounded
    # dependency-fetch posture, and the editable-IDE Save/revision affordances.
    return {"target": targets, "node": nodes, "edge": _EDGE,
            "features": {"build": _build_enabled(), "build_fetch": _build_fetch_enabled(),
                         "source_edit": _source_edit_enabled(), "fuzzing": fuzz, "poc": poc}}
