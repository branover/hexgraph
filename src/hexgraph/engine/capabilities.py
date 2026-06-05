"""Task capability table (P3-2, design §6).

Server-driven map of which task *types* are offered for a given anchor (a node of
some type, an edge, a target, ...). The UI filters the launch dialog from this, so
adding a task type or anchor never means editing the frontend. Task *types* stay
the canonical set; relational work is an anchor, not a new type (ruling #8).
"""

from __future__ import annotations

# task types available per target kind.
#
# BYTE targets have an artifact at rest, so they offer the byte pipeline (recon over the
# file, decompile, harness-gen, …). SURFACE targets (web_app/service/remote) have NO bytes
# — they're a reachable surface reached via a Channel, with `path=""` — so byte 'recon'
# (and harness-gen / static-analysis, which assume a byte file) must NOT be offered for
# them; the worker would route byte recon to a confusing "artifact not found" / a clear
# NotImplementedError. Surfaces get their own surface-appropriate task set below.
_TARGET = {
    "firmware_image": ["recon", "unpack"],
    "executable": ["recon", "static_analysis", "reverse_engineering", "harness_generation"],
    "shared_library": ["recon", "static_analysis", "reverse_engineering", "harness_generation"],
    "unknown": ["recon"],
}

# SURFACE targets (no bytes at rest). These are kept SEPARATE from `_TARGET` so the byte
# 'recon' default never leaks onto a surface. The base set is the surface-appropriate,
# always-available (offline, no egress) task; live/dynamic tasks fold in only when the
# relevant opt-in feature is enabled (see `_surface_caps`).
#
# - web_app  → `surface_recon` (deterministic, offline: materialise the route spec into
#              endpoint/param nodes + routes_to handler edges — the surface analogue of
#              byte recon). With features.network: the live `web_recon` / `web_discover`
#              (bounded, audited egress) fold in.
# - service  → a bare network listener: NO offline deterministic probe. Assessed by a
#              network fuzz campaign (Fuzz button) / run_tcp_probe under features.network.
#              No single-shot Run-menu task is wired, so the base set is honestly empty.
# - remote   → a live device over SSH/telnet: assessed via the read-only remote MCP tools
#              (features.remote), not a Run-menu task. Base set honestly empty.
_SURFACE_BASE = {
    "web_app": ["surface_recon"],
    "service": [],
    "remote": [],
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


def _gate(name: str) -> bool:
    """A POLICY gate (fuzzing/poc/network/remote/build/build_fetch/…), read through the
    startup ceiling clamp — NOT raw settings — so the advertised capability matches what
    the RUNNING policy will actually permit. A gate flipped on in settings.json mid-session
    that current_policy() is clamping off until restart must NOT be offered here (otherwise
    the launch dialog promises a task the worker's policy seam will refuse at run time)."""
    try:
        from hexgraph import policy

        return name in policy.effective_gates()
    except Exception:  # noqa: BLE001 — never advertise more than the policy permits
        return False


def _fuzzing_enabled() -> bool:
    return _gate("fuzzing")


def _agent_enabled() -> bool:
    # features.agent is NOT a policy gate (it relaxes no sandbox/exec/egress boundary — it
    # picks which sandboxed MCP tools a delegated agent sees), so it is read live, unclamped.
    return _flag("features.agent.enabled")


def _network_enabled() -> bool:
    return _gate("network")


def _remote_enabled() -> bool:
    return _gate("remote")


def _poc_enabled() -> bool:
    return _gate("poc")


def _build_enabled() -> bool:
    return _gate("build")


def _build_fetch_enabled() -> bool:
    # The bounded dependency-fetch tier is a sub-capability of building (Phase 7); both
    # legs are ceiling-clamped (mirrors current_policy: build_fetch_on = build_on and ...).
    return _gate("build") and _gate("build_fetch")


def _source_edit_enabled() -> bool:
    # The editable IDE (Phase 7). A UI/capability flag — never touches policy.
    return _flag("features.source.edit")


def _surface_caps(subtype: str) -> list[str]:
    """Task set for a SURFACE target kind (web_app/service/remote).

    Byte tasks (recon over a file, harness-gen, …) are deliberately absent — a surface has
    no bytes. The offline base set folds in live/dynamic tasks only when the matching opt-in
    feature is enabled, mirroring the worker's dispatch (`web_recon`/`web_discover` are
    bounded-egress, audited; gated by features.network)."""
    caps = list(_SURFACE_BASE.get(subtype, []))
    if subtype == "web_app" and _network_enabled():
        # Live, bounded-egress web assessment (features.network); audited.
        caps += ["web_recon", "web_discover"]
    return caps


def capabilities_for(anchor_kind: str, subtype: str | None = None) -> list[str]:
    if anchor_kind == "target":
        if subtype in _SURFACE_BASE:
            return _surface_caps(subtype)
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
    # SURFACE kinds carry their own surface-appropriate sets (NOT the byte 'recon' default).
    targets.update({k: _surface_caps(k) for k in _SURFACE_BASE})
    nodes = {k: extra(k, v) for k, v in _NODE.items()}
    # `features` carries non-anchor affordance flags the SPA reads to show/hide UI
    # that isn't keyed to a target/node/edge — e.g. the Source-tab Build button
    # (build is anchored on a source_tree, gated by features.build), the bounded
    # dependency-fetch posture, and the editable-IDE Save/revision affordances.
    return {"target": targets, "node": nodes, "edge": _EDGE,
            "features": {"build": _build_enabled(), "build_fetch": _build_fetch_enabled(),
                         "source_edit": _source_edit_enabled(), "fuzzing": fuzz, "poc": poc}}
