"""The VR skill module — the spine + capability sub-files and the helpers that render
them. These pin the split's contract: the spine routes to every sub-file, the bundle is
whole (so no inlined consumer gets a dangling pointer), and the headline behaviours the
skill must teach an agent — ingest-from-path, the engagement arc, parallel decomposition —
stay present. Offline; no backend, no network.
"""

from __future__ import annotations

from hexgraph import vr_skill
from hexgraph.vr_skill import (
    SPINE, SUBFILES, full_skill_markdown, skill_markdown,
)


def test_skill_markdown_has_frontmatter_and_is_the_spine():
    md = skill_markdown()
    assert md.startswith("---\n")
    assert "name: hexgraph-vr" in md and "description:" in md
    # the body after the frontmatter IS the spine, verbatim
    assert md.endswith(SPINE)
    # back-compat alias used by agent_setup / agent_delegate / older tests
    assert vr_skill.SKILL == SPINE


def test_spine_routes_to_every_subfile():
    """Progressive disclosure only works if the spine names each sub-file, so the agent
    knows which to open for the phase it's in."""
    for name in SUBFILES:
        assert name in SPINE, name
    # and the spine names the sub-files in a "field manual" routing section
    assert "Field manual" in SPINE


def test_full_bundle_is_spine_plus_every_subfile():
    """The whole-bundle render (for --print-skill and the delegate brief) must carry the
    spine AND every sub-file body, so a consumer that can't read on-demand files is whole."""
    bundle = full_skill_markdown()
    assert SPINE in bundle
    for name, body in SUBFILES.items():
        assert body in bundle, name
        assert name in bundle, name


def test_spine_teaches_the_headline_engagement_behaviours():
    """The point of the refactor: `/hexgraph-vr find vulns in /path/to/fw` should drive a
    full engagement. The spine must teach ingest-from-path, the phased arc, and parallel
    decomposition over the shared graph — pin them so they can't quietly regress."""
    # Phase 0: get the target in from a path (not "assume it's already ingested")
    assert "target_ingest" in SPINE and "proj_create" in SPINE
    # the phased engagement arc
    assert "engagement arc" in SPINE.lower()
    # parallel decomposition + the shared graph as the coordination substrate
    assert "parallel" in SPINE.lower()
    for token in ("sub-agent", "shared", "WAL"):
        assert token in SPINE, token
    # the hard hostile-target rule and the surface-don't-prune stance survive into the spine
    assert "Never execute" in SPINE
    assert "You SURFACE for the analyst to TRIAGE" in SPINE


def test_subfiles_state_their_gates_in_the_right_file():
    """Gating must be discoverable in the file for that capability — an agent should never
    learn a tier only by being refused. Spot-check the load-bearing gates land correctly."""
    assert "features.network" in SUBFILES["dynamic-analysis.md"]
    assert "features.remote" in SUBFILES["dynamic-analysis.md"]
    assert "features.rehost" in SUBFILES["dynamic-analysis.md"]
    assert "features.build" in SUBFILES["fuzzing.md"]
    assert "features.fuzzing" in SUBFILES["fuzzing.md"]
    assert "features.fuzz_remote" in SUBFILES["fuzzing.md"]
    # the two solver tools are HIDDEN until the gate is on — the agent must be told why
    assert "features.angr" in SUBFILES["static-analysis.md"]
    assert "features.emulation" in SUBFILES["static-analysis.md"]


def test_assurance_ladder_lives_in_proving():
    """The unifying methodology — the assurance triple and its rungs — is the proving file's
    job; the spine carries only the summary."""
    proving = SUBFILES["proving.md"]
    for rung in ("code_present / static", "code_present / dynamic",
                 "input_reachable / dynamic", "input_reachable / static"):
        assert rung in proving, rung
    assert "finding_verify_poc" in proving and "finding_reachability" in proving
