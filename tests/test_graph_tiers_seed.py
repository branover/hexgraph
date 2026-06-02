"""Guard the graph-presentation complexity-tier seed against bitrot.

`scripts/seed_graph_tiers.py` builds the four A/B fixture projects (SMALL/MEDIUM/
LARGE/PATHOLOGICAL) the graph redesign's before/after Playwright captures run against
(docs/design-graph-presentation.md §9). It must keep seeding cleanly on the mock
backend, offline ($0, no Docker), producing graphs in the size bands each tier targets.
Fast offline test — it does NOT capture screenshots.
"""

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _load_tiers():
    path = REPO / "scripts" / "seed_graph_tiers.py"
    spec = importlib.util.spec_from_file_location("seed_graph_tiers", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def _mock_fuzzer(monkeypatch):
    # MEDIUM (the showcase) runs the offline MockFuzzer (no Docker, deterministic).
    monkeypatch.setenv("HEXGRAPH_FUZZER", "mock")


# Approximate size bands per tier — generous so reasonable tuning won't break the guard,
# tight enough to catch a tier collapsing to empty or exploding.
BANDS = {
    "small": (8, 30, 12, 40),          # nodes_lo, nodes_hi, edges_lo, edges_hi
    "medium": (18, 60, 30, 110),
    "large": (120, 240, 400, 900),
    "pathological": (380, 700, 1500, 3000),
}


def test_graph_tiers_seed_clean_and_sized(hg_home, _mock_fuzzer):
    from hexgraph import settings as st
    from hexgraph.db.session import session_scope

    st.update_settings({"features.fuzzing.enabled": True, "features.poc.enabled": True,
                        "features.network.enabled": True, "features.build.enabled": True})
    tiers = _load_tiers()

    seen_ids = set()
    with session_scope() as s:
        for tier, (n_lo, n_hi, e_lo, e_hi) in BANDS.items():
            info = tiers.seed_tier(s, tier, reset=True)
            assert info["reused"] is False
            assert info["project_id"] not in seen_ids, "each tier must be its own project"
            seen_ids.add(info["project_id"])
            assert n_lo <= info["nodes"] <= n_hi, (
                f"{tier}: {info['nodes']} nodes outside [{n_lo},{n_hi}]")
            assert e_lo <= info["edges"] <= e_hi, (
                f"{tier}: {info['edges']} edges outside [{e_lo},{e_hi}]")
            assert info["findings"] >= 1


def test_graph_tiers_seed_deterministic_and_idempotent(hg_home, _mock_fuzzer):
    from hexgraph import settings as st
    from hexgraph.db.session import session_scope

    st.update_settings({"features.fuzzing.enabled": True})
    tiers = _load_tiers()

    # LARGE is procedurally generated from a fixed RNG seed → identical sizes each run.
    with session_scope() as s:
        first = tiers.seed_tier(s, "large", reset=True)
    with session_scope() as s:
        again = tiers.seed_tier(s, "large", reset=False)
        assert again["reused"] is True
        assert again["project_id"] == first["project_id"]
    with session_scope() as s:
        rebuilt = tiers.seed_tier(s, "large", reset=True)
        # Deterministic: a fresh rebuild reproduces the same node/edge counts.
        assert rebuilt["nodes"] == first["nodes"]
        assert rebuilt["edges"] == first["edges"]
