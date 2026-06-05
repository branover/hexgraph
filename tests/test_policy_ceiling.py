"""The startup policy ceiling: a long-lived process (the API server, an MCP session)
freezes which policy-relaxing gates it may use at startup, so enabling a gate in
settings.json mid-session is *saved* but stays inactive until the next restart. This
closes the escalation where an agent (or any host-local writer) flips a `features.*`
toggle to grant itself execution/egress against an already-running server. Disabling is
always live; only enabling something that was off at startup is deferred."""

import pytest

from hexgraph import policy
from hexgraph import settings as st

# The process-global `policy._ceiling` is reset around every test by the autouse
# `_reset_policy_ceiling` fixture in conftest, so each test below starts read-live.


def test_no_ceiling_reads_live_settings(hg_home):
    # Short-lived processes (CLI, tests) never snapshot — each run is its own "boot",
    # so enabling fuzzing takes effect immediately, exactly as before this feature.
    assert policy.current_ceiling() is None
    assert not policy.current_policy().allow_execution
    st.update_settings({"features.fuzzing.enabled": True})
    assert policy.current_policy().allow_execution  # live, no ceiling to clamp


def test_ceiling_clamps_enabling_a_gate_that_was_off_at_startup(hg_home):
    # Boot with everything off, then an agent flips fuzzing on in settings.json.
    policy.snapshot_ceiling()
    assert policy.current_ceiling() == frozenset()
    st.update_settings({"features.fuzzing.enabled": True})

    # Saved, but the running process refuses to widen past its frozen ceiling.
    assert st.get("features.fuzzing.enabled") is True
    assert not policy.current_policy().allow_execution
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_execution()


def test_disabling_is_always_live_even_with_a_ceiling(hg_home):
    # Boot with fuzzing on (it's within the ceiling), then turn it off mid-session.
    st.update_settings({"features.fuzzing.enabled": True})
    policy.snapshot_ceiling()
    assert "fuzzing" in policy.current_ceiling()
    assert policy.current_policy().allow_execution

    st.update_settings({"features.fuzzing.enabled": False})
    # Narrowing takes effect at once — clamp(off) and live(off) both give off.
    assert not policy.current_policy().allow_execution


def test_re_enabling_within_the_ceiling_is_live(hg_home):
    # On at boot ⇒ within the ceiling. Toggling off then on again is live (re-enabling
    # something already permitted is not a widen past the frozen ceiling).
    st.update_settings({"features.fuzzing.enabled": True})
    policy.snapshot_ceiling()
    st.update_settings({"features.fuzzing.enabled": False})
    assert not policy.current_policy().allow_execution
    st.update_settings({"features.fuzzing.enabled": True})
    assert policy.current_policy().allow_execution


def test_policy_feature_states_reports_configured_vs_effective(hg_home):
    policy.snapshot_ceiling()  # boot with all gates off
    st.update_settings({"features.network.enabled": True})

    states = policy.policy_feature_states()
    net = states["features"]["network"]
    assert net == {"configured": True, "effective": False, "pending_restart": True}
    assert states["restart_required"] is True
    assert states["pending"] == ["network"]

    # A gate left off is neither configured nor pending.
    assert states["features"]["poc"] == {
        "configured": False, "effective": False, "pending_restart": False,
    }


def test_policy_feature_states_no_ceiling_is_never_pending(hg_home):
    # Without a snapshot, configured == effective for every gate (nothing is deferred).
    st.update_settings({"features.poc.enabled": True})
    states = policy.policy_feature_states()
    assert states["restart_required"] is False
    assert states["pending"] == []
    assert states["features"]["poc"] == {
        "configured": True, "effective": True, "pending_restart": False,
    }


def test_read_settings_includes_policy_block(hg_home):
    view = st.read_settings()
    assert set(view["policy"]) == {"restart_required", "pending", "features"}
    # every policy gate is reported, even the ones with no toggle on the Settings page
    assert set(view["policy"]["features"]) == set(policy.POLICY_GATES)


def test_ceiling_does_not_block_a_gate_that_was_on_at_startup(hg_home):
    # build implies build alone; verify a gate enabled at boot stays effective.
    st.update_settings({"features.network.enabled": True})
    policy.snapshot_ceiling()
    p = policy.current_policy()
    assert p.allow_network and not p.static_only
