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


def test_ceiling_clamps_the_network_tier_and_egress(hg_home):
    # The clamp must hold for the egress path, not just execution. Boot with everything
    # off, then enable network mid-session.
    policy.snapshot_ceiling()
    st.update_settings({"features.network.enabled": True})

    p = policy.current_policy()
    assert not p.allow_network and p.static_only and p.tier == policy.TIER_STATIC_ONLY
    # assert_allows_egress fails closed on the (clamped) policy regardless of the scope.
    scope = policy.local_network_scope("http://127.0.0.1")
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_egress("127.0.0.1:80", scope)


def test_ceiling_clamps_the_remote_tier(hg_home):
    policy.snapshot_ceiling()  # boot with remote off
    st.update_settings({"features.remote.enabled": True})

    p = policy.current_policy()
    assert not p.allow_remote and not p.allow_network and p.tier == policy.TIER_STATIC_ONLY
    with pytest.raises(policy.PolicyViolation):
        policy.assert_allows_remote()


def test_build_fetch_effective_is_honest_about_its_build_dependency(hg_home):
    # No ceiling: enabling build_fetch WITHOUT build leaves it ineffective in the real
    # policy (build_fetch_on = build_on and ...). `effective` must reflect that, while
    # pending_restart stays False (no restart fixes a missing prerequisite).
    st.update_settings({"features.build_fetch.enabled": True})
    bf = policy.policy_feature_states()["features"]["build_fetch"]
    assert bf == {"configured": True, "effective": False, "pending_restart": False}
    assert policy.current_policy().allow_build_fetch is False

    # Turn build on too → build_fetch becomes effective.
    st.update_settings({"features.build.enabled": True})
    assert policy.current_policy().allow_build_fetch is True
    assert policy.policy_feature_states()["features"]["build_fetch"]["effective"] is True


def test_build_is_effective_when_implied_by_execution(hg_home):
    # build is implied by exec (build_on = on('build') or exec_on). With fuzzing on and
    # build's own toggle off, build's capability is active — `effective` reflects the real
    # policy outcome, not just build's own toggle.
    st.update_settings({"features.fuzzing.enabled": True})
    states = policy.policy_feature_states()["features"]
    assert policy.current_policy().allow_build is True
    assert states["build"]["effective"] is True
    assert states["build"]["configured"] is False


def test_capability_table_respects_the_ceiling(hg_home):
    from hexgraph.engine.capabilities import capabilities_for

    # No ceiling (CLI/test default): enabling fuzzing offers the fuzzing task.
    st.update_settings({"features.fuzzing.enabled": True})
    assert "fuzzing" in capabilities_for("target", "executable")

    # A running server that booted with fuzzing OFF must NOT advertise it after a
    # mid-session enable — the worker's policy seam would refuse it at run time.
    policy.reset_ceiling()
    st.update_settings({"features.fuzzing.enabled": False})
    policy.snapshot_ceiling()  # boot: fuzzing off
    st.update_settings({"features.fuzzing.enabled": True})  # mid-session widen
    assert "fuzzing" not in capabilities_for("target", "executable")
