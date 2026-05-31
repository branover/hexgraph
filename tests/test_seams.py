"""P0 seams: local defaults grant/allow everything; the hooks exist for v2."""

import pytest


def test_entitlements_allow_everything_locally():
    from hexgraph.entitlements import current_entitlements, require

    ent = current_entitlements()
    assert ent.allows("task.static_analysis")
    assert ent.allows("anything.at.all")
    require("task.recon")  # no raise in the local build


def test_metering_records_without_error(caplog):
    from hexgraph.llm.base import Usage
    from hexgraph.metering import record_usage

    record_usage("task.static_analysis", Usage(input_tokens=10, output_tokens=2), task_id="t1")


def test_policy_is_static_only_by_default(hg_home):
    # hg_home isolates HEXGRAPH_HOME so this is hermetic regardless of the
    # developer's real ~/.hexgraph/settings.json (current_policy() reads the
    # fuzzing toggle from settings).
    from hexgraph.policy import PolicyViolation, assert_allows_execution, current_policy

    p = current_policy()
    assert p.static_only and not p.allow_execution and not p.allow_network
    with pytest.raises(PolicyViolation):
        assert_allows_execution()


def test_executor_factory_returns_local_docker():
    from hexgraph.sandbox.executor import Executor, LocalDockerExecutor, get_executor

    ex = get_executor()
    assert isinstance(ex, LocalDockerExecutor)
    assert isinstance(ex, Executor)  # satisfies the protocol
    with pytest.raises(ValueError):
        get_executor("remote")  # not implemented yet


def test_principal_is_local():
    from hexgraph.principal import current_principal

    p = current_principal()
    assert p.id == "local" and p.is_local


def test_hexgraph_api_key_slot_reserved(monkeypatch):
    from hexgraph.config import get_hexgraph_api_key

    monkeypatch.delenv("HEXGRAPH_API_KEY", raising=False)
    assert get_hexgraph_api_key() is None
    monkeypatch.setenv("HEXGRAPH_API_KEY", "hxg-test")
    assert get_hexgraph_api_key() == "hxg-test"
