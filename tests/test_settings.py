"""Settings system: managed settings.json layer, validation, secret status
(presence only — never the value), and config layering precedence."""

import json
import os

import pytest
from fastapi.testclient import TestClient

from hexgraph import settings as st
from hexgraph.api.app import create_app


def test_defaults_when_unset(hg_home):
    v = st.read_settings()
    assert v["settings"]["llm"]["backend"] == "mock"
    assert v["settings"]["features"]["ghidra"]["enabled"] is False
    assert v["settings"]["features"]["ghidra"]["mode"] == "headless"


def test_update_and_persist(hg_home):
    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "bridge"})
    assert st.get("features.ghidra.enabled") is True
    assert st.get("features.ghidra.mode") == "bridge"
    # persisted to settings.json
    assert json.loads(st.settings_path().read_text())["features"]["ghidra"]["enabled"] is True


def test_nested_patch_accepted(hg_home):
    st.update_settings({"features": {"ghidra": {"bridge": {"port": 5005}}}})
    assert st.get("features.ghidra.bridge.port") == 5005


def test_rejects_unknown_key(hg_home):
    with pytest.raises(st.SettingsError):
        st.update_settings({"features.ghidra.secret_backdoor": True})


def test_rejects_bad_type_and_choice(hg_home):
    with pytest.raises(st.SettingsError):
        st.update_settings({"server.port": "not-an-int"})
    with pytest.raises(st.SettingsError):
        st.update_settings({"server.port": True})  # bool is not an int here
    with pytest.raises(st.SettingsError):
        st.update_settings({"llm.backend": "gpt"})  # not an allowed choice


def test_secrets_are_status_only(hg_home, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret-value-должно-never-leak")
    view = st.read_settings()
    blob = json.dumps(view)
    assert "sk-secret-value" not in blob  # the value never appears anywhere
    assert view["secrets"]["anthropic_api_key"] == {"present": True, "source": "env"}


def test_cannot_write_secret_via_settings(hg_home):
    with pytest.raises(st.SettingsError):
        st.update_settings({"anthropic": {"api_key": "sk-nope"}})


def test_managed_layer_overrides_config_default(hg_home, monkeypatch):
    from hexgraph.config import load_config

    # conftest sets HEXGRAPH_LLM_BACKEND=mock globally; clear it to test the
    # managed > config.toml > default layer (env precedence is its own test).
    monkeypatch.delenv("HEXGRAPH_LLM_BACKEND", raising=False)
    assert load_config().llm_backend == "mock"
    st.update_settings({"llm.backend": "anthropic"})
    assert load_config().llm_backend == "anthropic"


def test_env_beats_managed(hg_home, monkeypatch):
    from hexgraph.config import load_config

    st.update_settings({"llm.backend": "anthropic"})
    monkeypatch.setenv("HEXGRAPH_LLM_BACKEND", "claude_code")
    assert load_config().llm_backend == "claude_code"


def test_settings_api_roundtrip(hg_home):
    c = TestClient(create_app())
    assert c.get("/api/settings").json()["settings"]["features"]["ghidra"]["enabled"] is False
    r = c.patch("/api/settings", json={"features.ghidra.enabled": True})
    assert r.status_code == 200
    assert r.json()["settings"]["features"]["ghidra"]["enabled"] is True
    bad = c.patch("/api/settings", json={"server.port": "x"})
    assert bad.status_code == 400


def test_lenses_default_empty(hg_home):
    assert st.read_settings()["settings"]["ui"]["lenses"] == []


def test_lenses_roundtrip_and_persist(hg_home):
    lens = {"name": "Attack surface", "view": "graph", "groupBy": "type",
            "filters": {"severity": "high"}, "layers": {"nodes": {"string": False}}}
    st.update_settings({"ui.lenses": [lens]})
    got = st.get("ui.lenses")
    assert got == [lens]
    # persisted to settings.json
    assert json.loads(st.settings_path().read_text())["ui"]["lenses"][0]["name"] == "Attack surface"


def test_lenses_reject_bad_shapes(hg_home):
    with pytest.raises(st.SettingsError):
        st.update_settings({"ui.lenses": "not-a-list"})
    with pytest.raises(st.SettingsError):
        st.update_settings({"ui.lenses": [{"view": "graph"}]})  # missing name
    with pytest.raises(st.SettingsError):
        st.update_settings({"ui.lenses": [{"name": ""}]})  # empty name
    with pytest.raises(st.SettingsError):
        st.update_settings({"ui.lenses": [{"name": "x", "evil": 1}]})  # unknown key
    with pytest.raises(st.SettingsError):
        st.update_settings({"ui.lenses": [{"name": "dup"}, {"name": "dup"}]})  # dup name


def test_lenses_api_roundtrip(hg_home):
    c = TestClient(create_app())
    assert c.get("/api/settings").json()["settings"]["ui"]["lenses"] == []
    r = c.patch("/api/settings", json={"ui.lenses": [{"name": "Findings only", "view": "table"}]})
    assert r.status_code == 200
    assert r.json()["settings"]["ui"]["lenses"][0]["name"] == "Findings only"
    bad = c.patch("/api/settings", json={"ui.lenses": [{"view": "x"}]})
    assert bad.status_code == 400


def test_ghidra_test_endpoint_disabled(hg_home):
    c = TestClient(create_app())
    r = c.post("/api/settings/ghidra/test")
    assert r.status_code == 200
    assert r.json() == {"enabled": False, "ok": False, "detail": "Ghidra is disabled in Settings."}
