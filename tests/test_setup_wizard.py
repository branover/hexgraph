"""Tests for the interactive setup wizard's headless core (`setup_catalog` +
`setup_wizard`).

The interactive prompts (questionary) are NOT exercised here — the wizard is factored
so all decisions flow through pure functions (`build_plan` / `apply_settings` /
`default_plan`) that need no TTY. These tests cover:

- the feature/gate REGISTRY: every `features.*` `enabled`/`edit` toggle in
  settings.ALLOWED has a catalog entry; every policy-changing feature has a non-empty
  security implication string; build-step → justfile recipe mapping is sane,
- the apply layer: writes the right settings, disables de-selected features, and NEVER
  writes a secret,
- the loopback invariant: a non-loopback bind is refused without the override env,
- the non-interactive / default path: applies the static-only baseline, never prompts,
- the build-step mapping per feature.
"""

from __future__ import annotations

import json

import pytest

from hexgraph import policy, settings
from hexgraph import setup_catalog as cat
from hexgraph import setup_wizard as wiz


# ---------------------------------------------------------------------------
# Registry coverage / accuracy
# ---------------------------------------------------------------------------


def _toggle_keys_in_allowed() -> set[str]:
    """The user-facing on/off toggles among settings.ALLOWED: the bool `enabled` keys
    plus `features.source.edit` and the three `features.mcp.*` flags."""
    keys = set()
    for path, (typ, _choices) in settings.ALLOWED.items():
        if not path.startswith("features."):
            continue
        is_bool = typ is bool or (isinstance(typ, tuple) and bool in typ)
        if not is_bool:
            continue
        leaf = path.rsplit(".", 1)[-1]
        if leaf in ("enabled", "edit", "read", "write", "run"):
            keys.add(path)
    return keys


def test_registry_covers_every_feature_toggle():
    catalog_keys = set(cat.features_by_key())
    allowed_toggles = _toggle_keys_in_allowed()
    missing = allowed_toggles - catalog_keys
    assert not missing, f"catalog is missing entries for toggles: {sorted(missing)}"
    # And no catalog entry points at a key the settings layer would reject.
    for key in catalog_keys:
        assert key in settings.ALLOWED, f"catalog key {key!r} is not a writable setting"


def test_every_feature_has_label_and_unlocks():
    for f in cat.FEATURES:
        assert f.label.strip()
        assert f.unlocks.strip()


def test_policy_changing_features_have_security_implication():
    for f in cat.FEATURES:
        if f.policy_changing:
            assert f.security.strip(), f"{f.key} is policy-changing but has no implication"


def test_non_policy_changing_features_dont_claim_a_tier():
    # A feature that doesn't relax a gate must not advertise a policy tier.
    for f in cat.FEATURES:
        if not f.policy_changing:
            assert f.tier is None, f"{f.key} is non-policy yet claims tier {f.tier}"


def test_exec_features_map_to_sandboxed_exec_tier():
    by_key = cat.features_by_key()
    assert by_key["features.poc.enabled"].tier == policy.TIER_SANDBOXED_EXEC
    assert by_key["features.fuzzing.enabled"].tier == policy.TIER_SANDBOXED_EXEC
    assert by_key["features.network.enabled"].tier == policy.TIER_LOCAL_NETWORK
    assert by_key["features.remote.enabled"].tier == policy.TIER_LIVE_REMOTE


def test_security_text_does_not_understate_exec_gate():
    by_key = cat.features_by_key()
    for k in ("features.poc.enabled", "features.fuzzing.enabled"):
        s = by_key[k].security.lower()
        assert "execut" in s  # mentions executing the target
        assert "sandbox" in s
        assert "--network none" in s  # still no egress
    # network tier must say loopback/private only + audited
    net = by_key["features.network.enabled"].security.lower()
    assert "private" in net and ("loopback" in net) and "audit" in net
    # remote tier must flag external host + secret creds
    rem = by_key["features.remote.enabled"].security.lower()
    assert "external" in rem and "secret" in rem


def test_secret_bearing_features_warn_creds_are_secrets():
    by_key = cat.features_by_key()
    for k in ("features.remote.enabled", "features.fuzz_remote.enabled"):
        assert "secret" in by_key[k].security.lower()


# ---------------------------------------------------------------------------
# Build-step mapping
# ---------------------------------------------------------------------------


def test_build_steps_reference_real_recipes():
    # Every BUILD_STEPS recipe name should appear in the justfile.
    import pathlib

    jf = pathlib.Path(__file__).resolve().parents[1] / "justfile"
    text = jf.read_text()
    for step in cat.BUILD_STEPS.values():
        recipe = step.recipe.split()[0]
        assert f"\n{recipe}" in text or f"\n{recipe}:" in text or recipe in text, \
            f"recipe {recipe!r} for build step {step.key!r} not found in justfile"


def test_feature_build_mapping():
    assert "fuzz" in cat.build_steps_for({"features.fuzzing.enabled"})
    assert "build" in cat.build_steps_for({"features.build.enabled"})
    assert "build" in cat.build_steps_for({"features.build_fetch.enabled"})
    assert set(cat.build_steps_for({"features.rehost.enabled"})) == {"firmae", "qemu"}
    # poc/network/remote/source/mcp need no dedicated image build
    assert cat.build_steps_for({"features.poc.enabled"}) == []
    assert cat.build_steps_for({"features.network.enabled"}) == []
    assert cat.build_steps_for({"features.source.edit"}) == []


# ---------------------------------------------------------------------------
# Plan building + apply (the testable headless core)
# ---------------------------------------------------------------------------


def _state(**over):
    base = dict(
        enable_keys=set(),
        host="127.0.0.1",
        port=8765,
        llm_backend="mock",
        llm_model=None,
        ghidra_mode="headless",
        current_enabled=set(),
        docker=True,
        built_images={},
    )
    base.update(over)
    return base


def test_build_plan_enables_selected_features():
    plan = wiz.build_plan(**_state(enable_keys={"features.poc.enabled"}))
    assert plan.settings_patch["features.poc.enabled"] is True


def test_build_plan_disables_deselected_features():
    plan = wiz.build_plan(**_state(
        enable_keys=set(), current_enabled={"features.poc.enabled"}))
    assert plan.settings_patch["features.poc.enabled"] is False


def test_build_plan_never_emits_a_secret_key():
    plan = wiz.build_plan(**_state(enable_keys=set(cat.features_by_key())))
    for key in plan.settings_patch:
        assert not wiz._is_secret_path(key), key
        assert key.startswith(("features.", "server.", "llm."))


def test_build_plan_refuses_non_loopback_without_override():
    plan = wiz.build_plan(**_state(host="0.0.0.0", i_know=False))
    assert plan.settings_patch["server.host"] == "127.0.0.1"
    assert any("REFUSED" in n for n in plan.notes)


def test_build_plan_allows_non_loopback_with_override():
    plan = wiz.build_plan(**_state(host="0.0.0.0", i_know=True))
    assert plan.settings_patch["server.host"] == "0.0.0.0"
    assert any("WARNING" in n for n in plan.notes)


def test_build_plan_ghidra_headless_uses_ghidra_image():
    plan = wiz.build_plan(**_state(
        enable_keys={"features.ghidra.enabled"}, ghidra_mode="headless"))
    assert "sandbox_ghidra" in plan.build_keys
    assert "sandbox" not in plan.build_keys  # superseded
    assert plan.settings_patch["features.ghidra.mode"] == "headless"


def test_build_plan_ghidra_headless_rebuilds_even_if_plain_sandbox_tag_exists():
    # The plain sandbox + ghidra image SHARE a tag, so a pre-existing radare2-only image
    # reports built_images['sandbox_ghidra']=True. Newly enabling headless Ghidra must
    # NOT be silently skipped — it must (re)build the Ghidra image.
    plan = wiz.build_plan(**_state(
        enable_keys={"features.ghidra.enabled"}, ghidra_mode="headless",
        current_enabled=set(), built_images={"sandbox": True, "sandbox_ghidra": True}))
    assert "sandbox_ghidra" in plan.build_keys


def test_build_plan_ghidra_already_headless_can_skip_existing():
    # If Ghidra-headless was ALREADY enabled, the existing image is trusted (no forced rebuild).
    plan = wiz.build_plan(**_state(
        enable_keys={"features.ghidra.enabled"}, ghidra_mode="headless",
        current_enabled={"features.ghidra.enabled"},
        built_images={"sandbox_ghidra": True}))
    assert "sandbox_ghidra" not in plan.build_keys


def test_build_plan_ghidra_bridge_does_not_force_ghidra_image():
    plan = wiz.build_plan(**_state(
        enable_keys={"features.ghidra.enabled"}, ghidra_mode="bridge"))
    assert "sandbox_ghidra" not in plan.build_keys
    assert "sandbox" in plan.build_keys


def test_build_plan_skips_existing_images():
    plan = wiz.build_plan(**_state(built_images={"sandbox": True}))
    assert "sandbox" not in plan.build_keys
    assert any("already present" in n for n in plan.notes)


def test_build_plan_rebuild_forces_existing():
    plan = wiz.build_plan(**_state(built_images={"sandbox": True}, rebuild_existing=True))
    assert "sandbox" in plan.build_keys


def test_build_plan_skips_docker_builds_without_docker():
    plan = wiz.build_plan(**_state(docker=False))
    assert plan.build_keys == []
    assert any("Docker not available" in n for n in plan.notes)


def test_apply_settings_writes_features(hg_home):
    plan = wiz.build_plan(**_state(enable_keys={"features.poc.enabled"}))
    wiz.apply_settings(plan)
    assert settings.get("features.poc.enabled") is True
    # And it round-trips through the resolved policy.
    assert policy.current_policy().allow_execution is True


def test_apply_settings_never_writes_a_secret_to_disk(hg_home):
    plan = wiz.build_plan(**_state(enable_keys=set(cat.features_by_key()),
                                   host="127.0.0.1"))
    wiz.apply_settings(plan)
    raw = json.loads(settings.settings_path().read_text())
    flat = settings._flatten(raw)
    for key in flat:
        assert not wiz._is_secret_path(key), f"secret-shaped key persisted: {key}"
    # No value in the file looks like an api key etc.
    blob = settings.settings_path().read_text().lower()
    assert "api_key" not in blob and "password" not in blob and "secret" not in blob


def test_apply_settings_rejects_smuggled_secret(hg_home):
    bad = wiz.SetupPlan(settings_patch={"anthropic.api_key": "sk-zzz"})
    with pytest.raises(AssertionError):
        wiz.apply_settings(bad)


# ---------------------------------------------------------------------------
# The non-interactive / default path (CI-safe, never prompts)
# ---------------------------------------------------------------------------


def test_default_plan_enables_nothing_new(hg_home):
    state = wiz.DetectedState(
        settings_exists=False, enabled_feature_keys=set(), server_host="127.0.0.1",
        server_port=8765, llm_backend="mock", llm_model=None, ghidra_mode="headless",
        docker=True, built_images={}, secrets={})
    plan = wiz.default_plan(state)
    # No feature toggles flipped on.
    assert all(v is False for k, v in plan.settings_patch.items() if k.startswith("features.")) \
        or not any(k.startswith("features.") for k in plan.settings_patch)
    assert plan.settings_patch["server.host"] == "127.0.0.1"


def test_default_plan_preserves_already_enabled(hg_home):
    state = wiz.DetectedState(
        settings_exists=True, enabled_feature_keys={"features.poc.enabled"},
        server_host="127.0.0.1", server_port=8765, llm_backend="mock", llm_model=None,
        ghidra_mode="headless", docker=True, built_images={}, secrets={})
    plan = wiz.default_plan(state)
    # poc was already on → not disabled by the baseline.
    assert plan.settings_patch.get("features.poc.enabled") is not False


def test_run_setup_non_interactive_does_not_prompt(hg_home, monkeypatch):
    # Force the headless branch and make sure no questionary call is attempted.
    import hexgraph.setup_wizard as w

    def _boom(*a, **k):  # pragma: no cover
        raise AssertionError("interactive prompt invoked in non-interactive mode")

    monkeypatch.setattr(w, "_run_interactive", _boom)
    # Avoid actually running docker/just builds.
    monkeypatch.setattr(w, "run_build_step", lambda *a, **k: 0)
    monkeypatch.setattr(w, "_docker_image_exists", lambda tag: True)
    rc = w.run_setup(non_interactive=True)
    assert rc == 0


def test_run_setup_non_interactive_fails_on_core_build_failure(hg_home, monkeypatch):
    import hexgraph.setup_wizard as w

    # Force a plan that builds the core sandbox, and make that build fail.
    monkeypatch.setattr(w, "_interactive_available", lambda: False)
    monkeypatch.setattr(w, "_docker_image_exists", lambda tag: False)
    monkeypatch.setattr(w, "docker_available", lambda: True)
    monkeypatch.setattr(w, "run_build_step", lambda *a, **k: 7)  # non-zero core build
    rc = w.run_setup(non_interactive=True)
    assert rc == 7  # a broken CORE install surfaces as a non-zero exit


def test_run_setup_non_interactive_tolerates_optional_build_failure(hg_home, monkeypatch):
    import hexgraph.setup_wizard as w

    # Pre-enable fuzzing so the optional fuzz image is in the plan; sandbox already built.
    settings.update_settings({"features.fuzzing.enabled": True})
    monkeypatch.setattr(w, "_interactive_available", lambda: False)
    monkeypatch.setattr(w, "docker_available", lambda: True)
    monkeypatch.setattr(w, "_docker_image_exists",
                        lambda tag: tag == "hexgraph-sandbox:latest")  # only sandbox built

    def _build(key, **k):
        return 0 if key in w._CORE_BUILDS else 9  # optional fuzz build fails

    monkeypatch.setattr(w, "run_build_step", _build)
    rc = w.run_setup(non_interactive=True)
    assert rc == 0  # optional image failure must NOT fail the bootstrap


def test_run_setup_falls_back_when_no_tty(hg_home, monkeypatch):
    import hexgraph.setup_wizard as w

    monkeypatch.setattr(w, "_interactive_available", lambda: False)
    called = {}

    def _ni(state, *, reason, rebuild):
        called["reason"] = reason
        return 0

    monkeypatch.setattr(w, "_run_non_interactive", _ni)
    rc = w.run_setup(non_interactive=False)
    assert rc == 0
    assert "TTY" in called["reason"] or "TUI" in called["reason"]


# ---------------------------------------------------------------------------
# Proactive sandbox-image staleness warning (complements meta_check_features,
# which catches a broken dep reactively — this warns when the image merely
# predates docker/sandbox.Dockerfile). The staleness PROBE is unit-tested in
# test_sandbox_staleness.py; here we cover the wizard's WARNING wiring.
# ---------------------------------------------------------------------------


def test_staleness_warning_when_stale(monkeypatch):
    import hexgraph.setup_wizard as w

    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image_staleness", lambda *a, **k: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image", lambda: "hexgraph-sandbox:latest")
    msg = w._sandbox_staleness_warning()
    assert msg and "just sandbox-build" in msg
    assert "older" in msg.lower()


def test_staleness_warning_silent_when_fresh_or_unknown(monkeypatch):
    import hexgraph.setup_wizard as w

    for verdict in (False, None):
        monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image_staleness", lambda *a, **k: verdict)
        assert w._sandbox_staleness_warning() is None


def test_staleness_warning_suppressed_when_rebuilding(monkeypatch):
    import hexgraph.setup_wizard as w

    # Even a STALE image is not flagged when this setup run is about to rebuild it —
    # the staleness is about to be fixed, so a warning would be noise.
    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image_staleness", lambda *a, **k: True)
    assert w._sandbox_staleness_warning(will_rebuild=True) is None


def test_staleness_warning_never_raises(monkeypatch):
    import hexgraph.setup_wizard as w

    def _boom(*a, **k):
        raise RuntimeError("docker fell over")

    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image_staleness", _boom)
    assert w._sandbox_staleness_warning() is None  # swallowed, never propagates


def test_non_interactive_setup_prints_staleness_warning(hg_home, monkeypatch, capsys):
    import hexgraph.setup_wizard as w

    # Sandbox already built (so the plan won't rebuild it), but it's STALE → warn.
    monkeypatch.setattr(w, "_interactive_available", lambda: False)
    monkeypatch.setattr(w, "docker_available", lambda: True)
    monkeypatch.setattr(w, "_docker_image_exists", lambda tag: True)
    monkeypatch.setattr(w, "run_build_step", lambda *a, **k: 0)
    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image_staleness", lambda *a, **k: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.sandbox_image", lambda: "hexgraph-sandbox:latest")
    rc = w.run_setup(non_interactive=True)
    out = capsys.readouterr().out
    assert rc == 0
    assert "OLDER than" in out and "just sandbox-build" in out


# ---------------------------------------------------------------------------
# Coding-agent integration: MCP-server registration + VR-skill install
# (the wizard's new optional step). The registration helpers in agent_setup
# PERFORM the install by editing the agent's own config file directly, so they
# are exercised headlessly here — and the step itself is driven with fakes.
# ---------------------------------------------------------------------------


def test_register_claude_user_creates_and_is_idempotent(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    res = agent_setup.register_agent("claude", scope="user")
    assert res["changed"] is True
    assert res["path"] == str(tmp_path / ".claude.json")
    data = json.loads((tmp_path / ".claude.json").read_text())
    assert data["mcpServers"]["hexgraph"] == agent_setup.mcp_server_entry()
    # Re-running is a no-op (idempotent).
    res2 = agent_setup.register_agent("claude", scope="user")
    assert res2["changed"] is False
    assert json.loads((tmp_path / ".claude.json").read_text()) == data


def test_register_claude_project_writes_dot_mcp_json(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.chdir(proj)
    res = agent_setup.register_agent("claude", scope="project")
    assert res["path"] == str(proj / ".mcp.json")
    data = json.loads((proj / ".mcp.json").read_text())
    assert data["mcpServers"]["hexgraph"] == agent_setup.mcp_server_entry()


def test_register_gemini_user(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    res = agent_setup.register_agent("gemini", scope="user")
    assert res["path"] == str(tmp_path / ".gemini" / "settings.json")
    data = json.loads((tmp_path / ".gemini" / "settings.json").read_text())
    assert data["mcpServers"]["hexgraph"] == agent_setup.mcp_server_entry()


def test_register_preserves_existing_keys(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = tmp_path / ".claude.json"
    cfg.write_text(json.dumps({"theme": "dark",
                               "mcpServers": {"other": {"command": "x", "args": []}}}))
    agent_setup.register_agent("claude", scope="user")
    data = json.loads(cfg.read_text())
    assert data["theme"] == "dark"
    assert data["mcpServers"]["other"] == {"command": "x", "args": []}
    assert data["mcpServers"]["hexgraph"] == agent_setup.mcp_server_entry()


def test_register_refuses_unparseable_json(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    cfg = tmp_path / ".claude.json"
    cfg.write_text("{ this is not json ")
    with pytest.raises(RuntimeError):
        agent_setup.register_agent("claude", scope="user")
    assert cfg.read_text() == "{ this is not json "  # left untouched


def test_register_codex_user_appends_table_and_is_idempotent(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    res = agent_setup.register_agent("codex", scope="user")
    assert res["changed"] is True
    path = tmp_path / ".codex" / "config.toml"
    text = path.read_text()
    assert "[mcp_servers.hexgraph]" in text
    res2 = agent_setup.register_agent("codex", scope="user")
    assert res2["changed"] is False  # idempotent
    assert path.read_text() == text


def test_register_codex_preserves_existing_toml(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".codex" / "config.toml"
    path.parent.mkdir(parents=True)
    path.write_text('model = "o3"\n')
    agent_setup.register_agent("codex", scope="user")
    text = path.read_text()
    assert 'model = "o3"' in text and "[mcp_servers.hexgraph]" in text
    tomllib = pytest.importorskip("tomllib")
    parsed = tomllib.loads(text)
    assert parsed["model"] == "o3" and "hexgraph" in parsed["mcp_servers"]


def test_register_codex_project_scope_rejected(monkeypatch, tmp_path):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(ValueError):
        agent_setup.register_agent("codex", scope="project")


def test_register_unknown_agent_rejected():
    from hexgraph import agent_setup

    with pytest.raises(ValueError):
        agent_setup.register_agent("nope", scope="user")


def test_default_skill_dir_under_home(tmp_path, monkeypatch):
    from hexgraph import agent_setup

    monkeypatch.setenv("HOME", str(tmp_path))
    assert agent_setup.default_skill_dir() == str(tmp_path / ".claude" / "skills")


# --- The wizard step driven with fakes (no real TTY) -----------------------


class _FakeAnswer:
    def __init__(self, value):
        self._value = value

    def ask(self):
        return self._value


class _FakeQuestionary:
    """Scripts answers in order; confirm/select/text each pop the next value."""

    def __init__(self, answers):
        self._answers = list(answers)

    def _next(self):
        return _FakeAnswer(self._answers.pop(0))

    def confirm(self, *a, **k):
        return self._next()

    def select(self, *a, **k):
        return self._next()

    def text(self, *a, **k):
        return self._next()

    class Choice:
        def __init__(self, title, value=None):
            self.title = title
            self.value = value


class _FakeConsole:
    def rule(self, *a, **k):
        pass

    def print(self, *a, **k):
        pass


def test_coding_agent_step_registers_and_installs(tmp_path, monkeypatch):
    from hexgraph import agent_setup
    from hexgraph.setup_wizard import _coding_agent_step

    monkeypatch.setenv("HOME", str(tmp_path))
    skill_dir = tmp_path / "skills"
    q = _FakeQuestionary([
        True, "claude", "user",                 # register MCP for claude, user scope
        True, "__custom__", str(skill_dir),     # install skill to a custom dir
    ])
    _coding_agent_step(_FakeConsole(), q)
    data = json.loads((tmp_path / ".claude.json").read_text())
    assert data["mcpServers"]["hexgraph"] == agent_setup.mcp_server_entry()
    assert (skill_dir / "hexgraph-vr" / "SKILL.md").is_file()


def test_coding_agent_step_skip_both(tmp_path, monkeypatch):
    from hexgraph.setup_wizard import _coding_agent_step

    monkeypatch.setenv("HOME", str(tmp_path))
    q = _FakeQuestionary([False, False])  # decline both prompts
    _coding_agent_step(_FakeConsole(), q)
    assert not (tmp_path / ".claude.json").exists()
    assert not (tmp_path / ".claude" / "skills").exists()


def test_non_interactive_setup_skips_agent_step(hg_home, tmp_path, monkeypatch):
    # The whole agent step lives on the interactive path, so the CI-safe baseline
    # must never reach it — guard that explicitly.
    import hexgraph.setup_wizard as w

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(w, "run_build_step", lambda *a, **k: 0)
    monkeypatch.setattr(w, "_docker_image_exists", lambda tag: True)
    monkeypatch.setattr(w, "_coding_agent_step",
                        lambda *a, **k: pytest.fail("agent step ran non-interactively"))
    rc = w.run_setup(non_interactive=True)
    assert rc == 0
    assert not (tmp_path / ".claude.json").exists()
    assert not (tmp_path / ".codex").exists()
    assert not (tmp_path / ".gemini").exists()
