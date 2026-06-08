"""Tests for the `hexgraph setup --refresh` sanity-sync (`setup_wizard.run_refresh` +
its decision helpers, and the `agent_setup` detection it relies on).

The refresh path is factored like the wizard: the side-effecting orchestration
(`run_refresh`) is thin, and the decisions flow through pure functions that need no
Docker/git — so these tests cover, with everything mocked:

- `refresh_build_keys`: rebuild the core sandbox when missing/stale OR present-but-Ghidra-
  less (the self-heal for the old `with_ghidra=1` arg bug), and every OTHER image only when
  it is ALREADY built AND stale (never build one you didn't opt into),
- `_dockerfile_for`: the Dockerfile is read from the build step's command (can't drift),
- `agent_setup.detect_skill_dirs`: only bases that already hold the skill,
- `agent_setup.detect_registrations` / `refresh_registrations`: find the existing MCP
  registrations (incl. Claude's per-project "local" scope) and re-affirm a drifted one
  while leaving a current one untouched.
"""

from __future__ import annotations

import json

from hexgraph import setup_wizard as wiz
from hexgraph.agent import agent_setup


# ---------------------------------------------------------------------------
# refresh_build_keys — pure decision logic (staleness/ghidra probes mocked)
# ---------------------------------------------------------------------------


def _state(**kw) -> wiz.DetectedState:
    base = dict(
        settings_exists=True, enabled_feature_keys=set(), server_host="127.0.0.1",
        server_port=8765, llm_backend="mock", llm_model=None, ghidra_mode="headless",
        docker=True, built_images={}, secrets={},
    )
    base.update(kw)
    return wiz.DetectedState(**base)


def test_dockerfile_for_reads_the_build_command():
    assert wiz._dockerfile_for("sandbox") == "docker/sandbox.Dockerfile"
    assert wiz._dockerfile_for("fuzz") == "docker/fuzz.Dockerfile"
    assert wiz._dockerfile_for("angr") == "docker/angr.Dockerfile"


def test_refresh_rebuilds_ghidra_when_image_lacks_it(monkeypatch):
    # Config wants headless Ghidra, the sandbox tag exists and is NOT stale, but the image
    # has no Ghidra (the old build-arg bug) → refresh must rebuild WITH Ghidra.
    monkeypatch.setattr(wiz, "_build_step_stale", lambda k, root: False)
    monkeypatch.setattr(wiz, "_sandbox_has_ghidra", lambda: False)
    st = _state(enabled_feature_keys={"features.ghidra.enabled"}, ghidra_mode="headless",
                built_images={"sandbox": True})
    assert wiz.refresh_build_keys(st, root="/x") == ["sandbox_ghidra"]


def test_refresh_skips_ghidra_sandbox_when_present_and_fresh(monkeypatch):
    monkeypatch.setattr(wiz, "_build_step_stale", lambda k, root: False)
    monkeypatch.setattr(wiz, "_sandbox_has_ghidra", lambda: True)
    st = _state(enabled_feature_keys={"features.ghidra.enabled"}, ghidra_mode="headless",
                built_images={"sandbox": True})
    assert wiz.refresh_build_keys(st, root="/x") == []


def test_refresh_rebuilds_stale_plain_sandbox(monkeypatch):
    # No Ghidra wanted (bridge mode / feature off); sandbox present but its Dockerfile moved.
    monkeypatch.setattr(wiz, "_build_step_stale", lambda k, root: k == "sandbox")
    monkeypatch.setattr(wiz, "_sandbox_has_ghidra", lambda: None)
    st = _state(enabled_feature_keys=set(), ghidra_mode="bridge", built_images={"sandbox": True})
    assert wiz.refresh_build_keys(st, root="/x") == ["sandbox"]


def test_refresh_builds_missing_sandbox(monkeypatch):
    monkeypatch.setattr(wiz, "_build_step_stale", lambda k, root: None)
    monkeypatch.setattr(wiz, "_sandbox_has_ghidra", lambda: None)
    st = _state(enabled_feature_keys=set(), ghidra_mode="bridge", built_images={})
    assert wiz.refresh_build_keys(st, root="/x") == ["sandbox"]


def test_refresh_only_rebuilds_other_images_that_are_built_and_stale(monkeypatch):
    stale = {"sandbox": False, "fuzz": True, "build": True, "angr": False,
             "firmae": False, "qemu": False}
    monkeypatch.setattr(wiz, "_build_step_stale", lambda k, root: stale.get(k))
    monkeypatch.setattr(wiz, "_sandbox_has_ghidra", lambda: None)
    # fuzz is built AND stale → rebuilt; build is stale but NOT built → skipped; sandbox fresh.
    st = _state(enabled_feature_keys=set(), ghidra_mode="bridge",
                built_images={"sandbox": True, "fuzz": True})
    assert wiz.refresh_build_keys(st, root="/x") == ["fuzz"]


# ---------------------------------------------------------------------------
# agent_setup — skill-location + MCP-registration detection
# ---------------------------------------------------------------------------


def test_detect_skill_dirs_only_where_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    proj = str(tmp_path / "proj")
    assert agent_setup.detect_skill_dirs(project_dir=proj) == []

    base = tmp_path / ".claude" / "skills" / "hexgraph-vr"
    base.mkdir(parents=True)
    (base / "SKILL.md").write_text("# skill\n")
    dirs = agent_setup.detect_skill_dirs(project_dir=proj)
    assert str(tmp_path / ".claude" / "skills") in dirs


def test_detect_and_refresh_registrations(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    want = agent_setup.mcp_server_entry()
    drift = {"command": "/old/venv/bin/python", "args": ["-m", "hexgraph.cli", "mcp"]}
    proj = str(tmp_path / "proj")
    claude = {
        "mcpServers": {"hexgraph": dict(want)},                              # user scope: current
        "projects": {proj: {"mcpServers": {"hexgraph": dict(drift)}}},       # local scope: drifted
    }
    (tmp_path / ".claude.json").write_text(json.dumps(claude))

    regs = {(r["agent"], r["scope"]): r for r in agent_setup.detect_registrations(project_dir=proj)}
    assert regs[("claude", "user")]["current"] is True
    assert regs[("claude", f"local:{proj}")]["current"] is False

    res = {(r["agent"], r["scope"]): r["action"]
           for r in agent_setup.refresh_registrations(project_dir=proj)}
    assert res[("claude", "user")] == "unchanged"
    assert res[("claude", f"local:{proj}")] == "updated"

    # the drifted local entry is now rewritten to the current launch command
    data = json.loads((tmp_path / ".claude.json").read_text())
    assert data["projects"][proj]["mcpServers"]["hexgraph"] == want
    # the already-current user entry is untouched
    assert data["mcpServers"]["hexgraph"] == want


def test_refresh_registrations_noop_when_none(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert agent_setup.refresh_registrations(project_dir=str(tmp_path / "proj")) == []


# ---------------------------------------------------------------------------
# run_refresh — a FAILED sandbox rebuild must still surface the staleness hint
# (regression: the staleness warning must not be suppressed unless a sandbox image
# was rebuilt SUCCESSFULLY this run)
# ---------------------------------------------------------------------------


def test_run_refresh_failed_sandbox_build_still_warns(monkeypatch):
    st = _state(docker=True, built_images={"sandbox": True})
    monkeypatch.setattr(wiz, "detect_state", lambda: st)
    monkeypatch.setattr(wiz, "_repo_root", lambda: "/x")
    monkeypatch.setattr(wiz, "refresh_build_keys", lambda state, root: ["sandbox"])
    monkeypatch.setattr(wiz, "run_build_step", lambda b: 1)  # the rebuild FAILS

    monkeypatch.setattr(agent_setup, "refresh_registrations", lambda project_dir=None: [])
    monkeypatch.setattr(agent_setup, "detect_skill_dirs", lambda project_dir=None: [])
    import hexgraph.db.migrate as mig

    monkeypatch.setattr(mig, "prepare_database", lambda: None)

    seen: dict = {}
    monkeypatch.setattr(
        wiz, "_sandbox_staleness_warning",
        lambda *, will_rebuild=False: (seen.update(will_rebuild=will_rebuild), None)[1],
    )

    rc = wiz.run_refresh()
    assert rc == 1                       # a CORE (sandbox) build failure → non-zero exit
    assert seen["will_rebuild"] is False  # failed rebuild must NOT suppress the staleness warning
