"""re_script — the escape-hatch that runs an AGENT-SUPPLIED Python-3 script over a target's WARM
Ghidra project READ-ONLY, inside the SAME hardened sandbox every probe uses.

Since the PyGhidra re-platform the agent's script is real Python 3 run IN-PROCESS by
pyghidra_lib.script_core against the resident program (no more Jython postScript / analyzeHeadless
subprocess). The host DELIVERY seam is unchanged: the body rides HEXGRAPH_USER_SCRIPT_B64 (base64,
off the argv), with `--script` + the warm project bind-mounted; the probe decodes it, opens the
program read-only (open_target(read_only=True) → getReadOnlyDomainObject), and execs it.

Offline coverage (no Docker / no Ghidra):
  * the dispatch base64-encodes the script into extra_env, passes `--script` + project_mount, opens
    the warm project, records exactly ONE `script` Observation and ZERO graph nodes;
  * the FEATURE GATE hides the catalog tool when off, and the dispatch REFUSES it when off
    (defence in depth);
  * a WARM MISS returns the re_analyze lead (re_script is warm-only, never runs a cold analysis);
  * radare2 (non-Ghidra backend) is rejected with a clear error;
  * an oversized script is rejected host-side;
  * probe-level: the `--script` arg-parse + base64 decode + size cap (`_load_user_script`); that a
    cold `--script` run refuses WITHOUT starting Ghidra (never runs `L.start`/`L.open_target`); and
    that `script_core` execs the body against the resident program and collects its JSON result.
"""

import base64
import json
import os

import pytest

from hexgraph.db.models import Edge, Node, Observation
from hexgraph.db.session import session_scope
from hexgraph.agent import agent_tools as AT
from hexgraph.agent.agent_tools import ToolContext, run_tool
from hexgraph.agent import mcp_catalog as C
from hexgraph.engine.re import ghidra_project as gp
from hexgraph.engine.targets.ingest import create_project, ingest_file

from conftest import fixture_path


# ── a fake executor that records exactly how the probe was invoked ────────────────────

class _FakeExec:
    """Records the run_json_probe call (probe, extra_args, extra_env, project_mount) and returns a
    fixed JSON payload — the agent-script's output shape."""

    def __init__(self, result=None):
        self.result = result if result is not None else {"tool": "ghidra_probe", "cached": True,
                                                          "function_count": 3}
        self.calls = []

    def run_json_probe(self, probe, artifact, *, extra_args=None, extra_env=None,
                       project_mount=None, **kw):
        self.calls.append({"probe": probe, "artifact": artifact,
                           "extra_args": list(extra_args or []),
                           "extra_env": dict(extra_env or {}),
                           "project_mount": project_mount})
        return dict(self.result)


def _ctx(s):
    p = create_project(s, name="rescript")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    return ToolContext(session=s, project=p, target=t), p, t


def _make_warm(project, target):
    """Fabricate a committed warm Ghidra slot for the target so `slot.exists()` is True — mirrors
    test_re_analyze's _make_warm, keyed off the target's real artifact bytes."""
    gp._VERSION_CACHE.clear()
    slot = gp.resolve(project.data_dir, gp.content_hash(target.path), None)
    slot.prepare()
    (slot.project_dir / "hexgraph.gpr").write_text("project")
    slot.write_meta()
    return slot


def _wire_warm(monkeypatch, result=None):
    """Enable scripting + headless Ghidra, put Docker 'up', force the version resolve to match the
    warm slot key (None), and install the fake executor. Returns the fake."""
    fake = _FakeExec(result)
    monkeypatch.setattr(AT, "_scripting_enabled", lambda: True)
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    # The gate consults analysis_state; force 'analyzed' so run_tool doesn't short-circuit before
    # _run_script runs (the gate path is exercised separately in the warm-miss test).
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})
    # The slot key uses the ghidra version; _make_warm resolves with None, so match it here.
    monkeypatch.setattr(gp, "ghidra_version_for_image", lambda image, **kw: None)
    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", lambda *a, **k: fake)
    return fake


# ── dispatch: base64 → extra_env, --script, project_mount, one Observation, no nodes ──

def test_run_script_dispatch_passes_script_b64_and_project_mount(hg_home, monkeypatch):
    fake = _wire_warm(monkeypatch)
    script = "import json\nopen(getScriptArgs()[0],'w').write(json.dumps({'ok': 1}))\n"
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        slot = _make_warm(p, t)
        nb, eb = s.query(Node).count(), s.query(Edge).count()

        out = run_tool(ctx, "run_script", {"script": script})

        # exactly one probe call, in --script mode
        assert len(fake.calls) == 1
        call = fake.calls[0]
        assert call["probe"] == "ghidra_probe.py"
        assert call["extra_args"] == ["--script"]
        # the script rides extra_env as base64 (OFF the argv), decoding back to the exact body
        assert "HEXGRAPH_USER_SCRIPT_B64" in call["extra_env"]
        decoded = base64.b64decode(call["extra_env"]["HEXGRAPH_USER_SCRIPT_B64"]).decode("utf-8")
        assert decoded == script
        # the warm project slot is bind-mounted (project_mount == slot.root)
        assert call["project_mount"] == str(slot.root)
        # the script body is NOT on the argv (defence: never leaks via the docker command line)
        assert all("import json" not in a for a in call["extra_args"])

        # the probe's JSON output is surfaced
        assert "function_count" in out

        # QUERY: records exactly ONE `script` Observation and ZERO graph nodes/edges
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "script").all()
        assert len(obs) == 1 and obs[0].tool == "run_script" and obs[0].content_hash == "abc123"
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb


def test_run_script_records_error_observation_but_still_no_graph(hg_home, monkeypatch):
    """A probe-level error is surfaced + recorded (status error), still zero graph mutation."""
    fake = _wire_warm(monkeypatch, result={"error": "postscript exception: boom"})
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _make_warm(p, t)
        nb, eb = s.query(Node).count(), s.query(Edge).count()
        out = run_tool(ctx, "run_script", {"script": "raise Exception('boom')"})
        assert "boom" in out
        obs = s.query(Observation).filter(Observation.target_id == t.id,
                                          Observation.result_kind == "script").all()
        assert len(obs) == 1 and obs[0].status == "error"
        assert s.query(Node).count() == nb and s.query(Edge).count() == eb


# ── the feature gate: hidden in the catalog when off, refused by the dispatch when off ─

def test_catalog_hides_re_script_when_gate_off(hg_home):
    # Default OFF (features.ghidra.scripting=False) ⇒ the real predicate hides re_script.
    assert C._scripting_advertised() is False
    names = {t["name"] for t in C.catalog()}
    assert "re_script" not in names


def test_catalog_shows_re_script_when_gate_on(hg_home):
    from hexgraph import settings as st

    st.update_settings({"features.ghidra.scripting": True})
    assert C._scripting_advertised() is True
    tools = {t["name"]: t for t in C.catalog()}
    assert "re_script" in tools
    assert tools["re_script"]["group"] == "run"  # heavier gated exec-surface tool, not a plain read
    # ...and it re-hides when the gate flips back off.
    st.update_settings({"features.ghidra.scripting": False})
    assert "re_script" not in {t["name"] for t in C.catalog()}


def test_dispatch_refuses_when_gate_off(hg_home, monkeypatch):
    """Defence in depth: even if it's somehow dispatched while off, _run_script refuses and NEVER
    touches the executor."""
    monkeypatch.setattr(AT, "_scripting_enabled", lambda: False)
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    # analysis gate must not block first — force analyzed so we reach the scripting check
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})

    def _explode(*a, **k):
        raise AssertionError("must not run the probe when scripting is disabled")

    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", _explode)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "run_script", {"script": "x = 1"})
        assert "features.ghidra.scripting" in out and "disabled" in out


def test_scripting_enabled_reads_settings(hg_home):
    from hexgraph import settings as st

    assert AT._scripting_enabled() is False  # default OFF
    st.update_settings({"features.ghidra.scripting": True})
    assert AT._scripting_enabled() is True
    st.update_settings({"features.ghidra.scripting": False})
    assert AT._scripting_enabled() is False


# ── warm miss → the re_analyze lead; radare2 → rejected; oversize → rejected ──────────

def test_warm_miss_returns_re_analyze_lead(hg_home, monkeypatch):
    """No warm project ⇒ the dispatch returns the re_analyze lead (warm-only) — via the analysis
    gate, which fires BEFORE _run_script for a `none` state."""
    monkeypatch.setattr(AT, "_scripting_enabled", lambda: True)
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "none", "detail": "(none)"})

    def _explode(*a, **k):
        raise AssertionError("must not run the probe on a warm miss")

    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", _explode)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "run_script", {"script": "x = 1"})
        assert "re_analyze" in out


def test_warm_miss_via_slot_resolve_returns_lead(hg_home, monkeypatch):
    """Even if the analysis gate reports 'analyzed' but the slot can't be resolved/committed,
    _run_script itself refuses with the re_analyze lead (never runs cold)."""
    monkeypatch.setattr(AT, "_scripting_enabled", lambda: True)
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "analyzed", "detail": "(warm)"})
    monkeypatch.setattr(AT, "_resolve_warm_ghidra_slot", lambda ctx: None)  # no slot

    def _explode(*a, **k):
        raise AssertionError("must not run the probe when there's no warm slot")

    monkeypatch.setattr("hexgraph.sandbox.executor.get_executor", _explode)
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "run_script", {"script": "x = 1"})
        assert "re_analyze" in out and "warm-only" in out


def test_radare2_backend_rejected(hg_home, monkeypatch):
    monkeypatch.setattr(AT, "_scripting_enabled", lambda: True)
    monkeypatch.setattr(AT, "_ghidra_xrefs_active", lambda: False)  # not headless Ghidra
    monkeypatch.setattr("hexgraph.engine.re.analysis.analysis_state",
                        lambda project, target: {"state": "unavailable", "detail": "(r2)"})
    with session_scope() as s:
        ctx, _p, _t = _ctx(s)
        out = run_tool(ctx, "run_script", {"script": "x = 1"})
        assert "headless Ghidra" in out and "radare2" in out


def test_oversize_script_rejected_host_side(hg_home, monkeypatch):
    _wire_warm(monkeypatch)
    big = "x = 0\n" * (AT._SCRIPT_MAX_BYTES // 5)  # comfortably over the cap
    assert len(big.encode("utf-8")) > AT._SCRIPT_MAX_BYTES
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _make_warm(p, t)
        out = run_tool(ctx, "run_script", {"script": big})
        assert "over the" in out and "cap" in out


def test_missing_script_arg_rejected(hg_home, monkeypatch):
    _wire_warm(monkeypatch)
    with session_scope() as s:
        ctx, p, t = _ctx(s)
        _make_warm(p, t)
        out = run_tool(ctx, "run_script", {"script": "   "})
        assert "required" in out


# ── probe-level: _load_user_script arg-parse + size cap + cold refusal ────────────────

def test_probe_load_user_script_roundtrips(monkeypatch):
    from hexgraph.sandbox.probes import ghidra_probe as G

    body = "import json\nopen(getScriptArgs()[0],'w').write('{}')\n"
    monkeypatch.setenv(G.USER_SCRIPT_ENV, base64.b64encode(body.encode()).decode())
    got, err = G._load_user_script()
    assert err is None and got == body


def test_probe_load_user_script_missing_env(monkeypatch):
    from hexgraph.sandbox.probes import ghidra_probe as G

    monkeypatch.delenv(G.USER_SCRIPT_ENV, raising=False)
    got, err = G._load_user_script()
    assert got is None and err and "base64" in err


def test_probe_load_user_script_bad_base64(monkeypatch):
    from hexgraph.sandbox.probes import ghidra_probe as G

    monkeypatch.setenv(G.USER_SCRIPT_ENV, "!!!not base64!!!")
    got, err = G._load_user_script()
    assert got is None and err and "base64" in err


def test_probe_load_user_script_size_cap(monkeypatch):
    from hexgraph.sandbox.probes import ghidra_probe as G

    big = b"a" * (G.USER_SCRIPT_MAX_BYTES + 1)
    monkeypatch.setenv(G.USER_SCRIPT_ENV, base64.b64encode(big).decode())
    got, err = G._load_user_script()
    assert got is None and err and "cap" in err


def test_probe_load_user_script_empty_body(monkeypatch):
    from hexgraph.sandbox.probes import ghidra_probe as G

    monkeypatch.setenv(G.USER_SCRIPT_ENV, base64.b64encode(b"   \n  ").decode())
    got, err = G._load_user_script()
    assert got is None and err and "empty" in err


def test_probe_script_mode_bad_script_exits_early(monkeypatch, capsys):
    """`--script` with no/invalid body prints an {error} and returns 2 BEFORE any Ghidra work."""
    from hexgraph.sandbox.probes import ghidra_probe as G

    monkeypatch.delenv(G.USER_SCRIPT_ENV, raising=False)
    monkeypatch.setattr(G.sys, "argv", ["ghidra_probe.py", "/artifact", "--script"])
    rc = G.main()
    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert "error" in out and G.USER_SCRIPT_ENV in out["error"]


def test_probe_script_mode_cold_refuses_without_warm(tmp_path, monkeypatch, capsys):
    """A `--script` run with NO warm project (no /ghidra-project marker) must refuse with the
    re_analyze lead and NEVER start Ghidra — the native path fails fast on the warm-check before
    `L.start`/`L.open_target`, so neither is reached (nor is any subprocess spawned)."""
    from hexgraph.sandbox.probes import ghidra_probe as G
    from hexgraph.sandbox.probes import pyghidra_lib as L

    art = tmp_path / "bin"
    art.write_bytes(b"\x7fELF fake bytes")
    body = "result = {'ok': 1}"
    monkeypatch.setenv(G.USER_SCRIPT_ENV, base64.b64encode(body.encode()).decode())
    # Make Ghidra "look installed" so the install-check passes and the ONLY reason to refuse is the
    # missing warm slot — isolating the warm-check (rc=5), not the toolchain-missing rc=3.
    ghidra_dir = tmp_path / "ghidra"
    (ghidra_dir / "Ghidra").mkdir(parents=True)
    monkeypatch.setattr(G, "GHIDRA_DIR", str(ghidra_dir))
    monkeypatch.setattr(G, "_pyghidra_installed", lambda: True)
    # No PROJECT_MOUNT dir ⇒ non-persistent ⇒ warm=False ⇒ script-mode must refuse.
    monkeypatch.setattr(G, "PROJECT_MOUNT", str(tmp_path / "nope"))

    def _no_ghidra(*a, **k):
        raise AssertionError("cold --script must NOT start Ghidra / open the target")

    monkeypatch.setattr(L, "start", _no_ghidra)
    monkeypatch.setattr(L, "open_target", _no_ghidra)
    monkeypatch.setattr(G.subprocess, "run", _no_ghidra)  # nor shell out (the native path never does)
    monkeypatch.setattr(G.sys, "argv", ["ghidra_probe.py", str(art), "--script"])
    rc = G.main()
    # rc=0 with a STRUCTURED needs_analysis payload (not a non-zero exit run_probe would raise on) —
    # the host surfaces the lead gracefully. The refusal is in the payload, not the exit code.
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out.get("needs_analysis") is True
    assert "error" in out and "re_analyze" in out["error"] and "warm-only" in out["error"]


def test_probe_script_mode_warm_runs_core_read_only(tmp_path, monkeypatch, capsys):
    """A `--script` run WITH a committed warm slot opens the program READ-ONLY and runs script_core
    over it. Stubs `L.open_target` (asserting read_only=True was requested + cold_analyze=False) and
    `L.script_core` so the driver wiring is exercised without a JVM; the core's JSON is surfaced."""
    from hexgraph.sandbox.probes import ghidra_probe as G

    # Patch on G.L — the EXACT pyghidra_lib module object the probe dereferences. ghidra_probe imports
    # it dual-mode (bare `pyghidra_lib` when run as a script, else the package path), so under a full
    # suite that could be a different object than `import pyghidra_lib as L` here would resolve to.
    L = G.L

    art = tmp_path / "bin"
    art.write_bytes(b"\x7fELF fake bytes")
    # Fabricate a committed warm slot at a redirected PROJECT_MOUNT so _script_warm() is True.
    mount = tmp_path / "gp"
    (mount / "project").mkdir(parents=True)
    (mount / "project" / "hexgraph.gpr").write_text("x")
    (mount / G.META_NAME).write_text(json.dumps({"program_name": "hexgraph"}))
    monkeypatch.setattr(G, "PROJECT_MOUNT", str(mount))
    # Pretend Ghidra is installed so main() reaches the run (it never touches a real JVM — stubbed).
    monkeypatch.setattr(G, "_pyghidra_installed", lambda: True)
    _real_isdir = os.path.isdir  # capture BEFORE patching so the shim can delegate (no recursion)
    monkeypatch.setattr(G.os.path, "isdir",
                        lambda p: True if str(p).endswith("Ghidra") else _real_isdir(p))
    monkeypatch.setattr(L, "start", lambda: None)
    # _run imports ghidra.util.task for a real TaskMonitor; there's no JVM on the host and both cores
    # here are stubbed (the monitor value is irrelevant), so inject a tiny fake module tree so the
    # import resolves — this exercises the DRIVER WIRING, not Ghidra itself.
    import sys as _sys
    import types as _types

    fake_task = _types.ModuleType("ghidra.util.task")
    fake_task.ConsoleTaskMonitor = object
    monkeypatch.setitem(_sys.modules, "ghidra", _types.ModuleType("ghidra"))
    monkeypatch.setitem(_sys.modules, "ghidra.util", _types.ModuleType("ghidra.util"))
    monkeypatch.setitem(_sys.modules, "ghidra.util.task", fake_task)

    seen = {}

    class _FakeProg:
        pass

    import contextlib as _cl

    @_cl.contextmanager
    def _fake_open(artifact, *, cold_analyze=True, read_only=False):
        seen["read_only"] = read_only
        seen["cold_analyze"] = cold_analyze
        yield _FakeProg(), object(), True

    def _fake_core(program, flat, monitor, user_script, **kw):
        seen["script"] = user_script
        return {"tool": "ghidra_script", "answer": 42}

    monkeypatch.setattr(L, "open_target", _fake_open)
    monkeypatch.setattr(L, "script_core", _fake_core)
    body = "result = {'answer': 42}"
    monkeypatch.setenv(G.USER_SCRIPT_ENV, base64.b64encode(body.encode()).decode())
    monkeypatch.setattr(G.sys, "argv", ["ghidra_probe.py", str(art), "--script"])

    rc = G.main()
    assert rc == 0
    # The program was opened READ-ONLY and warm-only (never cold-analyzed) for the query.
    assert seen["read_only"] is True and seen["cold_analyze"] is False
    assert seen["script"] == body                       # the decoded body reached the core
    out = json.loads(capsys.readouterr().out)
    assert out["answer"] == 42 and out["tool"] == "ghidra_script"
    assert out["cached"] is True


# ── probe-level: script_core execs the body against the resident program ──────────────

class _FakeProgram:
    """A stand-in Program: script_core only touches whatever the user script asks for, so a script
    that reads program.getName() works with no JVM."""

    def getName(self):
        return "vuln_httpd"


def test_script_core_collects_result_variable(tmp_path):
    """A script that assigns `result` has that surfaced as the JSON payload (the resident program is
    reachable in the namespace — here it reads program.getName())."""
    from hexgraph.sandbox.probes import pyghidra_lib as L

    out = L.script_core(_FakeProgram(), object(), object(),
                        "result = {'name': program.getName(), 'n': 1 + 2}",
                        out_path=str(tmp_path / "o.json"))
    assert out["name"] == "vuln_httpd" and out["n"] == 3
    assert out["tool"] == "ghidra_script"               # defaulted when the script omits it


def test_script_core_reads_out_path_when_no_result(tmp_path):
    """A script written to the postScript contract (write JSON to getScriptArgs()[0] / out_path) is
    read back from that file when it sets no `result` — the back-compat path."""
    from hexgraph.sandbox.probes import pyghidra_lib as L

    op = str(tmp_path / "o.json")
    body = "import json\nopen(getScriptArgs()[0], 'w').write(json.dumps({'via': 'out_path'}))\n"
    out = L.script_core(_FakeProgram(), object(), object(), body, out_path=op)
    assert out["via"] == "out_path" and out["tool"] == "ghidra_script"


def test_script_core_exception_is_data_not_a_crash(tmp_path):
    """A body that raises is caught and returned as {error, tb} — one bad script never takes down
    the probe/bridge."""
    from hexgraph.sandbox.probes import pyghidra_lib as L

    out = L.script_core(_FakeProgram(), object(), object(),
                        "raise ValueError('boom')", out_path=str(tmp_path / "o.json"))
    assert "boom" in out["error"] and "tb" in out and out["tool"] == "ghidra_script"


def test_script_core_no_output_is_a_clear_error(tmp_path):
    """A body that neither assigns `result` nor writes out_path gets an actionable error, not a
    silent empty payload."""
    from hexgraph.sandbox.probes import pyghidra_lib as L

    out = L.script_core(_FakeProgram(), object(), object(),
                        "x = 1  # produces nothing", out_path=str(tmp_path / "o.json"))
    assert "no result" in out["error"] and "out_path" in out["error"]


def test_script_core_stale_out_path_is_cleared(tmp_path):
    """A stale out_path from a prior run is removed before exec so it can't be mistaken for this
    run's result (the no-output error fires, not the stale file)."""
    from hexgraph.sandbox.probes import pyghidra_lib as L

    op = tmp_path / "o.json"
    op.write_text(json.dumps({"stale": True}))
    out = L.script_core(_FakeProgram(), object(), object(),
                        "y = 2  # writes nothing this run", out_path=str(op))
    assert "no result" in out["error"] and "stale" not in out
