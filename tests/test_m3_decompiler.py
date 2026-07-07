"""M3-T1: the radare2 decompiler behind the Decompiler seam (sandboxed)."""

from conftest import fixture_path, warm_r2_slot


def test_r2_decompiler_focus_function(sandbox, monkeypatch, hg_home):
    monkeypatch.delenv("HEXGRAPH_DISABLE_DECOMPILE", raising=False)
    from hexgraph.db.session import session_scope
    from hexgraph.engine.targets.ingest import create_project, ingest_file
    from hexgraph.sandbox.decompiler import R2Decompiler

    # Decompile is warm-only now (the analysis invariant): analyze once (the re_analyze step), then
    # decompile against that warm r2 project.
    with session_scope() as s:
        p = create_project(s, name="m3")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        warm_r2_slot(t.path, p.data_dir)
        out = R2Decompiler(sandbox).decompile(t.path, "cgi_handler", project=p)
    assert any("cgi_handler" in f for f in out["functions"])
    assert out["focus"]["resolved"] == "sym.cgi_handler"
    assert out["focus"]["pseudocode"]  # non-empty pseudo-C/disasm


def test_xrefs_finds_sink_callers(sandbox, tmp_path):
    # The cross-reference accelerator: vuln_httpd's only strcpy is reached from
    # cgi_handler. Both the targeted query and the default sink sweep must show it.
    # xrefs_probe is warm-only now (the analysis invariant): analyze once (the re_analyze step) and
    # pass the warm r2 project so each query reloads it instead of running a cold `aaa`.
    from conftest import warm_r2_slot

    mount = warm_r2_slot(fixture_path("vuln_httpd"), tmp_path / "r2home")
    out = sandbox.run_json_probe("xrefs_probe.py", fixture_path("vuln_httpd"),
                                 extra_args=["strcpy"], project_mount=mount)
    callers = {c["caller"].lstrip("sym.") for c in out["callers"]}
    assert "cgi_handler" in callers

    sweep = sandbox.run_json_probe("xrefs_probe.py", fixture_path("vuln_httpd"), project_mount=mount)
    assert "strcpy" in sweep["sinks"]
    # printf is reported in the separate format-string tier (it's only a bug when
    # the format arg is attacker-controlled), not the memory/exec sink list.
    assert "printf" in sweep["format_sinks"]
    assert "printf" not in sweep["sinks"]


def test_get_decompiler_default_is_r2(hg_home):
    # hg_home isolates HEXGRAPH_HOME so this is hermetic regardless of the
    # developer's real ~/.hexgraph/settings.json (Ghidra may be enabled there).
    from hexgraph.sandbox.decompiler import R2Decompiler, get_decompiler

    assert isinstance(get_decompiler(), R2Decompiler)


def test_ghidra_decompiler_is_opt_in(hg_home):
    # Ghidra is now wired behind the Decompiler seam, but stays opt-in: radare2 is
    # the default and Ghidra is only selected when enabled in Settings (or asked
    # for explicitly). Selecting it returns the wrapper without running anything.
    from hexgraph.sandbox.decompiler import GhidraDecompiler, R2Decompiler, get_decompiler

    assert isinstance(get_decompiler(), R2Decompiler)  # default unchanged
    assert isinstance(get_decompiler("ghidra"), GhidraDecompiler)
