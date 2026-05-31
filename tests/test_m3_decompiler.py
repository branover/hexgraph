"""M3-T1: the radare2 decompiler behind the Decompiler seam (sandboxed)."""

from conftest import fixture_path


def test_r2_decompiler_focus_function(sandbox, monkeypatch):
    monkeypatch.delenv("HEXGRAPH_DISABLE_DECOMPILE", raising=False)
    from hexgraph.sandbox.decompiler import R2Decompiler

    out = R2Decompiler(sandbox).decompile(fixture_path("vuln_httpd"), "cgi_handler")
    assert any("cgi_handler" in f for f in out["functions"])
    assert out["focus"]["resolved"] == "sym.cgi_handler"
    assert out["focus"]["pseudocode"]  # non-empty pseudo-C/disasm


def test_xrefs_finds_sink_callers(sandbox):
    # The cross-reference accelerator: vuln_httpd's only strcpy is reached from
    # cgi_handler. Both the targeted query and the default sink sweep must show it.
    out = sandbox.run_json_probe("xrefs_probe.py", fixture_path("vuln_httpd"), extra_args=["strcpy"])
    callers = {c["caller"].lstrip("sym.") for c in out["callers"]}
    assert "cgi_handler" in callers

    sweep = sandbox.run_json_probe("xrefs_probe.py", fixture_path("vuln_httpd"))
    assert "strcpy" in sweep["sinks"]


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
