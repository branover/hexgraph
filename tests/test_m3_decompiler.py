"""M3-T1: the radare2 decompiler behind the Decompiler seam (sandboxed)."""

from conftest import fixture_path


def test_r2_decompiler_focus_function(sandbox, monkeypatch):
    monkeypatch.delenv("HEXGRAPH_DISABLE_DECOMPILE", raising=False)
    from hexgraph.sandbox.decompiler import R2Decompiler

    out = R2Decompiler(sandbox).decompile(fixture_path("vuln_httpd"), "cgi_handler")
    assert any("cgi_handler" in f for f in out["functions"])
    assert out["focus"]["resolved"] == "sym.cgi_handler"
    assert out["focus"]["pseudocode"]  # non-empty pseudo-C/disasm


def test_get_decompiler_default_is_r2():
    from hexgraph.sandbox.decompiler import R2Decompiler, get_decompiler

    assert isinstance(get_decompiler(), R2Decompiler)


def test_ghidra_decompiler_is_opt_in():
    import pytest

    from hexgraph.sandbox.decompiler import get_decompiler

    with pytest.raises(NotImplementedError):
        get_decompiler("ghidra")
