"""Decompiler & xref fallbacks for stripped firmware (fix/re-decompiler-fallbacks).

Ghidra and the r2 probes do NOT share a function inventory, so a focus r2/recon surfaced
can be absent from Ghidra's DEFINED set — Ghidra then returns focus=null and the focus is
silently rejected. These cover:

1. GhidraDecompiler.decompile falls back ONCE to radare2 for an EXPLICIT focus Ghidra missed
   (and NOT for a plain list_functions, an error, or a focus Ghidra found), and the not-found
   wording calls the list "defined functions" + points at re_decompile_at(<addr>).

(function_xrefs's recon fallback and the focus-only decompilation payload live in
tests/test_breadth_xrefs.py alongside the other Observation-substrate fallbacks.)
"""

from __future__ import annotations

from hexgraph.agent.agent_tools import _format_decomp
from hexgraph.sandbox.decompiler import GhidraDecompiler, R2Decompiler


# --- (1) the seam fallback: Ghidra missed the focus → radare2 resolves it ----------


def _focus(name="cgi_handler", addr="0x401200"):
    return {"name": name, "address": addr, "pseudocode": "int cgi_handler(){...}", "disasm": ""}


def test_ghidra_falls_back_to_r2_for_explicit_focus_it_missed(monkeypatch):
    """Ghidra returns focus=null for a function it didn't define; radare2 (always present)
    resolves it. The fallback fires ONCE and adopts r2's focus while keeping Ghidra's richer
    whole-program inventory (functions/calls/structs)."""
    g = GhidraDecompiler.__new__(GhidraDecompiler)
    g.runner = object()  # the fallback constructs its own R2Decompiler; never touched
    ghidra_out = {"functions": ["main", "helper"], "focus": None,
                  "calls": [["main", "helper"]], "structs": [{"name": "cfg_t"}]}
    monkeypatch.setattr(GhidraDecompiler, "_decompile_ghidra",
                        lambda self, *a, **k: dict(ghidra_out))
    r2_calls = []

    def fake_r2_decompile(self, artifact, function=None, **kw):
        r2_calls.append(function)
        return {"functions": ["sym.cgi_handler"], "focus": _focus()}

    monkeypatch.setattr(R2Decompiler, "decompile", fake_r2_decompile)

    out = g.decompile("/artifact", "cgi_handler", project=None)
    assert out["focus"] == _focus()            # r2's focus adopted
    assert out["functions"] == ["main", "helper"]  # Ghidra's inventory kept
    assert out["calls"] and out["structs"]     # whole-program facts kept on the dict
    assert r2_calls == ["cgi_handler"]         # the r2 fallback fired ONCE for this focus
    # F16: the focus is TAGGED as a radare2 fallback so the caller knows Ghidra didn't define
    # it and the pseudocode isn't Ghidra-quality (r2dec can mis-resolve PLT/args / fabricate a call).
    assert out["focus_engine"] == "radare2"
    assert out["focus_fallback"] is True


def test_format_decomp_warns_on_fallback_engine():
    """F16: _format_decomp surfaces the fallback-engine warning BEFORE the body, so an agent
    can't silently read r2dec pseudocode as Ghidra-quality (the dogfood chased a fabricated call)."""
    fallback = {"focus": {"name": "cgi_handler", "address": "0x401200",
                          "pseudocode": "void cgi_handler(){ system(x); }", "callees": []},
                "focus_engine": "radare2", "focus_fallback": True}
    text = _format_decomp(fallback, "cgi_handler")
    assert "FALLBACK DECOMPILER" in text and "radare2" in text
    assert text.index("FALLBACK") < text.index("system(x)")  # warning precedes the body
    # a normal Ghidra focus carries NO warning
    normal = {"focus": {"name": "main", "pseudocode": "int main(){}", "callees": []}}
    assert "FALLBACK" not in _format_decomp(normal, "main")


def test_ghidra_fallback_does_not_fire_when_ghidra_resolved_the_focus(monkeypatch):
    g = GhidraDecompiler.__new__(GhidraDecompiler)
    g.runner = object()
    monkeypatch.setattr(GhidraDecompiler, "_decompile_ghidra",
                        lambda self, *a, **k: {"functions": ["cgi_handler"], "focus": _focus()})

    def boom(self, *a, **k):  # the fallback must NOT be reached
        raise AssertionError("r2 fallback fired despite Ghidra resolving the focus")

    monkeypatch.setattr(R2Decompiler, "decompile", boom)
    out = g.decompile("/artifact", "cgi_handler", project=None)
    assert out["focus"]["name"] == "cgi_handler"


def test_ghidra_fallback_does_not_fire_for_plain_list_functions(monkeypatch):
    """No explicit focus (a bare list_functions / inventory call) → never falls back."""
    g = GhidraDecompiler.__new__(GhidraDecompiler)
    g.runner = object()
    monkeypatch.setattr(GhidraDecompiler, "_decompile_ghidra",
                        lambda self, *a, **k: {"functions": ["main"], "focus": None})

    def boom(self, *a, **k):
        raise AssertionError("r2 fallback fired on a non-focused decompile")

    monkeypatch.setattr(R2Decompiler, "decompile", boom)
    out = g.decompile("/artifact", None, project=None)  # no function, no address
    assert out["focus"] is None


def test_ghidra_fallback_does_not_fire_on_error(monkeypatch):
    g = GhidraDecompiler.__new__(GhidraDecompiler)
    g.runner = object()
    monkeypatch.setattr(GhidraDecompiler, "_decompile_ghidra",
                        lambda self, *a, **k: {"error": "Ghidra not installed"})

    def boom(self, *a, **k):
        raise AssertionError("r2 fallback fired on an error result")

    monkeypatch.setattr(R2Decompiler, "decompile", boom)
    out = g.decompile("/artifact", "cgi_handler", project=None)
    assert out.get("error") and "focus" not in out


# --- (1) improved not-found wording -----------------------------------------------


def test_not_found_wording_says_defined_functions_and_suggests_decompile_at():
    out = {"functions": ["main", "helper"], "focus": None}
    msg = _format_decomp(out, "function 'cgi_handler'")
    assert "defined functions" in msg          # not "imports"
    assert "main" in msg and "helper" in msg
    assert "re_decompile_at(<addr>)" in msg     # the address-based recovery hint for a NAME miss


def test_not_found_wording_no_addr_hint_for_an_address_miss():
    """An address miss already used the address path — don't tell it to use re_decompile_at."""
    out = {"functions": ["main"], "focus": None}
    msg = _format_decomp(out, "address 0xdeadbeef")
    assert "defined functions" in msg
    assert "re_decompile_at" not in msg
