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
from hexgraph.sandbox.decompiler import (
    _FOCUS_PAYLOAD_FUNCTION_SAMPLE,
    GhidraDecompiler,
    R2Decompiler,
    focus_only_payload,
)


def test_focus_only_payload_guards_none_functions_total():
    """focus_only_payload derives functions_total from a PRESENT-but-None value (a stale managed bridge
    returns `functions_total: None`), not only a missing key — else the stored payload would hold null.
    It also caps the whole-program name list to a bounded sample (the full inventory is its own
    `function_list` Observation)."""
    # present-but-None ⇒ falls back to len(functions), not stored as null
    p = focus_only_payload({"functions": ["a", "b", "c"], "functions_total": None,
                            "focus": {"name": "a"}})
    assert p["functions_total"] == 3
    # a real total is preserved; the name list is a bounded sample, not the whole inventory
    big = [f"f{i}" for i in range(1000)]
    p2 = focus_only_payload({"functions": big, "functions_total": 9000, "focus": None})
    assert p2["functions_total"] == 9000
    assert len(p2["functions"]) == _FOCUS_PAYLOAD_FUNCTION_SAMPLE
    # a missing key defaults to len too
    assert focus_only_payload({"functions": ["x"], "focus": None})["functions_total"] == 1


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


def test_format_decomp_surfaces_promoted_node_id_for_mention():
    """F11: _format_decomp renders the promoted node id in the header (truncation-safe) in the
    journal @-mention syntax, so a just-decompiled function is mention-able without a lookup."""
    out = {"focus": {"name": "cgi_handler", "address": "0x401200",
                     "pseudocode": "void cgi_handler(){ body(); }", "callees": []},
           "focus_node_id": "abc-123-uuid"}
    text = _format_decomp(out, "cgi_handler")
    assert "graph node abc-123-uuid" in text
    assert "@[cgi_handler](node:abc-123-uuid)" in text          # the literal mention syntax
    assert text.index("abc-123-uuid") < text.index("body()")    # id line precedes the body
    # no node line when nothing was promoted (e.g. a not-found focus)
    nomatch = {"focus": {"name": "m", "pseudocode": "x", "callees": []}}
    assert "graph node" not in _format_decomp(nomatch, "m")


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


def test_not_found_wording_for_an_address_miss_points_at_raw_disasm():
    """An address that resolves to no function gets a DISTINCT message: it explains the address isn't
    inside a defined function and points at re_disassemble_range (raw disasm) + a reanalyze pass —
    NOT a dump of the function-name list, which can't help an address lookup."""
    out = {"functions": ["main", "helper"], "functions_total": 2, "focus": None}
    msg = _format_decomp(out, "address 0xdeadbeef")
    assert "not inside any defined function" in msg
    assert "re_disassemble_range" in msg
    assert "reanalyze=True" in msg
    assert "main" not in msg and "helper" not in msg   # no useless name-list dump for an address


def test_not_found_wording_reports_true_total_not_capped_slice():
    """The reported count is the TRUE whole-program total (functions_total), not the length of the
    returned (possibly capped) name slice — the fix for a large firmware reading as 'only 400
    functions'. A sample of the inventory is shown, marked '+N more' so it isn't read as the whole
    set."""
    out = {"functions": ["f0", "f1", "f2"], "functions_total": 3812, "focus": None}
    msg = _format_decomp(out, "function 'cgi_handler'")
    assert "3812 defined functions" in msg      # the true total, not 3 (the returned slice length)
    assert "more" in msg                          # the sample is explicitly marked partial
