"""F13: Ghidra's analysis of a 100 MB+ monolith is bounded two ways — (1) a fast-profile preScript
disables the passes proven pathological on a huge binary (Call-Fixup Installer's O(n^2) AddressSet,
the per-processor Constant Reference Analyzer, the decompile-every-function passes) while KEEPING
the call-graph/reference analyzers; (2) auto-analysis is told to stop+save just under the host's
wall-clock budget. These check the pure host-side logic; the end-to-end behavior is validated
against a real monolith separately. The probe is stdlib-only at import (Ghidra API is lazy)."""

from __future__ import annotations

from hexgraph.sandbox.probes import ghidra_probe as G


def test_analysis_timeout_sits_just_under_the_host_budget(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "1000")        # large: budget = 1000 - overhead
    assert G._analysis_timeout_args() == ["-analysisTimeoutPerFile", str(1000 - G.GHIDRA_SAVE_OVERHEAD_S)]


def test_small_nontrivial_budget_still_gets_a_graceful_stop(monkeypatch):
    # A lowered resources.sandbox.timeout (e.g. 200s) must NOT silently drop the graceful save:
    # the budget floors at ~half the wall-clock (here 100s) rather than vanishing.
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "200")
    assert G._analysis_timeout_args() == ["-analysisTimeoutPerFile", "100"]


def test_no_analysis_timeout_when_budget_absent_or_bad(monkeypatch):
    monkeypatch.delenv("HEXGRAPH_PROBE_TIMEOUT_S", raising=False)
    assert G._analysis_timeout_args() == []                       # no budget advertised -> let it run
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "90")          # < 120 -> too small to split usefully
    assert G._analysis_timeout_args() == []
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "not-a-number")
    assert G._analysis_timeout_args() == []


def test_fast_profile_threshold_default_is_100mib():
    assert G.GHIDRA_FAST_PROFILE_BYTES == 100 * 1024 * 1024


def test_fast_profile_disables_the_proven_slow_passes():
    s = G.FAST_PROFILE_SCRIPT
    for slow in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                 "Aggressive Instruction Finder"):
        assert slow in s
    # processor-agnostic match for the constant-propagation pass ("PowerPC/ARM/x86 … "):
    assert "Constant Reference Analyzer" in s and "Scalar Operand References" in s
    assert "setBoolean" in s and "False" in s


def test_fast_profile_keeps_the_call_graph_analyzers():
    # The recon value (function list + CALL GRAPH + xrefs) depends on these — they must NOT be named
    # in the disable script. (Checked names are not substrings of any disabled analyzer name.)
    s = G.FAST_PROFILE_SCRIPT
    for keep in ("Subroutine References", "Function ID", "Demangler GNU", "Disassemble Entry Points"):
        assert keep not in s
