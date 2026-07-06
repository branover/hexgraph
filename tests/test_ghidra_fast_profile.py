"""Ghidra's analysis of a 100 MB+ monolith is bounded two ways — (1) a fast profile disables the
passes proven pathological on a huge binary (Call-Fixup Installer's O(n^2) AddressSet, the
per-processor Constant Reference Analyzer, the decompile-every-function passes) while KEEPING the
call-graph/reference analyzers; (2) auto-analysis is told to stop+save just under the host's
wall-clock budget. Since the PyGhidra re-platform these are pure host-side helpers in `pyghidra_lib`
(`_analysis_budget` + `_slow_analyzer` + `_FAST_PROFILE_BYTES`), driven in-process by `_analyze`
instead of the old Jython preScript / `-analysisTimeoutPerFile` args. The end-to-end behavior is
validated against a real monolith separately. The module is stdlib-only at import (Ghidra is lazy)."""

from __future__ import annotations

from hexgraph.sandbox.probes import pyghidra_lib as L


def test_analysis_budget_sits_just_under_the_host_budget(monkeypatch):
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "1000")        # large: budget = 1000 - overhead
    assert L._analysis_budget() == 1000 - L._SAVE_OVERHEAD_S


def test_small_nontrivial_budget_still_gets_a_graceful_stop(monkeypatch):
    # A lowered resources.sandbox.timeout (e.g. 200s) must NOT silently drop the graceful save:
    # the budget floors at ~half the wall-clock (here 100s) rather than vanishing.
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "200")
    assert L._analysis_budget() == 100


def test_no_analysis_budget_when_absent_or_bad(monkeypatch):
    monkeypatch.delenv("HEXGRAPH_PROBE_TIMEOUT_S", raising=False)
    assert L._analysis_budget() is None                          # no budget advertised -> let it run
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "90")         # < 120 -> too small to split usefully
    assert L._analysis_budget() is None
    monkeypatch.setenv("HEXGRAPH_PROBE_TIMEOUT_S", "not-a-number")
    assert L._analysis_budget() is None


def test_fast_profile_threshold_default_is_100mib():
    assert L._FAST_PROFILE_BYTES == 100 * 1024 * 1024


def test_fast_profile_disables_the_proven_slow_passes():
    for slow in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                 "Aggressive Instruction Finder"):
        assert L._slow_analyzer(slow), slow
    # processor-agnostic match for the constant-propagation passes ("PowerPC/ARM/x86 … "):
    assert L._slow_analyzer("PowerPC Constant Reference Analyzer")
    assert L._slow_analyzer("ARM Scalar Operand References")


def test_fast_profile_keeps_the_call_graph_analyzers():
    # The recon value (function list + CALL GRAPH + xrefs) depends on these — they must stay ENABLED
    # (not matched by _slow_analyzer). A dotted sub-option name is never disabled either.
    for keep in ("Subroutine References", "Function ID", "Demangler GNU",
                 "Disassemble Entry Points", "Some Analyzer.some sub-option"):
        assert not L._slow_analyzer(keep), keep
