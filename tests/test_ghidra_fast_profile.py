"""Ghidra's analysis of a 100 MB+ monolith is bounded by a fast profile that disables the passes
proven pathological on a huge binary (Call-Fixup Installer's O(n^2) AddressSet, the per-processor
Constant Reference Analyzer, the decompile-every-function passes, and the Non-Returning Functions
analyzers whose ClearFlowAndRepair wedges on a monolith) while KEEPING the call-graph/
reference analyzers. Since the PyGhidra re-platform these are pure host-side helpers in `pyghidra_lib`
(`_slow_analyzer` + `_FAST_PROFILE_BYTES`), applied in-process by `_analyze` before AutoAnalysisManager
runs. The analysis otherwise runs to completion — `re_analyze` runs it detached with a generous budget
(the Jython `-analysisTimeoutPerFile` graceful-partial-save is not replicated: cancelling analysis
mid-pass corrupts the DB transaction, and the fast profile + detached budget bound the monolith case).
The end-to-end behavior is validated against a real monolith separately; the module is stdlib-only at
import (Ghidra is lazy)."""

from __future__ import annotations

from hexgraph.sandbox.probes import pyghidra_lib as L


def test_fast_profile_threshold_default_is_100mib():
    assert L._FAST_PROFILE_BYTES == 100 * 1024 * 1024


def test_fast_profile_disables_the_proven_slow_passes():
    for slow in ("Call-Fixup Installer", "Decompiler Parameter ID", "Decompiler Switch Analysis",
                 "Aggressive Instruction Finder"):
        assert L._slow_analyzer(slow), slow
    # processor-agnostic match for the constant-propagation passes ("PowerPC/ARM/x86 … "):
    assert L._slow_analyzer("PowerPC Constant Reference Analyzer")
    assert L._slow_analyzer("ARM Scalar Operand References")
    # Non-Returning Functions analyzers: ClearFlowAndRepair wedges on a monolith (both variants).
    assert L._slow_analyzer("Non-Returning Functions - Discovered")
    assert L._slow_analyzer("Non-Returning Functions - Known")
    # ...but a dotted SUB-option of it is still never disabled (the "." rule wins):
    assert not L._slow_analyzer("Non-Returning Functions - Discovered.Create Analysis Bookmarks")


def test_fast_profile_keeps_the_call_graph_analyzers():
    # The recon value (function list + CALL GRAPH + xrefs) depends on these — they must stay ENABLED
    # (not matched by _slow_analyzer). A dotted sub-option name is never disabled either.
    for keep in ("Subroutine References", "Function ID", "Demangler GNU",
                 "Disassemble Entry Points", "Some Analyzer.some sub-option"):
        assert not L._slow_analyzer(keep), keep
