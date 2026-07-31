"""Direct coverage of `recover_data_refs_core` — the pass itself, not just the staging around it.

Every durable write and the slice-boundary arithmetic live here, and both independent reviews of
PR #306 noted this function had NO host-side coverage: the staging tests all monkeypatch it away,
which is how a complete-but-unsaved slice earning the permanent marker, and an off-by-one that
dropped one instruction per slice boundary, both shipped green.

The core imports Ghidra lazily (function-local), so a fake program/listing/memory/reference-manager
exercises it with no JVM. The fakes model only what the core actually touches.
"""

from __future__ import annotations

import sys
import types

import pytest

from hexgraph.sandbox.probes import pyghidra_lib as L


class FakeAddr:
    def __init__(self, value):
        self.value = int(value)

    def toString(self):
        return "%08x" % self.value

    def __eq__(self, other):
        return isinstance(other, FakeAddr) and other.value == self.value

    def __hash__(self):
        return hash(self.value)


class FakeScalar:
    def __init__(self, value):
        self.value = int(value)

    def getUnsignedValue(self):
        return self.value


class FakeRef:
    def __init__(self, to):
        self.to = to

    def getToAddress(self):
        return self.to


class FakeInsn:
    def __init__(self, addr, operands, existing=()):
        self.addr = FakeAddr(addr)
        self.operands = operands           # list of lists of operand objects
        self.existing = [FakeRef(FakeAddr(a)) for a in existing]

    def getAddress(self):
        return self.addr

    def getNumOperands(self):
        return len(self.operands)

    def getOpObjects(self, k):
        return self.operands[k]

    def getReferencesFrom(self):
        return list(self.existing)


class FakeIter:
    """Ghidra's iterator protocol (hasNext/next), which is what the core drives — NOT a Python
    generator. Getting this wrong is the difference between testing the code and testing a mock."""

    def __init__(self, items):
        self._items = list(items)
        self._i = 0

    def hasNext(self):
        return self._i < len(self._items)

    def next(self):
        item = self._items[self._i]
        self._i += 1
        return item


class FakeBlock:
    def __init__(self, execute):
        self._execute = execute

    def isExecute(self):
        return self._execute


class FakeProgram:
    """Records addMemoryReference calls, transaction boundaries, and saves."""

    def __init__(self, insns, exec_ranges=(), save_error=None):
        self.insns = insns
        self.exec_ranges = exec_ranges
        self.added: list[tuple[str, str, int]] = []
        self.tx_open = 0
        self.tx_count = 0
        self.saves = 0
        self.save_error = save_error

    # -- the surface the core uses -------------------------------------------------
    def getListing(self):
        return self

    def getMemory(self):
        return self

    def getAddressFactory(self):
        return self

    def getReferenceManager(self):
        return self

    def getInstructions(self, a, b=None):
        start = a if isinstance(a, FakeAddr) else None
        items = [i for i in self.insns
                 if start is None or i.getAddress().value >= start.value]
        return FakeIter(items)

    def getBlock(self, addr):
        if not (0x1000 <= addr.value < 0x9000):
            return None                                    # unmapped
        return FakeBlock(any(lo <= addr.value < hi for lo, hi in self.exec_ranges))

    def getDefaultDataSpace(self):
        return self

    def getAddress(self, v):
        return FakeAddr(int(v, 16) if isinstance(v, str) else v)

    def addMemoryReference(self, frm, to, kind, src, opnd):
        self.added.append((frm.toString(), to.toString(), opnd))

    def startTransaction(self, name):
        self.tx_open += 1
        return self.tx_open

    def endTransaction(self, txid, commit):
        self.tx_count += 1

    def save(self, msg, monitor):
        if self.save_error:
            raise RuntimeError(self.save_error)
        self.saves += 1


@pytest.fixture(autouse=True)
def _fake_ghidra(monkeypatch):
    """Inject the three lazily-imported Ghidra modules the core needs."""
    scalar_mod = types.ModuleType("ghidra.program.model.scalar")
    scalar_mod.Scalar = FakeScalar
    symbol_mod = types.ModuleType("ghidra.program.model.symbol")
    symbol_mod.RefType = types.SimpleNamespace(DATA="DATA")
    symbol_mod.SourceType = types.SimpleNamespace(ANALYSIS="ANALYSIS")
    task_mod = types.ModuleType("ghidra.util.task")
    task_mod.ConsoleTaskMonitor = lambda: object()
    for name, mod in (("ghidra", types.ModuleType("ghidra")),
                      ("ghidra.program", types.ModuleType("ghidra.program")),
                      ("ghidra.program.model", types.ModuleType("ghidra.program.model")),
                      ("ghidra.program.model.scalar", scalar_mod),
                      ("ghidra.program.model.symbol", symbol_mod),
                      ("ghidra.util", types.ModuleType("ghidra.util")),
                      ("ghidra.util.task", task_mod)):
        monkeypatch.setitem(sys.modules, name, mod)


def _insns(n, base=0x2000, target=0x5000):
    """Targets are wrapped to stay inside the mapped, non-exec window (0x5000-0x8000).

    Letting them walk past 0x9000 makes getBlock return None, so instructions beyond the first
    ~16k propose NOTHING — which silently made the slice-boundary test vacuous: the instruction at
    the boundary produced no reference, so losing it was undetectable."""
    return [FakeInsn(base + i * 4, [[FakeScalar(target + (i % 0x3000))]]) for i in range(n)]


# --- what it proposes ----------------------------------------------------------------------------

def test_adds_a_reference_for_a_scalar_landing_in_mapped_non_exec_memory():
    prog = FakeProgram(_insns(3))
    out = L.recover_data_refs_core(prog, object())
    assert out["added"] == 3
    assert prog.added[0] == ("00002000", "00005000", 0)
    assert out["saved"] is True and prog.saves == 1


def test_skips_executable_targets():
    """Control flow is already indexed by the passes the fast profile keeps, and is not what a
    string/global xref query asks for."""
    prog = FakeProgram(_insns(3), exec_ranges=[(0x5000, 0x6000)])
    assert L.recover_data_refs_core(prog, object())["added"] == 0


def test_skips_unmapped_scalars():
    prog = FakeProgram([FakeInsn(0x2000, [[FakeScalar(0xDEAD)]])])
    assert L.recover_data_refs_core(prog, object())["added"] == 0


def test_is_idempotent_when_the_reference_already_exists():
    prog = FakeProgram([FakeInsn(0x2000, [[FakeScalar(0x5000)]], existing=[0x5000])])
    assert L.recover_data_refs_core(prog, object())["added"] == 0


def test_non_scalar_operands_are_ignored():
    prog = FakeProgram([FakeInsn(0x2000, [[object(), "RDI"]])])
    assert L.recover_data_refs_core(prog, object())["added"] == 0


# --- durability ----------------------------------------------------------------------------------

def test_a_failed_save_is_reported_not_raised():
    """The stage runs after the analysis is already committed; it must degrade, never throw."""
    prog = FakeProgram(_insns(2), save_error="disk full")
    out = L.recover_data_refs_core(prog, object())
    assert out["saved"] is False and "disk full" in out["save_error"]


def test_nothing_is_saved_when_nothing_was_added():
    prog = FakeProgram(_insns(1), exec_ranges=[(0x5000, 0x6000)])
    out = L.recover_data_refs_core(prog, object())
    assert prog.saves == 0 and out["saved"] is False


def test_references_commit_in_chunks(monkeypatch):
    """Bounds Ghidra's undo buffer: ~10M refs in one open transaction grows it until the commit
    itself is what dies."""
    monkeypatch.setattr(L, "_DATA_REF_TX_CHUNK", 2)
    prog = FakeProgram(_insns(5))
    L.recover_data_refs_core(prog, object())
    assert prog.tx_count >= 3, prog.tx_count


# --- slice boundaries: the property that must hold ------------------------------------------------

def test_a_truncated_slice_plus_its_resume_covers_every_instruction(monkeypatch):
    """THE slice-boundary property. `through` must name the last instruction actually SCANNED, so
    resuming after it drops nothing: two budgeted slices must produce exactly what one unbudgeted
    pass does. An off-by-one here silently loses one instruction's references per boundary."""
    whole = FakeProgram(_insns(70000))
    L.recover_data_refs_core(whole, object())
    expected = set(whole.added)

    first = FakeProgram(_insns(70000))
    a = L.recover_data_refs_core(first, object(), budget_s=-1)   # truncate at the first clock check
    assert a["truncated"] is True and a["through"]

    second = FakeProgram(_insns(70000))
    b = L.recover_data_refs_core(second, object(), start_after=a["through"])
    assert b["truncated"] is False

    assert set(first.added) | set(second.added) == expected
    assert not (set(first.added) & set(second.added)), "an instruction was scanned twice"


def test_resume_starts_after_the_recorded_address():
    prog = FakeProgram(_insns(4))
    L.recover_data_refs_core(prog, object(), start_after="00002004")
    assert [a[0] for a in prog.added] == ["00002008", "0000200c"]
