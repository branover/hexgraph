"""The fast profile buys a bounded analysis of a monolith by disabling the per-processor constant/
scalar reference analyzers — and that specifically empties the code->DATA half of the xref index
(control flow, hence the call graph, is untouched). `recover_data_refs_core` rebuilds the
statically-resolvable majority of it in one linear pass, exploiting the fact that SLEIGH already
resolved a RIP-relative operand at DISASSEMBLY time (`LEA RDI,[0x102004]` -> pcode
`COPY (const,0x102004,8)`), so no constant propagation is needed to know the target.

Measured IN-REGIME against full-analysis ground truth on a 130 MB x86-64 library (this stage only
runs above the 100 MB threshold, so a small-binary number does not characterise it): 135,273
references recovered at precision 0.9945 (742 that full analysis does not produce), closing 21% of
the gap the fast profile opens. The remainder needs real propagation (MIPS lui/addiu, AArch64
adrp/add pairs). An earlier 6.1 MB sample read 1.000 / 63% — both optimistic, which is why the
in-regime figure is the one quoted.

These are host-side tests of the wiring and the staging/marker contract — the Ghidra-dependent pass
itself is exercised against a real binary in the sandbox (a JVM is not available in the offline
tier). `pyghidra_lib` and `ghidra_probe` are stdlib-only at import; Ghidra imports are lazy.
"""

from __future__ import annotations

import json
import sys

from hexgraph.sandbox.probes import ghidra_probe as G
from hexgraph.sandbox.probes import pyghidra_lib as L


# --- which targets get the recovery stage --------------------------------------------------------

def test_fast_profile_applies_tracks_the_analysis_threshold(tmp_path):
    """Recovery is gated on the SAME predicate that disabled the analyzers — anything else would
    either scan a target whose refs are already complete or skip one that is missing them."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 1024)
    big = tmp_path / "big.bin"
    big.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))

    assert L.fast_profile_applies(str(big)) is True
    assert L.fast_profile_applies(str(small)) is False


def test_tx_chunk_is_floored_at_one():
    """The chunk size is used as a MODULUS inside the scan loop, so a 0 from the environment would
    be a ZeroDivisionError tens of minutes into a pass."""
    assert L._DATA_REF_TX_CHUNK >= 1
    import importlib
    import os as _os
    prev = _os.environ.get("HEXGRAPH_DATA_REF_TX_CHUNK")
    _os.environ["HEXGRAPH_DATA_REF_TX_CHUNK"] = "0"
    try:
        assert importlib.reload(L)._DATA_REF_TX_CHUNK == 1
    finally:
        if prev is None:
            _os.environ.pop("HEXGRAPH_DATA_REF_TX_CHUNK", None)
        else:
            _os.environ["HEXGRAPH_DATA_REF_TX_CHUNK"] = prev
        importlib.reload(L)


def test_fast_profile_applies_is_false_for_a_missing_artifact():
    # Must never raise: it is called on every probe mode to report the capability state.
    assert L.fast_profile_applies("/nonexistent/artifact") is False
    assert L.fast_profile_applies(None) is False


# --- the marker contract -------------------------------------------------------------------------

def test_update_marker_merges_and_preserves_host_written_keys(tmp_path, monkeypatch):
    """The marker is co-owned: the HOST writes content_hash/ghidra_version into it, and clobbering
    content_hash would make the host treat a warm slot as a different binary and re-analyze it."""
    monkeypatch.setattr(L, "PROJECT_MOUNT", str(tmp_path))
    marker = tmp_path / L.META_NAME
    marker.write_text(json.dumps({"content_hash": "abc123", "ghidra_version": "12.1",
                                  "program_name": "artifact"}))

    L.update_marker(data_refs_recovered=True)

    data = json.loads(marker.read_text())
    assert data["data_refs_recovered"] is True
    assert data["content_hash"] == "abc123"
    assert data["ghidra_version"] == "12.1"
    assert data["program_name"] == "artifact"


def test_read_marker_tolerates_absent_and_corrupt(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "PROJECT_MOUNT", str(tmp_path))
    assert L.read_marker() == {}
    (tmp_path / L.META_NAME).write_text("{not json")
    assert L.read_marker() == {}


# --- staging: recovery must never cost the analysis that preceded it -----------------------------

def test_recovery_is_skipped_once_a_complete_pass_is_recorded(monkeypatch):
    """Re-running re_analyze on a warm target must not re-pay the scan (~48 min on a 160M-instruction
    image). The pass is idempotent, but idempotent is not free."""
    monkeypatch.setattr(G.L, "read_marker", lambda: {"data_refs_recovered": True})

    def _boom(*a, **k):
        raise AssertionError("must not reopen the project once recovery is recorded")

    monkeypatch.setattr(G.L, "open_target", _boom)
    out = G._recover_data_refs("/artifact")
    assert out == {"skipped": "already recovered", "added": 0}


def test_a_truncated_slice_records_a_resume_point_and_is_not_marked_complete(monkeypatch):
    """A budget-truncated slice left the index INCOMPLETE — it must record where it got to and NOT
    claim completion, so the next run resumes rather than skipping forever."""
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": True,
                                         "through": "0x41000"})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())
    monkeypatch.setattr(G.L, "_DATA_REF_TOTAL_S", 0)     # one slice, then stop

    out = G._recover_data_refs("/artifact")
    assert out["complete"] is False
    assert not recorded.get("data_refs_recovered"), "a truncated slice must not be marked complete"
    assert recorded["data_refs_recovered_through"] == "0x41000"


def test_a_later_slice_resumes_from_the_recorded_point(monkeypatch):
    """Without this the scan restarts at instruction 0 every time and, on an image whose full pass
    is close to the slice budget, re-truncates at the same address forever."""
    seen = []

    def _core(program, monitor, *, start_after=None, **k):
        seen.append(start_after)
        return {"scanned": 5, "added": 1, "truncated": False}

    monkeypatch.setattr(G.L, "read_marker", lambda: {"data_refs_recovered_through": "0x41000"})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: None)
    monkeypatch.setattr(G.L, "recover_data_refs_core", _core)
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    G._recover_data_refs("/artifact")
    assert seen == ["0x41000"]


def test_a_truncated_slice_whose_save_failed_does_not_advance(monkeypatch):
    """`through` is None when the slice's writes never persisted. Advancing past that range would
    skip it permanently, leaving a silent hole in the index."""
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": True,
                                         "through": None})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    G._recover_data_refs("/artifact")
    assert "data_refs_recovered_through" not in recorded
    assert not recorded.get("data_refs_recovered")


def test_a_complete_pass_earns_the_marker(monkeypatch):
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": False})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    out = G._recover_data_refs("/artifact")
    assert out["added"] == 3
    assert out["complete"] is True
    assert recorded["data_refs_recovered"] is True
    # resume state is cleared so a later cold re-analysis starts from a clean slate
    assert recorded["data_refs_recovered_through"] is None
    assert recorded["data_ref_recovery_running"] is None


def test_recovery_failure_never_propagates(monkeypatch):
    """The analysis is already saved and committed by the time recovery runs; a recovery failure
    must degrade to a reported error, never fail the analyze that produced the warm slot."""
    monkeypatch.setattr(G.L, "read_marker", lambda: {})

    def _raise(*a, **k):
        raise RuntimeError("no warm analysis for this target")

    monkeypatch.setattr(G.L, "open_target", _raise)
    out = G._recover_data_refs("/artifact")
    assert out["added"] == 0
    assert "no warm analysis" in out["error"]


def _fake_open_target():
    import contextlib

    @contextlib.contextmanager
    def _ctx(*a, **k):
        yield object(), object(), True

    return _ctx


# --- the recovery-only probe mode ----------------------------------------------------------------

def test_recover_data_refs_is_its_own_mode():
    assert G._parse(["p", "/artifact", "--recover-data-refs"])["mode"] == "recover_data_refs"


def test_recover_data_refs_wins_over_analyze():
    """The two are passed together by nothing today, but the recovery-only run must never be
    reinterpreted as a cold whole-binary analysis of an already-warm slot."""
    assert G._parse(["p", "/artifact", "--analyze",
                     "--recover-data-refs"])["mode"] == "recover_data_refs"


def test_recovery_mode_is_refused_on_a_cold_miss(tmp_path, monkeypatch, capsys):
    """It reopens an EXISTING slot, so on a cold miss it must hit `main`'s warm-only guard
    (`mode != "analyze" and not _warm_slot_present()`) and return the re_analyze lead. A mode that
    slipped past that guard would turn a recovery request into a cold whole-binary analysis."""
    (tmp_path / "Ghidra").mkdir()
    monkeypatch.setattr(G, "GHIDRA_DIR", str(tmp_path))
    monkeypatch.setattr(G, "_pyghidra_installed", lambda: True)
    monkeypatch.setattr(G, "_warm_slot_present", lambda: False)
    monkeypatch.setattr(sys, "argv", ["ghidra_probe.py", "/artifact", "--recover-data-refs"])

    # rc=0 with a structured lead is the contract (a non-zero exit is what run_probe raises on).
    assert G.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["needs_analysis"] is True
    assert "re_analyze" in payload["error"]


# --- reaching targets that were ALREADY analyzed --------------------------------------------------
# start_analysis short-circuits on a warm slot, so without this check every target analyzed before
# the recovery stage existed would stay permanently missing its code->data references.

def _slot_ctx_stub(tmp_path, artifact, monkeypatch):
    from hexgraph.engine.re import analysis as A

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME

    monkeypatch.setattr(A, "_slot_ctx", lambda *a, **k: (_Slot(), str(artifact), "c", "p"))
    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    return A


def _big(tmp_path):
    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    return art


def test_warm_slot_without_the_flag_needs_recovery(tmp_path, monkeypatch):
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "abc"}))
    assert A._needs_data_ref_recovery(object(), object()) is True


def test_warm_slot_with_the_flag_does_not(tmp_path, monkeypatch):
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "abc",
                                                    "data_refs_recovered": True}))
    assert A._needs_data_ref_recovery(object(), object()) is False


def test_a_small_target_never_needs_recovery(tmp_path, monkeypatch):
    """Below the threshold the analyzers ran, so the index is already complete — launching a scan
    would be pure cost."""
    small = tmp_path / "small.bin"
    small.write_bytes(b"\x00" * 4096)
    A = _slot_ctx_stub(tmp_path, small, monkeypatch)
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "abc"}))
    assert A._needs_data_ref_recovery(object(), object()) is False


def test_an_unreadable_marker_does_not_trigger_a_speculative_scan(tmp_path, monkeypatch):
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    # no marker at all, then a corrupt one — neither may launch a ~48 min pass on a guess
    assert A._needs_data_ref_recovery(object(), object()) is False
    (tmp_path / L.META_NAME).write_text("{not json")
    assert A._needs_data_ref_recovery(object(), object()) is False


def test_host_write_meta_preserves_probe_recorded_stage_state(tmp_path):
    """The marker is co-owned: the host writes content_hash/ghidra_version, the probe records
    per-stage state. A host-side commit must not un-record a completed recovery pass, or the next
    re_analyze re-runs a scan measured in tens of minutes."""
    from hexgraph.engine.re.ghidra_project import GhidraProject

    root = tmp_path / "slot"
    slot = GhidraProject(root=root, project_dir=root / "project", meta_path=root / "meta.json",
                         content_sha="a" * 64, ghidra_version="12.1")
    slot.prepare()
    slot.meta_path.write_text(json.dumps({"data_refs_recovered": True, "other": "keep-me"}))

    slot.write_meta()

    data = json.loads(slot.meta_path.read_text())
    assert data["data_refs_recovered"] is True, "a completed recovery stage was un-recorded"
    assert data["other"] == "keep-me"
    assert data["content_hash"] == "a" * 64
    assert data["ghidra_version"] == "12.1"


def test_recovery_is_ghidra_only(tmp_path, monkeypatch):
    """The fast profile is a Ghidra analyzer configuration and `--recover-data-refs` is a Ghidra-probe
    flag; radare2 builds its own xrefs in `aaa` and its probe would reject the flag outright."""
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "abc"}))

    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    assert A._needs_data_ref_recovery(object(), object()) is True

    monkeypatch.setattr(A, "_active_backend", lambda: "radare2")
    assert A._needs_data_ref_recovery(object(), object()) is False


# --- contention: recovery holds the project's single writer slot ---------------------------------
# Ghidra permits one writer per project. While a slice runs, a per-call tool opening the same project
# fails on a lock. These pin the signalling that turns that into an actionable lead.

def test_recovery_in_progress_is_reported_but_still_analyzed(tmp_path, monkeypatch):
    import time as _t
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

        def exists(self):
            return True

    monkeypatch.setattr(A, "_slot_ctx", lambda *a, **k: (_Slot(), str(_big(tmp_path)), "c", "p"))
    monkeypatch.setattr(A, "docker_available", lambda: True, raising=False)
    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    (tmp_path / L.META_NAME).write_text(json.dumps({"data_ref_recovery_running": _t.time()}))

    st = A.analysis_state(object(), object(), runner=_FakeEx())
    assert st["state"] == "analyzed", "the warm analysis is intact; this is not a re-analysis"
    assert st["recovery_running"] is True

    lead = A.analysis_lead(object(), object(), runner=_FakeEx())
    assert lead is not None and "retry" in lead.lower()


def test_a_stale_recovery_heartbeat_does_not_lock_the_target_out(tmp_path, monkeypatch):
    """If the recovery container dies without clearing the flag, the target must not read as
    permanently held."""
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)

    class _Slot:
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

    stale = __import__("time").time() - (L._DATA_REF_SLICE_S * 10)
    (tmp_path / L.META_NAME).write_text(json.dumps({"data_ref_recovery_running": stale}))
    assert A._recovery_running(_Slot()) is False


def test_recovery_is_not_launched_into_a_live_bridge(tmp_path, monkeypatch):
    """A bridge owns the project for its whole session — a slice would only fail on the lock, over
    and over, while an operator is actively working that target."""
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "abc"}))

    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: False)
    assert A._needs_data_ref_recovery(object(), object()) is True

    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: True)
    assert A._needs_data_ref_recovery(object(), object()) is False


def test_an_in_flight_slice_is_not_relaunched(tmp_path, monkeypatch):
    import time as _t
    A = _slot_ctx_stub(tmp_path, _big(tmp_path), monkeypatch)
    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: False)
    (tmp_path / L.META_NAME).write_text(json.dumps({"data_ref_recovery_running": _t.time()}))
    assert A._needs_data_ref_recovery(object(), object()) is False


# --- resumability: a truncated slice must converge, not restart -----------------------------------

def test_env_overrides_survive_garbage(monkeypatch):
    """These parse at module import and this module backs the whole Ghidra surface — one typo'd
    value must not take decompile/xrefs/taint down with it."""
    assert L._env_num("HEXGRAPH_NOPE_MISSING", "900", float, 1.0) == 900.0
    monkeypatch.setenv("HEXGRAPH_NOPE_GARBAGE", "not-a-number")
    assert L._env_num("HEXGRAPH_NOPE_GARBAGE", "900", float, 1.0) == 900.0
    monkeypatch.setenv("HEXGRAPH_NOPE_TINY", "0")
    assert L._env_num("HEXGRAPH_NOPE_TINY", "900", float, 1.0) == 1.0


def test_commit_marker_preserves_recovery_state(tmp_path, monkeypatch):
    """_commit_marker is the LIVE marker writer; replacing wholesale would discard a completed or
    partially-completed pass and make the next run redo tens of minutes of work."""
    monkeypatch.setattr(L, "PROJECT_MOUNT", str(tmp_path))
    (tmp_path / L.META_NAME).write_text(json.dumps({"data_refs_recovered": True,
                                                     "data_refs_recovered_through": "0x4000"}))
    L._commit_marker()
    data = json.loads((tmp_path / L.META_NAME).read_text())
    assert data["data_refs_recovered"] is True
    assert data["data_refs_recovered_through"] == "0x4000"
    assert data["program_name"] == L.PROJECT_NAME


class _FakeEx:
    def poll_detached(self, name):
        return {}

    def stop_detached(self, name, remove=False):
        return None


def test_bridge_check_polls_the_bridge_container_not_the_analyze_one(tmp_path, monkeypatch):
    """`_bridge_live` must ask about `hexgraph-ghidra-bridge-<sha>`. Polling the analyze container
    instead would read a running RECOVERY as "a bridge owns this", and recovery would refuse to
    continue its own work."""
    from hexgraph.engine.re import analysis as A

    polled = []

    class _Ex:
        def poll_detached(self, name):
            polled.append(name)
            return {"running": name.startswith("hexgraph-ghidra-bridge-")}

    class _Slot:
        content_sha = "b" * 64

    assert A._bridge_live(_Slot(), runner=_Ex()) is True
    assert polled and all(n.startswith("hexgraph-ghidra-bridge-") for n in polled), polled

    class _Ex2:
        def poll_detached(self, name):
            return {"running": False}

    assert A._bridge_live(_Slot(), runner=_Ex2()) is False


def test_bridge_check_failure_does_not_block_recovery(monkeypatch):
    """If liveness can't be determined, recovery proceeds — a guess must not permanently stall the
    stage (the slice would just fail on the lock and retry, which is recoverable; never running is
    not)."""
    from hexgraph.engine.re import analysis as A

    class _Ex:
        def poll_detached(self, name):
            raise RuntimeError("docker down")

    class _Slot:
        content_sha = "c" * 64

    assert A._bridge_live(_Slot(), runner=_Ex()) is False
