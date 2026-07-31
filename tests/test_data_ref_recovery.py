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
    monkeypatch.setattr(G, "_SLICE_GAP_S", 0)            # don't pay the real inter-slice pause

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
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": False,
                                         "saved": True})
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


# --- review A blockers: polling must not destroy the work it is waiting for ----------------------

def _recovery_in_flight_ctx(tmp_path, monkeypatch, *, heartbeat=None, analyze_poll=None):
    import time as _t
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    (tmp_path / L.META_NAME).write_text(json.dumps(
        {"data_ref_recovery_running": _t.time() if heartbeat is None else heartbeat}))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

        def exists(self):
            return True

        def prepare(self):
            pass

    class _Ex:
        def __init__(self):
            self.stopped, self.started = [], []

        def poll_detached(self, name):
            if name.startswith("hexgraph-ghidra-bridge-"):
                return {"exists": False, "running": False}
            return dict(analyze_poll or {"exists": True, "running": True})

        def stop_detached(self, name, remove=False):
            self.stopped.append(name)

        def start_detached(self, *a, **k):
            self.started.append(k.get("name"))

    monkeypatch.setattr(A, "_slot_ctx",
                        lambda *a, **k: (_Slot(), str(art), "hexgraph-analyze-ghidra-dead", "p"))
    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    import hexgraph.sandbox.runner as R
    monkeypatch.setattr(R, "docker_available", lambda: True)
    return A, _Ex()


def test_polling_does_not_kill_an_in_flight_recovery(tmp_path, monkeypatch):
    """`stop_detached` is `docker kill` + `docker rm -f`. A warm slot whose recovery slice is in
    flight takes the already-analyzed early return, so reaping on `exists` alone would SIGKILL the
    pass the poll is waiting on — and since nothing is durable until `program.save()`, the whole
    slice is lost while the killed probe never clears its heartbeat."""
    A, ex = _recovery_in_flight_ctx(tmp_path, monkeypatch)

    st = A.start_analysis(object(), object(), runner=ex)

    assert st["state"] == "analyzed" and st.get("recovery_running") is True
    assert ex.stopped == [], "polling killed the in-flight recovery container"


def test_a_merely_lingering_container_is_still_reaped(tmp_path, monkeypatch):
    """The housekeeping the reap exists for must survive the fix: an EXITED container is removed."""
    A, ex = _recovery_in_flight_ctx(tmp_path, monkeypatch, heartbeat=0,
                                    analyze_poll={"exists": True, "running": False})
    # heartbeat=0 -> stale -> not "running", so this is the ordinary already-analyzed path
    monkeypatch.setattr(A, "_needs_data_ref_recovery", lambda *a, **k: False)
    A.start_analysis(object(), object(), runner=ex)
    assert ex.stopped == ["hexgraph-analyze-ghidra-dead"]


def test_a_future_dated_heartbeat_is_not_treated_as_fresh(tmp_path, monkeypatch):
    """`delta < window` with no lower bound reads a clock-skewed FUTURE timestamp as perpetually
    fresh, locking every gated Ghidra tool out of the target forever."""
    from hexgraph.engine.re import analysis as A
    import time as _t

    class _Slot:
        meta_path = tmp_path / L.META_NAME

    (tmp_path / L.META_NAME).write_text(json.dumps({"data_ref_recovery_running": _t.time() + 99999}))
    assert A._recovery_running(_Slot()) is False


# --- the fast-profile state has to reach the agent, not just the payload -------------------------

def test_empty_xrefs_on_an_unrecovered_target_says_why():
    """An empty result on a fast-profiled target whose index is not rebuilt is a TOOLING state, not
    a fact about the binary. Reporting it as 'nothing points at this address' is the exact wrong
    turn this stage exists to prevent."""
    from hexgraph.agent import agent_tools as T

    pending = {"fast_profile": True, "data_refs_recovered": False}
    msg = T._no_data_xrefs_msg("0x41000", pending)
    assert "has NOT been rebuilt" in msg and "re_analyze" in msg

    done = {"fast_profile": True, "data_refs_recovered": True}
    assert T._pending_recovery_caveat(done) == ""
    assert T._pending_recovery_caveat({"fast_profile": False}) == ""
    assert T._pending_recovery_caveat(None) == ""
    # unchanged for a small target: no caveat, original wording intact
    assert "NOTE:" not in T._no_data_xrefs_msg("0x41000", {"fast_profile": False})


# --- operator overrides must reach the container --------------------------------------------------

def test_recovery_env_overrides_are_forwarded_to_the_probe(monkeypatch):
    """The host sizes its staleness window from its own slice budget while the container slices on
    whatever IT sees; if an override does not cross the boundary the two disagree and every
    in-flight pass looks stale to the host that launched it."""
    from hexgraph.engine.re import analysis as A

    monkeypatch.setenv("HEXGRAPH_DATA_REF_SLICE_S", "1800")
    monkeypatch.delenv("HEXGRAPH_DATA_REF_TOTAL_S", raising=False)
    env = A._analysis_env()
    assert env["HEXGRAPH_DATA_REF_SLICE_S"] == "1800"
    assert "HEXGRAPH_PROBE_TIMEOUT_S" in env
    assert "HEXGRAPH_DATA_REF_TOTAL_S" not in env, "an unset knob must not be forwarded"


def test_a_complete_slice_whose_save_failed_is_not_marked_recovered(monkeypatch):
    """"Scanned to the end" is not "persisted". The core reports a failed `program.save()` rather
    than raising, so a complete-but-unsaved slice would otherwise earn the PERMANENT marker with
    every reference discarded — and nothing would ever rebuild them."""
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 135273, "truncated": False,
                                         "saved": False, "save_error": "disk full"})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())
    monkeypatch.setattr(G, "_SLICE_GAP_S", 0)

    G._recover_data_refs("/artifact")
    assert not recorded.get("data_refs_recovered"), \
        "a slice whose writes were discarded must not be marked permanently recovered"


def test_a_complete_slice_that_added_nothing_is_marked_recovered(monkeypatch):
    """The other side of the same guard: with nothing to add there is nothing to save, so an
    empty-but-complete pass IS done and must not loop forever."""
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 0, "truncated": False,
                                         "saved": False})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())
    monkeypatch.setattr(G, "_SLICE_GAP_S", 0)

    G._recover_data_refs("/artifact")
    assert recorded.get("data_refs_recovered") is True


# --- gaps both re-reviews proved by mutation: these paths vanished with the tier still green ------

def test_caveat_fires_through_the_production_path(tmp_path, monkeypatch):
    """GAP A: hardwiring `data_ref_index_pending` to False passed the whole tier, because nothing
    exercised the host-side path the production call sites actually take."""
    from hexgraph.agent import agent_tools as T
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    monkeypatch.setattr(A, "_slot_ctx", lambda *a, **k: (_Slot(), str(art), "c", "p"))
    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: False)
    ctx = type("Ctx", (), {"project": object(), "target": object()})()

    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "x"}))
    assert "has NOT been rebuilt" in T._pending_recovery_caveat(None, ctx)

    (tmp_path / L.META_NAME).write_text(json.dumps({"data_refs_recovered": True}))
    assert T._pending_recovery_caveat(None, ctx) == ""


def test_caveat_names_the_bridge_when_that_is_the_blocker(tmp_path, monkeypatch):
    """Otherwise the advice is a closed loop: recovery defers to the bridge, the caveat says 'run
    re_analyze', re_analyze reports 'analyzed' and starts nothing, forever."""
    from hexgraph.agent import agent_tools as T
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "x"}))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    monkeypatch.setattr(A, "_slot_ctx", lambda *a, **k: (_Slot(), str(art), "c", "p"))
    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: True)
    ctx = type("Ctx", (), {"project": object(), "target": object()})()

    msg = T._pending_recovery_caveat(None, ctx)
    assert "re_bridge_stop" in msg, msg


def test_a_payload_saying_pending_is_not_discarded_by_a_host_that_cannot_tell(monkeypatch):
    """The host fails CLOSED on an unreadable marker; if that overrode a payload positively
    reporting 'not recovered', the caveat would go silent exactly when warranted."""
    from hexgraph.agent import agent_tools as T
    from hexgraph.engine.re import analysis as A

    monkeypatch.setattr(A, "data_ref_index_pending", lambda *a, **k: False)
    ctx = type("Ctx", (), {"project": object(), "target": object()})()
    payload = {"fast_profile": True, "data_refs_recovered": False}
    assert "has NOT been rebuilt" in T._pending_recovery_caveat(payload, ctx)


def test_the_inter_slice_pause_actually_happens(monkeypatch):
    """GAP B: deleting the sleep passed the full tier — the tests only stubbed it to 0 to avoid
    paying it, so nothing asserted the yield exists at all."""
    slept = []
    monkeypatch.setattr(G.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(G, "_SLICE_GAP_S", 7)

    calls = {"n": 0}

    def _core(program, monitor, *, start_after=None, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"scanned": 1, "added": 1, "truncated": True, "through": "0x2000", "saved": True}
        return {"scanned": 1, "added": 1, "truncated": False, "saved": True}

    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: None)
    monkeypatch.setattr(G.L, "recover_data_refs_core", _core)
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    G._recover_data_refs("/artifact")
    assert slept == [7], f"the inter-slice yield did not happen: {slept}"


def test_the_heartbeat_is_cleared_before_the_pause(monkeypatch):
    """Order matters: while the heartbeat is set the host refuses every gated Ghidra tool on this
    target, so sleeping first would keep them locked out for the whole gap and make the yield
    useless to the callers it exists for."""
    events = []
    monkeypatch.setattr(G.time, "sleep", lambda s: events.append("sleep"))
    monkeypatch.setattr(G, "_SLICE_GAP_S", 1)

    calls = {"n": 0}

    def _core(program, monitor, *, start_after=None, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return {"scanned": 1, "added": 1, "truncated": True, "through": "0x2000", "saved": True}
        return {"scanned": 1, "added": 1, "truncated": False, "saved": True}

    def _update(**kw):
        if "data_ref_recovery_running" in kw and kw["data_ref_recovery_running"] is None:
            events.append("heartbeat_cleared")

    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", _update)
    monkeypatch.setattr(G.L, "recover_data_refs_core", _core)
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    G._recover_data_refs("/artifact")
    assert events.index("heartbeat_cleared") < events.index("sleep"), events


def test_a_wedged_recovery_is_reapable_but_a_healthy_one_is_not(tmp_path, monkeypatch):
    """Requiring `not running` to reap removed the last automatic kill, and the probe has no
    self-timeout — so a pass wedged inside Ghidra would hold the deterministic name forever. The
    heartbeat is the evidence: stale means wedged, ABSENT means the cold analysis phase (hours on a
    monolith) and must never be killed."""
    from hexgraph.engine.re import analysis as A
    import time as _t

    class _Slot:
        meta_path = tmp_path / L.META_NAME

    (tmp_path / L.META_NAME).write_text(json.dumps({}))
    assert A._recovery_heartbeat_stale(_Slot()) is False, "absent heartbeat must not read as wedged"

    (tmp_path / L.META_NAME).write_text(json.dumps({"data_ref_recovery_running": _t.time()}))
    assert A._recovery_heartbeat_stale(_Slot()) is False, "fresh heartbeat is healthy"

    (tmp_path / L.META_NAME).write_text(
        json.dumps({"data_ref_recovery_running": _t.time() - L._DATA_REF_SLICE_S * 10}))
    assert A._recovery_heartbeat_stale(_Slot()) is True


def test_slice_gap_env_override_reaches_the_container():
    """It was absent from the forwarded set, so a host-side setting could never reach the probe —
    the same class of bug the env-forwarding fix closed for the other knobs."""
    from hexgraph.engine.re import analysis as A

    assert "HEXGRAPH_DATA_REF_SLICE_GAP_S" in A._RECOVERY_ENV_KEYS


def test_recovery_env_reaches_start_detached(monkeypatch, tmp_path):
    """A-L3: asserting `_analysis_env()` in isolation proves the dict is built, not that it is
    WIRED — the bug it guards against is the value never crossing into the container."""
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "x"}))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

        def exists(self):
            return True

        def prepare(self):
            pass

    class _Ex:
        def __init__(self):
            self.started = []

        def poll_detached(self, name):
            return {"exists": False, "running": False}

        def stop_detached(self, name, remove=False):
            pass

        def start_detached(self, probe, artifact, **k):
            self.started.append(k)

    monkeypatch.setenv("HEXGRAPH_DATA_REF_SLICE_GAP_S", "99")
    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    monkeypatch.setattr(A, "_slot_ctx",
                        lambda *a, **k: (_Slot(), str(art), "hexgraph-analyze-ghidra-x", "p"))
    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: False)
    import hexgraph.sandbox.runner as R
    monkeypatch.setattr(R, "docker_available", lambda: True)

    ex = _Ex()
    A.start_analysis(object(), object(), runner=ex)

    assert ex.started, "no detached run was launched"
    assert ex.started[0]["extra_env"]["HEXGRAPH_DATA_REF_SLICE_GAP_S"] == "99"


def test_pending_fails_closed_on_an_absent_or_corrupt_marker(tmp_path, monkeypatch):
    """A-2 / B3-1 (both reviewers, independently): deleting the `bool(meta)` guard left the whole
    tier green. Without it `not {}.get(...)` is True, so the caveat fires on a target we know
    nothing about — and a caveat that fires when it shouldn't trains the reader to ignore it."""
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    monkeypatch.setattr(A, "_slot_ctx", lambda *a, **k: (_Slot(), str(art), "c", "p"))
    monkeypatch.setattr(A, "_bridge_live", lambda slot, runner=None: False)

    # absent marker
    assert A.data_ref_index_pending(object(), object()) is False
    # corrupt marker
    (tmp_path / L.META_NAME).write_text("{not json")
    assert A.data_ref_index_pending(object(), object()) is False
    # a real, unrecovered marker still reports pending
    (tmp_path / L.META_NAME).write_text(json.dumps({"content_hash": "x"}))
    assert A.data_ref_index_pending(object(), object()) is True


def test_a_malformed_slice_gap_does_not_break_the_probe_at_import(monkeypatch):
    """A-3: reverting `_env_num` to a bare `float()` left the tier green. That call runs at MODULE
    IMPORT of ghidra_probe — the entry point for decompile/xrefs/taint/emulate/script/analyze — so
    one typo'd env value would take the entire Ghidra surface down in-container."""
    import importlib

    monkeypatch.setenv("HEXGRAPH_DATA_REF_SLICE_GAP_S", "30s")
    reloaded = importlib.reload(G)
    try:
        assert reloaded._SLICE_GAP_S == 45.0, "a malformed value must fall back, not propagate"
    finally:
        monkeypatch.delenv("HEXGRAPH_DATA_REF_SLICE_GAP_S", raising=False)
        importlib.reload(G)


def test_the_probe_stamps_the_fast_profile_state_on_every_mode(tmp_path, monkeypatch):
    """B3-2: the payload half of the OR was mutation-green. Both production call sites pass `ctx`
    so the host answer normally wins, but the payload is the only signal a caller gets when it
    reads the probe output directly — it should not be silently droppable."""
    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    (tmp_path / "meta.json").write_text(json.dumps({"data_refs_recovered": True}))

    # `_run` imports ConsoleTaskMonitor at its top; stub the module so no JVM is needed.
    import sys as _sys
    import types as _types
    task_mod = _types.ModuleType("ghidra.util.task")
    task_mod.ConsoleTaskMonitor = lambda: object()
    for name, mod in (("ghidra", _types.ModuleType("ghidra")),
                      ("ghidra.util", _types.ModuleType("ghidra.util")),
                      ("ghidra.util.task", task_mod)):
        monkeypatch.setitem(_sys.modules, name, mod)

    monkeypatch.setattr(G.L, "PROJECT_MOUNT", str(tmp_path))
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())
    monkeypatch.setattr(G.L, "xrefs_core", lambda *a, **k: {"mode": "data", "data_refs": []})

    out = G._run({"artifact": str(art), "mode": "xrefs", "xrefs_mode": "data",
                  "xrefs_subject": "0x1000", "focus": None, "rename": None, "user_script": None,
                  "search_bytes": None, "search_imm": None})

    assert out["fast_profile"] is True
    assert out["data_refs_recovered"] is True

    # B4-1: and the UNRECOVERED direction, which is the dangerous one — hardcoding True here would
    # make the payload half of the caveat's OR go silently dark on exactly the targets that need it.
    (tmp_path / "meta.json").write_text(json.dumps({}))
    out = G._run({"artifact": str(art), "mode": "xrefs", "xrefs_mode": "data",
                  "xrefs_subject": "0x1000", "focus": None, "rename": None, "user_script": None,
                  "search_bytes": None, "search_imm": None})
    assert out["data_refs_recovered"] is False


def test_a_wedged_container_is_actually_reaped_and_the_pass_relaunched(tmp_path, monkeypatch):
    """A-4: folding the duplicate reap into an `elif` was right, but it removed a backstop.

    Under the old double-`if`, deleting the reap in the `running` branch was silently covered by the
    `exists` block below it (`poll_detached` sets `exists` whenever `running` is true). With the
    `elif` this reap is the ONLY thing that clears a wedged container — and the failure it prevents
    is terminal: `start_detached` hits "name already in use", which reads as `running`, and a wedged
    pass never sets `data_refs_recovered`, so every later `re_analyze` reports `running` forever.
    The predicate (`_recovery_heartbeat_stale`) and the guard are pinned; this pins the ACTION.
    """
    import time as _t
    from hexgraph.engine.re import analysis as A

    art = tmp_path / "big.bin"
    art.write_bytes(b"\x00" * (L._FAST_PROFILE_BYTES + 1))
    # running container + a heartbeat that went stale == wedged
    (tmp_path / L.META_NAME).write_text(
        json.dumps({"data_ref_recovery_running": _t.time() - L._DATA_REF_SLICE_S * 10}))

    class _Slot:
        root = tmp_path
        meta_path = tmp_path / L.META_NAME
        content_sha = "a" * 64

        def exists(self):
            return True

        def prepare(self):
            pass

    class _Ex:
        def __init__(self):
            self.stopped, self.started = [], []

        def poll_detached(self, name):
            if name.startswith("hexgraph-ghidra-bridge-"):
                return {"exists": False, "running": False}
            return {"exists": True, "running": True}

        def stop_detached(self, name, remove=False):
            self.stopped.append(name)

        def start_detached(self, probe, artifact, **k):
            self.started.append(k.get("name"))

    monkeypatch.setattr(A, "_active_backend", lambda: "ghidra")
    monkeypatch.setattr(A, "_slot_ctx",
                        lambda *a, **k: (_Slot(), str(art), "hexgraph-analyze-ghidra-wedged", "p"))
    import hexgraph.sandbox.runner as R
    monkeypatch.setattr(R, "docker_available", lambda: True)

    ex = _Ex()
    st = A.start_analysis(object(), object(), runner=ex)

    assert ex.stopped == ["hexgraph-analyze-ghidra-wedged"], "the wedged container was not reaped"
    assert ex.started, "nothing relaunched after reaping the wedge"
    assert st["state"] == "started"
