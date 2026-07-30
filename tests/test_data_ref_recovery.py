"""The fast profile buys a bounded analysis of a monolith by disabling the per-processor constant/
scalar reference analyzers — and that specifically empties the code->DATA half of the xref index
(control flow, hence the call graph, is untouched). `recover_data_refs_core` rebuilds the
statically-resolvable majority of it in one linear pass, exploiting the fact that SLEIGH already
resolved a RIP-relative operand at DISASSEMBLY time (`LEA RDI,[0x102004]` -> pcode
`COPY (const,0x102004,8)`), so no constant propagation is needed to know the target.

Measured against full Ghidra analysis on a real 6.1 MB x86-64 library: 21,686 references proposed,
all of which full analysis also produces (precision 1.000), closing 63% of the gap the fast profile
opens. The remainder needs real propagation (MIPS lui/addiu, AArch64 adrp/add pairs).

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


def test_a_truncated_pass_does_not_earn_the_marker(monkeypatch):
    """A budget-truncated pass left the index INCOMPLETE — the next re_analyze must retry it rather
    than skip it forever."""
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": True})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    out = G._recover_data_refs("/artifact")
    assert out["truncated"] is True
    assert recorded == {}, "a truncated pass must not be marked complete"


def test_a_complete_pass_earns_the_marker(monkeypatch):
    recorded = {}
    monkeypatch.setattr(G.L, "read_marker", lambda: {})
    monkeypatch.setattr(G.L, "update_marker", lambda **kw: recorded.update(kw))
    monkeypatch.setattr(G.L, "recover_data_refs_core",
                        lambda *a, **k: {"scanned": 10, "added": 3, "truncated": False})
    monkeypatch.setattr(G.L, "open_target", _fake_open_target())

    out = G._recover_data_refs("/artifact")
    assert out["added"] == 3
    assert recorded == {"data_refs_recovered": True}


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
