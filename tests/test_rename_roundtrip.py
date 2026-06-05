"""Phase 3 PR4 — rename/retype round-trip into the persistent Ghidra project (design §7).

A confirmed function rename writes into the warm Ghidra project (so it sticks for every
future decompile) and re-decompiles, re-recording the result so the graph reflects it.

Offline coverage of the Python orchestration (`engine.ghidra.propagate_function_rename`)
and the `annotate(rename)` wiring with the Ghidra decompiler faked — the actual project
write (Jython `setName` + analyzeHeadless -process save) runs only inside the sandbox and
is exercised by the WITH_GHIDRA CI lane. The key behaviours pinned here:

- propagate is a NO-OP unless headless Ghidra is the active backend (radare2 users pay only
  a config check; no Docker run),
- it validates the address/name before any probe,
- the re-decompile is recorded under args={"function": new_name} — a DISTINCT Observation
  from the pre-rename one (the new name IS the cache-bust dimension), never a stale-cache hit,
- a Ghidra failure never breaks the confirmed graph rename.
"""

from hexgraph.db.models import Observation
from hexgraph.db.session import session_scope
from hexgraph.engine import annotations as A
from hexgraph.engine import ghidra as G
from hexgraph.engine import observations as O
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node

from hexgraph import settings as st
from conftest import fixture_path


def _setup(s):
    p = create_project(s, name="rename")
    t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
    t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
    s.flush()
    node = get_or_create_node(s, project_id=p.id, node_type="function",
                              name="fcn.00401000", target_id=t.id, address="0x401000")
    return p, t, node


class _FakeGhidra:
    """Stands in for GhidraDecompiler: records the rename call, returns a fresh focus."""
    last = {}

    def __init__(self, *a, **k):
        pass

    def rename_function(self, artifact, *, address, new_name, project=None):
        _FakeGhidra.last = {"artifact": artifact, "address": address, "new_name": new_name}
        return {"tool": "ghidra_probe", "cached": True,
                "focus": {"name": new_name, "address": address,
                          "pseudocode": "void %s(void) { /* renamed */ }" % new_name,
                          "prototype": "void %s(void)" % new_name, "callees": []}}


def _enable_ghidra():
    st.update_settings({"features.ghidra.enabled": True, "features.ghidra.mode": "headless"})


def _ghidra_active(monkeypatch):
    _enable_ghidra()
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)
    monkeypatch.setattr("hexgraph.sandbox.decompiler.GhidraDecompiler", _FakeGhidra)


# --- no-op unless headless Ghidra is active ----------------------------------

def test_propagate_noop_when_ghidra_not_active(hg_home):
    with session_scope() as s:
        _p, _t, node = _setup(s)
        node.name = "handle_request"  # _apply_rename would have set this first
        res = G.propagate_function_rename(s, node, "handle_request")
        assert res["propagated"] is False and "backend" in res["reason"]
        # nothing recorded (no Docker run, no observation)
        assert s.query(Observation).filter(Observation.result_kind == "decompilation").count() == 0


def test_propagate_validates_address_and_name(hg_home, monkeypatch):
    _ghidra_active(monkeypatch)
    with session_scope() as s:
        _p, _t, node = _setup(s)
        node.address = "not-an-address"
        assert G.propagate_function_rename(s, node, "ok_name")["propagated"] is False
        node.address = "0x401000"
        assert G.propagate_function_rename(s, node, "bad name!")["propagated"] is False


def test_propagate_noop_for_non_function_node(hg_home, monkeypatch):
    _ghidra_active(monkeypatch)
    with session_scope() as s:
        p, t, _node = _setup(s)
        strnode = get_or_create_node(s, project_id=p.id, node_type="string",
                                     name="/bin/sh", target_id=t.id)
        assert G.propagate_function_rename(s, strnode, "whatever")["propagated"] is False


# --- the write + re-decompile + cache-bust -----------------------------------

def test_rename_propagates_and_rerecords_without_stale_cache(hg_home, monkeypatch):
    _ghidra_active(monkeypatch)
    with session_scope() as s:
        p, t, node = _setup(s)
        # A PRE-rename decompilation Observation exists under the OLD name.
        O.record_observation(s, project_id=p.id, target_id=t.id, source="test",
                             tool="decompile_function", args={"function": "fcn.00401000"},
                             result_kind="decompilation",
                             payload={"focus": {"name": "fcn.00401000", "pseudocode": "old"}},
                             summary="old", content_hash="abc123")

        ann = A.create_annotation(s, p.id, node_kind="node", node_id=node.id,
                                  kind="rename", value="handle_request", origin="human")
        assert ann.status == "confirmed"

        # graph rename applied + history kept
        assert node.name == "handle_request"
        assert "fcn.00401000" in (node.attrs_json or {}).get("name_history", [])
        # the probe was asked to rename at the right address
        assert _FakeGhidra.last == {"artifact": t.path, "address": "0x401000",
                                    "new_name": "handle_request"}
        # cache-bust: a SECOND, distinct decompilation Observation under the new name —
        # the stale old-name one is untouched (the new name is the dedup discriminator).
        decomps = s.query(Observation).filter(Observation.result_kind == "decompilation").all()
        assert len(decomps) == 2
        new = [d for d in decomps if (d.args_json or {}).get("function") == "handle_request"]
        assert len(new) == 1 and new[0].source == "annotate-rename"
        # the node's body was refreshed to the renamed decompile
        assert "renamed" in (node.attrs_json or {}).get("pseudocode", "")


def test_rename_still_applies_when_ghidra_write_errors(hg_home, monkeypatch):
    """A Ghidra failure must not break the confirmed graph rename — propagation is gravy."""
    _enable_ghidra()
    monkeypatch.setattr("hexgraph.sandbox.runner.docker_available", lambda: True)

    class _BoomGhidra:
        def __init__(self, *a, **k):
            pass

        def rename_function(self, *a, **k):
            raise RuntimeError("ghidra exploded")

    monkeypatch.setattr("hexgraph.sandbox.decompiler.GhidraDecompiler", _BoomGhidra)
    with session_scope() as s:
        p, _t, node = _setup(s)
        A.create_annotation(s, p.id, node_kind="node", node_id=node.id,
                            kind="rename", value="renamed_anyway", origin="human")
        assert node.name == "renamed_anyway"  # graph rename succeeded despite the Ghidra boom


def test_rename_error_result_does_not_record(hg_home, monkeypatch):
    _ghidra_active(monkeypatch)

    class _ErrGhidra:
        def __init__(self, *a, **k):
            pass

        def rename_function(self, *a, **k):
            return {"error": "ghidra project busy"}

    monkeypatch.setattr("hexgraph.sandbox.decompiler.GhidraDecompiler", _ErrGhidra)
    with session_scope() as s:
        p, _t, node = _setup(s)
        node.name = "x"
        res = G.propagate_function_rename(s, node, "x")
        assert res["propagated"] is False
        assert s.query(Observation).filter(Observation.result_kind == "decompilation").count() == 0
