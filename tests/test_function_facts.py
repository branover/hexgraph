"""Phase 3 PR1 — rich function facts on the decompiled focus (design-re-tooling.md §7).

The decompiled focus now carries recovered prototype / calling-convention / params /
locals: the radare2 path builds them from `afij` (function info) + `afvj` (variables),
the Ghidra path from the function's signature/parameters/locals. The enrichment path
(already whitelisted in Phase O) attaches them to the function node when it's promoted.

Pure-offline: unit-test the radare2 fact parser with a fake r2, and prove the full rich
set enriches a node through record_observation → join-at-create (no Docker, no decompiler).
"""

import json

from hexgraph.db.session import session_scope
from hexgraph.engine import observations as O
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node
from hexgraph.sandbox.probes import decompile_probe as DP

from conftest import fixture_path


class _FakeR2:
    """Returns canned output for an r2 command by prefix (`afij @ …`, `afvj @ …`)."""

    def __init__(self, responses):
        self.responses = responses

    def cmd(self, c):
        for prefix, out in self.responses.items():
            if c.startswith(prefix):
                return out
        return ""


def test_function_facts_dict_of_groups_with_isarg_marker():
    # Real r2 `afvj` (dict-of-storage-groups): `kind` is the STORAGE class (reg/bpv), and a
    # parameter is flagged by the `isarg` boolean — NOT kind=="arg".
    r2 = _FakeR2({
        "afij": json.dumps([{"signature": "int handler(char *buf)", "calltype": "cdecl",
                             "nargs": 1, "nlocals": 2}]),
        "afvj": json.dumps({"reg": [{"name": "buf", "type": "char *", "kind": "reg", "isarg": True}],
                            "bp": [{"name": "i", "type": "int", "kind": "bpv"},
                                   {"name": "len", "type": "size_t", "kind": "bpv"}]}),
    })
    facts = DP._function_facts(r2, "sym.handler")
    assert facts["prototype"] == "int handler(char *buf)"
    assert facts["signature"] == "int handler(char *buf)"
    assert facts["calling_convention"] == "cdecl"
    assert facts["param_count"] == 1
    assert facts["local_count"] == 2
    assert facts["params"] == [{"name": "buf", "type": "char *"}]
    assert {v["name"] for v in facts["locals"]} == {"i", "len"}


def test_function_facts_flat_list_shape():
    # Some r2 versions return `afvj` as a flat list, not a dict-of-groups — handle it.
    r2 = _FakeR2({
        "afij": json.dumps([{"signature": "void f(int a)"}]),
        "afvj": json.dumps([{"name": "a", "type": "int", "isarg": True},
                            {"name": "tmp", "type": "int", "kind": "bpv"}]),
    })
    facts = DP._function_facts(r2, "sym.f")
    assert facts["params"] == [{"name": "a", "type": "int"}]
    assert facts["locals"] == [{"name": "tmp", "type": "int"}]


def test_function_facts_legacy_kind_arg_marker_still_works():
    # Older r2 used kind=="arg"; keep it in the marker union.
    r2 = _FakeR2({"afij": "[]",
                  "afvj": json.dumps([{"name": "x", "type": "int", "kind": "arg"}])})
    assert DP._function_facts(r2, "x")["params"] == [{"name": "x", "type": "int"}]


def test_function_facts_unmarked_vars_default_to_local():
    # No arg marker present → classify as local (omitting a param beats a wrong param).
    r2 = _FakeR2({"afij": "[]",
                  "afvj": json.dumps([{"name": "v", "type": "int", "kind": "bpv"}])})
    facts = DP._function_facts(r2, "x")
    assert "params" not in facts and facts["locals"] == [{"name": "v", "type": "int"}]
    assert facts["local_count"] == 1


def test_function_facts_is_defensive_on_garbage():
    # malformed JSON / missing fields / empty responses → empty facts, never raises
    assert DP._function_facts(_FakeR2({"afij": "not json", "afvj": "{["}), "x") == {}
    assert DP._function_facts(_FakeR2({}), "x") == {}


def test_function_facts_counts_fall_back_to_list_lengths():
    # afij gives no counts, but afvj has vars → counts derive from the lists
    r2 = _FakeR2({
        "afij": json.dumps([{"signature": "void f(int a)"}]),
        "afvj": json.dumps([{"name": "a", "type": "int", "isarg": True},
                            {"name": "tmp", "type": "int", "kind": "bpv"}]),
    })
    facts = DP._function_facts(r2, "sym.f")
    assert facts["param_count"] == 1 and facts["local_count"] == 1
    assert facts["params"] == [{"name": "a", "type": "int"}]


def test_rich_focus_facts_enrich_promoted_function(hg_home):
    """A decompilation focus carrying the full rich set enriches the function node at
    promotion (join-at-create pulls the just-indexed always-welcome facts)."""
    with session_scope() as s:
        p = create_project(s, name="ff")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "abc123"}
        s.flush()
        focus = {"name": "handler", "address": "0x401000",
                 "prototype": "int handler(char*)", "calling_convention": "cdecl",
                 "params": [{"name": "buf", "type": "char *"}], "param_count": 1,
                 "locals": [{"name": "i", "type": "int"}], "local_count": 1}
        O.record_observation(s, project_id=p.id, target_id=t.id, source="test",
                             tool="decompile_function", args={"function": "handler"},
                             result_kind="decompilation", payload={"focus": focus},
                             summary="decompiled handler", content_hash="abc123")
        node = get_or_create_node(s, project_id=p.id, node_type="function",
                                  name="handler", target_id=t.id)
        a = node.attrs_json or {}
        assert a.get("prototype") == "int handler(char*)"
        assert a.get("calling_convention") == "cdecl"
        assert a.get("param_count") == 1 and a.get("local_count") == 1
        assert a.get("params") == [{"name": "buf", "type": "char *"}]
        assert a.get("locals") == [{"name": "i", "type": "int"}]
