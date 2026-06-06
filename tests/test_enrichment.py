"""The enrichment index + always-welcome extractor registry (Phase O, PR 2).

Covers design §5.4 (the always-welcome whitelist) and §5.5 (the enrichment index:
extract-at-write + join-at-create), exactly the §9 test matrix:

- convergence both directions (node-before-observation AND observation-before-node
  end at the SAME enriched node),
- idempotency (re-applying a fact is a no-op),
- relationship-edge timing (a `calls` edge materializes exactly when the second
  endpoint is promoted, not before),
- whitelist discipline (a non-whitelisted fact is NEVER auto-applied; enrichment
  never creates a node),
- address-fill re-lookup (a name-keyed node that later gains an address picks up
  address-keyed facts),
- passive invalidation (facts under an old content_hash don't match a new-hash node),
- an extractor unit test (only whitelisted facts come out of a fixture payload).

Mock backend, offline — no Docker, no key.
"""

from hexgraph.db.models import Edge, EnrichmentFact, Node
from hexgraph.db.session import session_scope
from hexgraph.engine import enrichment as E
from hexgraph.engine import observations as O
from hexgraph.engine.ingest import create_project, ingest_file
from hexgraph.engine.nodes import get_or_create_node, materialize_function

from conftest import fixture_path

HASH = "deadbeef"


def _seed():
    with session_scope() as s:
        p = create_project(s, name="enrich")
        t = ingest_file(s, p, fixture_path("vuln_httpd"), name="httpd")
        t.metadata_json = {**(t.metadata_json or {}), "sha256": HASH}
        s.flush()
        return p.id, t.id


def _record_decomp(s, pid, tid, focus, content_hash=HASH):
    return O.record_observation(
        s, project_id=pid, target_id=tid, source="task", tool="decompile_function",
        args={"function": focus["name"]}, result_kind="decompilation",
        payload={"focus": focus}, summary=focus["name"], content_hash=content_hash)


def _attrs(s, pid, tid, name):
    n = (s.query(Node)
         .filter(Node.project_id == pid, Node.target_id == tid,
                 Node.node_type == "function", Node.fq_name == name)
         .one())
    return dict(n.attrs_json or {}), n


# --- extractor unit test: only whitelisted facts come out --------------------

def test_extractor_keeps_only_whitelisted_function_facts(hg_home):
    focus = {
        "name": "sym.cgi_handler", "address": "0x401200",
        "prototype": "int cgi_handler(char*)", "calling_convention": "cdecl",
        "param_count": 1,
        # NOT whitelisted — must be dropped:
        "severity": "critical", "summary": "buffer overflow!", "is_vulnerability": True,
        "callees": [{"name": "sym.imp.system", "address": "0x401300"}],
    }
    facts = E._extract_functions({"focus": focus})
    attr_facts = [f for f in facts if f.fact_kind == "attrs"]
    # The function attribute fact carries ONLY whitelisted keys.
    keys = set()
    for f in attr_facts:
        keys |= set(f.fact_json)
    assert keys <= E._ATTRIBUTE_WHITELIST["function"]
    assert "severity" not in keys and "summary" not in keys and "is_vulnerability" not in keys
    assert "prototype" in keys and "calling_convention" in keys and "address" in keys
    # The name key is normalized; the address key is canonical hex.
    name_keys = {f.subject_key for f in attr_facts if f.subject_kind == "name"}
    assert "cgi_handler" in name_keys  # sym. prefix stripped
    addr_keys = {f.subject_key for f in attr_facts if f.subject_kind == "address"}
    assert "0x401200" in addr_keys
    # A `calls` relationship fact was produced (pair of normalized names).
    pairs = [f for f in facts if f.fact_kind == "calls"]
    assert pairs and E._unpair(pairs[0].subject_key) == ("cgi_handler", "system")


# --- convergence: observation BEFORE node ------------------------------------

def test_observation_before_node_enriches_on_create(hg_home):
    pid, tid = _seed()
    focus = {"name": "cgi_handler", "address": "0x401200",
             "prototype": "int cgi_handler(char*)", "calling_convention": "cdecl"}
    with session_scope() as s:
        _record_decomp(s, pid, tid, focus)
        # No node yet — the fact is waiting in the index.
        assert s.query(Node).filter(Node.node_type == "function").count() == 0
        assert s.query(EnrichmentFact).count() >= 1
        # Now create the node — it must pull the waiting facts.
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="cgi_handler", target_id=tid)
        a, node = _attrs(s, pid, tid, "cgi_handler")
        assert a.get("prototype") == "int cgi_handler(char*)"
        assert a.get("calling_convention") == "cdecl"
        assert node.address == "0x401200"  # address-column filled
        assert a.get("provenance")  # source observation recorded


# --- convergence: node BEFORE observation ------------------------------------

def test_node_before_observation_enriches_at_write(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        # Node exists first (curated, address unknown).
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="cgi_handler", target_id=tid)
        focus = {"name": "sym.cgi_handler", "address": "0x401200",
                 "prototype": "int cgi_handler(char*)", "calling_convention": "cdecl"}
        _record_decomp(s, pid, tid, focus)  # forward-enriches the existing node
        a, node = _attrs(s, pid, tid, "cgi_handler")
        assert a.get("prototype") == "int cgi_handler(char*)"
        assert node.address == "0x401200"


def test_both_directions_converge_to_same_attrs(hg_home):
    """The whole point of §5.5: order must not matter."""
    focus = {"name": "cgi_handler", "address": "0x401200",
             "prototype": "int cgi_handler(char*)", "calling_convention": "cdecl",
             "param_count": 1}

    # Direction A: observation, then node.
    pidA, tidA = _seed()
    with session_scope() as s:
        _record_decomp(s, pidA, tidA, dict(focus))
        get_or_create_node(s, project_id=pidA, node_type="function",
                           name="cgi_handler", target_id=tidA)
        a_attrs, _ = _attrs(s, pidA, tidA, "cgi_handler")

    # Direction B: node, then observation.
    pidB, tidB = _seed()
    with session_scope() as s:
        get_or_create_node(s, project_id=pidB, node_type="function",
                           name="cgi_handler", target_id=tidB)
        _record_decomp(s, pidB, tidB, dict(focus))
        b_attrs, _ = _attrs(s, pidB, tidB, "cgi_handler")

    drop = {"provenance", "name_raw"}
    assert {k: v for k, v in a_attrs.items() if k not in drop} == \
           {k: v for k, v in b_attrs.items() if k not in drop}


# --- idempotency --------------------------------------------------------------

def test_reapplying_a_fact_is_a_noop(hg_home):
    pid, tid = _seed()
    focus = {"name": "cgi_handler", "address": "0x401200",
             "prototype": "int cgi_handler(char*)"}
    with session_scope() as s:
        _record_decomp(s, pid, tid, focus)
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="cgi_handler", target_id=tid)
        a1, node = _attrs(s, pid, tid, "cgi_handler")
        # Re-record the identical observation (cached) AND re-fetch the node twice.
        _record_decomp(s, pid, tid, focus)
        applied = E.apply_facts_for_node(s, node)
        a2, _ = _attrs(s, pid, tid, "cgi_handler")
        assert applied == 0  # nothing changed
        assert a1 == a2
        # No duplicate fact rows piled up either.
        assert s.query(EnrichmentFact).filter(
            EnrichmentFact.subject_kind == "name",
            EnrichmentFact.subject_key == "cgi_handler",
            EnrichmentFact.fact_kind == "attrs").count() == 1


# --- relationship-edge timing -------------------------------------------------

def test_calls_edge_materializes_when_second_endpoint_promoted(hg_home):
    pid, tid = _seed()
    focus = {"name": "cgi_handler", "address": "0x401200",
             "callees": [{"name": "helper", "address": "0x401400"}]}
    with session_scope() as s:
        _record_decomp(s, pid, tid, focus)
        # Promote only the caller — the callee endpoint doesn't exist yet.
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="cgi_handler", target_id=tid)
        calls = s.query(Edge).filter(Edge.type == "calls").all()
        assert not calls, "edge must NOT materialize before both endpoints exist"

        # Promote the callee — NOW the edge materializes.
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="helper", target_id=tid)
        calls = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(calls) == 1
        assert "0x401400" in (calls[0].attrs_json or {}).get("call_sites", [])
        assert (calls[0].attrs_json or {}).get("provenance")


def test_calls_edge_idempotent_merge(hg_home):
    pid, tid = _seed()
    focus = {"name": "a", "callees": [{"name": "b", "address": "0x10"}]}
    with session_scope() as s:
        get_or_create_node(s, project_id=pid, node_type="function", name="a", target_id=tid)
        get_or_create_node(s, project_id=pid, node_type="function", name="b", target_id=tid)
        _record_decomp(s, pid, tid, focus)
        _record_decomp(s, pid, tid, focus)  # cached re-run
        E.apply_facts_for_node(s, s.query(Node).filter(Node.fq_name == "a").one())
        calls = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(calls) == 1
        assert (calls[0].attrs_json or {}).get("call_sites") == ["0x10"]


def test_calls_edge_provenance_accumulates_across_distinct_observations(hg_home):
    """Two DISTINCT observations that both report `a calls b` must retain BOTH
    provenance ids on the single merged edge (design §5.2), not overwrite to the
    latest — the edge path must accumulate provenance like the node path does."""
    pid, tid = _seed()
    with session_scope() as s:
        get_or_create_node(s, project_id=pid, node_type="function", name="a", target_id=tid)
        get_or_create_node(s, project_id=pid, node_type="function", name="b", target_id=tid)
        # Distinct args so neither dedups as cached → two real observations, same edge.
        O.record_observation(
            s, project_id=pid, target_id=tid, source="task", tool="decompile_function",
            args={"function": "a", "depth": 1}, result_kind="decompilation",
            payload={"focus": {"name": "a", "callees": [{"name": "b", "address": "0x10"}]}},
            summary="a", content_hash=HASH)
        O.record_observation(
            s, project_id=pid, target_id=tid, source="task", tool="decompile_function",
            args={"function": "a", "depth": 2}, result_kind="decompilation",
            payload={"focus": {"name": "a", "callees": [{"name": "b", "address": "0x20"}]}},
            summary="a", content_hash=HASH)
        calls = s.query(Edge).filter(Edge.type == "calls").all()
        assert len(calls) == 1  # one merged edge
        prov = (calls[0].attrs_json or {}).get("provenance") or []
        assert len(prov) == 2  # BOTH observations retained, not overwritten
        # call_sites still accumulate too (sanity).
        assert set((calls[0].attrs_json or {}).get("call_sites") or []) == {"0x10", "0x20"}


# --- whitelist discipline -----------------------------------------------------

def test_non_whitelisted_fact_never_auto_applied(hg_home):
    pid, tid = _seed()
    focus = {"name": "cgi_handler", "severity": "critical",
             "summary": "totally a vuln", "speculative_type": "evil_t"}
    with session_scope() as s:
        before_nodes = s.query(Node).count()
        _record_decomp(s, pid, tid, focus)
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="cgi_handler", target_id=tid)
        a, _ = _attrs(s, pid, tid, "cgi_handler")
        assert "severity" not in a and "summary" not in a and "speculative_type" not in a


def test_enrichment_never_creates_a_node(hg_home):
    pid, tid = _seed()
    focus = {"name": "ghost_fn", "address": "0x999",
             "prototype": "void ghost_fn(void)",
             "callees": [{"name": "other_ghost"}]}
    with session_scope() as s:
        before = s.query(Node).filter(Node.node_type == "function").count()
        _record_decomp(s, pid, tid, focus)
        # Facts are indexed, but NO function node was created by enrichment.
        assert s.query(Node).filter(Node.node_type == "function").count() == before
        assert s.query(EnrichmentFact).count() >= 1


# --- address-fill re-lookup ---------------------------------------------------

def test_address_fill_picks_up_address_keyed_facts(hg_home):
    """A fact known ONLY by address must reach a name-keyed node once it gains the
    address (the decompilation that knows the address arrives keyed by address)."""
    pid, tid = _seed()
    with session_scope() as s:
        # An xrefs-style observation can't carry names+addresses; simulate an
        # address-only function fact by recording a decompilation whose record is
        # keyed under the address path. Use a payload with an address but a name the
        # node won't initially have, so the match happens via the address key.
        focus = {"name": "fcn.00401500", "address": "0x401500",
                 "prototype": "int handler(int)"}
        _record_decomp(s, pid, tid, focus)
        # Create the node WITHOUT the address; it can't match the address-keyed fact.
        node = get_or_create_node(s, project_id=pid, node_type="function",
                                  name="renamed_handler", target_id=tid)
        assert "prototype" not in (node.attrs_json or {})
        # Now the node gains its address (an address-fill) → re-lookup by address key.
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="renamed_handler", target_id=tid, address="0x401500")
        a, refreshed = _attrs(s, pid, tid, "renamed_handler")
        assert a.get("prototype") == "int handler(int)"


# --- passive invalidation -----------------------------------------------------

def test_facts_scoped_by_content_hash_dont_cross_versions(hg_home):
    from hexgraph.db.models import Target

    pid, tid = _seed()
    focus = {"name": "cgi_handler", "prototype": "OLD_PROTO"}
    with session_scope() as s:
        # Facts written under the OLD analyzed-bytes hash (the target's sha256).
        _record_decomp(s, pid, tid, focus, content_hash="oldhash")
        # Re-ingest changes the bytes → the target's analyzed-bytes hash changes.
        t = s.get(Target, tid)
        t.metadata_json = {**(t.metadata_json or {}), "sha256": "newhash"}
        s.flush()
        # A node created now (under the new bytes) must NOT match the stale facts.
        node = get_or_create_node(s, project_id=pid, node_type="function",
                                  name="cgi_handler", target_id=tid)
        assert "prototype" not in (node.attrs_json or {})


# --- is_sink tagging from xrefs ----------------------------------------------

def test_dangerous_import_gets_is_sink_tag(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        get_or_create_node(s, project_id=pid, node_type="symbol",
                           name="sym.imp.system", target_id=tid)
        O.record_observation(
            s, project_id=pid, target_id=tid, source="task", tool="xrefs", args={},
            result_kind="xrefs", payload={"sinks": {"system": ["cgi_handler"],
                                                     "harmless_fn": ["main"]}},
            summary="xrefs", content_hash=HASH)
        sym = (s.query(Node).filter(Node.node_type == "symbol",
                                    Node.fq_name == "system").one())
        assert (sym.attrs_json or {}).get("is_sink") is True
        # A non-dangerous name is never tagged (no node, no fact).
        assert s.query(EnrichmentFact).filter(
            EnrichmentFact.subject_key == "harmless_fn").count() == 0


# --- conflict resolution: most-recent wins -----------------------------------

def test_conflicting_facts_most_recent_wins(hg_home):
    pid, tid = _seed()
    with session_scope() as s:
        get_or_create_node(s, project_id=pid, node_type="function",
                           name="f", target_id=tid)
        # Two DISTINCT observations (different args so neither dedups as cached) that
        # disagree on the prototype — the later one wins, with provenance retained.
        O.record_observation(
            s, project_id=pid, target_id=tid, source="task", tool="decompile_function",
            args={"function": "f", "depth": 1}, result_kind="decompilation",
            payload={"focus": {"name": "f", "prototype": "int f(int)"}},
            summary="f", content_hash=HASH)
        O.record_observation(
            s, project_id=pid, target_id=tid, source="task", tool="decompile_function",
            args={"function": "f", "depth": 2}, result_kind="decompilation",
            payload={"focus": {"name": "f", "prototype": "int f(char*)"}},
            summary="f", content_hash=HASH)
        a, _ = _attrs(s, pid, tid, "f")
        assert a.get("prototype") == "int f(char*)"  # the later value wins
        assert len(a.get("provenance") or []) == 2  # both observations recorded
        # And one merged fact row, not two parallel ones.
        assert s.query(EnrichmentFact).filter(
            EnrichmentFact.subject_kind == "name", EnrichmentFact.subject_key == "f",
            EnrichmentFact.fact_kind == "attrs").count() == 1


def test_extract_structs_filters_noise_by_name_not_just_flag():
    """The struct filter is name-based, not flag-based (finding NG). Ghidra's `builtin`
    flag is unreliable — it marks the bundled Elf64_*/_IO_*/evp_* types builtin:false (so
    the flag alone leaks them into the graph) while flagging std::*. Program-defined
    structs are kept, even small/empty ones; only compiler/library/ELF noise is dropped."""
    payload = {"structs": [
        # Bundled noise Ghidra reports as builtin:false — must still be dropped (by name).
        {"name": "Elf64_Shdr", "size": 64, "builtin": False,
         "fields": [{"name": "sh_name", "type": "dword", "offset": 0}]},
        {"name": "_IO_FILE", "size": 216, "builtin": False, "fields": []},
        {"name": "evp_pkey_ctx_st", "size": 80, "builtin": False, "fields": []},
        # Correctly-flagged C++ runtime noise — dropped by the flag.
        {"name": "std::vector", "size": 24, "builtin": True, "fields": []},
        # Real program structs — kept (Circle is empty/size-1 but not noise).
        {"name": "Circle", "size": 1, "builtin": False, "fields": []},
        {"name": "config_t", "size": 16, "builtin": False,
         "fields": [{"name": "port", "type": "int", "offset": 0}]},
    ]}
    kept = {f.subject_key for f in E._extract_structs(payload)}
    assert kept == {"Circle", "config_t"}, kept
