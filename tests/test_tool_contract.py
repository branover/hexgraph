"""Guard the MCP tool contract so the graph an agent builds is complete + low-variance.

These tests fail if a tool ships without a substantive description, if a node/edge type
lacks an attribute schema (the agent wouldn't know what to populate), or if the key
create/update tools stop telling the agent what's expected. The goal: the same analysis
run twice converges on the same graph.
"""

from hexgraph.db.models import EdgeType, NodeType
from hexgraph.agent import mcp_tools as M
from hexgraph.engine.edge_schemas import EDGE_ATTRIBUTE_SCHEMAS
from hexgraph.engine.node_schemas import NODE_ATTRIBUTE_SCHEMAS, describe_nodes


def test_every_node_type_has_a_schema_with_guidance():
    for t in NodeType:
        if t == NodeType.task:
            continue
        spec = NODE_ATTRIBUTE_SCHEMAS.get(t.value)
        assert spec, f"node type {t.value} has no attribute schema"
        assert spec.get("use_when"), f"{t.value} schema missing use_when guidance"
        assert spec.get("description"), f"{t.value} schema missing description"
        assert spec.get("attributes"), f"{t.value} schema lists no attributes"


def test_locatable_node_types_recommend_attributes():
    # the types an agent fills in by hand should each name at least one expected attr,
    # so a populated node is the norm rather than the exception.
    for t in ("function", "symbol", "input", "sink", "endpoint", "param", "socket"):
        recs = [n for n, a in NODE_ATTRIBUTE_SCHEMAS[t]["attributes"].items() if a.get("recommended")]
        assert recs, f"{t} recommends no attributes — the agent has nothing to populate"


def test_every_edge_type_has_a_schema_or_is_structural():
    # An agent draws *semantic* edges via create_edge(attrs=…); those MUST be documented.
    # The rest are either structural (self-explanatory containment/derivation) or created by
    # a dedicated tool that fills them in (link_evidence → confirms/refutes/supports/
    # contradicts; annotate → annotates; recon/dedup → imports_/exports_symbol, produced_by,
    # duplicate_of, dataflow_hint), so they need no freeform attr schema.
    structural = {"contains", "about", "instance_of_pattern", "related_to", "links_against",
                  "derived_from", "imports_symbol", "exports_symbol", "duplicate_of",
                  "produced_by", "confirms", "refutes", "supports", "contradicts",
                  "annotates", "dataflow_hint"}
    for t in EdgeType:
        assert t.value in EDGE_ATTRIBUTE_SCHEMAS or t.value in structural, \
            f"edge type {t.value} has neither an attribute schema nor a structural exemption"


def test_get_schemas_advertises_node_and_edge_contracts():
    gs = M.get_schemas()
    for key in ("node_attribute_schemas", "node_attributes_note", "edge_attribute_schemas",
                "node_types", "edge_types", "finding"):
        assert key in gs, f"get_schemas missing {key}"
    # the sink-vs-symbol rule must be surfaced (the source of the duplicate-`system` confusion)
    assert "is_sink" in gs["node_attributes_note"]
    assert set(describe_nodes()) == set(gs["node_attribute_schemas"])


def test_catalog_tools_are_documented():
    seen = set()
    for spec in M.catalog():
        name, desc, schema = spec["name"], spec["description"], spec["schema"]
        assert name not in seen, f"duplicate tool {name}"
        seen.add(name)
        assert len(desc) >= 40, f"tool {name} has a thin description ({len(desc)} chars)"
        assert schema.get("type") == "object", f"tool {name} has no object schema"


def test_authoring_tools_state_expectations():
    by_name = {s["name"]: s["description"] for s in M.catalog()}
    # create_node must point at the per-type contract and the sink rule
    assert "get_schemas" in by_name["graph_create_node"] and "is_sink" in by_name["graph_create_node"].lower() \
        or "is_sink" in by_name["graph_create_node"]
    assert "target_id" in by_name["graph_create_node"]
    # create_edge must point at the per-type edge attrs
    assert "get_schemas" in by_name["graph_create_edge"]
    # verify_poc must document both flavours + the nonce
    assert "{{NONCE}}" in by_name["finding_verify_poc"] and "features.network" in by_name["finding_verify_poc"]
    # http_request must exist and require network
    assert "features.network" in by_name["net_http_request"]


# --- discoverability guards (the tool surface stays routable + safe-by-name) ---------

_DOMAINS = {"proj", "target", "re", "fs", "obs", "graph", "journal", "finding", "src",
            "fuzz", "net", "task", "meta"}


def test_every_tool_name_is_domain_namespaced():
    # An agent routes from the NAME alone (no schema fetch under deferred loading), so every
    # name must be `<domain>_<verb>` with a known domain prefix and lowercase snake_case.
    import re
    for spec in M.catalog():
        name = spec["name"]
        assert re.fullmatch(r"[a-z]+(_[a-z0-9]+)+", name), f"{name} is not lowercase domain_verb"
        assert name.split("_")[0] in _DOMAINS, f"{name} has an unknown domain prefix"


def test_closed_value_set_params_carry_a_schema_enum():
    # A param with a semantically closed value set must be a real `enum` (sourced from the
    # codebase), so an agent can't pass a node/edge/finding/task type the engine rejects.
    by_name = {s["name"]: s["schema"]["properties"] for s in M.catalog()}
    must_enum = {
        ("graph_create_node", "node_type"), ("graph_create_edge", "type"),
        ("graph_annotate", "kind"), ("graph_create_socket", "kind"),
        ("graph_link_evidence", "relation"), ("graph_set_hypothesis_status", "status"),
        ("finding_record", "finding_type"), ("finding_update", "severity"),
        ("finding_update", "confidence"), ("finding_update", "status"),
        ("task_run", "type"), ("net_remote_run", "tool"), ("target_rehost", "brand"),
        ("target_register_service", "transport"), ("src_build", "system"),
        ("fuzz_start", "surface"), ("proj_create", "backend"),
        ("finding_reachability", "precondition"), ("journal_list", "author"),
    }
    for tool, param in must_enum:
        prop = by_name[tool].get(param, {})
        assert prop.get("enum"), f"{tool}.{param} should carry a schema enum"
    # the enums must equal the engine's own vocab, not a hand-typed subset (no drift) — these
    # are the exact authorities the engine validates against, so an enum that omits a value
    # would make a legitimate, engine-accepted call fail a strict client.
    from hexgraph.db.models import EdgeType, NodeType
    from hexgraph.engine.hypotheses import RELATIONS, STATUSES
    assert set(by_name["graph_create_node"]["node_type"]["enum"]) == {
        t.value for t in NodeType if t != NodeType.task}
    assert set(by_name["graph_create_edge"]["type"]["enum"]) == {t.value for t in EdgeType}
    assert set(by_name["graph_link_evidence"]["relation"]["enum"]) == set(RELATIONS)
    assert set(by_name["graph_set_hypothesis_status"]["status"]["enum"]) == set(STATUSES)
    # remote_run's allowlist = remote_probe.TOOLS keys + the `ls` op (the probe isn't host-
    # importable, so pin the two the original list dropped/wronged as a regression lock).
    remote_tools = set(by_name["net_remote_run"]["tool"]["enum"])
    assert {"processes_full", "ls"} <= remote_tools and len(remote_tools) == 12
    # build/fuzz enums must ALSO equal their importable authorities (they were hand-typed once
    # and that re-introduced the drift hazard — these lock them to the source).
    from hexgraph.engine.build.build import BUILD_SYSTEMS
    from hexgraph.engine.fuzzers.base import SURFACE_ENGINES, SURFACES
    assert set(by_name["src_build"]["system"]["enum"]) == set(BUILD_SYSTEMS)
    assert set(by_name["fuzz_start"]["surface"]["enum"]) == set(SURFACES)
    assert set(by_name["fuzz_start"]["engine"]["enum"]) == {e for es in SURFACE_ENGINES.values() for e in es}
    # the reachability precondition enum is the engine's PRECONDITIONS authority (no drift).
    from hexgraph.engine.assurance import PRECONDITIONS
    assert set(by_name["finding_reachability"]["precondition"]["enum"]) == set(PRECONDITIONS)
    # the journal author enum is the engine's AUTHORS authority (no drift).
    from hexgraph.engine.journal import AUTHORS
    assert set(by_name["journal_list"]["author"]["enum"]) == set(AUTHORS)


def test_gated_tools_name_their_feature_in_the_description():
    # No agent should learn a capability tier exists only by being refused: every tool that
    # touches the network / executes / boots an image / edits source declares its features.* gate.
    by_name = {s["name"]: s["description"] for s in M.catalog()}
    gated = ["target_register_service", "target_register_remote", "target_rehost",
             "re_recover_constant", "finding_verify_poc", "net_http_request", "net_tcp_request",
             "net_remote_list_files", "net_remote_read_file", "net_remote_run", "net_remote_launch",
             "src_build", "src_save_revision", "fuzz_start", "fuzz_list_environments"]
    for name in gated:
        assert "features." in by_name[name], f"{name} doesn't name its features.* gate"
