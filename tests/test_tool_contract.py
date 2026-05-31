"""Guard the MCP tool contract so the graph an agent builds is complete + low-variance.

These tests fail if a tool ships without a substantive description, if a node/edge type
lacks an attribute schema (the agent wouldn't know what to populate), or if the key
create/update tools stop telling the agent what's expected. The goal: the same analysis
run twice converges on the same graph.
"""

from hexgraph.db.models import EdgeType, NodeType
from hexgraph.engine import mcp_tools as M
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
    assert "get_schemas" in by_name["create_node"] and "is_sink" in by_name["create_node"].lower() \
        or "is_sink" in by_name["create_node"]
    assert "target_id" in by_name["create_node"]
    # create_edge must point at the per-type edge attrs
    assert "get_schemas" in by_name["create_edge"]
    # verify_poc must document both flavours + the nonce
    assert "{{NONCE}}" in by_name["verify_poc"] and "features.network" in by_name["verify_poc"]
    # http_request must exist and require network
    assert "features.network" in by_name["http_request"]
